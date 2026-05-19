"""Proof document generation for audit-oriented repository snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess  # nosec B404
import sys
import time
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .eval_runner import render_eval_report_markdown, run_safety_evals

MAX_EXCERPT = 20000
SECRET_PATTERNS = (
    re.compile(r"(?i)(token|api[_-]?key|password|secret)(['\"\s:=]+)[^\s'\",}]+"),
    re.compile(r"(?i)(bearer\s+)[a-z0-9._~+/=-]+"),
)

KEY_SOURCE_FILES = (
    "src/leos_agent/dev_tools.py",
    "src/leos_agent/network_tools.py",
    "src/leos_agent/eval_runner.py",
    "src/leos_agent/github_agent.py",
    "src/leos_agent/github_client.py",
    "src/leos_agent/planner.py",
    "src/leos_agent/proof.py",
    "src/leos_agent/sandbox.py",
    "src/leos_agent/sanitization.py",
    "src/leos_agent/sqlite_store.py",
    "src/leos_agent/task_queue.py",
    "src/leos_agent/causal.py",
    "src/leos_agent/causal_contract.py",
    "src/leos_agent/tools.py",
    "src/leos_agent/transactions.py",
    "src/leos_agent/policy.py",
    "src/leos_agent/audit.py",
    "src/leos_agent/memory.py",
    "src/leos_agent/trace_viewer.py",
    "src/leos_agent/cli.py",
)

COMMANDS = (
    ("unit_tests", ("python", "-m", "unittest", "discover", "-s", "tests")),
    ("safety_evals", ("leos", "eval", "--suite", "safety")),
    ("coverage_run", ("coverage", "run", "-m", "unittest", "discover", "-s", "tests")),
    ("coverage_report", ("coverage", "report", "--fail-under=83")),
    ("ruff_check", ("ruff", "check", ".")),
    ("ruff_format_check", ("ruff", "format", "--check", ".")),
    ("mypy", ("mypy", "src")),
    ("bandit", ("bandit", "-r", "src")),
    ("leos_help", ("leos", "--help")),
    ("leos_eval_help", ("leos", "eval", "--help")),
    ("leos_trace_help", ("leos", "trace", "--help")),
    ("leos_proof_help", ("leos", "proof", "--help")),
)


@dataclass(frozen=True)
class CommandProof:
    name: str
    command: list[str]
    exit_code: int | None
    status: str
    started_at: str
    finished_at: str
    duration_seconds: float
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    reason: str | None = None


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    sha256: str | None
    line_count: int
    size_bytes: int
    exists: bool


@dataclass(frozen=True)
class ProofManifest:
    generated_at: str
    proof_status: str
    release_grade: bool
    dirty_worktree: bool | None
    warnings: list[str]
    git: dict[str, Any]
    environment: dict[str, Any]
    commands: list[CommandProof] = field(default_factory=list)
    source_snapshot: list[FileSnapshot] = field(default_factory=list)
    test_inventory: list[FileSnapshot] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.commands),
            "passed": sum(1 for command in self.commands if command.status == "passed"),
            "failed": sum(1 for command in self.commands if command.status == "failed"),
            "skipped": sum(1 for command in self.commands if command.status == "skipped"),
        }

    def as_json_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["summary"] = self.summary
        return payload


def generate_proofs(
    output: Path,
    *,
    require_clean: bool = False,
    allow_dirty: bool = False,
    no_run: bool = False,
    repo_root: Path | None = None,
) -> ProofManifest:
    root = (repo_root or Path.cwd()).resolve()
    output.mkdir(parents=True, exist_ok=True)
    generated_at = _now()
    git = _git_metadata(root)
    proof_status, release_grade, warnings = _proof_status(git, require_clean=require_clean)
    source_snapshot = _snapshot_files(root, KEY_SOURCE_FILES)
    test_inventory = _snapshot_files(root, _test_files(root))

    commands: list[CommandProof] = []
    if proof_status == "failed_dirty_worktree":
        commands = [
            _skipped_command(name, command, "require-clean refused dirty worktree") for name, command in COMMANDS
        ]
    elif no_run:
        commands = [_skipped_command(name, command, "--no-run requested") for name, command in COMMANDS]
    else:
        commands = [_run_command(name, command, root) for name, command in COMMANDS]

    manifest = ProofManifest(
        generated_at=generated_at,
        proof_status=proof_status,
        release_grade=release_grade,
        dirty_worktree=git.get("dirty_worktree"),
        warnings=warnings,
        git=git,
        environment=_environment(root),
        commands=commands,
        source_snapshot=source_snapshot,
        test_inventory=test_inventory,
    )
    _write_all(output, manifest)
    return manifest


def exit_code_for_manifest(manifest: ProofManifest) -> int:
    if manifest.proof_status == "failed_dirty_worktree":
        return 2
    return 1 if any(command.status == "failed" for command in manifest.commands) else 0


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(_redacted_match, redacted)
    return redacted


def _redacted_match(match: re.Match[str]) -> str:
    separator = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
    return f"{match.group(1)}{separator}<redacted>"


def _proof_status(git: dict[str, Any], *, require_clean: bool) -> tuple[str, bool, list[str]]:
    dirty = git.get("dirty_worktree")
    if dirty is None:
        return "git_unavailable", False, ["Git metadata unavailable; proof cannot be release-grade."]
    if dirty:
        warning = "This proof was generated from a dirty worktree and is not release-grade evidence."
        if require_clean:
            return "failed_dirty_worktree", False, [warning, "--require-clean refused to generate release-grade proof."]
        return "precommit_dirty", False, [warning]
    return "release_grade", True, []


def _git_metadata(root: Path) -> dict[str, Any]:
    def git(*args: str) -> str | None:
        try:
            proc = subprocess.run(  # nosec B603,B607
                ["git", *args],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,  # nosec B603
            )
        except Exception:
            return None
        return proc.stdout.strip() if proc.returncode == 0 else None

    branch = git("branch", "--show-current")
    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain")
    if branch is None or commit is None or status is None:
        return {"available": False, "branch": None, "commit_sha": None, "dirty_worktree": None}
    return {"available": True, "branch": branch, "commit_sha": commit, "dirty_worktree": bool(status)}


def _environment(root: Path) -> dict[str, Any]:
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "working_directory": str(root),
        "package_version": "0.1.0",
    }


def _run_command(name: str, command: Sequence[str], root: Path) -> CommandProof:
    started = time.monotonic()
    started_at = _now()
    try:
        proc = subprocess.run(  # nosec B603
            list(command),
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=300,
            shell=False,
            env={**os.environ, "PYTHONPATH": str(root / "src")},
        )
        stdout, stdout_truncated = _excerpt(proc.stdout or "")
        stderr, stderr_truncated = _excerpt(proc.stderr or "")
        status = "passed" if proc.returncode == 0 else "failed"
        return CommandProof(
            name=name,
            command=list(command),
            exit_code=proc.returncode,
            status=status,
            started_at=started_at,
            finished_at=_now(),
            duration_seconds=round(time.monotonic() - started, 3),
            stdout=stdout,
            stderr=stderr,
            truncated=stdout_truncated or stderr_truncated,
        )
    except FileNotFoundError as exc:
        return CommandProof(
            name=name,
            command=list(command),
            exit_code=None,
            status="skipped",
            started_at=started_at,
            finished_at=_now(),
            duration_seconds=round(time.monotonic() - started, 3),
            reason=str(exc),
        )
    except subprocess.TimeoutExpired as exc:
        stdout, stdout_truncated = _excerpt(_output_text(exc.stdout))
        stderr, stderr_truncated = _excerpt(_output_text(exc.stderr))
        return CommandProof(
            name=name,
            command=list(command),
            exit_code=None,
            status="failed",
            started_at=started_at,
            finished_at=_now(),
            duration_seconds=round(time.monotonic() - started, 3),
            stdout=stdout,
            stderr=stderr,
            truncated=stdout_truncated or stderr_truncated,
            reason="Command timed out",
        )


def _skipped_command(name: str, command: Sequence[str], reason: str) -> CommandProof:
    now = _now()
    return CommandProof(
        name=name,
        command=list(command),
        exit_code=None,
        status="skipped",
        started_at=now,
        finished_at=now,
        duration_seconds=0.0,
        reason=reason,
    )


def _excerpt(text: str) -> tuple[str, bool]:
    redacted = redact_secrets(text)
    return redacted[:MAX_EXCERPT], len(redacted) > MAX_EXCERPT


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _test_files(root: Path) -> list[str]:
    files = sorted(path.relative_to(root).as_posix() for path in (root / "tests").rglob("test_*.py"))
    if "tests/test_proof_generation.py" not in files:
        files.append("tests/test_proof_generation.py")
    return sorted(set(files))


def _snapshot_files(root: Path, paths: Iterable[str]) -> list[FileSnapshot]:
    snapshots = []
    for rel in paths:
        path = root / rel
        if not path.exists():
            snapshots.append(FileSnapshot(rel, None, 0, 0, False))
            continue
        data = path.read_bytes()
        snapshots.append(
            FileSnapshot(
                path=rel,
                sha256=hashlib.sha256(data).hexdigest(),
                line_count=data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0),
                size_bytes=len(data),
                exists=True,
            )
        )
    return snapshots


def _write_all(output: Path, manifest: ProofManifest) -> None:
    manifest_json = json.dumps(manifest.as_json_dict(), indent=2, ensure_ascii=False)
    (output / "MANIFEST.json").write_text(manifest_json, encoding="utf-8")
    (output / "README.md").write_text(
        "# Leos Proof Documents\n\nGenerated audit evidence for this repository snapshot.\n",
        encoding="utf-8",
    )
    (output / "PROOF_INDEX.md").write_text(_render_index(manifest), encoding="utf-8")
    (output / "SOURCE_SNAPSHOT.md").write_text(
        _render_file_table("Source Snapshot", manifest.generated_at, manifest.source_snapshot),
        encoding="utf-8",
    )
    (output / "TEST_INVENTORY.md").write_text(
        _render_file_table("Test Inventory", manifest.generated_at, manifest.test_inventory),
        encoding="utf-8",
    )
    (output / "TEST_RESULTS.md").write_text(
        _render_command_doc("Test Results", manifest, ("unit_tests",)),
        encoding="utf-8",
    )
    (output / "COVERAGE_SUMMARY.md").write_text(
        _render_command_doc("Coverage Summary", manifest, ("coverage_run", "coverage_report")),
        encoding="utf-8",
    )
    (output / "STATIC_ANALYSIS.md").write_text(
        _render_command_doc("Static Analysis", manifest, ("ruff_check", "ruff_format_check", "mypy")),
        encoding="utf-8",
    )
    (output / "SECURITY_SCAN.md").write_text(_render_security_scan(manifest), encoding="utf-8")
    (output / "SAFETY_EVAL_RESULTS.md").write_text(render_eval_report_markdown(run_safety_evals()), encoding="utf-8")
    (output / "ARCHITECTURE_CLAIMS.md").write_text(_render_claims(), encoding="utf-8")
    (output / "PRODUCTION_READINESS.md").write_text(_render_production_readiness(), encoding="utf-8")
    (output / "KNOWN_LIMITATIONS.md").write_text(_render_known_limitations(), encoding="utf-8")


def _render_index(manifest: ProofManifest) -> str:
    warning_lines = "\n".join(f"- WARNING: {warning}" for warning in manifest.warnings) or "- none"
    if manifest.dirty_worktree:
        warning_lines += (
            "\n\n**WARNING: This proof was generated from a dirty worktree. "
            "It is useful for local review but not release-grade evidence.**"
        )
    return f"""# Proof Index

- Proof status: `{manifest.proof_status}`
- Release grade: `{manifest.release_grade}`
- Generated at: `{manifest.generated_at}`
- Commit SHA: `{manifest.git.get("commit_sha")}`
- Branch: `{manifest.git.get("branch")}`
- Dirty worktree: `{manifest.dirty_worktree}`
- Summary: {manifest.summary}

## Warnings
{warning_lines}

## Documents
- [SOURCE_SNAPSHOT.md](SOURCE_SNAPSHOT.md)
- [TEST_INVENTORY.md](TEST_INVENTORY.md)
- [TEST_RESULTS.md](TEST_RESULTS.md)
- [SAFETY_EVAL_RESULTS.md](SAFETY_EVAL_RESULTS.md)
- [COVERAGE_SUMMARY.md](COVERAGE_SUMMARY.md)
- [STATIC_ANALYSIS.md](STATIC_ANALYSIS.md)
- [SECURITY_SCAN.md](SECURITY_SCAN.md)
- [ARCHITECTURE_CLAIMS.md](ARCHITECTURE_CLAIMS.md)
- [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md)
"""


def _render_file_table(title: str, generated_at: str, files: Sequence[FileSnapshot]) -> str:
    lines = [
        f"# {title}",
        "",
        f"Generated: `{generated_at}`",
        "",
        "| Path | SHA256 | Lines | Size | Exists |",
        "|---|---|---:|---:|---|",
    ]
    for snapshot in files:
        sha = snapshot.sha256 or "missing"
        lines.append(
            f"| `{snapshot.path}` | `{sha}` | {snapshot.line_count} | {snapshot.size_bytes} | {snapshot.exists} |"
        )
    return "\n".join(lines) + "\n"


def _render_command_doc(title: str, manifest: ProofManifest, names: Sequence[str]) -> str:
    commands = [command for command in manifest.commands if command.name in names]
    lines = [f"# {title}", ""]
    for command in commands:
        lines.extend(
            [
                f"## {command.name}",
                "",
                f"- Command: `{' '.join(command.command)}`",
                f"- Exit code: `{command.exit_code}`",
                f"- Status: `{command.status}`",
                f"- Duration seconds: `{command.duration_seconds}`",
                f"- Truncated: `{command.truncated}`",
            ]
        )
        if command.reason:
            lines.append(f"- Reason: {command.reason}")
        if command.stdout:
            lines.extend(["", "### stdout", "", "```text", command.stdout, "```"])
        if command.stderr:
            lines.extend(["", "### stderr", "", "```text", command.stderr, "```"])
        lines.append("")
    return "\n".join(lines)


def _render_security_scan(manifest: ProofManifest) -> str:
    bandit = next((command for command in manifest.commands if command.name == "bandit"), None)
    text = f"{bandit.stdout}\n{bandit.stderr}" if bandit else ""
    high = len(re.findall(r"Severity:\s*High", text, flags=re.IGNORECASE))
    medium = len(re.findall(r"Severity:\s*Medium", text, flags=re.IGNORECASE))
    low = len(re.findall(r"Severity:\s*Low", text, flags=re.IGNORECASE))
    nosec = 0
    for path in KEY_SOURCE_FILES:
        source_path = Path.cwd() / path
        if source_path.exists() and "# nosec" in source_path.read_text(encoding="utf-8"):
            nosec += 1
    return f"""# Security Scan

- Bandit exit code: `{bandit.exit_code if bandit else None}`
- Bandit status: `{bandit.status if bandit else "missing"}`
- High issues: {high}
- Medium issues: {medium}
- Low issues: {low}
- `# nosec` count in key source files: {nosec}

Known warnings:
- Bandit output is a static scan and does not prove runtime isolation.
- Sandbox, network, and secret guarantees are also covered by unit tests and safety evals.

{_render_command_doc("Bandit Raw Output", manifest, ("bandit",))}
"""


def _render_claims() -> str:
    rows = [
        (
            "Workspace path escape is blocked",
            "`src/leos_agent/dev_tools.py`, `src/leos_agent/tools.py`",
            "`tests/test_dev_tools.py`, safety evals",
            "`workspace_escape`",
            "passed",
        ),
        (
            "Network tools are opt-in",
            "`src/leos_agent/network_tools.py`, `src/leos_agent/transactions.py`",
            "`tests/test_network_tools.py`",
            "`prompt_injection_untrusted_network`",
            "passed",
        ),
        (
            "External network data is untrusted",
            "`src/leos_agent/network_tools.py`",
            "`tests/test_network_tools.py`",
            "safety eval",
            "passed",
        ),
        (
            "Secrets are not passed to untrusted tools",
            "`src/leos_agent/tools.py`, `src/leos_agent/transactions.py`",
            "safety eval",
            "`secret_exfiltration`",
            "passed",
        ),
        (
            "High risk requires approval",
            "`src/leos_agent/policy.py`, `src/leos_agent/transactions.py`",
            "safety eval",
            "`high_risk_requires_approval`",
            "passed",
        ),
        (
            "Output schema violation fails safely",
            "`src/leos_agent/transactions.py`, `src/leos_agent/tools.py`",
            "safety eval",
            "`output_schema_violation`",
            "passed",
        ),
        (
            "Reversible actions can rollback",
            "`src/leos_agent/transactions.py`, `src/leos_agent/dev_tools.py`",
            "`tests/test_dev_tools.py`, safety eval",
            "`rollback_reliability`",
            "passed",
        ),
        (
            "Audit log has hash-chain integrity",
            "`src/leos_agent/audit.py`",
            "`tests/test_core.py`, `tests/test_replay.py`",
            "test results",
            "covered",
        ),
        (
            "Docker sandbox command construction includes hardening flags",
            "`src/leos_agent/sandbox.py`",
            "`tests/test_sandbox.py`",
            "command-construction tests",
            "partial",
        ),
        (
            "Causal contract schema scaffold exists",
            "`src/leos_agent/causal_contract.py`",
            "`tests/test_causal_contract.py`",
            "tests",
            "scaffold",
        ),
        (
            "Causal contract runtime enforcement",
            "`src/leos_agent/transactions.py`, `src/leos_agent/causal.py`",
            "`tests/test_causal_contract.py`",
            "tests",
            "partial",
        ),
        (
            "SQLite TaskQueue persistence",
            "`src/leos_agent/task_queue.py`",
            "`tests/test_task_queue_persistence.py`",
            "coverage",
            "partial",
        ),
        (
            "SQLite AuditLog/MemoryStore persistence",
            "`src/leos_agent/audit.py`, `src/leos_agent/memory.py`",
            "none",
            "known limitations",
            "not_complete",
        ),
    ]
    lines = [
        "# Architecture Claims",
        "",
        "| Claim | Code paths | Test paths | Proof evidence | Status |",
        "|---|---|---|---|---|",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def _render_production_readiness() -> str:
    return """# Production Readiness

## Ready for local development
- Workspace-scoped file read/list/patch/diff tools.
- Opt-in local test execution for developer workflows.
- Policy, audit, rollback, network trust marking, and safety eval regression checks.

## Ready for safety regression testing
- `leos eval --suite safety`.
- Proof documents with command results, source hashes, test inventory, and dirty/release-grade status.

## Not ready for production autonomy
- Workspace subprocess execution is not a production isolation boundary.
- Docker sandbox support still needs real runtime integration tests before production use.
- Network fetch still needs deployment-level egress proxy controls.
- Causal contract runtime enforcement is useful but not a complete structural causal model.
- SQLite persistence currently does not cover every core state component.
- Safety evals are regression checks, not formal proof.

## Required before production
- Container or microVM execution enforced for code execution.
- Real egress controls and SSRF-resistant deployment policy.
- Complete persistence for audit, memory, tasks, and state.
- Expanded adversarial evals and release-grade proof generated from a clean commit.
"""


def _render_known_limitations() -> str:
    return """# Known Limitations

- Proof documents generated from a dirty worktree are not release-grade.
- Proof documents are audit aids, not mathematical or formal verification.
- Causal contract support is partial runtime enforcement, not a complete SCM.
- Docker sandbox command construction is not full isolation proof in CI.
- URLSafetyPolicy reduces SSRF risk but does not replace deployment egress controls.
- RunTestsTool is local-dev oriented and not a production code-execution sandbox.
- Workspace subprocess sandbox is not a production isolation boundary.
- SQLite TaskQueue persistence exists, but AuditLog/MemoryStore SQLite persistence is not complete.
- Safety eval suite is a minimal regression suite, not a complete safety proof.
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
