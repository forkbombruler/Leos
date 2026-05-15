"""Workspace-scoped local developer tools."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import subprocess  # nosec B404
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .enums import CompensationStrategy, Permission, Reversibility, RiskLevel, SandboxPolicy
from .errors import DryRunFailed, LeosError, WorkspaceEscapeBlocked
from .state import WorldState
from .tools import EchoTool, ToolRegistry, ToolResult, ToolSpec

DEFAULT_EXCLUDES = (".git/**", ".venv/**", "__pycache__/**", "*.pyc", "dist/**", "build/**", "*.egg-info/**")
SECRET_ENV_MARKERS = ("TOKEN", "API_KEY", "PASSWORD", "SECRET")


def _resolve_workspace_path(workspace_root: Path, path: str = ".") -> Path:
    root = workspace_root.resolve()
    resolved = (root / path).resolve()
    if os.path.commonpath([root, resolved]) != str(root):
        raise WorkspaceEscapeBlocked("Path escapes workspace root")
    return resolved


def _is_binary(path: Path, sample_size: int = 4096) -> bool:
    try:
        return b"\0" in path.read_bytes()[:sample_size]
    except OSError:
        return False


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(Path(path).name, pattern) for pattern in patterns)


def _safe_test_env() -> dict[str, str]:
    allowed = ("PATH", "PYTHONPATH", "VIRTUAL_ENV")
    return {
        key: value
        for key, value in os.environ.items()
        if key in allowed and not any(marker in key.upper() for marker in SECRET_ENV_MARKERS)
    }


class ListFilesTool:
    spec = ToolSpec(
        name="list_files",
        description="List files recursively inside a workspace.",
        permissions=(Permission.READ_FILES,),
        default_risk=RiskLevel.LOW,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        input_schema={"type": "object", "additionalProperties": True},
        output_schema={
            "type": "object",
            "required": ["files_listed", "file_count"],
            "properties": {"files_listed": {"type": "array"}, "file_count": {"type": "integer"}},
            "additionalProperties": True,
        },
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        try:
            _resolve_workspace_path(self.workspace_root, str(arguments.get("path", ".")))
        except WorkspaceEscapeBlocked as exc:
            return ToolResult(False, str(exc), error=exc)
        return ToolResult(True, "Would list workspace files")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry_run = self.dry_run(arguments, state)
        if not dry_run.ok:
            return dry_run
        base = _resolve_workspace_path(self.workspace_root, str(arguments.get("path", ".")))
        include = tuple(arguments.get("include_globs") or ("*", "**/*"))
        exclude = tuple(arguments.get("exclude_globs") or DEFAULT_EXCLUDES)
        max_files = int(arguments.get("max_files", 1000))
        files: list[str] = []
        for item in sorted(base.rglob("*")):
            if not item.is_file():
                continue
            rel = item.relative_to(self.workspace_root).as_posix()
            if _matches_any(rel, exclude) or not _matches_any(rel, include):
                continue
            files.append(rel)
            if len(files) >= max_files:
                break
        delta = {"files_listed": files, "file_count": len(files)}
        return ToolResult(True, f"Listed {len(files)} file(s)", observed_state_delta=delta)

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "List files has no rollback side effect")


class ReadFileTool:
    spec = ToolSpec(
        name="read_file",
        description="Read a UTF-8 text file inside a workspace.",
        permissions=(Permission.READ_FILES,),
        default_risk=RiskLevel.LOW,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        input_schema={"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}},
        output_schema={"type": "object", "required": ["file_read", "content", "truncated"]},
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        try:
            path = _resolve_workspace_path(self.workspace_root, str(arguments["path"]))
        except WorkspaceEscapeBlocked as exc:
            return ToolResult(False, str(exc), error=exc)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(False, str(exc), error=DryRunFailed(str(exc)))
        if not path.exists() or not path.is_file():
            return ToolResult(False, "File does not exist", error=DryRunFailed("File does not exist"))
        if _is_binary(path):
            return ToolResult(False, "Binary files are not supported", error=DryRunFailed("Binary file"))
        return ToolResult(True, f"Would read {path}")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry_run = self.dry_run(arguments, state)
        if not dry_run.ok:
            return dry_run
        path = _resolve_workspace_path(self.workspace_root, str(arguments["path"]))
        max_bytes = int(arguments.get("max_bytes", 65536))
        raw = path.read_bytes()
        truncated = len(raw) > max_bytes
        content = raw[:max_bytes].decode("utf-8", errors="strict")
        rel = path.relative_to(self.workspace_root).as_posix()
        delta = {"file_read": rel, "content": content, "truncated": truncated}
        return ToolResult(True, f"Read {rel}", observed_state_delta=delta)

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Read file has no rollback side effect")


class PatchFileTool:
    spec = ToolSpec(
        name="patch_file",
        description="Replace a UTF-8 file inside a workspace with rollback support.",
        permissions=(Permission.WRITE_FILES,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.REVERSIBLE,
        compensation_strategy=CompensationStrategy.UNDO,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        input_schema={"type": "object", "required": ["path", "new_content"]},
        output_schema={"type": "object", "required": ["file_patched", "content_hash"]},
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        try:
            path = _resolve_workspace_path(self.workspace_root, str(arguments["path"]))
        except WorkspaceEscapeBlocked as exc:
            return ToolResult(False, str(exc), error=exc)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(False, str(exc), error=DryRunFailed(str(exc)))
        if not isinstance(arguments.get("new_content"), str):
            return ToolResult(False, "new_content must be a string", error=DryRunFailed("Invalid new_content"))
        if path.exists() and _is_binary(path):
            return ToolResult(False, "Binary files are not supported", error=DryRunFailed("Binary file"))
        expected = arguments.get("expected_previous")
        if expected is not None:
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != expected:
                return ToolResult(False, "expected_previous mismatch", error=DryRunFailed("Content mismatch"))
        return ToolResult(True, f"Would patch {path}")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry_run = self.dry_run(arguments, state)
        if not dry_run.ok:
            return dry_run
        path = _resolve_workspace_path(self.workspace_root, str(arguments["path"]))
        previous = path.read_text(encoding="utf-8") if path.exists() else None
        existed = path.exists()
        new_content = str(arguments["new_content"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_content, encoding="utf-8")
        digest = hashlib.sha256(new_content.encode("utf-8")).hexdigest()
        return ToolResult(
            True,
            f"Patched {path}",
            observed_state_delta={"file_patched": str(path), "content_hash": digest},
            rollback_token={"path": str(path), "previous": previous, "existed": existed},
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        path = Path(str(token["path"]))
        if token.get("existed"):
            path.write_text(str(token.get("previous", "")), encoding="utf-8")
        else:
            path.unlink(missing_ok=True)
        return ToolResult(True, f"Rolled back {path}")


class GitDiffTool:
    spec = ToolSpec(
        name="git_diff",
        description="Return git diff for the workspace.",
        permissions=(Permission.READ_FILES,),
        default_risk=RiskLevel.LOW,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        output_schema={"type": "object", "required": ["git_diff", "truncated"]},
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Would run git diff")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        max_output = int(arguments.get("max_output_bytes", 65536))
        try:
            proc = subprocess.run(  # nosec B603,B607
                ["git", "diff"],
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                timeout=float(arguments.get("timeout_seconds", 10)),
                shell=False,  # nosec B603
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(False, f"git diff failed: {exc}", error=LeosError(str(exc)))
        output = proc.stdout or ""
        truncated = len(output) > max_output
        output = output[:max_output]
        if proc.returncode != 0:
            return ToolResult(False, "git diff failed", data={"stderr": proc.stderr, "returncode": proc.returncode})
        return ToolResult(True, "Read git diff", observed_state_delta={"git_diff": output, "truncated": truncated})

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Git diff has no rollback side effect")


class RunTestsTool:
    spec = ToolSpec(
        name="run_tests",
        description="Run local test command inside the workspace.",
        permissions=(Permission.EXECUTE_CODE,),
        default_risk=RiskLevel.HIGH,
        reversibility=Reversibility.IRREVERSIBLE,
        compensation_strategy=CompensationStrategy.MANUAL,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        secrets_allowed=False,
        output_schema={"type": "object", "required": ["tests_ok", "returncode", "stdout", "stderr", "truncated"]},
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        command = arguments.get("argv", ["python", "-m", "unittest", "discover", "-s", "tests"])
        if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
            return ToolResult(False, "argv must be a list of strings", error=DryRunFailed("Invalid argv"))
        return ToolResult(True, "Would run tests")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry_run = self.dry_run(arguments, state)
        if not dry_run.ok:
            return dry_run
        command = list(arguments.get("argv", ["python", "-m", "unittest", "discover", "-s", "tests"]))
        max_output = int(arguments.get("max_output_bytes", 65536))
        try:
            proc = subprocess.run(  # nosec B603
                command,
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                timeout=float(arguments.get("timeout_seconds", 60)),
                env=_safe_test_env(),
                shell=False,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            truncated = len(stdout) > max_output or len(stderr) > max_output
            delta = {
                "tests_ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout[:max_output],
                "stderr": stderr[:max_output],
                "truncated": truncated,
            }
            return ToolResult(proc.returncode == 0, "Tests completed", observed_state_delta=delta)
        except subprocess.TimeoutExpired as exc:
            delta = {"tests_ok": False, "returncode": None, "stdout": "", "stderr": str(exc), "truncated": False}
            return ToolResult(False, "Tests timed out", observed_state_delta=delta, error=LeosError("Tests timed out"))

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Run tests has no rollback capability")


def default_dev_registry(workspace_root: Path, include_execute: bool = False) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(EchoTool())
    registry.register(ListFilesTool(workspace_root))
    registry.register(ReadFileTool(workspace_root))
    registry.register(PatchFileTool(workspace_root))
    registry.register(GitDiffTool(workspace_root))
    if include_execute:
        registry.register(RunTestsTool(workspace_root))
    return registry
