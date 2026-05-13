"""Workspace-scoped developer tools for local code maintenance."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import shutil
import subprocess  # nosec B404 - argv-only subprocess execution for local dev tools
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .enums import CompensationStrategy, Permission, Reversibility, RiskLevel, SandboxPolicy
from .errors import DryRunFailed, SchemaValidationFailed, ToolTimeout, WorkspaceEscapeBlocked
from .state import WorldState
from .tools import EchoTool, ToolRegistry, ToolResult, ToolSpec

DEFAULT_EXCLUDE_GLOBS = (
    ".git",
    ".git/**",
    ".venv",
    ".venv/**",
    "__pycache__",
    "**/__pycache__/**",
    "*.pyc",
    "dist",
    "dist/**",
    "build",
    "build/**",
    "*.egg-info",
    "*.egg-info/**",
)


def _resolve_workspace_path(workspace_root: Path, relative_path: str = ".") -> Path:
    root = workspace_root.resolve()
    target = (root / relative_path).resolve()
    if os.path.commonpath([root, target]) != str(root):
        raise WorkspaceEscapeBlocked("Path escapes workspace root")
    return target


def _relpath(workspace_root: Path, path: Path) -> str:
    return path.resolve().relative_to(workspace_root.resolve()).as_posix()


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data


class ListFilesTool:
    spec = ToolSpec(
        name="list_files",
        description="List files recursively inside the workspace.",
        permissions=(Permission.READ_FILES,),
        default_risk=RiskLevel.LOW,
        reversibility=Reversibility.IRREVERSIBLE,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "include_globs": {"type": "array", "items": {"type": "string"}},
                "exclude_globs": {"type": "array", "items": {"type": "string"}},
                "max_files": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["files_listed", "file_count"],
            "properties": {
                "files_listed": {"type": "array", "items": {"type": "string"}},
                "file_count": {"type": "integer"},
            },
            "additionalProperties": False,
        },
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        issues = self.spec.validate_input(arguments)
        if issues:
            return ToolResult(False, "Input schema validation failed", {"schema_issues": issues})
        try:
            _resolve_workspace_path(self.workspace_root, str(arguments.get("path", ".")))
        except WorkspaceEscapeBlocked as exc:
            return ToolResult(False, str(exc), error=exc)
        return ToolResult(True, "Would list workspace files")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        base = _resolve_workspace_path(self.workspace_root, str(arguments.get("path", ".")))
        include = tuple(str(p) for p in arguments.get("include_globs", ("**",)))
        exclude = (*DEFAULT_EXCLUDE_GLOBS, *(str(p) for p in arguments.get("exclude_globs", ())))
        max_files = int(arguments.get("max_files", 1000))
        files: list[str] = []
        for path in sorted(base.rglob("*")):
            rel = _relpath(self.workspace_root, path)
            if _matches_any(rel, exclude):
                if path.is_dir():
                    continue
                continue
            if not path.is_file():
                continue
            if include and not _matches_any(rel, include):
                continue
            files.append(rel)
            if len(files) >= max_files:
                break
        delta = {"files_listed": files, "file_count": len(files)}
        return ToolResult(True, f"Listed {len(files)} file(s)", data=delta, observed_state_delta=delta)

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "List files has no rollback side effect")


class ReadFileTool:
    spec = ToolSpec(
        name="read_file",
        description="Read a UTF-8 text file inside the workspace.",
        permissions=(Permission.READ_FILES,),
        default_risk=RiskLevel.LOW,
        reversibility=Reversibility.IRREVERSIBLE,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        input_schema={
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
                "max_bytes": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["file_read", "content", "truncated"],
            "properties": {
                "file_read": {"type": "string"},
                "content": {"type": "string"},
                "truncated": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        issues = self.spec.validate_input(arguments)
        if issues:
            return ToolResult(False, "Input schema validation failed", {"schema_issues": issues})
        try:
            path = _resolve_workspace_path(self.workspace_root, str(arguments["path"]))
        except WorkspaceEscapeBlocked as exc:
            return ToolResult(False, str(exc), error=exc)
        if not path.exists() or not path.is_file():
            return ToolResult(False, "File does not exist", error=DryRunFailed("File does not exist"))
        return ToolResult(True, f"Would read {path}")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        path = _resolve_workspace_path(self.workspace_root, str(arguments["path"]))
        max_bytes = int(arguments.get("max_bytes", 65536))
        raw = path.read_bytes()
        if _looks_binary(raw[: max_bytes + 1]):
            return ToolResult(False, "Binary file rejected", error=DryRunFailed("Binary file rejected"))
        truncated = len(raw) > max_bytes
        try:
            content = raw[:max_bytes].decode("utf-8")
        except UnicodeDecodeError as exc:
            return ToolResult(False, "File is not valid UTF-8", error=DryRunFailed(str(exc)))
        delta = {"file_read": _relpath(self.workspace_root, path), "content": content, "truncated": truncated}
        return ToolResult(True, f"Read {path}", data=delta, observed_state_delta=delta)

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Read file has no rollback side effect")


class PatchFileTool:
    spec = ToolSpec(
        name="patch_file",
        description="Replace a workspace text file with new content.",
        permissions=(Permission.WRITE_FILES,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.REVERSIBLE,
        compensation_strategy=CompensationStrategy.UNDO,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        input_schema={
            "type": "object",
            "required": ["path", "new_content"],
            "properties": {
                "path": {"type": "string"},
                "expected_previous": {"type": "string"},
                "new_content": {"type": "string"},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["file_patched", "content_hash"],
            "properties": {
                "file_patched": {"type": "string"},
                "content_hash": {"type": "string"},
            },
            "additionalProperties": False,
        },
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        issues = self.spec.validate_input(arguments)
        if issues:
            return ToolResult(
                False,
                "Input schema validation failed",
                {"schema_issues": issues},
                error=SchemaValidationFailed("Input schema validation failed"),
            )
        try:
            path = _resolve_workspace_path(self.workspace_root, str(arguments["path"]))
        except WorkspaceEscapeBlocked as exc:
            return ToolResult(False, str(exc), error=exc)
        previous = None
        if path.exists():
            raw = path.read_bytes()
            if _looks_binary(raw):
                return ToolResult(False, "Binary file rejected", error=DryRunFailed("Binary file rejected"))
            try:
                previous = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                return ToolResult(False, "File is not valid UTF-8", error=DryRunFailed(str(exc)))
        expected = arguments.get("expected_previous")
        if expected is not None and previous != expected:
            return ToolResult(False, "expected_previous does not match current content")
        return ToolResult(True, f"Would patch {path}", data={"path": str(path)})

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        path = _resolve_workspace_path(self.workspace_root, str(arguments["path"]))
        existed = path.exists()
        previous = path.read_text(encoding="utf-8") if existed else None
        new_content = str(arguments["new_content"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_content, encoding="utf-8")
        digest = hashlib.sha256(new_content.encode("utf-8")).hexdigest()
        delta = {"file_patched": str(path), "content_hash": digest}
        return ToolResult(
            True,
            f"Patched {path}",
            data=delta,
            observed_state_delta=delta,
            rollback_token={"path": str(path), "existed": existed, "previous": previous},
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        path = _resolve_workspace_path(self.workspace_root, str(token["path"]))
        if token.get("existed"):
            path.write_text(str(token.get("previous", "")), encoding="utf-8")
        else:
            path.unlink(missing_ok=True)
        return ToolResult(True, f"Rolled back {path}")


class GitDiffTool:
    spec = ToolSpec(
        name="git_diff",
        description="Return git diff for the workspace repository.",
        permissions=(Permission.READ_FILES,),
        default_risk=RiskLevel.LOW,
        reversibility=Reversibility.IRREVERSIBLE,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        input_schema={
            "type": "object",
            "properties": {
                "timeout_seconds": {"type": "number", "minimum": 0.1},
                "max_output_bytes": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["git_diff", "truncated"],
            "properties": {
                "git_diff": {"type": "string"},
                "truncated": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        issues = self.spec.validate_input(arguments)
        if issues:
            return ToolResult(False, "Input schema validation failed", {"schema_issues": issues})
        if not (self.workspace_root / ".git").exists():
            return ToolResult(False, "Workspace is not a git repository")
        return ToolResult(True, "Would run git diff")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        timeout = float(arguments.get("timeout_seconds", 10.0))
        max_bytes = int(arguments.get("max_output_bytes", 65536))
        git_bin = shutil.which("git")
        if not git_bin:
            return ToolResult(False, "git executable not found")
        try:
            proc = subprocess.run(  # nosec B603 - argv-only git invocation
                [git_bin, "diff"],
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(False, "git diff timed out", error=ToolTimeout("git diff timed out"))
        output = proc.stdout or ""
        truncated = len(output) > max_bytes
        delta = {"git_diff": output[:max_bytes], "truncated": truncated}
        if proc.returncode != 0:
            return ToolResult(False, proc.stderr or "git diff failed", data=delta)
        return ToolResult(True, "git diff completed", data=delta, observed_state_delta=delta)

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Git diff has no rollback side effect")


class RunTestsTool:
    spec = ToolSpec(
        name="run_tests",
        description="Run an argv-only test command inside the workspace.",
        permissions=(Permission.EXECUTE_CODE,),
        default_risk=RiskLevel.HIGH,
        reversibility=Reversibility.IRREVERSIBLE,
        compensation_strategy=CompensationStrategy.MANUAL,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        filesystem_scope="workspace",
        input_schema={
            "type": "object",
            "properties": {
                "argv": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "timeout_seconds": {"type": "number", "minimum": 0.1},
                "max_output_bytes": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
        output_schema={
            "type": "object",
            "required": ["tests_ok", "returncode", "stdout", "stderr", "truncated"],
            "properties": {
                "tests_ok": {"type": "boolean"},
                "returncode": {"type": ["integer", "null"]},
                "stdout": {"type": "string"},
                "stderr": {"type": "string"},
                "truncated": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        issues = self.spec.validate_input(arguments)
        if issues:
            return ToolResult(False, "Input schema validation failed", {"schema_issues": issues})
        argv = arguments.get("argv", ["python", "-m", "unittest", "discover", "-s", "tests"])
        if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
            return ToolResult(False, "argv must be a list of strings")
        return ToolResult(True, f"Would run tests: {' '.join(argv)}")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        dry = self.dry_run(arguments, state)
        if not dry.ok:
            return dry
        argv = [str(value) for value in arguments.get("argv", ["python", "-m", "unittest", "discover", "-s", "tests"])]
        timeout = float(arguments.get("timeout_seconds", 60.0))
        max_bytes = int(arguments.get("max_output_bytes", 65536))
        try:
            proc = subprocess.run(  # nosec B603 - argv-only test command
                argv,
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                timeout=timeout,
                env={},
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            returncode: int | None = proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
            stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
            returncode = None
            delta = _test_delta(False, returncode, stdout, stderr, max_bytes)
            return ToolResult(False, "Test command timed out", data=delta, observed_state_delta=delta)
        delta = _test_delta(returncode == 0, returncode, stdout, stderr, max_bytes)
        return ToolResult(
            returncode == 0,
            "Tests passed" if returncode == 0 else "Tests failed",
            data=delta,
            observed_state_delta=delta,
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Run tests has no rollback capability")


def _test_delta(ok: bool, returncode: int | None, stdout: str, stderr: str, max_bytes: int) -> dict[str, Any]:
    truncated = len(stdout) > max_bytes or len(stderr) > max_bytes
    return {
        "tests_ok": ok,
        "returncode": returncode,
        "stdout": stdout[:max_bytes],
        "stderr": stderr[:max_bytes],
        "truncated": truncated,
    }


def default_dev_registry(workspace_root: Path, *, include_execute: bool = False) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(EchoTool())
    registry.register(ListFilesTool(workspace_root))
    registry.register(ReadFileTool(workspace_root))
    registry.register(PatchFileTool(workspace_root))
    registry.register(GitDiffTool(workspace_root))
    if include_execute:
        registry.register(RunTestsTool(workspace_root))
    return registry
