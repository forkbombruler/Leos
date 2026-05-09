"""Sandbox runner abstraction for tool execution isolation.

Provides a protocol and implementations for running commands in
workspace-subprocess, container, or microVM sandboxes.

The workspace subprocess sandbox is NOT a production isolation boundary.
It constrains filesystem access to a workspace root but does not provide
network isolation, memory limits, or OS-level security guarantees.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 — intentional subprocess sandboxing
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .enums import CompensationStrategy, Permission, Reversibility, RiskLevel, SandboxPolicy
from .errors import LeosError, SandboxViolation, WorkspaceEscapeBlocked
from .state import WorldState
from .tools import ToolResult, ToolSpec


class SandboxUnavailable(LeosError):
    """Raised when a sandbox runtime (container, microVM) is not available."""


# -- data classes ----------------------------------------------------------


@dataclass
class SandboxCommand:
    """A single command to execute in a sandbox."""

    argv: list[str]
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 10.0
    max_output_bytes: int = 65536


@dataclass
class SandboxResult:
    """Result of a sandbox command execution."""

    ok: bool
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    message: str = ""


# -- runner protocol -------------------------------------------------------


class SandboxRunner(Protocol):
    """Protocol for sandbox command execution backends."""

    def run(self, command: SandboxCommand) -> SandboxResult: ...


# -- workspace subprocess runner -------------------------------------------


class WorkspaceSubprocessSandboxRunner:
    """Execute commands in a subprocess constrained to a workspace root.

    WARNING: This runner provides filesystem scoping only. It does NOT
    isolate network access, memory, or OS-level attack surface. It is
    suitable for development and testing but is NOT a production
    isolation boundary.
    """

    def __init__(
        self,
        workspace_root: Path,
        allowed_env_keys: Sequence[str] = (),
    ) -> None:
        self.workspace_root = workspace_root.resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.allowed_env_keys = set(allowed_env_keys)

    def run(self, command: SandboxCommand) -> SandboxResult:
        if not command.argv:
            raise SandboxViolation("argv must not be empty")

        if command.cwd is not None:
            cwd = (self.workspace_root / command.cwd).resolve()
            if os.path.commonpath([self.workspace_root, cwd]) != str(self.workspace_root):
                raise WorkspaceEscapeBlocked(f"cwd '{command.cwd}' escapes workspace root")
        else:
            cwd = self.workspace_root

        env: dict[str, str] = {}
        for key in self.allowed_env_keys:
            if key in command.env:
                env[key] = command.env[key]

        try:
            proc = subprocess.run(  # nosec B603 — workspace-scoped
                command.argv,
                capture_output=True,
                cwd=str(cwd),
                env=env if env else None,
                timeout=command.timeout_seconds,
                text=True,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                ok=False,
                returncode=None,
                stdout="",
                stderr="",
                timed_out=True,
                message="Command timed out",
            )
        except OSError as exc:
            return SandboxResult(
                ok=False,
                returncode=None,
                stdout="",
                stderr=str(exc),
                message=f"Command failed to start: {exc}",
            )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        truncated = False
        if len(stdout) > command.max_output_bytes:
            stdout = stdout[: command.max_output_bytes]
            truncated = True
        if len(stderr) > command.max_output_bytes:
            stderr = stderr[: command.max_output_bytes]
            truncated = True

        return SandboxResult(
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            truncated=truncated,
            message="Command completed" if proc.returncode == 0 else f"Command exited with {proc.returncode}",
        )


# -- container / microVM placeholders --------------------------------------


class ContainerSandboxRunner:
    """Placeholder for container-based sandbox execution.

    Raises SandboxUnavailable because a container runtime is not bundled.
    """

    def run(self, command: SandboxCommand) -> SandboxResult:
        raise SandboxUnavailable("container sandbox requires external runtime")


class MicroVMSandboxRunner:
    """Placeholder for microVM-based sandbox execution.

    Raises SandboxUnavailable because a microVM runtime is not bundled.
    """

    def run(self, command: SandboxCommand) -> SandboxResult:
        raise SandboxUnavailable("microVM sandbox requires external runtime")


# -- sandbox command tool ---------------------------------------------------


class SandboxCommandTool:
    """Execute a subprocess command inside the workspace sandbox.

    This tool is intentionally NOT registered in `default_registry`.
    If needed, add it explicitly with a conservative policy profile.
    """

    spec = ToolSpec(
        name="sandbox_command",
        description="Run a subprocess command inside the workspace sandbox.",
        permissions=(Permission.EXECUTE_CODE,),
        default_risk=RiskLevel.HIGH,
        reversibility=Reversibility.IRREVERSIBLE,
        compensation_strategy=CompensationStrategy.MANUAL,
        sandbox_policy=SandboxPolicy.WORKSPACE,
        secrets_allowed=False,
        filesystem_scope="workspace",
        input_schema={
            "type": "object",
            "required": ["argv"],
            "properties": {
                "argv": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"},
                },
                "cwd": {"type": "string"},
                "timeout_seconds": {"type": "number"},
            },
            "additionalProperties": False,
        },
    )

    def __init__(self, workspace_root: Path) -> None:
        self.runner = WorkspaceSubprocessSandboxRunner(workspace_root)

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        argv = arguments.get("argv", [])
        if not isinstance(argv, list) or not argv:
            return ToolResult(False, "argv must be a non-empty list of strings")
        cwd = arguments.get("cwd")
        if cwd is not None and (not isinstance(cwd, str) or not cwd.strip()):
            return ToolResult(False, "cwd must be a non-empty string")
        return ToolResult(True, f"Would run: {' '.join(str(a) for a in argv)}")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        argv = [str(a) for a in arguments.get("argv", [])]
        cmd = SandboxCommand(
            argv=argv,
            cwd=str(arguments["cwd"]) if arguments.get("cwd") else None,
            timeout_seconds=float(arguments.get("timeout_seconds", 10.0)),
        )
        result = self.runner.run(cmd)
        return ToolResult(
            ok=result.ok,
            message=result.message,
            data={
                "stdout": result.stdout,
                "stderr": result.stderr,
                "timed_out": result.timed_out,
                "truncated": result.truncated,
            },
            observed_state_delta={
                "command_returncode": result.returncode,
                "command_ok": result.ok,
            },
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Sandbox command has no rollback capability")
