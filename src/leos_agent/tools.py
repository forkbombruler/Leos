"""Tool protocol, registry, and built-in tools."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .enums import (
    CompensationStrategy,
    Permission,
    Reversibility,
    RiskLevel,
    SandboxPolicy,
)
from .errors import (
    DryRunFailed,
    LeosError,
    SchemaValidationFailed,
    WorkspaceEscapeBlocked,
)
from .manifest import JSONSchema, ToolManifest, validate_json_schema
from .state import WorldState


class Secret:
    """Wrapper that marks a value as secret.

    Secrets are only unwrapped when passed to tools with `secrets_allowed=True`.
    In all other contexts (audit logs, memory, untrusted tools), they are redacted.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def __repr__(self) -> str:
        return "<secret>"

    def unwrap(self) -> str:
        return self._value


def _redact_secrets(arguments: Mapping[str, Any]) -> dict[str, Any]:
    return {k: "<secret>" if isinstance(v, Secret) else v for k, v in arguments.items()}


def _contains_secrets(arguments: Mapping[str, Any]) -> bool:
    return any(isinstance(v, Secret) for v in arguments.values())


@dataclass
class ToolResult:
    ok: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    observed_state_delta: dict[str, Any] = field(default_factory=dict)
    rollback_token: dict[str, Any] | None = None
    error: LeosError | None = None


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    permissions: Sequence[Permission]
    default_risk: RiskLevel = RiskLevel.LOW
    reversible: bool = False
    reversibility: Reversibility | None = None
    rollback_reliability: float = 1.0
    compensation_strategy: CompensationStrategy = CompensationStrategy.NONE
    version: str = "0.1.0"
    input_schema: JSONSchema = field(default_factory=dict)
    output_schema: JSONSchema = field(default_factory=dict)
    timeout_ms: int = 3000
    network_access: bool = False
    filesystem_scope: str = "none"
    secrets_allowed: bool = False
    sandbox_policy: SandboxPolicy = SandboxPolicy.NONE
    requires_human_for: Sequence[str] = ()
    causal_contract: Any | None = None

    def __post_init__(self) -> None:
        reversibility = self.reversibility
        if reversibility is None:
            reversibility = Reversibility.REVERSIBLE if self.reversible else Reversibility.IRREVERSIBLE
        else:
            reversibility = Reversibility(reversibility)
        compensation_strategy = CompensationStrategy(self.compensation_strategy)
        sandbox_policy = SandboxPolicy(self.sandbox_policy)
        if not 0.0 <= self.rollback_reliability <= 1.0:
            raise ValueError("rollback_reliability must be between 0.0 and 1.0")
        object.__setattr__(self, "reversibility", reversibility)
        object.__setattr__(self, "reversible", reversibility is Reversibility.REVERSIBLE)
        object.__setattr__(self, "compensation_strategy", compensation_strategy)
        object.__setattr__(self, "sandbox_policy", sandbox_policy)

    def manifest(self) -> ToolManifest:
        return ToolManifest(
            name=self.name,
            version=self.version,
            permissions=self.permissions,
            risk=self.default_risk,
            reversibility=self.reversibility or Reversibility.IRREVERSIBLE,
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            timeout_ms=self.timeout_ms,
            network_access=self.network_access,
            filesystem_scope=self.filesystem_scope,
            secrets_allowed=self.secrets_allowed,
            sandbox_policy=self.sandbox_policy,
            requires_human_for=self.requires_human_for,
            rollback_reliability=self.rollback_reliability,
            compensation_strategy=self.compensation_strategy,
        )

    def validate_input(self, arguments: Mapping[str, Any]) -> list[dict[str, Any]]:
        return validate_json_schema(arguments, self.input_schema)

    def validate_output(self, output: Mapping[str, Any]) -> list[dict[str, Any]]:
        return validate_json_schema(output, self.output_schema)


class Tool(Protocol):
    spec: ToolSpec

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult: ...

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult: ...

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult: ...


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.spec.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.spec.name}")
        self._tools[tool.spec.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name]

    def names(self) -> list[str]:
        return sorted(self._tools)


class EchoTool:
    spec = ToolSpec(
        name="echo",
        description="Return a message and record it in observed state.",
        permissions=(),
        default_risk=RiskLevel.LOW,
        reversible=False,
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        if "message" not in arguments:
            return ToolResult(False, "Missing required argument: message")
        return ToolResult(True, f"Would echo: {arguments['message']}")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        message = str(arguments["message"])
        return ToolResult(True, message, observed_state_delta={"last_echo": message})

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Echo has no rollback side effect")


class SafeFileWriteTool:
    """A reversible file writer constrained to a workspace root."""

    spec = ToolSpec(
        name="safe_file_write",
        description="Write a UTF-8 file inside the configured workspace root.",
        permissions=(Permission.WRITE_FILES,),
        default_risk=RiskLevel.MEDIUM,
        reversible=True,
        reversibility=Reversibility.REVERSIBLE,
        compensation_strategy=CompensationStrategy.UNDO,
        input_schema={
            "type": "object",
            "required": ["path", "content"],
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "file_written": {"type": "string"},
            },
            "additionalProperties": True,
        },
        output_schema={
            "type": "object",
            "properties": {
                "file_written": {"type": "string"},
            },
            "additionalProperties": True,
        },
        filesystem_scope="workspace",
        sandbox_policy=SandboxPolicy.WORKSPACE,
        requires_human_for=("outside_workspace",),
    )

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, path: str) -> Path:
        resolved = (self.workspace_root / path).resolve()
        if os.path.commonpath([self.workspace_root, resolved]) != str(self.workspace_root):
            raise WorkspaceEscapeBlocked("Path escapes workspace root")
        return resolved

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        schema_issues = self.spec.validate_input(arguments)
        if schema_issues:
            return ToolResult(
                False,
                "Input schema validation failed",
                {"schema_issues": schema_issues},
                error=SchemaValidationFailed("Input schema validation failed"),
            )
        try:
            path = self._resolve(str(arguments["path"]))
        except WorkspaceEscapeBlocked as exc:
            return ToolResult(False, f"Invalid path: {exc}", error=exc)
        except Exception as exc:  # noqa: BLE001 - dry-run should report any validation issue
            return ToolResult(False, f"Invalid path: {exc}", error=DryRunFailed(str(exc)))
        if "content" not in arguments:
            return ToolResult(
                False, "Missing required argument: content", error=DryRunFailed("Missing required argument: content")
            )
        return ToolResult(True, f"Would write {path}", data={"path": str(path)})

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        path = self._resolve(str(arguments["path"]))
        previous = path.read_text(encoding="utf-8") if path.exists() else None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(arguments["content"]), encoding="utf-8")
        return ToolResult(
            True,
            f"Wrote {path}",
            observed_state_delta={"file_written": str(path)},
            rollback_token={"path": str(path), "previous": previous},
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        path = Path(str(token["path"]))
        previous = token.get("previous")
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(str(previous), encoding="utf-8")
        return ToolResult(True, f"Rolled back {path}")


def default_registry(workspace_root: Path | None = None) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(EchoTool())
    if workspace_root:
        registry.register(SafeFileWriteTool(workspace_root))
    return registry
