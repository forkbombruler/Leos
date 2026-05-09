"""Tool manifest metadata and minimal JSON Schema validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Sequence

from .enums import CompensationStrategy, Permission, Reversibility, RiskLevel, SandboxPolicy


JSONSchema = Dict[str, Any]


@dataclass(frozen=True)
class ToolManifest:
    name: str
    version: str
    permissions: Sequence[Permission]
    risk: RiskLevel
    reversibility: Reversibility
    input_schema: JSONSchema
    output_schema: JSONSchema = field(default_factory=dict)
    timeout_ms: int = 3000
    network_access: bool = False
    filesystem_scope: str = "none"
    secrets_allowed: bool = False
    sandbox_policy: SandboxPolicy = SandboxPolicy.NONE
    requires_human_for: Sequence[str] = ()
    rollback_reliability: float = 1.0
    compensation_strategy: CompensationStrategy = CompensationStrategy.NONE


TASK_FILE_SCHEMA: JSONSchema = {
    "type": "object",
    "required": ["goal", "steps"],
    "properties": {
        "goal": {
            "type": "object",
            "required": ["description", "success_criteria"],
            "properties": {
                "description": {"type": "string"},
                "success_criteria": {"type": "array"},
                "constraints": {"type": "array"},
                "stop_conditions": {"type": "array"},
                "priority": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        "steps": {"type": "array"},
    },
    "additionalProperties": False,
}


PLAN_PROPOSAL_SCHEMA: JSONSchema = {
    "type": "object",
    "required": ["steps", "rationale"],
    "properties": {
        "steps": {"type": "array"},
        "rationale": {"type": "string"},
        "estimated_cost": {"type": "number"},
        "expected_benefit": {"type": "number"},
    },
    "additionalProperties": False,
}


def validate_task_file(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    return validate_json_schema(data, TASK_FILE_SCHEMA)


def validate_json_schema(instance: Any, schema: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Validate a small, dependency-free subset of JSON Schema.

    Supported keywords: type, required, properties, additionalProperties.
    This is intentionally narrow until the runtime adopts a full schema engine.
    """

    if not schema:
        return []
    issues: list[dict[str, Any]] = []
    _validate_node(instance, schema, path="$", issues=issues)
    return issues


def _validate_node(instance: Any, schema: Mapping[str, Any], *, path: str, issues: list[dict[str, Any]]) -> None:
    expected_type = schema.get("type")
    if expected_type and not _matches_type(instance, str(expected_type)):
        issues.append(
            {
                "path": path,
                "reason": "type_mismatch",
                "expected": expected_type,
                "observed": type(instance).__name__,
            }
        )
        return

    if expected_type != "object":
        return
    if not isinstance(instance, Mapping):
        return

    properties = schema.get("properties", {})
    required = schema.get("required", ())
    for key in required:
        if key not in instance:
            issues.append({"path": f"{path}.{key}", "reason": "required_missing"})

    if isinstance(properties, Mapping):
        for key, child_schema in properties.items():
            if key in instance and isinstance(child_schema, Mapping):
                _validate_node(instance[key], child_schema, path=f"{path}.{key}", issues=issues)

    if schema.get("additionalProperties", True) is False and isinstance(properties, Mapping):
        allowed = set(properties)
        for key in instance:
            if key not in allowed:
                issues.append({"path": f"{path}.{key}", "reason": "additional_property_not_allowed"})


def _matches_type(value: Any, expected_type: str) -> bool:
    if expected_type == "object":
        return isinstance(value, Mapping)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "null":
        return value is None
    return True
