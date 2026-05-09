"""Tool manifest metadata and JSON Schema validation via jsonschema."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from jsonschema import Draft202012Validator, validators

from .enums import (
    CompensationStrategy,
    Permission,
    Reversibility,
    RiskLevel,
    SandboxPolicy,
)

JSONSchema = dict[str, Any]


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
                "success_criteria": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"},
                },
                "constraints": {"type": "array", "items": {"type": "string"}},
                "stop_conditions": {"type": "array", "items": {"type": "string"}},
                "priority": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["tool_name", "arguments", "reason"],
                "properties": {
                    "tool_name": {"type": "string"},
                    "arguments": {"type": "object"},
                    "reason": {"type": "string", "minLength": 1},
                    "idempotency_key": {"type": "string"},
                    "preconditions": {"type": "array"},
                    "postconditions": {"type": "array"},
                    "invariants": {"type": "array"},
                },
                "additionalProperties": False,
            },
        },
    },
    "additionalProperties": False,
}


PLAN_PROPOSAL_SCHEMA: JSONSchema = {
    "type": "object",
    "required": ["steps", "rationale"],
    "properties": {
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["tool_name", "arguments", "reason"],
                "properties": {
                    "tool_name": {"type": "string"},
                    "arguments": {"type": "object"},
                    "reason": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
        },
        "rationale": {"type": "string", "minLength": 1},
        "estimated_cost": {"type": "number", "minimum": 0},
        "expected_benefit": {"type": "number", "minimum": 0},
    },
    "additionalProperties": False,
}


def _build_validator(schema: Mapping[str, Any]) -> Draft202012Validator:
    return validators.validator_for(schema, default=Draft202012Validator)(schema)


def validate_task_file(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    return validate_json_schema(data, TASK_FILE_SCHEMA)


def validate_json_schema(instance: Any, schema: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not schema:
        return []
    v = _build_validator(schema)
    issues: list[dict[str, Any]] = []
    for error in sorted(v.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        issues.append(
            {
                "path": "/" + "/".join(str(p) for p in error.absolute_path) if error.absolute_path else "$",
                "reason": error.validator,
                "message": error.message,
                "validator": error.validator,
                "expected": error.schema.get("enum") or error.schema,
                "observed": error.instance if hasattr(error, "instance") else None,
            }
        )
    return issues
