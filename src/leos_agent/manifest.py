"""Tool manifest metadata and JSON Schema validation via jsonschema."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
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


TOOL_MANIFEST_SCHEMA: JSONSchema = {
    "type": "object",
    "required": ["name", "version", "permissions", "risk", "reversibility", "input_schema"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
        "permissions": {
            "type": "array",
            "items": {"type": "string", "enum": [permission.value for permission in Permission]},
        },
        "risk": {"type": "string", "enum": [risk.value for risk in RiskLevel]},
        "reversibility": {"type": "string", "enum": [value.value for value in Reversibility]},
        "input_schema": {"type": "object"},
        "output_schema": {"type": "object"},
        "timeout_ms": {"type": "integer", "minimum": 1},
        "network_access": {"type": "boolean"},
        "filesystem_scope": {"type": "string"},
        "secrets_allowed": {"type": "boolean"},
        "sandbox_policy": {"type": "string", "enum": [policy.value for policy in SandboxPolicy]},
        "requires_human_for": {"type": "array", "items": {"type": "string"}},
        "rollback_reliability": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "compensation_strategy": {"type": "string", "enum": [value.value for value in CompensationStrategy]},
    },
    "additionalProperties": False,
}


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
                    "preconditions": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/condition"},
                    },
                    "postconditions": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/condition"},
                    },
                    "invariants": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/condition"},
                    },
                },
                "additionalProperties": False,
            },
        },
    },
    "$defs": {
        "condition": {
            "type": "object",
            "required": ["variable"],
            "properties": {
                "variable": {"type": "string", "minLength": 1},
                "operator": {
                    "type": "string",
                    "enum": ["exists", "not_exists", "equals"],
                    "default": "exists",
                },
                "value": {},
                "trust_level": {
                    "type": "string",
                    "enum": [
                        "verified",
                        "observed",
                        "user_provided",
                        "tool_reported",
                        "model_inferred",
                        "untrusted_external",
                    ],
                },
            },
            "additionalProperties": False,
        }
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


def validate_tool_manifest(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    return validate_json_schema(data, TOOL_MANIFEST_SCHEMA)


def tool_manifest_from_mapping(data: Mapping[str, Any]) -> ToolManifest:
    issues = validate_tool_manifest(data)
    if issues:
        formatted = "; ".join(f"{issue['path']}: {issue['message']}" for issue in issues)
        raise ValueError(f"Invalid tool manifest: {formatted}")
    return ToolManifest(
        name=str(data["name"]),
        version=str(data["version"]),
        permissions=tuple(Permission(value) for value in data["permissions"]),
        risk=RiskLevel(str(data["risk"])),
        reversibility=Reversibility(str(data["reversibility"])),
        input_schema=dict(data["input_schema"]),
        output_schema=dict(data.get("output_schema", {})),
        timeout_ms=int(data.get("timeout_ms", 3000)),
        network_access=bool(data.get("network_access", False)),
        filesystem_scope=str(data.get("filesystem_scope", "none")),
        secrets_allowed=bool(data.get("secrets_allowed", False)),
        sandbox_policy=SandboxPolicy(str(data.get("sandbox_policy", SandboxPolicy.NONE.value))),
        requires_human_for=tuple(str(value) for value in data.get("requires_human_for", ())),
        rollback_reliability=float(data.get("rollback_reliability", 1.0)),
        compensation_strategy=CompensationStrategy(
            str(data.get("compensation_strategy", CompensationStrategy.NONE.value))
        ),
    )


def load_tool_manifest_file(path: str | Path) -> ToolManifest:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("Tool manifest must be a JSON object")
    return tool_manifest_from_mapping(data)


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
