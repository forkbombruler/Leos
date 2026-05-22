"""Registry for validating tool manifests against runtime tools."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .enums import CompensationStrategy, Reversibility, _risk_value
from .errors import LeosError
from .manifest import ToolManifest, tool_manifest_from_mapping, validate_tool_manifest
from .tools import Tool, ToolSpec


class ToolManifestRegistryError(LeosError):
    """Raised when tool manifest registration or validation fails."""


class ToolManifestRegistry:
    """In-memory registry of tool manifest metadata."""

    def __init__(self) -> None:
        self.manifests: dict[str, ToolManifest] = {}

    def register(self, manifest: ToolManifest) -> None:
        normalized = self._normalize_manifest(manifest)
        if normalized.name in self.manifests:
            raise ToolManifestRegistryError(f"Tool manifest already registered: {normalized.name}")
        self._validate_manifest_semantics(normalized)
        self.manifests[normalized.name] = normalized

    def unregister(self, name: str) -> None:
        if name not in self.manifests:
            raise ToolManifestRegistryError(f"Tool manifest not registered: {name}")
        del self.manifests[name]

    def get(self, name: str) -> ToolManifest:
        if name not in self.manifests:
            raise ToolManifestRegistryError(f"Tool manifest not registered: {name}")
        return self.manifests[name]

    def names(self) -> list[str]:
        return sorted(self.manifests)

    def validate_against_tool(self, tool: Tool) -> None:
        manifest = self.get(tool.spec.name)
        spec = tool.spec
        if manifest.name != spec.name:
            raise ToolManifestRegistryError("Manifest name does not match tool spec")
        if tuple(manifest.permissions) != tuple(spec.permissions):
            raise ToolManifestRegistryError("Manifest permissions do not match tool spec")
        if _risk_value(manifest.risk) < _risk_value(spec.default_risk):
            raise ToolManifestRegistryError("Manifest risk is lower than tool spec risk")
        if manifest.risk != spec.default_risk:
            raise ToolManifestRegistryError("Manifest risk does not match tool spec")
        if manifest.secrets_allowed and not spec.secrets_allowed:
            raise ToolManifestRegistryError("Manifest allows secrets but tool spec does not")
        if manifest.secrets_allowed != spec.secrets_allowed:
            raise ToolManifestRegistryError("Manifest secrets_allowed does not match tool spec")
        if manifest.input_schema != spec.input_schema:
            raise ToolManifestRegistryError("Manifest input_schema does not match tool spec")
        if manifest.output_schema != spec.output_schema:
            raise ToolManifestRegistryError("Manifest output_schema does not match tool spec")

    def load_directory(self, path: Path) -> None:
        for manifest_path in sorted(path.glob("*.json")):
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                if not isinstance(data, Mapping):
                    raise ToolManifestRegistryError("manifest must be a JSON object")
                self.register(tool_manifest_from_mapping(data))
            except Exception as exc:
                reason = str(exc) if isinstance(exc, ToolManifestRegistryError) else type(exc).__name__
                raise ToolManifestRegistryError(f"{manifest_path.name}: {reason}") from exc

    def to_tool_specs(self) -> dict[str, ToolSpec]:
        return {
            name: ToolSpec(
                name=manifest.name,
                description=f"Manifest-declared tool: {manifest.name}",
                permissions=tuple(manifest.permissions),
                default_risk=manifest.risk,
                reversibility=manifest.reversibility,
                rollback_reliability=manifest.rollback_reliability,
                compensation_strategy=manifest.compensation_strategy,
                version=manifest.version,
                input_schema=manifest.input_schema,
                output_schema=manifest.output_schema,
                timeout_ms=manifest.timeout_ms,
                network_access=manifest.network_access,
                egress_host=manifest.egress_host,
                egress_methods=tuple(manifest.egress_methods),
                filesystem_scope=manifest.filesystem_scope,
                secrets_allowed=manifest.secrets_allowed,
                sandbox_policy=manifest.sandbox_policy,
                requires_human_for=manifest.requires_human_for,
            )
            for name, manifest in self.manifests.items()
        }

    @staticmethod
    def _normalize_manifest(manifest: ToolManifest) -> ToolManifest:
        data = _manifest_to_mapping(manifest)
        issues = validate_tool_manifest(data)
        if issues:
            formatted = "; ".join(f"{issue['path']}: {issue['message']}" for issue in issues)
            raise ToolManifestRegistryError(f"Invalid tool manifest: {formatted}")
        try:
            return tool_manifest_from_mapping(data)
        except Exception as exc:
            raise ToolManifestRegistryError(f"Invalid tool manifest: {type(exc).__name__}") from exc

    @staticmethod
    def _validate_manifest_semantics(manifest: ToolManifest) -> None:
        if not manifest.name:
            raise ToolManifestRegistryError("Manifest name must be non-empty")
        if not isinstance(manifest.input_schema, dict) or not isinstance(manifest.output_schema, dict):
            raise ToolManifestRegistryError("Manifest schemas must be JSON schema objects")
        if (
            manifest.reversibility is Reversibility.IRREVERSIBLE
            and manifest.compensation_strategy is CompensationStrategy.UNDO
        ):
            raise ToolManifestRegistryError("Irreversible tools cannot use undo compensation")


def _manifest_to_mapping(manifest: ToolManifest) -> dict[str, Any]:
    return {
        "name": manifest.name,
        "version": manifest.version,
        "permissions": [getattr(permission, "value", permission) for permission in manifest.permissions],
        "risk": getattr(manifest.risk, "value", manifest.risk),
        "reversibility": getattr(manifest.reversibility, "value", manifest.reversibility),
        "input_schema": manifest.input_schema,
        "output_schema": manifest.output_schema,
        "timeout_ms": manifest.timeout_ms,
        "network_access": manifest.network_access,
        "egress_host": manifest.egress_host,
        "egress_methods": list(manifest.egress_methods),
        "filesystem_scope": manifest.filesystem_scope,
        "secrets_allowed": manifest.secrets_allowed,
        "sandbox_policy": getattr(manifest.sandbox_policy, "value", manifest.sandbox_policy),
        "requires_human_for": list(manifest.requires_human_for),
        "rollback_reliability": manifest.rollback_reliability,
        "compensation_strategy": getattr(manifest.compensation_strategy, "value", manifest.compensation_strategy),
    }
