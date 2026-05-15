"""Tool-level causal contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .causal import ActionConsequence, CausalEffect
from .state import WorldState


@dataclass(frozen=True)
class CausalContract:
    """A structured causal contract declared by a tool."""

    tool_name: str
    sets: Sequence[str] = ()
    changes: Sequence[str] = ()
    preserves: Sequence[str] = ()
    may_change: Sequence[str] = ()
    side_effects: Sequence[str] = ()
    rollback_effects: Sequence[str] = ()
    required_observations: Sequence[str] = ()
    without_action: Mapping[str, Any] = field(default_factory=dict)
    risk_notes: Sequence[str] = ()
    confidence: float = 0.5

    def predictions(self, step: Any, state: WorldState) -> list[ActionConsequence]:
        consequences: list[ActionConsequence] = []
        for variable in self.sets:
            before = state.facts.get(variable, state.assumptions.get(variable))
            expected = step.arguments.get(variable, "changed")
            consequences.append(
                ActionConsequence(
                    variable=variable,
                    before=before,
                    expected_after=expected,
                    confidence=self.confidence,
                    rationale=f"{self.tool_name} causal contract sets {variable}.",
                    effect=CausalEffect.SETS if expected != "changed" else CausalEffect.CHANGES,
                    expected_without_action=self.without_action.get(variable, before),
                )
            )
        for variable in self.changes:
            if variable in self.sets:
                continue
            before = state.facts.get(variable, state.assumptions.get(variable))
            consequences.append(
                ActionConsequence(
                    variable=variable,
                    before=before,
                    expected_after="changed",
                    confidence=self.confidence,
                    rationale=f"{self.tool_name} causal contract changes {variable}.",
                    effect=CausalEffect.CHANGES,
                    expected_without_action=self.without_action.get(variable, before),
                )
            )
        return consequences

    def missing_required_observations(self, observed_state_delta: Mapping[str, Any]) -> list[str]:
        return [key for key in self.required_observations if key not in observed_state_delta]


def safe_file_write_causal_contract() -> CausalContract:
    """Causal contract for the built-in safe file writer."""

    return CausalContract(
        tool_name="safe_file_write",
        sets=("file_written",),
        may_change=("disk_usage",),
        side_effects=("filesystem_modified",),
        rollback_effects=("restores_previous_file_content",),
        required_observations=("file_written",),
        without_action={"file_written": "target_file_unchanged"},
        risk_notes=("Modifies one workspace-scoped file.",),
        confidence=0.9,
    )
