"""Tool-level causal contract metadata."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .causal import ActionConsequence, CausalEffect
from .plans import StateCondition
from .state import WorldState


@dataclass(frozen=True)
class CausalContract:
    tool_name: str
    preconditions: Sequence[StateCondition] = ()
    sets: Sequence[str] = ()
    changes: Sequence[str] = ()
    preserves: Sequence[str] = ()
    may_change: Sequence[str] = ()
    side_effects: Sequence[str] = ()
    rollback_effects: Sequence[str] = ()
    required_observations: Sequence[str] = ()
    without_action: str = ""
    risk_notes: Sequence[str] = ()
    confidence: float = 0.5

    def predictions(self, step: Any, state: WorldState) -> list[ActionConsequence]:
        predictions: list[ActionConsequence] = []
        for variable in self.sets:
            before = state.facts.get(variable, state.assumptions.get(variable))
            predictions.append(
                ActionConsequence(
                    variable=variable,
                    before=before,
                    expected_after=step.arguments.get(variable, "changed"),
                    confidence=self.confidence,
                    rationale=f"{self.tool_name} causal contract sets {variable}",
                    effect=CausalEffect.SETS,
                    expected_without_action=before,
                )
            )
        for variable in self.changes:
            before = state.facts.get(variable, state.assumptions.get(variable))
            predictions.append(
                ActionConsequence(
                    variable=variable,
                    before=before,
                    expected_after="changed",
                    confidence=self.confidence,
                    rationale=f"{self.tool_name} causal contract changes {variable}",
                    effect=CausalEffect.CHANGES,
                    expected_without_action=before,
                )
            )
        return predictions

    def missing_required_observations(self, observed_delta: dict[str, Any]) -> list[str]:
        return [name for name in self.required_observations if name not in observed_delta]


def safe_file_write_causal_contract() -> CausalContract:
    return CausalContract(
        tool_name="safe_file_write",
        sets=("file_written",),
        may_change=("disk_usage",),
        side_effects=("filesystem_modified",),
        rollback_effects=("restores_previous_file_content",),
        required_observations=("file_written",),
        without_action="target_file_unchanged",
        risk_notes=("workspace scoped write",),
        confidence=0.9,
    )
