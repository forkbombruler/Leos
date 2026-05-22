"""Tool-level causal contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .causal import ActionConsequence, CausalEffect
from .state import WorldState


@dataclass(frozen=True)
class ObservationFieldRequirement:
    """Required nested field inside an observed state delta entry."""

    observation: str
    path: tuple[str, ...]
    operator: str = "exists"
    value: Any = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", tuple(self.path))
        if self.operator not in {"exists", "equals", "in", "not_equals"}:
            raise ValueError(f"Unsupported observation field operator: {self.operator}")
        if not self.observation:
            raise ValueError("Observation field requirement must name an observation")
        if not self.path:
            raise ValueError("Observation field requirement path must not be empty")


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
    required_fields: Sequence[ObservationFieldRequirement] = ()
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

    def field_violations(self, observed_state_delta: Mapping[str, Any]) -> list[str]:
        violations: list[str] = []
        for requirement in self.required_fields:
            if requirement.observation not in observed_state_delta:
                violations.append(f"{requirement.observation}.{'.'.join(requirement.path)} missing observation")
                continue
            found, actual = _nested_get(observed_state_delta[requirement.observation], requirement.path)
            label = f"{requirement.observation}.{'.'.join(requirement.path)}"
            if not found:
                violations.append(f"{label} missing")
                continue
            if requirement.operator == "exists":
                continue
            if requirement.operator == "equals" and actual != requirement.value:
                violations.append(f"{label} expected {requirement.value!r}")
            elif requirement.operator == "not_equals" and actual == requirement.value:
                violations.append(f"{label} unexpectedly matched {requirement.value!r}")
            elif requirement.operator == "in":
                try:
                    if actual not in requirement.value:
                        violations.append(f"{label} expected one of {requirement.value!r}")
                except TypeError:
                    violations.append(f"{label} expected one of {requirement.value!r}")
        return violations


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


def github_create_branch_causal_contract() -> CausalContract:
    return CausalContract(
        tool_name="github_create_branch",
        sets=("github_branch",),
        side_effects=("github_branch_created",),
        rollback_effects=("github_branch_deleted",),
        required_observations=("github_branch",),
        required_fields=(
            ObservationFieldRequirement("github_branch", ("branch",)),
            ObservationFieldRequirement("github_branch", ("base",)),
            ObservationFieldRequirement("github_branch", ("sha",)),
        ),
        risk_notes=("Creates a remote GitHub branch and requires cleanup on rollback.",),
        confidence=0.85,
    )


def github_update_file_causal_contract() -> CausalContract:
    return CausalContract(
        tool_name="github_update_file",
        sets=("github_file_updated",),
        side_effects=("github_repository_file_modified",),
        rollback_effects=("previous_github_file_content_restored_when_available",),
        required_observations=("github_file_updated",),
        required_fields=(
            ObservationFieldRequirement("github_file_updated", ("path",)),
            ObservationFieldRequirement("github_file_updated", ("branch",)),
            ObservationFieldRequirement("github_file_updated", ("sha",)),
        ),
        risk_notes=("Modifies repository content on a non-protected branch with optimistic guards.",),
        confidence=0.85,
    )


def github_open_pr_causal_contract() -> CausalContract:
    return CausalContract(
        tool_name="github_open_pr",
        sets=("github_pr",),
        side_effects=("github_pull_request_created",),
        rollback_effects=("github_pull_request_closed",),
        required_observations=("github_pr",),
        required_fields=(
            ObservationFieldRequirement("github_pr", ("number",)),
            ObservationFieldRequirement("github_pr", ("state",), operator="equals", value="open"),
            ObservationFieldRequirement("github_pr", ("head",)),
            ObservationFieldRequirement("github_pr", ("base",)),
        ),
        risk_notes=("Creates or reuses an idempotent GitHub pull request.",),
        confidence=0.85,
    )


def github_comment_causal_contract() -> CausalContract:
    return CausalContract(
        tool_name="github_comment",
        sets=("github_comment",),
        side_effects=("github_issue_comment_created",),
        rollback_effects=("github_issue_comment_deleted",),
        required_observations=("github_comment",),
        required_fields=(
            ObservationFieldRequirement("github_comment", ("id",)),
            ObservationFieldRequirement("github_comment", ("issue_number",)),
        ),
        risk_notes=("Posts a GitHub issue or PR comment.",),
        confidence=0.85,
    )


def _nested_get(value: Any, path: Sequence[str]) -> tuple[bool, Any]:
    current = value
    for key in path:
        if isinstance(current, Mapping):
            if key not in current:
                return False, None
            current = current[key]
            continue
        return False, None
    return True, current
