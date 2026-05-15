"""Causal consequence model and counterfactual review."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from .audit import AuditLog
from .enums import RiskLevel, _risk_value
from .errors import VerificationFailed
from .state import WorldState
from .tools import ToolResult


class CausalEffect(str, Enum):
    CHANGES = "changes"
    SETS = "sets"
    PRESERVES = "preserves"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ActionConsequence:
    """A predicted consequence of taking an action."""

    variable: str
    before: Any
    expected_after: Any
    confidence: float
    rationale: str
    effect: CausalEffect = CausalEffect.CHANGES
    expected_without_action: Any = None


@dataclass(frozen=True)
class EffectPrediction(ActionConsequence):
    """Backward-compatible name for an action consequence."""


@dataclass(frozen=True)
class CausalHypothesis:
    """A simple causal edge: taking an action changes one or more variables."""

    action_name: str
    affected_variables: Sequence[str]
    rationale: str
    confidence: float = 0.5


@dataclass(frozen=True)
class CounterfactualReport:
    """Action-vs-no-action review for a planned step."""

    step_id: str
    tool_name: str
    action_consequences: list[ActionConsequence]
    no_action_consequences: list[ActionConsequence]
    risk: RiskLevel
    expected_cost: float
    expected_benefit: float
    summary: dict[str, Any] = field(default_factory=dict)


class CausalGraph:
    """Action consequence model with counterfactual-friendly predictions."""

    def __init__(self, hypotheses: Iterable[CausalHypothesis] | None = None) -> None:
        self.hypotheses: list[CausalHypothesis] = list(hypotheses or [])

    def register(self, hypothesis: CausalHypothesis) -> None:
        self.hypotheses.append(hypothesis)

    def predict(self, step: Any, state: WorldState) -> list[ActionConsequence]:
        consequences: list[ActionConsequence] = []
        for hypothesis in self.hypotheses:
            if hypothesis.action_name != step.tool_name:
                continue
            for variable in hypothesis.affected_variables:
                before = state.facts.get(variable, state.assumptions.get(variable))
                expected = step.arguments.get(variable, "changed")
                effect = CausalEffect.CHANGES if expected == "changed" else CausalEffect.SETS
                consequences.append(
                    ActionConsequence(
                        variable=variable,
                        before=before,
                        expected_after=expected,
                        confidence=hypothesis.confidence,
                        rationale=hypothesis.rationale,
                        effect=effect,
                        expected_without_action=before,
                    )
                )
        return consequences

    def predict_for_tool(self, step: Any, state: WorldState, tool: Any | None = None) -> list[ActionConsequence]:
        contract = getattr(getattr(tool, "spec", None), "causal_contract", None)
        if contract is not None:
            return list(contract.predictions(step, state))
        return self.predict(step, state)

    def verify(self, predictions: Sequence[ActionConsequence], result: ToolResult) -> ToolResult:
        mismatches = []
        for consequence in predictions:
            if consequence.variable not in result.observed_state_delta:
                mismatches.append(
                    {
                        "variable": consequence.variable,
                        "effect": consequence.effect.value,
                        "expected_after": consequence.expected_after,
                        "observed": None,
                        "reason": "missing_observation",
                    }
                )
                continue
            observed = result.observed_state_delta[consequence.variable]
            if consequence.expected_after != "changed" and observed != consequence.expected_after:
                mismatches.append(
                    {
                        "variable": consequence.variable,
                        "effect": consequence.effect.value,
                        "expected_after": consequence.expected_after,
                        "observed": observed,
                        "reason": "consequence_mismatch",
                    }
                )
        if mismatches:
            return ToolResult(
                False,
                "Causal consequence verification failed",
                {"mismatches": mismatches},
                error=VerificationFailed("Causal consequence verification failed"),
            )
        return ToolResult(True, "Causal consequence verification passed")


class CausalWorldModel(CausalGraph):
    """Backward-compatible wrapper for the original causal model name."""

    def predict(self, step: Any, state: WorldState) -> list[ActionConsequence]:
        consequences = super().predict(step, state)
        return [
            EffectPrediction(
                variable=consequence.variable,
                before=consequence.before,
                expected_after=consequence.expected_after,
                confidence=consequence.confidence,
                rationale=consequence.rationale,
                effect=consequence.effect,
                expected_without_action=consequence.expected_without_action,
            )
            for consequence in consequences
        ]


class CounterfactualReview:
    """Reviews intended consequences against the no-action alternative."""

    def __init__(self, causal_graph: CausalGraph, audit_log: AuditLog | None = None) -> None:
        self.causal_graph = causal_graph
        self.audit_log = audit_log

    def review(
        self,
        step: Any,
        state: WorldState,
        predictions: Sequence[ActionConsequence] | None = None,
    ) -> CounterfactualReport:
        action_consequences = list(predictions) if predictions is not None else self.causal_graph.predict(step, state)
        no_action_consequences = [
            ActionConsequence(
                variable=consequence.variable,
                before=consequence.before,
                expected_after=consequence.before,
                confidence=consequence.confidence,
                rationale=f"Without {step.tool_name}, {consequence.variable} is expected to remain unchanged.",
                effect=CausalEffect.PRESERVES,
                expected_without_action=consequence.before,
            )
            for consequence in action_consequences
        ]
        expected_benefit = sum(consequence.confidence for consequence in action_consequences)
        expected_cost = float(_risk_value(step.risk))
        report = CounterfactualReport(
            step_id=step.step_id,
            tool_name=step.tool_name,
            action_consequences=action_consequences,
            no_action_consequences=no_action_consequences,
            risk=step.risk,
            expected_cost=expected_cost,
            expected_benefit=expected_benefit,
            summary={
                "action_variables": [consequence.variable for consequence in action_consequences],
                "no_action_variables": [consequence.variable for consequence in no_action_consequences],
            },
        )
        if self.audit_log:
            self.audit_log.record(
                "step.counterfactual_review",
                "Reviewed action consequences against no-action alternative",
                step_id=step.step_id,
                tool=step.tool_name,
                report=asdict(report),
            )
        return report
