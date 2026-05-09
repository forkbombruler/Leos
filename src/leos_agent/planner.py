"""Deterministic candidate planner."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, Sequence

from .audit import AuditLog
from .enums import _max_risk, _risk_value
from .goals import Goal
from .manifest import PLAN_PROPOSAL_SCHEMA, validate_json_schema
from .plans import ActionStep, PlanCandidate, PlanProposal, PlanScore, PlannerConfig, PlannerResult, TransactionPlan
from .policy import PolicyEngine
from .state import WorldState
from .tools import ToolRegistry


class Planner:
    """Deterministic satisficing planner for explicit candidate proposals."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy: PolicyEngine,
        config: Optional[PlannerConfig] = None,
        audit_log: Optional[AuditLog] = None,
    ) -> None:
        self.registry = registry
        self.policy = policy
        self.config = config or PlannerConfig()
        self.audit_log = audit_log

    def generate_candidates(self, goal: Goal, proposals: Sequence[PlanProposal]) -> list[PlanCandidate]:
        if not goal.success_criteria:
            raise ValueError("Goal must have explicit success criteria")
        candidates = [
            PlanCandidate(
                proposal=proposal,
                plan=TransactionPlan(goal=goal, steps=[self._clone_step(step) for step in proposal.steps]),
            )
            for proposal in proposals
        ]
        if self.audit_log:
            self.audit_log.record("planner.candidates_generated", "Generated plan candidates", goal_id=goal.goal_id, count=len(candidates))
        return candidates

    def score(self, candidate: PlanCandidate) -> PlanScore:
        risks = []
        for step in candidate.plan.steps:
            tool = self.registry.get(step.tool_name)
            risks.append(self.policy.assess(tool, step.arguments))
        risk = _max_risk(risks)
        risk_value = _risk_value(risk)
        estimated_cost = float(candidate.proposal.estimated_cost)
        expected_benefit = float(candidate.proposal.expected_benefit)
        utility = (
            expected_benefit * self.config.benefit_weight
            - estimated_cost * self.config.cost_weight
            - risk_value * self.config.risk_weight
        )
        satisfies = (
            risk_value <= _risk_value(self.config.max_risk)
            and estimated_cost <= self.config.max_cost
            and expected_benefit >= self.config.min_benefit
        )
        return PlanScore(
            risk=risk,
            risk_value=risk_value,
            estimated_cost=estimated_cost,
            expected_benefit=expected_benefit,
            utility=utility,
            satisfies=satisfies,
        )

    def select_satisfactory(self, candidates: Sequence[PlanCandidate]) -> Optional[PlanCandidate]:
        selected = None
        for candidate in candidates:
            candidate.score = candidate.score or self.score(candidate)
            if selected is None and candidate.score.satisfies:
                selected = candidate
        if self.audit_log:
            self.audit_log.record(
                "planner.selection_finished",
                "Selected satisfactory plan candidate" if selected else "No satisfactory plan candidate found",
                selected_proposal_id=selected.proposal.proposal_id if selected else None,
                candidate_count=len(candidates),
            )
        return selected

    def plan(self, goal: Goal, proposals: Sequence[PlanProposal]) -> PlannerResult:
        candidates = self.generate_candidates(goal, proposals)
        selected = self.select_satisfactory(candidates)
        return PlannerResult(goal=goal, candidates=candidates, selected=selected)

    @staticmethod
    def _clone_step(step: ActionStep) -> ActionStep:
        return ActionStep(
            tool_name=step.tool_name,
            arguments=dict(step.arguments),
            reason=step.reason,
            risk=step.risk,
        )


class LLMPlannerAdapter(Protocol):
    """Adapter protocol for LLM-based plan proposal generation.

    Implementations must produce structured JSON outputs that conform to
    `PLAN_PROPOSAL_SCHEMA`. The framework validates every proposal against this
    schema before accepting it, ensuring the LLM cannot inject malformed steps.
    """

    def generate_proposals(self, goal: Goal, registry: ToolRegistry, state: WorldState) -> list[PlanProposal]:
        ...


def validate_llm_proposals(proposals_data: list[Dict[str, Any]], available_tools: set[str]) -> list[PlanProposal]:
    """Validate and convert raw LLM proposal dicts into PlanProposal objects.

    Each proposal dict is first validated against PLAN_PROPOSAL_SCHEMA.
    Steps within each proposal are checked against available tool names.
    Returns validated PlanProposal list.
    Raises LLMOutputValidationError on any schema violation.
    """
    from .errors import LLMOutputValidationError

    validated: list[PlanProposal] = []
    for i, raw in enumerate(proposals_data):
        issues = validate_json_schema(raw, PLAN_PROPOSAL_SCHEMA)
        if issues:
            raise LLMOutputValidationError(
                f"Proposal [{i}] failed schema validation: "
                + "; ".join(f"{issue['path']}: {issue['reason']}" for issue in issues)
            )
        steps_data = raw.get("steps", [])
        steps: list[ActionStep] = []
        for j, s in enumerate(steps_data):
            if not isinstance(s, dict):
                raise LLMOutputValidationError(f"Proposal [{i}] step [{j}] is not an object")
            tool_name = s.get("tool_name", "")
            if tool_name not in available_tools:
                raise LLMOutputValidationError(
                    f"Proposal [{i}] step [{j}] references unknown tool: {tool_name}"
                )
            steps.append(ActionStep(
                tool_name=str(tool_name),
                arguments=dict(s.get("arguments", {})),
                reason=str(s.get("reason", "")),
            ))
        validated.append(PlanProposal(
            steps=steps,
            rationale=str(raw.get("rationale", "")),
            estimated_cost=float(raw.get("estimated_cost", 0.0)),
            expected_benefit=float(raw.get("expected_benefit", 0.5)),
        ))
    return validated
