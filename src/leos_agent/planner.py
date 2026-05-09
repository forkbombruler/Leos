"""Deterministic candidate planner."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Protocol

from .audit import AuditLog
from .enums import _max_risk, _risk_value
from .goals import Goal
from .manifest import PLAN_PROPOSAL_SCHEMA, validate_json_schema
from .model import ModelClient, ModelRequest, StructuredOutputError
from .plans import (
    ActionStep,
    PlanCandidate,
    PlannerConfig,
    PlannerResult,
    PlanProposal,
    PlanScore,
    TransactionPlan,
)
from .policy import PolicyEngine
from .prompts import DEFAULT_PROMPT_REGISTRY, PromptRegistry
from .state import WorldState
from .tools import ToolRegistry


class Planner:
    """Deterministic satisficing planner for explicit candidate proposals."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy: PolicyEngine,
        config: PlannerConfig | None = None,
        audit_log: AuditLog | None = None,
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
            self.audit_log.record(
                "planner.candidates_generated", "Generated plan candidates", goal_id=goal.goal_id, count=len(candidates)
            )
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

    def select_satisfactory(self, candidates: Sequence[PlanCandidate]) -> PlanCandidate | None:
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

    def generate_proposals(self, goal: Goal, registry: ToolRegistry, state: WorldState) -> list[PlanProposal]: ...


def validate_llm_proposals(proposals_data: list[dict[str, Any]], available_tools: set[str]) -> list[PlanProposal]:
    """Validate and convert raw LLM proposal dicts into PlanProposal objects.

    Each proposal dict is first validated against PLAN_PROPOSAL_SCHEMA.
    Steps within each proposal are checked against available tool names
    and for valid arguments/reason fields.
    Returns validated PlanProposal list.
    Raises LLMOutputValidationError on any schema violation.
    """
    from .errors import LLMOutputValidationError

    if not isinstance(proposals_data, list):
        raise LLMOutputValidationError("Proposals data must be a list")

    validated: list[PlanProposal] = []
    for i, raw in enumerate(proposals_data):
        if not isinstance(raw, dict):
            raise LLMOutputValidationError(f"Proposal [{i}] must be an object")
        issues = validate_json_schema(raw, PLAN_PROPOSAL_SCHEMA)
        if issues:
            raise LLMOutputValidationError(
                f"Proposal [{i}] failed schema validation: "
                + "; ".join(f"{issue['path']}: {issue['message']}" for issue in issues)
            )
        steps_data = raw["steps"]
        if not steps_data:
            raise LLMOutputValidationError(f"Proposal [{i}] steps must not be empty")
        steps: list[ActionStep] = []
        for j, s in enumerate(steps_data):
            if not isinstance(s, dict):
                raise LLMOutputValidationError(f"Proposal [{i}] step [{j}] must be an object")
            tool_name = s.get("tool_name", "")
            if not tool_name:
                raise LLMOutputValidationError(f"Proposal [{i}] step [{j}] tool_name is required")
            if tool_name not in available_tools:
                raise LLMOutputValidationError(f"Proposal [{i}] step [{j}] references unknown tool: {tool_name}")
            args = s.get("arguments")
            if not isinstance(args, dict):
                raise LLMOutputValidationError(f"Proposal [{i}] step [{j}] arguments must be an object")
            reason = s.get("reason", "")
            if not reason or not isinstance(reason, str) or not reason.strip():
                raise LLMOutputValidationError(f"Proposal [{i}] step [{j}] reason must be a non-empty string")
            steps.append(
                ActionStep(
                    tool_name=str(tool_name),
                    arguments=dict(args),
                    reason=reason.strip(),
                )
            )
        validated.append(
            PlanProposal(
                steps=steps,
                rationale=str(raw["rationale"]).strip(),
                estimated_cost=float(raw.get("estimated_cost", 0.0)),
                expected_benefit=float(raw.get("expected_benefit", 0.5)),
            )
        )
    return validated


class StructuredLLMPlanner:
    """LLM-based planner that enforces structured JSON output.

    Uses a ModelClient (vendor-neutral) and a PromptRegistry to generate
    PlanProposal candidates. Every LLM response is validated against
    PLAN_PROPOSAL_SCHEMA and tool availability before acceptance.
    """

    def __init__(
        self,
        model_client: ModelClient,
        prompt_registry: PromptRegistry | None = None,
        model: str = "unknown",
        max_retries: int = 1,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.model_client = model_client
        self.prompt_registry = prompt_registry or DEFAULT_PROMPT_REGISTRY
        self.model = model
        self.max_retries = max_retries
        self.audit_log = audit_log

    def generate_proposals(self, goal: Goal, registry: ToolRegistry, state: WorldState) -> list[PlanProposal]:
        template = self.prompt_registry.get("planner.proposal")
        available = registry.names()
        tool_list_lines = []
        for name in available:
            spec = registry.get(name).spec
            tool_list_lines.append(
                f"  - {name}: {spec.description} "
                f"[risk={spec.default_risk.value}, "
                f"permissions={[p.value for p in spec.permissions]}]"
            )
        tool_list = "\n".join(tool_list_lines)
        facts = json.dumps(
            {k: v for k, v in sorted(state.facts.items())},
            default=str,
        )

        prompt_text = template.render(
            goal_description=goal.description,
            goal_success_criteria=", ".join(goal.success_criteria),
            goal_constraints=", ".join(goal.constraints) if goal.constraints else "none",
            goal_stop_conditions=", ".join(goal.stop_conditions) if goal.stop_conditions else "none",
            tool_list=tool_list,
            world_state_facts=facts if facts != "{}" else "(empty)",
        )

        if self.audit_log:
            self.audit_log.record(
                "llm.planner.requested",
                "LLM planner request sent",
                model=self.model,
                prompt_id=template.prompt_id,
                prompt_version=template.version,
                prompt_hash=template.hash(),
                goal_id=goal.goal_id,
                available_tool_count=len(available),
            )

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            request = ModelRequest(
                prompt=prompt_text,
                schema=PLAN_PROPOSAL_SCHEMA,
                model=self.model,
                metadata={"goal_id": goal.goal_id, "attempt": attempt},
            )
            try:
                response = self.model_client.generate(request)
            except Exception as exc:
                last_error = exc
                continue

            if self.audit_log:
                preview = response.text[:200] + "..." if len(response.text) > 200 else response.text
                self.audit_log.record(
                    "llm.planner.response_received",
                    "LLM planner response received",
                    model=self.model,
                    text_preview=preview,
                    usage_input_tokens=response.usage.input_tokens if response.usage else 0,
                    usage_output_tokens=response.usage.output_tokens if response.usage else 0,
                )

            raw_data = response.parsed_json
            if raw_data is None:
                try:
                    raw_data = json.loads(response.text)
                except json.JSONDecodeError as exc:
                    last_error = exc
                    continue

            if not isinstance(raw_data, list):
                last_error = StructuredOutputError("LLM output must be a JSON array of proposals")
                continue

            try:
                validated = validate_llm_proposals(raw_data, set(available))
            except Exception as exc:
                last_error = exc
                if self.audit_log:
                    self.audit_log.record(
                        "llm.planner.proposals_rejected",
                        "LLM proposals rejected",
                        model=self.model,
                        error_type=type(exc).__name__,
                        error_message=str(exc),
                    )
                continue

            if self.audit_log:
                self.audit_log.record(
                    "llm.planner.proposals_validated",
                    "LLM proposals validated",
                    model=self.model,
                    proposal_count=len(validated),
                )
            return validated

        if self.audit_log:
            self.audit_log.record(
                "llm.planner.proposals_rejected",
                "LLM proposals exhausted retries",
                model=self.model,
                error_type=type(last_error).__name__ if last_error else "unknown",
                error_message=str(last_error) if last_error else "no valid proposals",
            )
        raise StructuredOutputError(
            f"LLM planner failed after {self.max_retries + 1} attempt(s): {last_error}"
        ) from last_error
