"""Agent kernel orchestration."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .audit import AuditLog
from .causal import CausalGraph, CounterfactualReview
from .enums import GoalStatus, SandboxPolicy
from .goals import Goal
from .memory import MemoryStore
from .planner import Planner
from .plans import (
    ActionStep,
    PlannerConfig,
    PlannerResult,
    PlanProposal,
    TransactionPlan,
)
from .policy import ApprovalGate, PolicyEngine
from .sandbox import SandboxRunner
from .state import WorldState
from .tools import ToolRegistry
from .transactions import TransactionManager


class AgentKernel:
    """The orchestration kernel for a Leos-style autonomous agent."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy: PolicyEngine,
        causal_model: CausalGraph | None = None,
        memory: MemoryStore | None = None,
        audit_log: AuditLog | None = None,
        approval_gate: ApprovalGate | None = None,
        planner_config: PlannerConfig | None = None,
        counterfactual_review: CounterfactualReview | None = None,
        allow_network_tools: bool = False,
        sandbox_runners: Mapping[SandboxPolicy, SandboxRunner] | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy
        self.causal_model = causal_model or CausalGraph()
        self.memory = memory or MemoryStore()
        self.audit_log = audit_log or AuditLog()
        self.state = WorldState()
        self.planner = Planner(registry=registry, policy=policy, config=planner_config, audit_log=self.audit_log)
        self.transactions = TransactionManager(
            registry=registry,
            policy=policy,
            causal_model=self.causal_model,
            audit_log=self.audit_log,
            approval_gate=approval_gate,
            counterfactual_review=counterfactual_review,
            allow_network_tools=allow_network_tools,
            sandbox_runners=sandbox_runners,
        )

    def build_plan(self, goal: Goal, steps: Sequence[ActionStep]) -> TransactionPlan:
        if not goal.success_criteria:
            raise ValueError("Goal must have explicit success criteria")
        if not goal.stop_conditions:
            self.audit_log.record("goal.warning", "Goal has no stop conditions", goal_id=goal.goal_id)
        self.audit_log.record(
            "goal.created",
            "Goal accepted by kernel",
            goal_id=goal.goal_id,
            description=goal.description,
            status=goal.status.value,
        )
        goal = self._transition_goal(goal, GoalStatus.PLANNING)
        return TransactionPlan(goal=goal, steps=list(steps))

    def plan(self, goal: Goal, proposals: Sequence[PlanProposal]) -> PlannerResult:
        if not goal.stop_conditions:
            self.audit_log.record("goal.warning", "Goal has no stop conditions", goal_id=goal.goal_id)
        self.audit_log.record(
            "goal.created",
            "Goal accepted by planner",
            goal_id=goal.goal_id,
            description=goal.description,
            status=goal.status.value,
        )
        goal = self._transition_goal(goal, GoalStatus.PLANNING)
        return self.planner.plan(goal, proposals)

    def run(self, plan: TransactionPlan) -> TransactionPlan:
        return self.transactions.execute_plan(plan, self.state)

    def _transition_goal(self, goal: Goal, status: GoalStatus) -> Goal:
        updated = goal.transition(status)
        self.audit_log.record(
            "goal.status_changed",
            "Goal status changed",
            goal_id=goal.goal_id,
            from_status=goal.status.value,
            to_status=updated.status.value,
        )
        return updated
