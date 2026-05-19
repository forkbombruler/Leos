"""Closed-loop agent runtime orchestration."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol, cast

from .audit import AuditLog
from .enums import GoalStatus
from .errors import InvalidGoalTransition
from .goal_evaluator import GoalEvaluation, GoalEvaluationStatus, GoalEvaluator
from .goals import Goal, GoalProgress
from .kernel import AgentKernel
from .memory import MemoryStore, MemoryType
from .plans import PlanProposal, TransactionPlan
from .runtime_store import RuntimeStore
from .state import WorldState
from .tools import ToolRegistry


class ProposalProvider(Protocol):
    """Produces candidate plans for a goal from the current state."""

    def propose(self, goal: Goal, state: WorldState, registry: ToolRegistry) -> list[PlanProposal]: ...


@dataclass(frozen=True)
class AgentLoopConfig:
    max_iterations: int = 3
    memory_scope: str = "agent_loop"
    use_goal_evaluator: bool = True

    def __post_init__(self) -> None:
        if self.max_iterations < 1:
            raise ValueError("max_iterations must be >= 1")


@dataclass
class AgentLoopResult:
    goal: Goal
    stop_reason: str
    iterations: int
    selected_plans: list[TransactionPlan] = field(default_factory=list)
    progress: GoalProgress | None = None
    evaluation: GoalEvaluation | None = None

    @property
    def succeeded(self) -> bool:
        if self.evaluation is not None:
            return self.evaluation.status is GoalEvaluationStatus.SUCCEEDED
        return self.goal.status is GoalStatus.SUCCEEDED


class DeterministicProposalProvider:
    """Deterministic proposal provider for tests and local demos."""

    def __init__(self, proposals: Sequence[PlanProposal] | Sequence[Sequence[PlanProposal]]) -> None:
        items = list(proposals)
        if items and isinstance(items[0], PlanProposal):
            self._batches = [cast(list[PlanProposal], items)]
        else:
            self._batches = [list(batch) for batch in cast(list[Sequence[PlanProposal]], items)]
        self.calls = 0

    def propose(self, goal: Goal, state: WorldState, registry: ToolRegistry) -> list[PlanProposal]:
        index = min(self.calls, len(self._batches) - 1) if self._batches else 0
        self.calls += 1
        return list(self._batches[index]) if self._batches else []


class AgentLoop:
    """Minimal observe-plan-act-verify loop built on AgentKernel."""

    def __init__(
        self,
        kernel: AgentKernel,
        proposal_provider: ProposalProvider,
        memory: MemoryStore | None = None,
        audit_log: AuditLog | None = None,
        config: AgentLoopConfig | None = None,
        goal_evaluator: GoalEvaluator | None = None,
        runtime_store: RuntimeStore | None = None,
    ) -> None:
        self.kernel = kernel
        self.proposal_provider = proposal_provider
        self.memory = memory or kernel.memory
        self.audit_log = audit_log or kernel.audit_log
        self.config = config or AgentLoopConfig()
        self.goal_evaluator = goal_evaluator or GoalEvaluator()
        self.runtime_store = runtime_store

    def run(self, goal: Goal) -> AgentLoopResult:
        self.audit_log.record(
            "loop.started",
            "Agent loop started",
            goal_id=goal.goal_id,
            max_iterations=self.config.max_iterations,
        )

        def save_goal(store: RuntimeStore) -> None:
            store.save_goal(goal)

        self._store("save_goal", save_goal)
        selected_plans: list[TransactionPlan] = []
        progress: GoalProgress | None = None
        evaluation: GoalEvaluation | None = None
        current_goal = goal
        stop_reason = "max_iterations_reached"

        for iteration in range(1, self.config.max_iterations + 1):
            self.audit_log.record(
                "loop.iteration_started",
                "Agent loop iteration started",
                goal_id=current_goal.goal_id,
                iteration=iteration,
                state_keys=sorted(self.kernel.state.facts),
            )

            def append_iteration_event(
                store: RuntimeStore,
                iteration: int = iteration,
                current_goal: Goal = current_goal,
            ) -> None:
                store.append_runtime_event(
                    {
                        "event_type": "loop.iteration_started",
                        "goal_id": current_goal.goal_id,
                        "iteration": iteration,
                        "state_keys": sorted(self.kernel.state.facts),
                    }
                )

            self._store("append_runtime_event", append_iteration_event)
            self._recall_goal_memory(current_goal)
            proposals = self.proposal_provider.propose(current_goal, self.kernel.state, self.kernel.registry)
            if not proposals:
                stop_reason = "no_plan"
                break

            planner_result = self.kernel.plan(current_goal, proposals)
            if planner_result.selected is None:
                stop_reason = "no_satisfactory_plan"
                break

            plan = planner_result.selected.plan
            selected_plans.append(plan)

            def save_plan(store: RuntimeStore, plan: TransactionPlan = plan) -> None:
                store.save_plan(plan)

            self._store("save_plan", save_plan)
            self.audit_log.record(
                "loop.plan_selected",
                "Agent loop selected a plan",
                goal_id=current_goal.goal_id,
                iteration=iteration,
                plan_id=plan.plan_id,
                proposal_id=planner_result.selected.proposal.proposal_id,
                step_count=len(plan.steps),
            )

            executed = self.kernel.run(plan)
            plan_goal = executed.goal
            self.audit_log.record(
                "loop.plan_executed",
                "Agent loop executed selected plan",
                goal_id=plan_goal.goal_id,
                iteration=iteration,
                plan_id=executed.plan_id,
                goal_status=plan_goal.status.value,
            )

            progress = self.kernel.transactions.track_progress(executed)
            self.audit_log.record(
                "loop.goal_progress_checked",
                "Agent loop checked goal progress",
                goal_id=plan_goal.goal_id,
                iteration=iteration,
                verified_steps=progress.verified_steps,
                blocked_steps=progress.blocked_steps,
                failed_steps=progress.failed_steps,
                rolled_back_steps=progress.rolled_back_steps,
                phase=progress.phase,
            )
            if self.config.use_goal_evaluator:
                evaluation = self.goal_evaluator.evaluate(plan_goal, self.kernel.state, progress)
                self.audit_log.record(
                    "loop.goal_evaluated",
                    "Agent loop evaluated goal success criteria",
                    goal_id=plan_goal.goal_id,
                    iteration=iteration,
                    evaluation_status=evaluation.status.value,
                    satisfied_criteria=list(evaluation.satisfied_criteria),
                    unsatisfied_criteria=list(evaluation.unsatisfied_criteria),
                    explanation=evaluation.explanation,
                    evidence_keys=sorted(evaluation.evidence),
                )
                if self._evaluation_stop_reason(evaluation):
                    current_goal = self._transition_goal_for_evaluation(plan_goal, evaluation)
            else:
                current_goal = plan_goal
            self._write_iteration_memory(current_goal, iteration, progress)

            if self.config.use_goal_evaluator:
                stop_reason = self._evaluation_stop_reason(evaluation)
            else:
                stop_reason = self._stop_reason(current_goal)
            if stop_reason:
                break
            # Only set max_iterations fallback if we haven't already found a stop reason
            if not stop_reason:
                stop_reason = "max_iterations_reached"

        iterations = (
            len(selected_plans)
            if selected_plans
            else min(self.config.max_iterations, getattr(self.proposal_provider, "calls", 0))
        )
        self.audit_log.record(
            "loop.finished",
            "Agent loop finished",
            goal_id=current_goal.goal_id,
            iterations=iterations,
            stop_reason=stop_reason,
            goal_status=current_goal.status.value,
        )

        def save_checkpoint(store: RuntimeStore) -> None:
            store.save_checkpoint(
                f"agent_loop:{current_goal.goal_id}:final",
                {
                    "goal_id": current_goal.goal_id,
                    "stop_reason": stop_reason,
                    "iterations": iterations,
                    "final_status": current_goal.status.value,
                    "evaluation_status": evaluation.status.value if evaluation is not None else None,
                    "selected_plan_ids": [plan.plan_id for plan in selected_plans],
                },
            )

        self._store("save_checkpoint", save_checkpoint)
        return AgentLoopResult(
            goal=current_goal,
            stop_reason=stop_reason,
            iterations=iterations,
            selected_plans=selected_plans,
            progress=progress,
            evaluation=evaluation,
        )

    def _store(self, operation: str, callback: Callable[[RuntimeStore], None]) -> None:
        if self.runtime_store is None:
            return
        try:
            callback(self.runtime_store)
        except Exception as exc:  # noqa: BLE001
            self.audit_log.record(
                "loop.runtime_store_failed",
                "Runtime store operation failed",
                operation=operation,
                error_type=type(exc).__name__,
                reason=str(exc),
            )

    def _recall_goal_memory(self, goal: Goal) -> None:
        memories = self.memory.recall(goal.goal_id, scope=self.config.memory_scope)
        self.audit_log.record(
            "loop.memory_recalled",
            "Agent loop recalled goal memory",
            goal_id=goal.goal_id,
            count=len(memories),
        )

    def _write_iteration_memory(self, goal: Goal, iteration: int, progress: GoalProgress) -> None:
        self.memory.remember(
            goal.goal_id,
            {
                "iteration": iteration,
                "goal_status": goal.status.value,
                "progress_phase": progress.phase,
                "verified_steps": progress.verified_steps,
            },
            confidence=1.0,
            provenance="agent_loop",
            memory_type=MemoryType.FACT,
            scope=self.config.memory_scope,
        )
        self.audit_log.record(
            "loop.memory_updated",
            "Agent loop wrote progress memory",
            goal_id=goal.goal_id,
            iteration=iteration,
            scope=self.config.memory_scope,
        )

    @staticmethod
    def _stop_reason(goal: Goal) -> str:
        if goal.status is GoalStatus.SUCCEEDED:
            return "goal_succeeded"
        if goal.status is GoalStatus.BLOCKED:
            return "goal_blocked"
        if goal.status is GoalStatus.FAILED:
            return "goal_failed"
        return ""

    @staticmethod
    def _evaluation_stop_reason(evaluation: GoalEvaluation | None) -> str:
        if evaluation is None:
            return ""
        if evaluation.status is GoalEvaluationStatus.SUCCEEDED:
            return "goal_succeeded"
        if evaluation.status is GoalEvaluationStatus.BLOCKED:
            return "goal_blocked"
        if evaluation.status is GoalEvaluationStatus.FAILED:
            return "goal_failed"
        return ""

    def _transition_goal_for_evaluation(self, goal: Goal, evaluation: GoalEvaluation) -> Goal:
        target = {
            GoalEvaluationStatus.SUCCEEDED: GoalStatus.SUCCEEDED,
            GoalEvaluationStatus.FAILED: GoalStatus.FAILED,
            GoalEvaluationStatus.BLOCKED: GoalStatus.BLOCKED,
        }.get(evaluation.status)
        if target is None or goal.status is target:
            return goal
        try:
            transitioned = goal.transition(target)
        except InvalidGoalTransition as exc:
            self.audit_log.record(
                "loop.goal_transition_skipped",
                "Goal transition from evaluation was not allowed",
                goal_id=goal.goal_id,
                from_status=goal.status.value,
                to_status=target.value,
                evaluation_status=evaluation.status.value,
                error_type=type(exc).__name__,
                reason=str(exc),
            )
            return goal
        self.audit_log.record(
            "loop.goal_transitioned",
            "Goal status changed from goal evaluation",
            goal_id=goal.goal_id,
            from_status=goal.status.value,
            to_status=transitioned.status.value,
            evaluation_status=evaluation.status.value,
        )
        return transitioned
