from __future__ import annotations

import unittest
from collections.abc import Mapping
from typing import Any

from leos_agent import (
    ActionStep,
    AgentKernel,
    AgentLoop,
    AgentLoopConfig,
    ApprovalGate,
    AuditLog,
    CausalGraph,
    DeterministicProposalProvider,
    Goal,
    GoalCriterion,
    PlannerConfig,
    PlanProposal,
    PolicyEngine,
    RiskLevel,
    ToolResult,
    ToolSpec,
)
from leos_agent.state import WorldState
from leos_agent.tools import EchoTool, ToolRegistry


class SpyEchoTool(EchoTool):
    def __init__(self) -> None:
        self.executed = False

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.executed = True
        return super().execute(arguments, state)


class BlockedTool:
    spec = ToolSpec(name="blocked", description="blocked", permissions=(), default_risk=RiskLevel.HIGH)

    def __init__(self) -> None:
        self.executed = False

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.executed = True
        return ToolResult(True, "executed", observed_state_delta={"blocked": False})

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "rollback")


class TestResultTool:
    def __init__(self, tests_ok: bool) -> None:
        self.tests_ok = tests_ok

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="test_result",
            description="Record a deterministic test outcome",
            permissions=(),
            default_risk=RiskLevel.LOW,
            output_schema={"type": "object", "required": ["tests_ok"]},
        )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Would record test result")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "Recorded test result", observed_state_delta={"tests_ok": self.tests_ok})

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "rollback")


class StaleEvalProposalProvider:
    """Returns plans but records the goal received so we can assert it updates."""

    def __init__(self, proposals: list[PlanProposal]) -> None:
        self._proposals = proposals
        self.calls = 0
        self.received_goal_statuses: list[str] = []

    def propose(self, goal: Goal, state: WorldState, registry: ToolRegistry) -> list[PlanProposal]:
        self.received_goal_statuses.append(goal.status.value)
        self.calls += 1
        return list(self._proposals)


class AgentLoopTests(unittest.TestCase):
    def _kernel(self, registry: ToolRegistry, audit: AuditLog | None = None) -> AgentKernel:
        return AgentKernel(
            registry=registry,
            policy=PolicyEngine(max_auto_risk=RiskLevel.HIGH),
            causal_model=CausalGraph(),
            audit_log=audit or AuditLog(),
            approval_gate=ApprovalGate(lambda step: False),
            planner_config=PlannerConfig(max_risk=RiskLevel.HIGH),
        )

    def test_loop_executes_echo_goal_and_succeeds(self) -> None:
        registry = ToolRegistry()
        tool = SpyEchoTool()
        registry.register(tool)
        kernel = self._kernel(registry)
        goal = Goal("echo", ["last_echo observed"], stop_conditions=["done"])
        proposal = PlanProposal([ActionStep("echo", {"message": "hi"}, "echo")], "echo")

        result = AgentLoop(kernel, DeterministicProposalProvider([proposal])).run(goal)

        self.assertTrue(result.succeeded)
        self.assertTrue(tool.executed)
        self.assertEqual(result.stop_reason, "goal_succeeded")

    def test_loop_stops_safely_without_proposals(self) -> None:
        kernel = self._kernel(ToolRegistry())
        goal = Goal("none", ["done"], stop_conditions=["stop"])

        result = AgentLoop(kernel, DeterministicProposalProvider([])).run(goal)

        self.assertEqual(result.stop_reason, "no_plan")
        self.assertFalse(result.succeeded)

    def test_loop_uses_goal_evaluator_for_tests_ok_success(self) -> None:
        registry = ToolRegistry()
        registry.register(TestResultTool(True))
        kernel = self._kernel(registry)
        goal = Goal("verify", ["tests pass"], stop_conditions=["stop"])
        proposal = PlanProposal([ActionStep("test_result", {}, "record")], "record")

        result = AgentLoop(kernel, DeterministicProposalProvider([proposal])).run(goal)

        self.assertTrue(result.succeeded)
        self.assertEqual(result.stop_reason, "goal_succeeded")
        self.assertIsNotNone(result.evaluation)
        self.assertEqual(result.evaluation.satisfied_criteria, ["tests pass"])

    def test_loop_does_not_succeed_when_steps_verified_but_tests_failed(self) -> None:
        registry = ToolRegistry()
        registry.register(TestResultTool(False))
        kernel = self._kernel(registry)
        goal = Goal("verify", ["tests pass"], stop_conditions=["stop"])
        proposal = PlanProposal([ActionStep("test_result", {}, "record")], "record")

        result = AgentLoop(kernel, DeterministicProposalProvider([proposal])).run(goal)

        self.assertFalse(result.succeeded)
        self.assertEqual(result.stop_reason, "goal_failed")
        self.assertIsNotNone(result.evaluation)
        self.assertEqual(result.evaluation.unsatisfied_criteria, ["tests pass"])
        self.assertNotEqual(result.selected_plans[0].goal.status.value, "succeeded")

    def test_loop_does_not_succeed_when_typed_criterion_missing(self) -> None:
        registry = ToolRegistry()
        registry.register(TestResultTool(True))
        kernel = self._kernel(registry)
        goal = Goal(
            "verify",
            ["tests pass"],
            criteria=(GoalCriterion("missing_required", "equals", True),),
            stop_conditions=["stop"],
        )
        proposal = PlanProposal([ActionStep("test_result", {}, "record")], "record")

        result = AgentLoop(
            kernel,
            DeterministicProposalProvider([proposal]),
            config=AgentLoopConfig(max_iterations=1),
        ).run(goal)

        self.assertFalse(result.succeeded)
        self.assertEqual(result.stop_reason, "goal_failed")
        self.assertNotEqual(result.selected_plans[0].goal.status.value, "succeeded")

    def test_loop_succeeds_when_verified_and_typed_criteria_satisfied(self) -> None:
        registry = ToolRegistry()
        registry.register(TestResultTool(True))
        kernel = self._kernel(registry)
        goal = Goal(
            "verify",
            ["tests pass"],
            criteria=(GoalCriterion("tests_ok", "equals", True),),
            stop_conditions=["stop"],
        )
        proposal = PlanProposal([ActionStep("test_result", {}, "record")], "record")

        result = AgentLoop(kernel, DeterministicProposalProvider([proposal])).run(goal)

        self.assertTrue(result.succeeded)
        self.assertEqual(result.stop_reason, "goal_succeeded")

    def test_loop_does_not_exceed_max_iterations(self) -> None:
        kernel = self._kernel(ToolRegistry())
        goal = Goal("echo", ["done"], stop_conditions=["stop"])

        result = AgentLoop(
            kernel,
            DeterministicProposalProvider([[], [], []]),
            config=AgentLoopConfig(max_iterations=2),
        ).run(goal)

        self.assertLessEqual(result.iterations, 2)

    def test_partial_goal_evaluation_replans_until_max_iterations(self) -> None:
        registry = ToolRegistry()
        registry.register(TestResultTool(True))
        kernel = self._kernel(registry)
        goal = Goal("verify", ["tests pass", "documentation updated"], stop_conditions=["stop"])
        proposal = PlanProposal([ActionStep("test_result", {}, "record")], "record")
        provider = DeterministicProposalProvider([[proposal], [proposal]])

        result = AgentLoop(
            kernel,
            provider,
            config=AgentLoopConfig(max_iterations=2),
        ).run(goal)

        self.assertEqual(provider.calls, 2)
        self.assertEqual(result.iterations, 2)
        self.assertEqual(result.stop_reason, "max_iterations_reached")
        self.assertFalse(result.succeeded)

    def test_blocked_step_stops_loop(self) -> None:
        registry = ToolRegistry()
        tool = BlockedTool()
        registry.register(tool)
        kernel = self._kernel(registry)
        goal = Goal("blocked", ["done"], stop_conditions=["stop"])
        proposal = PlanProposal([ActionStep("blocked", {}, "blocked")], "blocked")

        result = AgentLoop(kernel, DeterministicProposalProvider([proposal])).run(goal)

        self.assertEqual(result.stop_reason, "goal_blocked")
        self.assertFalse(tool.executed)

    def test_loop_writes_required_audit_events(self) -> None:
        registry = ToolRegistry()
        registry.register(EchoTool())
        audit = AuditLog()
        kernel = self._kernel(registry, audit)
        goal = Goal("echo", ["done"], stop_conditions=["stop"])
        proposal = PlanProposal([ActionStep("echo", {"message": "hi"}, "echo")], "echo")

        AgentLoop(kernel, DeterministicProposalProvider([proposal])).run(goal)

        event_types = {event.event_type for event in audit.events}
        for expected in {
            "loop.started",
            "loop.iteration_started",
            "loop.plan_selected",
            "loop.plan_executed",
            "loop.goal_progress_checked",
            "loop.goal_evaluated",
            "loop.memory_updated",
            "loop.finished",
        }:
            self.assertIn(expected, event_types)

    def test_eval_partial_updates_current_goal_for_next_iteration(self) -> None:
        registry = ToolRegistry()
        registry.register(TestResultTool(True))
        kernel = self._kernel(registry)
        goal = Goal("verify", ["tests pass", "coverage report"], stop_conditions=["stop"])
        proposal = PlanProposal([ActionStep("test_result", {}, "record")], "record")
        provider = StaleEvalProposalProvider([proposal, proposal])

        result = AgentLoop(
            kernel,
            provider,
            config=AgentLoopConfig(max_iterations=2),
        ).run(goal)

        self.assertEqual(result.iterations, 2)
        self.assertEqual(provider.calls, 2)
        self.assertGreaterEqual(len(provider.received_goal_statuses), 2)
        self.assertEqual(provider.received_goal_statuses[0], "created")
        self.assertNotEqual(
            provider.received_goal_statuses[1],
            "created",
            "After a partial evaluation, iteration 2 must receive the updated goal"
            " (status != 'created'), not the stale original goal.",
        )


if __name__ == "__main__":
    unittest.main()
