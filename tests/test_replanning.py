from __future__ import annotations

import unittest

from leos_agent import (
    ActionStep,
    AgentKernel,
    AgentLoop,
    AgentLoopConfig,
    EchoTool,
    Goal,
    PlanProposal,
    PolicyEngine,
    ToolRegistry,
)
from leos_agent.audit import AuditLog
from leos_agent.enums import StepStatus
from leos_agent.plans import TransactionPlan
from leos_agent.replanning import FailureAnalyzer, FailureType


class _RepairProvider:
    def __init__(self) -> None:
        self.calls = 0
        self.repairs = 0

    def propose(self, goal, state, registry):
        self.calls += 1
        return [PlanProposal([ActionStep("echo", {}, "missing message")], "bad")]

    def propose_repair(self, context, goal, state, registry):
        self.repairs += 1
        return [PlanProposal([ActionStep("echo", {"message": "fixed"}, "repair")], "repair")]


class _UnknownRepairProvider(_RepairProvider):
    def propose(self, goal, state, registry):
        self.calls += 1
        return [PlanProposal([ActionStep("missing", {}, "unknown")], "bad")]


class _RepeatedFailureProvider(_RepairProvider):
    def propose_repair(self, context, goal, state, registry):
        self.repairs += 1
        return [PlanProposal([ActionStep("echo", {}, "still missing message")], "bad repair")]


class ReplanningTests(unittest.TestCase):
    def _kernel(self) -> AgentKernel:
        registry = ToolRegistry()
        registry.register(EchoTool())
        return AgentKernel(registry, PolicyEngine())

    def test_dry_run_failure_triggers_replan(self) -> None:
        provider = _RepairProvider()
        loop = AgentLoop(
            self._kernel(),
            provider,
            config=AgentLoopConfig(max_iterations=3, max_replans=1),
        )

        result = loop.run(Goal("repair", ["do the task"], stop_conditions=["done"]))

        self.assertTrue(result.succeeded)
        self.assertEqual(result.stop_reason, "goal_succeeded")
        self.assertEqual(provider.repairs, 1)
        self.assertEqual(result.failure_analyses[0].failure_type, FailureType.DRY_RUN_FAILED)

    def test_unknown_tool_can_replan_to_known_tool(self) -> None:
        provider = _UnknownRepairProvider()
        result = AgentLoop(
            self._kernel(),
            provider,
            config=AgentLoopConfig(max_iterations=3, max_replans=1),
        ).run(Goal("repair", ["do the task"], stop_conditions=["done"]))

        self.assertTrue(result.succeeded)
        self.assertEqual(result.failure_analyses[0].failure_type, FailureType.UNKNOWN_TOOL)

    def test_repeated_failure_stops_after_budget(self) -> None:
        provider = _RepeatedFailureProvider()
        result = AgentLoop(
            self._kernel(),
            provider,
            config=AgentLoopConfig(max_iterations=3, max_replans=1),
        ).run(Goal("repair", ["do the task"], stop_conditions=["done"]))

        self.assertFalse(result.succeeded)
        self.assertEqual(result.stop_reason, "goal_failed")

    def test_tool_call_budget_stops_before_second_plan(self) -> None:
        provider = _RepairProvider()
        result = AgentLoop(
            self._kernel(),
            provider,
            config=AgentLoopConfig(max_iterations=3, max_replans=1, max_tool_calls=1),
        ).run(Goal("repair", ["do the task"], stop_conditions=["done"]))

        self.assertEqual(result.stop_reason, "tool_call_budget_exceeded")

    def test_causal_contract_policy_message_classifies_as_causal(self) -> None:
        analysis = _analyze_event(
            "causal_contract.missing",
            "Step blocked by production policy: missing causal_contract",
        )

        self.assertIs(analysis.failure_type, FailureType.CAUSAL_CONTRACT_FAILED)

    def test_causal_contract_verification_event_classifies_as_causal(self) -> None:
        analysis = _analyze_event("step.causal_contract_verification_failed", "field violation")

        self.assertIs(analysis.failure_type, FailureType.CAUSAL_CONTRACT_FAILED)

    def test_output_schema_event_classifies_before_execution(self) -> None:
        analysis = _analyze_event("step.output_schema_failed", "execution produced invalid output_schema")

        self.assertIs(analysis.failure_type, FailureType.OUTPUT_SCHEMA_FAILED)

    def test_egress_policy_block_classifies_as_network(self) -> None:
        analysis = _analyze_event("policy.blocked", "production egress policy does not allow GET api.github.com")

        self.assertIs(analysis.failure_type, FailureType.NETWORK_BLOCKED)

    def test_permission_missing_classifies_as_policy_denied(self) -> None:
        analysis = _analyze_event("policy.blocked", "missing permission write_files")

        self.assertIs(analysis.failure_type, FailureType.POLICY_DENIED)

    def test_approval_rejected_classifies_as_approval_denied(self) -> None:
        analysis = _analyze_event("approval.rejected", "human denied")

        self.assertIs(analysis.failure_type, FailureType.APPROVAL_DENIED)

    def test_sandbox_unavailable_classifies_as_sandbox(self) -> None:
        analysis = _analyze_event("step.blocked", "container sandbox not available")

        self.assertIs(analysis.failure_type, FailureType.SANDBOX_UNAVAILABLE)

    def test_timeout_classifies_as_timeout(self) -> None:
        analysis = _analyze_event("step.execution_failed", "timeout after 1 seconds")

        self.assertIs(analysis.failure_type, FailureType.TIMEOUT)


def _analyze_event(event_type: str, message: str):
    audit = AuditLog()
    audit.record(event_type, message, reason=message)
    step = ActionStep("echo", {"message": "x"}, "x")
    step.status = StepStatus.BLOCKED
    plan = TransactionPlan(Goal("g", ["done"]), [step])
    return FailureAnalyzer().analyze(plan, audit)


if __name__ == "__main__":
    unittest.main()
