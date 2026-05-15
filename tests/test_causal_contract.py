from __future__ import annotations

import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from leos_agent.audit import AuditLog
from leos_agent.causal import CausalGraph, CausalHypothesis
from leos_agent.enums import Permission, RiskLevel
from leos_agent.goals import Goal
from leos_agent.plans import ActionStep, TransactionPlan
from leos_agent.policy import ApprovalGate, PolicyEngine
from leos_agent.state import WorldState
from leos_agent.tools import EchoTool, SafeFileWriteTool, ToolRegistry, ToolResult, ToolSpec
from leos_agent.transactions import TransactionManager


class MissingObservationTool:
    spec = SafeFileWriteTool._spec()

    def __init__(self) -> None:
        self.rollback_called = False

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "execute", observed_state_delta={}, rollback_token={"ok": True})

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.rollback_called = True
        return ToolResult(True, "rollback")


class MediumNoContractTool:
    spec = ToolSpec("medium_no_contract", "medium", (Permission.WRITE_FILES,), default_risk=RiskLevel.MEDIUM)

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "execute", observed_state_delta={"ok": True})

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "rollback")


class CausalContractTests(unittest.TestCase):
    def test_safe_file_write_has_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tool = SafeFileWriteTool(Path(tmp))

        self.assertIsNotNone(tool.spec.causal_contract)
        self.assertIn("file_written", tool.spec.causal_contract.required_observations)

    def test_predict_for_tool_uses_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tool = SafeFileWriteTool(Path(tmp))
            step = ActionStep("safe_file_write", {"file_written": "x"}, "write")
            predictions = CausalGraph().predict_for_tool(step, WorldState(), tool=tool)

        self.assertEqual(predictions[0].variable, "file_written")
        self.assertEqual(predictions[0].expected_after, "x")

    def test_missing_required_observation_fails_and_rolls_back(self) -> None:
        tool = MissingObservationTool()
        registry = ToolRegistry()
        registry.register(tool)
        audit = AuditLog()
        manager = TransactionManager(registry, PolicyEngine(), CausalGraph(), audit, ApprovalGate(lambda step: True))
        result = manager.execute_plan(
            _plan(ActionStep("safe_file_write", {"path": "x", "content": "y"}, "write")),
            WorldState(),
        )

        self.assertEqual(result.steps[0].status.value, "rolled_back")
        self.assertTrue(tool.rollback_called)
        self.assertTrue(any(e.event_type == "step.causal_contract_verification_failed" for e in audit.events))

    def test_echo_without_contract_still_runs(self) -> None:
        registry = ToolRegistry()
        registry.register(EchoTool())
        manager = TransactionManager(registry, PolicyEngine(), CausalGraph(), AuditLog())
        result = manager.execute_plan(_plan(ActionStep("echo", {"message": "ok"}, "echo")), WorldState())

        self.assertEqual(result.steps[0].status.value, "verified")

    def test_medium_without_contract_records_warning(self) -> None:
        registry = ToolRegistry()
        registry.register(MediumNoContractTool())
        audit = AuditLog()
        manager = TransactionManager(
            registry,
            PolicyEngine(granted_permissions=(Permission.WRITE_FILES,)),
            CausalGraph(),
            audit,
            ApprovalGate(lambda step: True),
        )
        manager.execute_plan(_plan(ActionStep("medium_no_contract", {}, "medium")), WorldState())

        self.assertTrue(any(e.event_type == "step.causal_contract_missing_warning" for e in audit.events))

    def test_old_hypothesis_path_still_works(self) -> None:
        step = ActionStep("old", {"x": "y"}, "old")
        predictions = CausalGraph([CausalHypothesis("old", ["x"], "legacy")]).predict_for_tool(step, WorldState())

        self.assertEqual(predictions[0].variable, "x")


def _plan(step: ActionStep) -> TransactionPlan:
    return TransactionPlan(Goal("goal", ["ok"], stop_conditions=["done"]), [step])


if __name__ == "__main__":
    unittest.main()
