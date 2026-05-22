from __future__ import annotations

import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from leos_agent.audit import AuditLog
from leos_agent.causal import CausalGraph, CausalHypothesis
from leos_agent.causal_contract import CausalContract, ObservationFieldRequirement, github_open_pr_causal_contract
from leos_agent.enums import Permission, RiskLevel
from leos_agent.github_tools import (
    GitHubCommentTool,
    GitHubCreateBranchTool,
    GitHubOpenPRTool,
    GitHubUpdateFileTool,
    InMemoryGitHubClient,
)
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


class FieldViolationTool:
    spec = ToolSpec(
        "field_violation",
        "field violation",
        (),
        output_schema={"type": "object", "required": ["github_pr"]},
        causal_contract=CausalContract(
            "field_violation",
            required_observations=("github_pr",),
            required_fields=(ObservationFieldRequirement("github_pr", ("state",), operator="equals", value="open"),),
        ),
    )

    def __init__(self) -> None:
        self.rollback_called = False

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(
            True,
            "execute",
            observed_state_delta={"github_pr": {"number": 1, "state": "closed"}},
            rollback_token={"ok": True},
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.rollback_called = True
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

    def test_required_nested_field_missing_fails_contract(self) -> None:
        contract = github_open_pr_causal_contract()

        violations = contract.field_violations({"github_pr": {"number": 1, "state": "open", "head": "h"}})

        self.assertTrue(any("github_pr.base" in violation for violation in violations))

    def test_equals_nested_field_mismatch_fails_contract(self) -> None:
        contract = github_open_pr_causal_contract()

        violations = contract.field_violations(
            {"github_pr": {"number": 1, "state": "closed", "head": "feature", "base": "main"}}
        )

        self.assertTrue(any("github_pr.state" in violation for violation in violations))

    def test_github_pr_open_nested_fields_pass_contract(self) -> None:
        contract = github_open_pr_causal_contract()

        violations = contract.field_violations(
            {"github_pr": {"number": 1, "state": "open", "head": "feature", "base": "main"}}
        )

        self.assertEqual(violations, [])

    def test_field_violation_fails_and_rolls_back(self) -> None:
        tool = FieldViolationTool()
        registry = ToolRegistry()
        registry.register(tool)
        audit = AuditLog()
        manager = TransactionManager(registry, PolicyEngine(), CausalGraph(), audit, ApprovalGate(lambda step: True))

        result = manager.execute_plan(_plan(ActionStep("field_violation", {}, "field")), WorldState())

        self.assertEqual(result.steps[0].status.value, "rolled_back")
        self.assertTrue(tool.rollback_called)
        event = next(e for e in audit.events if e.event_type == "step.causal_contract_verification_failed")
        self.assertTrue(event.payload["field_violations"])

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

    def test_github_update_file_observation_satisfies_contract(self) -> None:
        client = InMemoryGitHubClient()
        old_sha = client.seed_file("o/r", "feature", "README.md", "old")
        tool = GitHubUpdateFileTool(client)
        registry = ToolRegistry()
        registry.register(tool)
        manager = TransactionManager(
            registry,
            PolicyEngine(granted_permissions=(Permission.WRITE_FILES,)),
            CausalGraph(),
            AuditLog(),
            ApprovalGate(lambda step: True),
            allow_network_tools=True,
        )

        result = manager.execute_plan(
            _plan(
                ActionStep(
                    "github_update_file",
                    {
                        "repo": "o/r",
                        "path": "README.md",
                        "branch": "feature",
                        "content": "new",
                        "message": "update",
                        "expected_sha": old_sha,
                    },
                    "update",
                )
            ),
            WorldState(),
        )

        self.assertEqual(result.steps[0].status.value, "verified")

    def test_github_open_pr_observation_satisfies_contract(self) -> None:
        client = InMemoryGitHubClient()
        tool = GitHubOpenPRTool(client)
        registry = ToolRegistry()
        registry.register(tool)
        manager = TransactionManager(
            registry,
            PolicyEngine(granted_permissions=(Permission.SEND_MESSAGE,)),
            CausalGraph(),
            AuditLog(),
            ApprovalGate(lambda step: True),
            allow_network_tools=True,
        )

        result = manager.execute_plan(
            _plan(
                ActionStep(
                    "github_open_pr",
                    {
                        "repo": "o/r",
                        "title": "Fix",
                        "body": "Body",
                        "head": "feature",
                        "base": "main",
                        "idempotency_key": "same",
                    },
                    "open",
                )
            ),
            WorldState(),
        )

        self.assertEqual(result.steps[0].status.value, "verified")

    def test_github_create_branch_observation_satisfies_contract(self) -> None:
        client = InMemoryGitHubClient()
        client.branches[("o/r", "main")] = "base-sha"
        tool = GitHubCreateBranchTool(client)
        registry = ToolRegistry()
        registry.register(tool)
        manager = TransactionManager(
            registry,
            PolicyEngine(granted_permissions=(Permission.WRITE_FILES,)),
            CausalGraph(),
            AuditLog(),
            ApprovalGate(lambda step: True),
            allow_network_tools=True,
        )

        result = manager.execute_plan(
            _plan(ActionStep("github_create_branch", {"repo": "o/r", "branch": "feature", "base": "main"}, "branch")),
            WorldState(),
        )

        self.assertEqual(result.steps[0].status.value, "verified")

    def test_github_comment_observation_satisfies_contract(self) -> None:
        client = InMemoryGitHubClient()
        tool = GitHubCommentTool(client)
        registry = ToolRegistry()
        registry.register(tool)
        manager = TransactionManager(
            registry,
            PolicyEngine(granted_permissions=(Permission.SEND_MESSAGE,)),
            CausalGraph(),
            AuditLog(),
            ApprovalGate(lambda step: True),
            allow_network_tools=True,
        )

        result = manager.execute_plan(
            _plan(ActionStep("github_comment", {"repo": "o/r", "issue_number": 1, "body": "hello"}, "comment")),
            WorldState(),
        )

        self.assertEqual(result.steps[0].status.value, "verified")


def _plan(step: ActionStep) -> TransactionPlan:
    return TransactionPlan(Goal("goal", ["ok"], stop_conditions=["done"]), [step])


if __name__ == "__main__":
    unittest.main()
