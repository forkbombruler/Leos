"""Red-team tests for policy bypass attempts."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent.enums import Permission
from leos_agent.errors import PolicyConfigurationError
from leos_agent.goals import Goal
from leos_agent.kernel import AgentKernel
from leos_agent.plans import ActionStep
from leos_agent.policy import CapabilityGrant, PolicyEngine, PolicyRule
from leos_agent.tools import ToolRegistry, default_registry


class PolicyBypassRedTeamTests(unittest.TestCase):
    def test_policy_rule_cannot_directly_approve(self) -> None:
        with self.assertRaises(PolicyConfigurationError):
            PolicyRule(
                name="auto_approve",
                when={"tool": "echo"},
                decision="approved",
            )

    def test_deny_beats_granted(self) -> None:
        policy = PolicyEngine(
            granted_permissions={Permission.WRITE_FILES},
            deny_permissions={Permission.WRITE_FILES},
        )
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(registry=registry, policy=policy)
            goal = Goal(description="t", success_criteria=["blocked"], stop_conditions=["blocked"])
            plan = agent.build_plan(
                goal,
                [ActionStep("safe_file_write", {"path": "x.txt", "content": "x"}, "test")],
            )
            result = agent.run(plan)
            self.assertNotEqual(result.steps[0].status.value, "verified")

    def test_high_risk_blocked_under_production(self) -> None:
        from leos_agent.enums import RiskLevel
        from leos_agent.tools import ToolResult, ToolSpec

        registry = ToolRegistry()

        class _HRT:
            spec = ToolSpec(
                name="high_risk_tool",
                description="h",
                permissions=(),
                default_risk=RiskLevel.HIGH,
            )

            def dry_run(self, *a, **kw):
                return ToolResult(True, "ok")

            def execute(self, *a, **kw):
                return ToolResult(True, "ok")

            def rollback(self, *a, **kw):
                return ToolResult(True, "ok")

        registry.register(_HRT())
        policy = PolicyEngine.from_profile("production")
        agent = AgentKernel(registry=registry, policy=policy)
        goal = Goal(description="t", success_criteria=["blocked"], stop_conditions=["blocked"])
        plan = agent.build_plan(goal, [ActionStep("high_risk_tool", {}, "test")])
        result = agent.run(plan)
        self.assertNotEqual(result.steps[0].status.value, "verified")

    def test_expired_grant_not_usable(self) -> None:
        import time

        grant = CapabilityGrant(
            principal="alice",
            permissions=["write_files"],
            tools=["safe_file_write"],
            expires_at=time.time() - 3600,
        )
        self.assertFalse(grant.applies_to("alice", "safe_file_write", now=time.time()))

    def test_max_uses_grant_exhausted(self) -> None:
        grant = CapabilityGrant(principal="bob", permissions=["write_files"], max_uses=1)
        self.assertTrue(grant.applies_to("bob", "safe_file_write"))
        grant.record_use()
        self.assertFalse(grant.applies_to("bob", "safe_file_write"))


if __name__ == "__main__":
    unittest.main()
