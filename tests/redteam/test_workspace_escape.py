"""Red-team tests for workspace escape attempts."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent.goals import Goal
from leos_agent.kernel import AgentKernel
from leos_agent.plans import ActionStep
from leos_agent.policy import PolicyEngine
from leos_agent.tools import default_registry


class WorkspaceEscapeRedTeamTests(unittest.TestCase):
    def _run_escape(self, path_str: str) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            policy = PolicyEngine(granted_permissions={"write_files"})
            agent = AgentKernel(registry=registry, policy=policy)
            goal = Goal(description="test", success_criteria=["blocked"], stop_conditions=["failed"])
            plan = agent.build_plan(
                goal,
                [ActionStep("safe_file_write", {"path": path_str, "content": "x"}, "escape test")],
            )
            result = agent.run(plan)
            return result.steps[0].status.value

    def test_relative_traversal_blocked(self) -> None:
        self.assertNotEqual(self._run_escape("../escape.txt"), "verified")

    def test_nested_traversal_blocked(self) -> None:
        self.assertNotEqual(self._run_escape("sub/../../escape.txt"), "verified")

    def test_dot_slash_traversal_blocked(self) -> None:
        self.assertNotEqual(self._run_escape("./../../escape.txt"), "verified")

    def test_normal_path_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            policy = PolicyEngine(granted_permissions={"write_files"})
            agent = AgentKernel(registry=registry, policy=policy)
            goal = Goal(description="test", success_criteria=["ok"], stop_conditions=["verified"])
            plan = agent.build_plan(
                goal,
                [ActionStep("safe_file_write", {"path": "normal.txt", "content": "x"}, "normal")],
            )
            result = agent.run(plan)
            self.assertEqual(result.steps[0].status.value, "verified")


if __name__ == "__main__":
    unittest.main()
