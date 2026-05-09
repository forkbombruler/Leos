"""Tests for workspace sandbox runner and related types."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent.enums import Permission, SandboxPolicy
from leos_agent.errors import SandboxViolation, WorkspaceEscapeBlocked
from leos_agent.policy import PolicyEngine
from leos_agent.sandbox import (
    ContainerSandboxRunner,
    MicroVMSandboxRunner,
    SandboxCommand,
    SandboxCommandTool,
    SandboxUnavailable,
    WorkspaceSubprocessSandboxRunner,
)
from leos_agent.tools import default_registry


class WorkspaceSubprocessSandboxRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        self.runner = WorkspaceSubprocessSandboxRunner(self.ws)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_command_runs_in_workspace(self) -> None:
        result = self.runner.run(SandboxCommand(argv=["echo", "hello"]))
        self.assertTrue(result.ok)
        self.assertIn("hello", result.stdout)

    def test_cwd_path_escape_blocked(self) -> None:
        with self.assertRaises(WorkspaceEscapeBlocked):
            self.runner.run(SandboxCommand(argv=["echo", "x"], cwd="../../etc"))

    def test_empty_argv_rejected(self) -> None:
        with self.assertRaises(SandboxViolation):
            self.runner.run(SandboxCommand(argv=[]))

    def test_timeout_works(self) -> None:
        result = self.runner.run(SandboxCommand(argv=["sleep", "5"], timeout_seconds=0.1))
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)

    def test_output_truncation_works(self) -> None:
        result = self.runner.run(
            SandboxCommand(
                argv=["python3", "-c", "print('x' * 50000)"],
                max_output_bytes=100,
            )
        )
        self.assertLessEqual(len(result.stdout), 100)

    def test_env_secret_not_inherited_by_default(self) -> None:
        result = self.runner.run(
            SandboxCommand(
                argv=["sh", "-c", "echo $SECRET_TOKEN"],
                env={"SECRET_TOKEN": "should-not-leak"},
            )
        )
        self.assertNotIn("should-not-leak", result.stdout)

    def test_env_allowed_key_is_passed(self) -> None:
        runner = WorkspaceSubprocessSandboxRunner(self.ws, allowed_env_keys=["PATH"])
        result = runner.run(SandboxCommand(argv=["sh", "-c", "echo path=$PATH"]))
        self.assertTrue(result.ok)


class ContainerMicroVMPlaceholderTests(unittest.TestCase):
    def test_container_raises_unavailable(self) -> None:
        runner = ContainerSandboxRunner()
        with self.assertRaises(SandboxUnavailable):
            runner.run(SandboxCommand(argv=["echo", "x"]))

    def test_microvm_raises_unavailable(self) -> None:
        runner = MicroVMSandboxRunner()
        with self.assertRaises(SandboxUnavailable):
            runner.run(SandboxCommand(argv=["echo", "x"]))


class SandboxCommandToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tool = SandboxCommandTool(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_tool_not_in_default_registry(self) -> None:
        self.assertNotIn("sandbox_command", default_registry().names())

    def test_dry_run_validates_argv(self) -> None:
        from leos_agent.state import WorldState

        result = self.tool.dry_run({"argv": ["echo", "hi"]}, WorldState())
        self.assertTrue(result.ok)

    def test_dry_run_rejects_empty_argv(self) -> None:
        from leos_agent.state import WorldState

        result = self.tool.dry_run({"argv": []}, WorldState())
        self.assertFalse(result.ok)

    def test_execute_runs_command(self) -> None:
        from leos_agent.state import WorldState

        result = self.tool.execute({"argv": ["echo", "-n", "hello"]}, WorldState())
        self.assertTrue(result.ok)
        self.assertEqual(result.data["stdout"], "hello")

    def test_sandbox_policy_is_workspace(self) -> None:
        self.assertEqual(self.tool.spec.sandbox_policy, SandboxPolicy.WORKSPACE)

    def test_tool_requires_execute_code_permission(self) -> None:
        self.assertIn(Permission.EXECUTE_CODE, self.tool.spec.permissions)

    def test_production_profile_blocks_execute_code(self) -> None:
        policy = PolicyEngine.from_profile("production")
        self.assertIn(Permission.EXECUTE_CODE, policy.require_human_for)


if __name__ == "__main__":
    unittest.main()
