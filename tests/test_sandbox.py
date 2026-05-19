"""Tests for workspace sandbox runner and related types."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent import ActionStep, ApprovalGate, AuditLog, CausalGraph, Goal, TransactionManager, TransactionPlan
from leos_agent.enums import Permission, SandboxPolicy
from leos_agent.errors import SandboxViolation, WorkspaceEscapeBlocked
from leos_agent.policy import PolicyEngine
from leos_agent.sandbox import (
    ContainerSandboxRunner,
    DockerSandboxRunner,
    MicroVMSandboxRunner,
    SandboxCommand,
    SandboxCommandTool,
    SandboxUnavailable,
    WorkspaceSubprocessSandboxRunner,
)
from leos_agent.state import WorldState
from leos_agent.tools import ToolRegistry, default_registry


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

    def test_parent_env_not_inherited(self) -> None:
        import os

        os.environ["LEOS_TEST_SHOULD_NOT_LEAK"] = "secret-leak-value"
        try:
            result = self.runner.run(SandboxCommand(argv=["sh", "-c", "echo $LEOS_TEST_SHOULD_NOT_LEAK"]))
            self.assertNotIn("secret-leak-value", result.stdout)
            self.assertNotIn("secret-leak-value", result.stderr)
            self.assertNotIn("secret-leak-value", result.message)
        finally:
            del os.environ["LEOS_TEST_SHOULD_NOT_LEAK"]

    def test_env_allowed_key_is_passed(self) -> None:
        runner = WorkspaceSubprocessSandboxRunner(self.ws, allowed_env_keys=["PATH"])
        result = runner.run(SandboxCommand(argv=["sh", "-c", "echo path=$PATH"]))
        self.assertTrue(result.ok)


class ContainerMicroVMPlaceholderTests(unittest.TestCase):
    def test_container_raises_unavailable(self) -> None:
        runner = ContainerSandboxRunner()
        with self.assertRaises(SandboxUnavailable):
            runner.run(SandboxCommand(argv=["echo", "x"]))


class DockerSandboxRunnerTests(unittest.TestCase):
    def test_build_argv_contains_hardening_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = DockerSandboxRunner(Path(tmp), runtime="docker")
            argv = runner.build_argv(SandboxCommand(argv=["python", "-V"]))

        self.assertIn("--network", argv)
        self.assertIn("none", argv)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("--security-opt", argv)
        self.assertIn("no-new-privileges", argv)
        self.assertIn("--memory", argv)
        self.assertIn("--cpus", argv)
        self.assertIn("--pids-limit", argv)
        self.assertIn("--read-only", argv)

    def test_unavailable_runtime_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = DockerSandboxRunner(Path(tmp), runtime="definitely-missing-runtime")
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

    def test_container_policy_tool_without_runner_is_blocked(self) -> None:
        runner = _FakeRunner()
        tool = SandboxCommandTool.container(runner)
        registry = ToolRegistry()
        registry.register(tool)
        manager = TransactionManager(
            registry,
            PolicyEngine(granted_permissions=(Permission.EXECUTE_CODE,)),
            CausalGraph(),
            AuditLog(),
            ApprovalGate(lambda step: True),
        )
        plan = TransactionPlan(
            Goal("container", ["done"]),
            [ActionStep("sandbox_command", {"argv": ["echo", "hi"]}, "run")],
        )

        result = manager.execute_plan(plan, WorldState())

        self.assertEqual(result.steps[0].status.value, "blocked")
        self.assertFalse(runner.called)

    def test_container_policy_tool_with_runner_can_execute(self) -> None:
        runner = _FakeRunner()
        tool = SandboxCommandTool.container(runner)
        registry = ToolRegistry()
        registry.register(tool)
        manager = TransactionManager(
            registry,
            PolicyEngine(granted_permissions=(Permission.EXECUTE_CODE,)),
            CausalGraph(),
            AuditLog(),
            ApprovalGate(lambda step: True),
            sandbox_runners={SandboxPolicy.CONTAINER: runner},
        )
        plan = TransactionPlan(
            Goal("container", ["done"]),
            [ActionStep("sandbox_command", {"argv": ["echo", "hi"]}, "run")],
        )

        result = manager.execute_plan(plan, WorldState())

        self.assertEqual(result.steps[0].status.value, "verified")
        self.assertTrue(runner.called)


class _FakeRunner:
    def __init__(self) -> None:
        self.called = False

    def run(self, command: SandboxCommand):
        from leos_agent.sandbox import SandboxResult

        self.called = True
        return SandboxResult(True, 0, "ok", "", message="ok")


if __name__ == "__main__":
    unittest.main()
