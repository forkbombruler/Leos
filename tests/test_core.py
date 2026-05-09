from __future__ import annotations

import json
import tempfile
import time
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from leos_agent import (
    BUILT_IN_POLICY_PROFILES,
    ActionStep,
    AgentKernel,
    ApprovalGate,
    AuditLog,
    AuditReplayer,
    CausalGraph,
    CausalHypothesis,
    CausalWorldModel,
    CompensationStrategy,
    Goal,
    GoalStatus,
    InvalidGoalTransition,
    MemorySensitivity,
    MemoryStore,
    MemoryType,
    Permission,
    PlannerConfig,
    PlanProposal,
    PolicyConfigurationError,
    PolicyEngine,
    PolicyProfile,
    ReplayResult,
    ResourceBudget,
    RetryPolicy,
    Reversibility,
    RiskLevel,
    RuntimeTask,
    SchemaValidationFailed,
    StateCondition,
    StepStatus,
    TaskQueue,
    TaskRunner,
    TaskStatus,
    TimeoutPolicy,
    ToolManifest,
    TrustLevel,
    Watchdog,
    default_registry,
    replay_audit_log,
    validate_json_schema,
    validate_policy_config,
)
from leos_agent.audit import AuditAnomalyDetector
from leos_agent.cli import (
    _dry_run,
    _list_tools,
    _replay,
    _run,
    _sign_policy,
    _validate_policy,
    build_demo_agent,
)
from leos_agent.core import (
    ToolRegistry,
    ToolResult,
    ToolSpec,
    TransactionManager,
    WorldState,
)
from leos_agent.enums import SandboxPolicy
from leos_agent.errors import (
    LLMOutputValidationError,
    PolicyIntegrityError,
    RollbackFailed,
    SecretBoundaryViolation,
    WorkspaceEscapeBlocked,
)
from leos_agent.planner import validate_llm_proposals
from leos_agent.policy import CapabilityGrant
from leos_agent.policy_manifest import (
    load_policy_from_file,
    sign_policy,
    verify_policy_manifest,
)
from leos_agent.tools import Secret


class DryRunFailingTool:
    spec = ToolSpec(
        name="dry_run_fails",
        description="Fails dry-run and records if execute is called.",
        permissions=(),
        default_risk=RiskLevel.LOW,
    )

    def __init__(self) -> None:
        self.executed = False

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(False, "dry-run failed")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.executed = True
        return ToolResult(True, "executed")

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "rolled back")


class HighRiskTool:
    spec = ToolSpec(
        name="high_risk",
        description="High-risk test tool.",
        permissions=(),
        default_risk=RiskLevel.HIGH,
    )

    def __init__(self) -> None:
        self.executed = False

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry-run passed")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.executed = True
        return ToolResult(True, "executed")

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "rolled back")


class RollbackFailingTool:
    spec = ToolSpec(
        name="rollback_fails",
        description="Executes successfully but cannot roll back.",
        permissions=(),
        default_risk=RiskLevel.LOW,
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry-run passed")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(
            True,
            "executed",
            observed_state_delta={"rollback_failing_tool_executed": True},
            rollback_token={"resource": "rollback-failure-test"},
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(False, "rollback failed", error=RollbackFailed("rollback failed"))


class RollbackSucceedingTool:
    spec = ToolSpec(
        name="rollback_succeeds",
        description="Executes successfully and rolls back successfully.",
        permissions=(),
        default_risk=RiskLevel.LOW,
    )

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry-run passed")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(
            True,
            "executed",
            observed_state_delta={"rollback_succeeding_tool_executed": True},
            rollback_token={"resource": "rollback-success-test"},
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "rollback succeeded")


class IrreversibleWriteTool:
    spec = ToolSpec(
        name="irreversible_write",
        description="Consequential write that cannot be undone.",
        permissions=(Permission.WRITE_FILES,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.IRREVERSIBLE,
        compensation_strategy=CompensationStrategy.MANUAL,
    )

    def __init__(self) -> None:
        self.executed = False

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry-run passed")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.executed = True
        return ToolResult(True, "executed")

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(False, "cannot roll back")


class CompensatableWriteTool:
    spec = ToolSpec(
        name="compensatable_write",
        description="Consequential write that can only be compensated.",
        permissions=(Permission.WRITE_FILES,),
        default_risk=RiskLevel.MEDIUM,
        reversibility=Reversibility.COMPENSATABLE,
        compensation_strategy=CompensationStrategy.COMPENSATE,
    )

    def __init__(self) -> None:
        self.executed = False

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry-run passed")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.executed = True
        return ToolResult(True, "executed")

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "compensated")


class NetworkTool:
    spec = ToolSpec(
        name="network_fetch",
        description="Network test tool.",
        permissions=(Permission.NETWORK,),
        default_risk=RiskLevel.LOW,
    )

    def __init__(self) -> None:
        self.executed = False

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry-run passed")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.executed = True
        return ToolResult(True, "executed")

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "rolled back")


class BadOutputSchemaTool:
    spec = ToolSpec(
        name="bad_output_schema",
        description="Returns observed state that violates its output schema.",
        permissions=(),
        default_risk=RiskLevel.LOW,
        reversible=True,
        output_schema={
            "type": "object",
            "required": ["external_id"],
            "properties": {
                "external_id": {"type": "string"},
            },
            "additionalProperties": False,
        },
    )

    def __init__(self) -> None:
        self.executed = False
        self.rolled_back = False

    def dry_run(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        return ToolResult(True, "dry-run passed")

    def execute(self, arguments: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.executed = True
        return ToolResult(
            True,
            "executed with malformed output",
            observed_state_delta={"external_id": 42, "unexpected": True},
            rollback_token={"external_id": 42},
        )

    def rollback(self, token: Mapping[str, Any], state: WorldState) -> ToolResult:
        self.rolled_back = True
        return ToolResult(True, "rolled back malformed output")


class AgentKernelTests(unittest.TestCase):
    def test_split_module_imports_match_core_exports(self) -> None:
        from leos_agent.audit import AuditLog as SplitAuditLog
        from leos_agent.core import AuditLog as CoreAuditLog
        from leos_agent.core import ToolSpec as CoreToolSpec
        from leos_agent.core import WorldState as CoreWorldState
        from leos_agent.state import WorldState as SplitWorldState
        from leos_agent.tools import ToolSpec as SplitToolSpec

        self.assertIs(CoreAuditLog, SplitAuditLog)
        self.assertIs(CoreToolSpec, SplitToolSpec)
        self.assertIs(CoreWorldState, SplitWorldState)

    def test_world_state_tracks_trust_without_promoting_assumptions(self) -> None:
        state = WorldState()

        state.set_assumption("user_timezone", "Asia/Shanghai", uncertainty=0.2)

        self.assertNotIn("user_timezone", state.facts)
        self.assertEqual(state.assumptions["user_timezone"], "Asia/Shanghai")
        self.assertEqual(state.trust["user_timezone"], TrustLevel.MODEL_INFERRED)
        self.assertEqual(state.snapshot()["trust"]["user_timezone"], "model_inferred")

        state.promote_assumption("user_timezone")

        self.assertEqual(state.facts["user_timezone"], "Asia/Shanghai")
        self.assertNotIn("user_timezone", state.assumptions)
        self.assertNotIn("user_timezone", state.uncertainty)
        self.assertEqual(state.trust["user_timezone"], TrustLevel.VERIFIED)

    def test_low_risk_echo_runs_and_verifies(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Echo a message",
            success_criteria=["last_echo equals the message"],
            stop_conditions=["one step complete"],
        )
        plan = agent.build_plan(goal, [ActionStep("echo", {"message": "hello"}, "test echo")])

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)
        self.assertEqual(agent.state.facts["last_echo"], "hello")

    def test_goal_lifecycle_success_transitions_are_audited(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Echo a message",
            success_criteria=["goal succeeds"],
            stop_conditions=["one step complete"],
        )
        plan = agent.build_plan(goal, [ActionStep("echo", {"message": "hello"}, "test lifecycle")])

        result = agent.run(plan)

        self.assertEqual(result.goal.status, GoalStatus.SUCCEEDED)
        transitions = [event for event in agent.audit_log.events if event.event_type == "goal.status_changed"]
        observed = [(event.payload["from_status"], event.payload["to_status"]) for event in transitions]
        self.assertIn(("created", "planning"), observed)
        self.assertIn(("planning", "running"), observed)
        self.assertIn(("running", "succeeded"), observed)

    def test_goal_lifecycle_partially_done_after_later_block(self) -> None:
        registry = default_registry()
        high_risk = HighRiskTool()
        registry.register(high_risk)
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Partially complete before a block",
            success_criteria=["partial status is explicit"],
            stop_conditions=["blocked"],
        )
        plan = agent.build_plan(
            goal,
            [
                ActionStep("echo", {"message": "first"}, "complete low-risk work"),
                ActionStep("high_risk", {}, "blocked high-risk work"),
            ],
        )

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)
        self.assertEqual(result.steps[1].status, StepStatus.BLOCKED)
        self.assertEqual(result.goal.status, GoalStatus.PARTIALLY_DONE)
        self.assertFalse(high_risk.executed)

    def test_goal_lifecycle_rejects_invalid_terminal_transition(self) -> None:
        goal = (
            Goal(
                description="Terminal transition boundary",
                success_criteria=["invalid transition fails"],
                stop_conditions=["exception"],
            )
            .transition(GoalStatus.PLANNING)
            .transition(GoalStatus.RUNNING)
            .transition(GoalStatus.SUCCEEDED)
        )

        with self.assertRaises(InvalidGoalTransition):
            goal.transition(GoalStatus.RUNNING)

    def test_task_queue_enqueues_and_claims_fifo(self) -> None:
        audit = AuditLog()
        queue = TaskQueue(audit)
        agent = AgentKernel(registry=default_registry(), policy=PolicyEngine(), audit_log=audit)
        first = agent.build_plan(
            Goal("First task", ["first runs"], stop_conditions=["done"]),
            [ActionStep("echo", {"message": "first"}, "first")],
        )
        second = agent.build_plan(
            Goal("Second task", ["second runs"], stop_conditions=["done"]),
            [ActionStep("echo", {"message": "second"}, "second")],
        )

        first_task = queue.enqueue(first)
        second_task = queue.enqueue(second)
        claimed = queue.claim("worker-1", now=10.0)

        self.assertIsInstance(first_task, RuntimeTask)
        self.assertEqual(claimed.task_id, first_task.task_id)
        self.assertEqual(second_task.status, TaskStatus.QUEUED)
        self.assertEqual(first_task.status, TaskStatus.RUNNING)
        self.assertEqual(first_task.locked_by, "worker-1")
        events = [event.event_type for event in audit.events]
        self.assertIn("task.enqueued", events)
        self.assertIn("task.claimed", events)

    def test_task_queue_idempotency_deduplicates_enqueued_tasks(self) -> None:
        audit = AuditLog()
        queue = TaskQueue(audit)
        agent = AgentKernel(registry=default_registry(), policy=PolicyEngine(), audit_log=audit)
        plan = agent.build_plan(
            Goal("Idempotent task", ["dedupe works"], stop_conditions=["done"]),
            [ActionStep("echo", {"message": "once"}, "once")],
        )

        first = queue.enqueue(plan, idempotency_key="task-once")
        duplicate = queue.enqueue(plan, idempotency_key="task-once")

        self.assertEqual(first.task_id, duplicate.task_id)
        self.assertEqual(len(queue.tasks()), 1)
        dedupe = [event for event in audit.events if event.event_type == "task.deduplicated"]
        self.assertEqual(dedupe[0].payload["idempotency_key"], "task-once")

    def test_watchdog_marks_stale_heartbeat_as_timed_out(self) -> None:
        audit = AuditLog()
        queue = TaskQueue(audit)
        watchdog = Watchdog(queue, audit)
        agent = AgentKernel(registry=default_registry(), policy=PolicyEngine(), audit_log=audit)
        plan = agent.build_plan(
            Goal("Watchdog task", ["timeout is explicit"], stop_conditions=["timed out"]),
            [ActionStep("echo", {"message": "slow"}, "slow")],
        )
        task = queue.enqueue(plan, timeout_policy=TimeoutPolicy(heartbeat_timeout_seconds=5.0))
        queue.claim("worker-1", now=10.0)

        timed_out = watchdog.check(now=16.0)

        self.assertEqual(timed_out[0].task_id, task.task_id)
        self.assertEqual(task.status, TaskStatus.TIMED_OUT)
        self.assertIsNone(task.locked_by)
        self.assertEqual(task.failure_reason, "Task heartbeat timed out")
        events = [event for event in audit.events if event.event_type == "task.timed_out"]
        self.assertEqual(events[0].payload["task_id"], task.task_id)

    def test_task_queue_pause_resume_and_worker_lock(self) -> None:
        queue = TaskQueue()
        agent = AgentKernel(registry=default_registry(), policy=PolicyEngine())
        plan = agent.build_plan(
            Goal("Pause task", ["pause and resume"], stop_conditions=["done"]),
            [ActionStep("echo", {"message": "pause"}, "pause")],
        )
        task = queue.enqueue(plan)
        queue.claim("worker-1")

        with self.assertRaises(PermissionError):
            queue.heartbeat(task.task_id, "worker-2")

        queue.pause(task.task_id, "worker-1")
        self.assertEqual(task.status, TaskStatus.PAUSED)
        queue.resume(task.task_id)
        self.assertEqual(task.status, TaskStatus.QUEUED)

    def test_task_runner_executes_next_task_to_completion(self) -> None:
        audit = AuditLog()
        agent = AgentKernel(registry=default_registry(), policy=PolicyEngine(), audit_log=audit)
        queue = TaskQueue(audit)
        runner = TaskRunner(queue, agent, worker_id="worker-1", audit_log=audit)
        plan = agent.build_plan(
            Goal("Run queued task", ["task succeeds"], stop_conditions=["done"]),
            [ActionStep("echo", {"message": "queued"}, "run queued echo")],
        )
        task = queue.enqueue(plan)

        result = runner.run_next(now=20.0)

        self.assertEqual(result.task_id, task.task_id)
        self.assertEqual(task.status, TaskStatus.SUCCEEDED)
        self.assertEqual(agent.state.facts["last_echo"], "queued")
        events = [event.event_type for event in audit.events]
        self.assertIn("task.runner_started", events)
        self.assertIn("task.runner_finished", events)
        self.assertIn("task.completed", events)

    def test_task_runner_fails_when_goal_does_not_succeed(self) -> None:
        audit = AuditLog()
        registry = ToolRegistry()
        high_risk = HighRiskTool()
        registry.register(high_risk)
        agent = AgentKernel(registry=registry, policy=PolicyEngine(), audit_log=audit)
        queue = TaskQueue(audit)
        runner = TaskRunner(queue, agent, worker_id="worker-1", audit_log=audit)
        plan = agent.build_plan(
            Goal("Blocked queued task", ["task blocks"], stop_conditions=["blocked"]),
            [ActionStep("high_risk", {}, "blocked")],
        )
        task = queue.enqueue(plan)

        result = runner.run_next(now=30.0)

        self.assertEqual(result.task_id, task.task_id)
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertEqual(task.failure_reason, "Goal ended with status blocked")
        self.assertFalse(high_risk.executed)

    def test_task_runner_reschedules_retryable_failure(self) -> None:
        audit = AuditLog()
        registry = ToolRegistry()
        high_risk = HighRiskTool()
        registry.register(high_risk)
        agent = AgentKernel(registry=registry, policy=PolicyEngine(), audit_log=audit)
        queue = TaskQueue(audit)
        runner = TaskRunner(queue, agent, worker_id="worker-1", audit_log=audit)
        plan = agent.build_plan(
            Goal("Retry blocked task", ["retry is scheduled"], stop_conditions=["blocked"]),
            [ActionStep("high_risk", {}, "blocked")],
        )
        task = queue.enqueue(plan, retry_policy=RetryPolicy(max_attempts=2))

        result = runner.run_next(now=40.0)

        self.assertEqual(result.task_id, task.task_id)
        self.assertEqual(task.status, TaskStatus.QUEUED)
        self.assertEqual(task.attempts, 1)
        retry_events = [event for event in audit.events if event.event_type == "task.retry_scheduled"]
        self.assertEqual(retry_events[0].payload["max_attempts"], 2)

    def test_task_runner_records_idle_when_queue_empty(self) -> None:
        audit = AuditLog()
        agent = AgentKernel(registry=default_registry(), policy=PolicyEngine(), audit_log=audit)
        queue = TaskQueue(audit)
        runner = TaskRunner(queue, agent, worker_id="worker-1", audit_log=audit)

        result = runner.run_next()

        self.assertIsNone(result)
        idle_events = [event for event in audit.events if event.event_type == "task.runner_idle"]
        self.assertEqual(idle_events[0].payload["worker_id"], "worker-1")

    def test_tool_spec_reversibility_keeps_bool_compatibility(self) -> None:
        legacy_reversible = ToolSpec(
            name="legacy_reversible",
            description="Uses the legacy boolean reversible flag.",
            permissions=(),
            reversible=True,
        )
        explicit_compensatable = ToolSpec(
            name="explicit_compensatable",
            description="Uses explicit reversibility metadata.",
            permissions=(),
            reversible=True,
            reversibility=Reversibility.COMPENSATABLE,
            compensation_strategy=CompensationStrategy.COMPENSATE,
            rollback_reliability=0.5,
        )

        self.assertTrue(legacy_reversible.reversible)
        self.assertEqual(legacy_reversible.reversibility, Reversibility.REVERSIBLE)
        self.assertFalse(explicit_compensatable.reversible)
        self.assertEqual(explicit_compensatable.reversibility, Reversibility.COMPENSATABLE)
        self.assertEqual(explicit_compensatable.compensation_strategy, CompensationStrategy.COMPENSATE)
        self.assertEqual(explicit_compensatable.rollback_reliability, 0.5)

    def test_policy_profile_factory_loads_builtin_profiles(self) -> None:
        developer = PolicyEngine.from_profile("developer_local")
        production = PolicyEngine.from_profile(BUILT_IN_POLICY_PROFILES["production"])

        self.assertEqual(developer.profile_name, "developer_local")
        self.assertIn(Permission.WRITE_FILES, developer.granted_permissions)
        self.assertIn(Permission.NETWORK, developer.deny_permissions)
        self.assertEqual(production.profile_name, "production")
        self.assertIn(Permission.WRITE_FILES, production.require_human_for)

        with self.assertRaises(KeyError):
            PolicyEngine.from_profile("missing_profile")

    def test_custom_policy_profile_can_be_used_directly(self) -> None:
        profile = PolicyProfile(
            name="custom_read_only",
            granted_permissions=(Permission.READ_FILES,),
            max_auto_risk=RiskLevel.LOW,
            deny_permissions=(Permission.WRITE_FILES,),
        )

        policy = PolicyEngine.from_profile(profile)

        self.assertEqual(policy.profile_name, "custom_read_only")
        self.assertIn(Permission.READ_FILES, policy.granted_permissions)
        self.assertIn(Permission.WRITE_FILES, policy.deny_permissions)

    def test_policy_as_code_loads_profile_from_mapping(self) -> None:
        policy = PolicyEngine.from_mapping(
            {
                "name": "locked_developer",
                "granted_permissions": ["write_files"],
                "max_auto_risk": "medium",
                "rules": [
                    {
                        "name": "deny_file_writer",
                        "when": {"tool": "safe_file_write"},
                        "decision": "denied",
                    }
                ],
            }
        )

        self.assertEqual(policy.profile_name, "locked_developer")
        self.assertIn(Permission.WRITE_FILES, policy.granted_permissions)
        self.assertEqual(policy.rules[0].name, "deny_file_writer")
        self.assertEqual(
            validate_policy_config(
                {
                    "name": "valid",
                    "rules": [{"name": "deny_network", "when": {"permission": "network"}, "decision": "denied"}],
                }
            ),
            [],
        )

    def test_policy_as_code_rejects_direct_approval_rules(self) -> None:
        config = {
            "name": "unsafe_policy",
            "rules": [
                {
                    "name": "approve_everything",
                    "when": {"risk_at_least": "low"},
                    "decision": "approved",
                }
            ],
        }

        issues = validate_policy_config(config)

        self.assertEqual(issues[0]["reason"], "policy_config_invalid")
        with self.assertRaises(PolicyConfigurationError):
            PolicyEngine.from_mapping(config)

    def test_policy_as_code_denies_matching_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            policy = PolicyEngine.from_mapping(
                {
                    "name": "deny_writes_by_rule",
                    "granted_permissions": ["write_files"],
                    "max_auto_risk": "medium",
                    "rules": [
                        {
                            "name": "deny_workspace_write",
                            "when": {"tool": "safe_file_write"},
                            "decision": "denied",
                        }
                    ],
                }
            )
            agent = AgentKernel(registry=registry, policy=policy)
            goal = Goal(
                description="Configured deny rule blocks writes",
                success_criteria=["file is not written"],
                stop_conditions=["blocked"],
            )
            plan = agent.build_plan(
                goal, [ActionStep("safe_file_write", {"path": "x.txt", "content": "x"}, "test policy rule")]
            )

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
            self.assertFalse((Path(tmp) / "x.txt").exists())
            blocked = [event for event in agent.audit_log.events if event.event_type == "step.blocked"]
            self.assertEqual(blocked[0].payload["decision"], "denied")

    def test_policy_as_code_requires_human_for_permission(self) -> None:
        registry = ToolRegistry()
        tool = NetworkTool()
        registry.register(tool)
        policy = PolicyEngine.from_mapping(
            {
                "name": "network_review",
                "granted_permissions": ["network"],
                "max_auto_risk": "medium",
                "rules": [
                    {
                        "name": "review_network",
                        "when": {"permission": "network"},
                        "decision": "needs_human",
                    }
                ],
            }
        )
        agent = AgentKernel(registry=registry, policy=policy)
        goal = Goal(
            description="Configured needs_human rule blocks without approver",
            success_criteria=["network does not execute"],
            stop_conditions=["blocked"],
        )
        plan = agent.build_plan(goal, [ActionStep("network_fetch", {}, "test needs_human rule")])

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        self.assertFalse(tool.executed)
        blocked = [event for event in agent.audit_log.events if event.event_type == "step.blocked"]
        self.assertEqual(blocked[0].payload["decision"], "denied")

    def test_resource_budget_rejects_negative_limits(self) -> None:
        with self.assertRaises(ValueError):
            ResourceBudget(max_tool_calls=-1)

    def test_resource_budget_blocks_before_tool_call_limit_is_exceeded(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Stay inside tool call budget",
            success_criteria=["no tool executes"],
            stop_conditions=["blocked"],
            budget=ResourceBudget(max_tool_calls=0),
        )
        plan = agent.build_plan(goal, [ActionStep("echo", {"message": "hello"}, "test budget boundary")])

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        self.assertNotIn("last_echo", agent.state.facts)
        budget_events = [event for event in agent.audit_log.events if event.event_type == "budget.exceeded"]
        self.assertEqual(budget_events[0].payload["error_type"], "BudgetExceeded")
        self.assertEqual(budget_events[0].payload["limit"], "max_tool_calls")

    def test_resource_budget_blocks_risk_above_goal_limit(self) -> None:
        registry = ToolRegistry()
        tool = HighRiskTool()
        registry.register(tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Stay inside risk budget",
            success_criteria=["high risk tool does not execute"],
            stop_conditions=["blocked"],
            budget=ResourceBudget(max_risk_level=RiskLevel.LOW),
        )
        plan = agent.build_plan(goal, [ActionStep("high_risk", {}, "test risk budget")])

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        self.assertFalse(tool.executed)
        budget_events = [event for event in agent.audit_log.events if event.event_type == "budget.exceeded"]
        self.assertEqual(budget_events[0].payload["limit"], "max_risk_level")
        self.assertEqual(budget_events[0].payload["allowed"], "low")
        self.assertEqual(budget_events[0].payload["actual"], "high")

    def test_resource_budget_blocks_file_write_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(registry=registry, policy=PolicyEngine.from_profile("developer_local"))
            goal = Goal(
                description="Stay inside file write budget",
                success_criteria=["file write does not execute"],
                stop_conditions=["blocked"],
                budget=ResourceBudget(max_file_writes=0),
            )
            plan = agent.build_plan(
                goal, [ActionStep("safe_file_write", {"path": "x.txt", "content": "x"}, "test file budget")]
            )

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
            self.assertFalse((Path(tmp) / "x.txt").exists())
            budget_events = [event for event in agent.audit_log.events if event.event_type == "budget.exceeded"]
            self.assertEqual(budget_events[0].payload["limit"], "max_file_writes")

    def test_step_precondition_blocks_before_dry_run(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Do not act without readiness fact",
            success_criteria=["echo does not execute"],
            stop_conditions=["blocked"],
        )
        plan = agent.build_plan(
            goal,
            [
                ActionStep(
                    "echo",
                    {"message": "hello"},
                    "test precondition boundary",
                    preconditions=(StateCondition("ready", "equals", True),),
                )
            ],
        )

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        self.assertNotIn("last_echo", agent.state.facts)
        failures = [event for event in agent.audit_log.events if event.event_type == "step.precondition_failed"]
        self.assertEqual(failures[0].payload["error_type"], "PreconditionFailed")
        self.assertEqual(failures[0].payload["issues"][0]["reason"], "value_mismatch")

    def test_step_postcondition_failure_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(registry=registry, policy=PolicyEngine.from_profile("developer_local"))
            goal = Goal(
                description="Rollback when postcondition is false",
                success_criteria=["file is rolled back"],
                stop_conditions=["failed"],
            )
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {"path": "x.txt", "content": "x"},
                        "test postcondition boundary",
                        postconditions=(StateCondition("file_written", "equals", "wrong-path"),),
                    )
                ],
            )

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.ROLLED_BACK)
            self.assertFalse((Path(tmp) / "x.txt").exists())
            failures = [event for event in agent.audit_log.events if event.event_type == "step.postcondition_failed"]
            self.assertEqual(failures[0].payload["error_type"], "PostconditionFailed")
            self.assertEqual(failures[0].payload["issues"][0]["reason"], "value_mismatch")

    def test_idempotency_key_blocks_duplicate_step(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Do not repeat the same idempotent step",
            success_criteria=["duplicate step blocks"],
            stop_conditions=["blocked"],
        )
        plan = agent.build_plan(
            goal,
            [
                ActionStep("echo", {"message": "first"}, "record idempotency", idempotency_key="echo-once"),
                ActionStep("echo", {"message": "second"}, "duplicate idempotency", idempotency_key="echo-once"),
            ],
        )

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)
        self.assertEqual(result.steps[1].status, StepStatus.BLOCKED)
        self.assertEqual(agent.state.facts["last_echo"], "first")
        self.assertIn("idempotency:echo-once", agent.state.facts)
        duplicates = [event for event in agent.audit_log.events if event.event_type == "step.idempotency_duplicate"]
        self.assertEqual(duplicates[0].payload["error_type"], "IdempotencyConflict")

    def test_safe_file_write_manifest_exposes_schema_and_safety_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            tool = registry.get("safe_file_write")

            manifest = tool.spec.manifest()

            self.assertIsInstance(manifest, ToolManifest)
            self.assertEqual(manifest.name, "safe_file_write")
            self.assertEqual(manifest.permissions, (Permission.WRITE_FILES,))
            self.assertEqual(manifest.risk, RiskLevel.MEDIUM)
            self.assertEqual(manifest.reversibility, Reversibility.REVERSIBLE)
            self.assertEqual(manifest.filesystem_scope, "workspace")
            self.assertFalse(manifest.network_access)
            self.assertFalse(manifest.secrets_allowed)
            self.assertEqual(manifest.input_schema["required"], ["path", "content"])

    def test_validate_json_schema_reports_required_and_type_issues(self) -> None:
        schema = {
            "type": "object",
            "required": ["path", "content"],
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "additionalProperties": False,
        }

        issues = validate_json_schema({"path": 3, "unexpected": True}, schema)

        reasons = {issue["reason"] for issue in issues}
        self.assertIn("required", reasons)
        self.assertIn("type", reasons)
        self.assertIn("additionalProperties", reasons)

    def test_safe_file_write_schema_failure_blocks_before_execute(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(
                registry=registry,
                policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}),
                approval_gate=ApprovalGate(lambda step: True),
            )
            goal = Goal(
                description="Reject malformed file write",
                success_criteria=["schema failure is recorded"],
                stop_conditions=["failed"],
            )
            plan = agent.build_plan(goal, [ActionStep("safe_file_write", {"path": "x.txt"}, "test schema boundary")])

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.FAILED)
            self.assertFalse((Path(tmp) / "x.txt").exists())
            failures = [event for event in agent.audit_log.events if event.event_type == "step.dry_run_failed"]
            self.assertEqual(failures[0].payload["error_type"], "SchemaValidationFailed")
            self.assertEqual(failures[0].payload["data"]["schema_issues"][0]["reason"], "required")

            dry_run = registry.get("safe_file_write").dry_run({"path": "x.txt"}, agent.state)
            self.assertIsInstance(dry_run.error, SchemaValidationFailed)

    def test_tool_output_schema_failure_rolls_back_before_state_write(self) -> None:
        registry = ToolRegistry()
        tool = BadOutputSchemaTool()
        registry.register(tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Reject malformed tool output",
            success_criteria=["bad output does not enter state"],
            stop_conditions=["rolled back"],
        )
        plan = agent.build_plan(goal, [ActionStep("bad_output_schema", {}, "test output schema boundary")])

        result = agent.run(plan)

        self.assertTrue(tool.executed)
        self.assertTrue(tool.rolled_back)
        self.assertEqual(result.steps[0].status, StepStatus.ROLLED_BACK)
        self.assertNotIn("external_id", agent.state.facts)
        self.assertNotIn("unexpected", agent.state.facts)
        failures = [event for event in agent.audit_log.events if event.event_type == "step.output_schema_failed"]
        self.assertEqual(failures[0].payload["error_type"], "SchemaValidationFailed")
        reasons = {issue["reason"] for issue in failures[0].payload["data"]["schema_issues"]}
        self.assertIn("type", reasons)
        self.assertIn("additionalProperties", reasons)

    def test_memory_lifecycle_filters_expired_items(self) -> None:
        memory = MemoryStore()
        memory.remember("preference", "short answers", confidence=0.9, provenance="user", ttl=0.01)

        self.assertEqual(len(memory.recall("preference")), 1)

        removed = memory.purge_expired(now=time.time() + 1.0)

        self.assertEqual(removed, 1)
        self.assertEqual(memory.recall("preference"), [])

    def test_memory_lifecycle_filters_scope_and_type(self) -> None:
        memory = MemoryStore()
        memory.remember(
            "deploy",
            "run release script",
            confidence=0.8,
            provenance="docs",
            memory_type=MemoryType.PROCEDURE,
            scope="project-a",
        )
        memory.remember(
            "deploy",
            "do not deploy Fridays",
            confidence=0.7,
            provenance="policy",
            memory_type=MemoryType.POLICY,
            scope="project-b",
        )

        procedures = memory.recall("deploy", scope="project-a", memory_type=MemoryType.PROCEDURE)

        self.assertEqual(len(procedures), 1)
        self.assertEqual(procedures[0]["memory_type"], "procedure")
        self.assertEqual(procedures[0]["scope"], "project-a")

    def test_memory_lifecycle_persists_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.json"
            memory = MemoryStore(path)
            memory.remember(
                "failure",
                "tool timed out",
                confidence=0.6,
                provenance="runtime",
                memory_type=MemoryType.FAILURE,
                sensitivity=MemorySensitivity.INTERNAL,
                source="watchdog",
                conflicts_with=("old-failure",),
                supersedes=("timeout-v1",),
            )

            loaded = MemoryStore(path).recall("failure")

            self.assertEqual(loaded[0]["memory_type"], "failure")
            self.assertEqual(loaded[0]["sensitivity"], "internal")
            self.assertEqual(loaded[0]["source"], "watchdog")
            self.assertEqual(tuple(loaded[0]["conflicts_with"]), ("old-failure",))
            self.assertEqual(tuple(loaded[0]["supersedes"]), ("timeout-v1",))

    def test_memory_secret_boundary_rejects_secret_values(self) -> None:
        memory = MemoryStore()

        with self.assertRaises(SecretBoundaryViolation):
            memory.remember(
                "github_token",
                "ghp_secret_value",
                confidence=1.0,
                provenance="user",
                sensitivity=MemorySensitivity.SECRET,
                memory_type=MemoryType.FACT,
            )

    def test_memory_secret_boundary_allows_secret_reference(self) -> None:
        memory = MemoryStore()

        record = memory.remember(
            "github_token",
            "secret://github_token_write_repo_scope",
            confidence=1.0,
            provenance="secret-manager",
            sensitivity=MemorySensitivity.SECRET,
            memory_type=MemoryType.SECRET_REF,
        )

        self.assertEqual(record.memory_type, MemoryType.SECRET_REF)
        recalled = memory.recall("github_token")
        self.assertEqual(recalled[0]["sensitivity"], "secret")
        self.assertEqual(recalled[0]["memory_type"], "secret_ref")

    def test_audit_log_records_sequence_and_hash_chain(self) -> None:
        audit = AuditLog()

        first = audit.record("test.first", "first event", value=1)
        second = audit.record("test.second", "second event", value=2)

        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(first.previous_hash, AuditLog.GENESIS_HASH)
        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertNotEqual(first.event_hash, second.event_hash)
        self.assertTrue(audit.verify_integrity().ok)

    def test_audit_log_detects_in_memory_tampering(self) -> None:
        audit = AuditLog()
        audit.record("test.first", "first event", value=1)
        audit.record("test.second", "second event", value=2)

        audit.events[0].payload["value"] = "tampered"
        result = audit.verify_integrity()

        self.assertFalse(result.ok)
        self.assertEqual(result.data["issues"][0]["reason"], "event_hash_mismatch")

    def test_audit_log_detects_persisted_log_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            audit = AuditLog(path)
            audit.record("test.first", "first event", value=1)
            audit.record("test.second", "second event", value=2)
            self.assertTrue(audit.verify_integrity().ok)

            lines = path.read_text(encoding="utf-8").splitlines()
            first_record = json.loads(lines[0])
            first_record["payload"]["value"] = "tampered"
            lines[0] = json.dumps(first_record)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            result = audit.verify_integrity()

            self.assertFalse(result.ok)
            self.assertEqual(result.data["issues"][0]["reason"], "event_hash_mismatch")

    def test_replay_reconstructs_world_state_from_audit_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            expected_path = str((Path(tmp) / "x.txt").resolve())
            registry = default_registry(Path(tmp))
            causal = CausalWorldModel(
                [
                    CausalHypothesis(
                        action_name="safe_file_write",
                        affected_variables=["file_written"],
                        rationale="Writing a file updates file_written",
                        confidence=0.9,
                    )
                ]
            )
            agent = AgentKernel(
                registry=registry,
                policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}),
                causal_model=causal,
                approval_gate=ApprovalGate(lambda step: True),
            )
            goal = Goal(
                description="Write a file",
                success_criteria=["file exists"],
                stop_conditions=["verified"],
            )
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {"path": "x.txt", "content": "x", "file_written": expected_path},
                        "test",
                    )
                ],
            )

            agent.run(plan)
            result = replay_audit_log(agent.audit_log)

            self.assertIsInstance(result, ReplayResult)
            self.assertTrue(result.ok)
            self.assertEqual(result.state.facts, agent.state.facts)
            self.assertEqual(result.state.facts["file_written"], expected_path)
            self.assertEqual(result.state.trust["file_written"], TrustLevel.VERIFIED)
            self.assertEqual(result.applied_events, 1)

    def test_replay_refuses_tampered_audit_log_by_default(self) -> None:
        audit = AuditLog()
        audit.record("step.executed", "executed", observed={"last_echo": "hello"})
        records = audit.records()
        records[0]["payload"]["observed"]["last_echo"] = "tampered"

        result = AuditReplayer().replay_records(records)

        self.assertFalse(result.ok)
        self.assertEqual(result.errors[0]["reason"], "event_hash_mismatch")

    def test_replay_can_skip_integrity_verification_for_debugging(self) -> None:
        audit = AuditLog()
        audit.record("step.executed", "executed", observed={"last_echo": "hello"})
        records = audit.records()
        records[0]["payload"]["observed"]["last_echo"] = "debug-value"

        result = AuditReplayer().replay_records(records, verify_integrity=False)

        self.assertTrue(result.ok)
        self.assertEqual(result.state.facts["last_echo"], "debug-value")

    def test_file_write_requires_permission_or_human_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(registry=registry, policy=PolicyEngine())
            goal = Goal(
                description="Write a file",
                success_criteria=["file exists"],
                stop_conditions=["blocked or verified"],
            )
            plan = agent.build_plan(goal, [ActionStep("safe_file_write", {"path": "x.txt", "content": "x"}, "test")])

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
            self.assertFalse((Path(tmp) / "x.txt").exists())

    def test_approved_file_write_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            expected_path = str((Path(tmp) / "x.txt").resolve())
            registry = default_registry(Path(tmp))
            causal = CausalWorldModel(
                [
                    CausalHypothesis(
                        action_name="safe_file_write",
                        affected_variables=["file_written"],
                        rationale="Writing a file updates file_written",
                        confidence=0.9,
                    )
                ]
            )
            agent = AgentKernel(
                registry=registry,
                policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}),
                causal_model=causal,
                approval_gate=ApprovalGate(lambda step: True),
            )
            goal = Goal(
                description="Write a file",
                success_criteria=["file exists"],
                stop_conditions=["verified"],
            )
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {"path": "x.txt", "content": "x", "file_written": expected_path},
                        "test",
                    )
                ],
            )

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)
            self.assertEqual(agent.state.trust["file_written"], TrustLevel.VERIFIED)
            self.assertEqual((Path(tmp) / "x.txt").read_text(encoding="utf-8"), "x")

    def test_workspace_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(
                registry=registry,
                policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}),
                approval_gate=ApprovalGate(lambda step: True),
            )
            goal = Goal(
                description="Attempt escaping workspace",
                success_criteria=["escape is rejected"],
                stop_conditions=["failed"],
            )
            plan = agent.build_plan(goal, [ActionStep("safe_file_write", {"path": "../x.txt", "content": "x"}, "test")])

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.FAILED)

    def test_workspace_escape_records_typed_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(
                registry=registry,
                policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}),
                approval_gate=ApprovalGate(lambda step: True),
            )
            goal = Goal(
                description="Attempt escaping workspace",
                success_criteria=["escape is rejected"],
                stop_conditions=["failed"],
            )
            plan = agent.build_plan(goal, [ActionStep("safe_file_write", {"path": "../x.txt", "content": "x"}, "test")])

            result = agent.run(plan)

            failures = [event for event in agent.audit_log.events if event.event_type == "step.dry_run_failed"]
            self.assertEqual(result.steps[0].status, StepStatus.FAILED)
            self.assertEqual(failures[0].payload["error_type"], "WorkspaceEscapeBlocked")

            tool = registry.get("safe_file_write")
            dry_run = tool.dry_run({"path": "../x.txt", "content": "x"}, agent.state)
            self.assertIsInstance(dry_run.error, WorkspaceEscapeBlocked)

    def test_dry_run_failure_prevents_execute(self) -> None:
        registry = ToolRegistry()
        tool = DryRunFailingTool()
        registry.register(tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Do not execute after failed dry-run",
            success_criteria=["execute is not called"],
            stop_conditions=["failed"],
        )
        plan = agent.build_plan(goal, [ActionStep("dry_run_fails", {}, "test dry-run boundary")])

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.FAILED)
        self.assertFalse(tool.executed)
        failures = [event for event in agent.audit_log.events if event.event_type == "step.dry_run_failed"]
        self.assertEqual(failures[0].payload["error_type"], "DryRunFailed")

    def test_unknown_tool_never_executes(self) -> None:
        agent = AgentKernel(registry=ToolRegistry(), policy=PolicyEngine())
        goal = Goal(
            description="Unknown tool is rejected",
            success_criteria=["tool cannot execute"],
            stop_conditions=["exception"],
        )
        plan = agent.build_plan(goal, [ActionStep("missing_tool", {}, "test unknown tool boundary")])

        with self.assertRaises(KeyError):
            agent.run(plan)

    def test_high_risk_tool_requires_human_approval(self) -> None:
        registry = ToolRegistry()
        tool = HighRiskTool()
        registry.register(tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="High risk action blocks without approval",
            success_criteria=["tool is blocked"],
            stop_conditions=["blocked"],
        )
        plan = agent.build_plan(goal, [ActionStep("high_risk", {}, "test high-risk boundary")])

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        self.assertFalse(tool.executed)
        blocked = [event for event in agent.audit_log.events if event.event_type == "step.blocked"]
        self.assertEqual(blocked[0].payload["error_type"], "PolicyDenied")

    def test_irreversible_consequential_tool_requires_human_even_with_permission(self) -> None:
        registry = ToolRegistry()
        tool = IrreversibleWriteTool()
        registry.register(tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}))
        goal = Goal(
            description="Irreversible writes require approval",
            success_criteria=["tool is blocked"],
            stop_conditions=["blocked"],
        )
        plan = agent.build_plan(goal, [ActionStep("irreversible_write", {}, "test irreversible boundary")])

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        self.assertFalse(tool.executed)
        self.assertEqual(result.steps[0].reversibility, Reversibility.IRREVERSIBLE)
        blocked = [event for event in agent.audit_log.events if event.event_type == "step.blocked"]
        self.assertEqual(blocked[0].payload["reversibility"], "irreversible")
        self.assertEqual(blocked[0].payload["compensation_strategy"], "manual")

    def test_compensatable_consequential_tool_requires_human_even_with_permission(self) -> None:
        registry = ToolRegistry()
        tool = CompensatableWriteTool()
        registry.register(tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}))
        goal = Goal(
            description="Compensatable writes require approval",
            success_criteria=["tool is blocked"],
            stop_conditions=["blocked"],
        )
        plan = agent.build_plan(goal, [ActionStep("compensatable_write", {}, "test compensatable boundary")])

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        self.assertFalse(tool.executed)
        self.assertEqual(result.steps[0].reversibility, Reversibility.COMPENSATABLE)
        blocked = [event for event in agent.audit_log.events if event.event_type == "step.blocked"]
        self.assertEqual(blocked[0].payload["reversibility"], "compensatable")
        self.assertEqual(blocked[0].payload["compensation_strategy"], "compensate")

    def test_developer_local_profile_allows_reversible_workspace_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            expected_path = str((Path(tmp) / "x.txt").resolve())
            registry = default_registry(Path(tmp))
            causal = CausalWorldModel(
                [
                    CausalHypothesis(
                        action_name="safe_file_write",
                        affected_variables=["file_written"],
                        rationale="Writing a file updates file_written",
                        confidence=0.9,
                    )
                ]
            )
            agent = AgentKernel(
                registry=registry,
                policy=PolicyEngine.from_profile("developer_local"),
                causal_model=causal,
            )
            goal = Goal(
                description="Developer local write",
                success_criteria=["file exists"],
                stop_conditions=["verified"],
            )
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {"path": "x.txt", "content": "x", "file_written": expected_path},
                        "test developer profile",
                    )
                ],
            )

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)
            self.assertEqual((Path(tmp) / "x.txt").read_text(encoding="utf-8"), "x")

    def test_developer_local_profile_denies_network(self) -> None:
        registry = ToolRegistry()
        tool = NetworkTool()
        registry.register(tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine.from_profile("developer_local"))
        goal = Goal(
            description="Network is denied locally",
            success_criteria=["network does not execute"],
            stop_conditions=["blocked"],
        )
        plan = agent.build_plan(goal, [ActionStep("network_fetch", {}, "test denied permission")])

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        self.assertFalse(tool.executed)
        blocked = [event for event in agent.audit_log.events if event.event_type == "step.blocked"]
        self.assertEqual(blocked[0].payload["decision"], "denied")

    def test_production_profile_requires_human_for_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(registry=registry, policy=PolicyEngine.from_profile("production"))
            goal = Goal(
                description="Production write requires human",
                success_criteria=["file is blocked"],
                stop_conditions=["blocked"],
            )
            plan = agent.build_plan(
                goal, [ActionStep("safe_file_write", {"path": "x.txt", "content": "x"}, "test production profile")]
            )

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
            self.assertFalse((Path(tmp) / "x.txt").exists())
            blocked = [event for event in agent.audit_log.events if event.event_type == "step.blocked"]
            self.assertEqual(blocked[0].payload["decision"], "denied")

    def test_rollback_failure_requires_manual_recovery(self) -> None:
        registry = ToolRegistry()
        rollback_tool = RollbackFailingTool()
        dry_run_tool = DryRunFailingTool()
        registry.register(rollback_tool)
        registry.register(dry_run_tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Rollback failure enters manual recovery",
            success_criteria=["manual recovery is recorded"],
            stop_conditions=["failed"],
        )
        plan = agent.build_plan(
            goal,
            [
                ActionStep("rollback_fails", {}, "create a rollback token"),
                ActionStep("dry_run_fails", {}, "trigger rollback"),
            ],
        )

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.FAILED)
        self.assertEqual(result.steps[1].status, StepStatus.FAILED)
        self.assertFalse(dry_run_tool.executed)
        event_types = [event.event_type for event in agent.audit_log.events]
        self.assertIn("rollback_attempted", event_types)
        self.assertIn("rollback_failed", event_types)
        self.assertIn("manual_recovery_required", event_types)
        failures = [event for event in agent.audit_log.events if event.event_type == "rollback_failed"]
        self.assertEqual(failures[0].payload["error_type"], "RollbackFailed")
        manual_recovery = [event for event in agent.audit_log.events if event.event_type == "manual_recovery_required"]
        self.assertEqual(manual_recovery[0].payload["rollback_token"], {"resource": "rollback-failure-test"})

    def test_mixed_rollback_results_record_partial_completion(self) -> None:
        registry = ToolRegistry()
        failing_tool = RollbackFailingTool()
        succeeding_tool = RollbackSucceedingTool()
        dry_run_tool = DryRunFailingTool()
        registry.register(failing_tool)
        registry.register(succeeding_tool)
        registry.register(dry_run_tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="Partial rollback is explicit",
            success_criteria=["partial rollback is recorded"],
            stop_conditions=["failed"],
        )
        plan = agent.build_plan(
            goal,
            [
                ActionStep("rollback_fails", {}, "create failing rollback token"),
                ActionStep("rollback_succeeds", {}, "create successful rollback token"),
                ActionStep("dry_run_fails", {}, "trigger rollback"),
            ],
        )

        result = agent.run(plan)

        self.assertEqual(result.steps[0].status, StepStatus.FAILED)
        self.assertEqual(result.steps[1].status, StepStatus.ROLLED_BACK)
        self.assertEqual(result.steps[2].status, StepStatus.FAILED)
        partial = [event for event in agent.audit_log.events if event.event_type == "rollback_partially_completed"]
        self.assertEqual(partial[0].payload["succeeded"], 1)
        self.assertEqual(partial[0].payload["failed"], 1)

    def test_cli_demo_requires_auto_approval_for_file_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            agent = build_demo_agent(workspace, auto_approve=False)
            goal = Goal(
                description="Demo write",
                success_criteria=["file exists"],
                stop_conditions=["blocked or verified"],
            )
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {
                            "path": "hello.txt",
                            "content": "hello",
                            "file_written": str((workspace / "hello.txt").resolve()),
                        },
                        "demo",
                    )
                ],
            )

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
            self.assertFalse((workspace / "hello.txt").exists())

    def test_cli_demo_auto_approval_allows_file_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            agent = build_demo_agent(workspace, auto_approve=True)
            goal = Goal(
                description="Demo write",
                success_criteria=["file exists"],
                stop_conditions=["blocked or verified"],
            )
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {
                            "path": "hello.txt",
                            "content": "hello",
                            "file_written": str((workspace / "hello.txt").resolve()),
                        },
                        "demo",
                    )
                ],
            )

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)
            self.assertEqual((workspace / "hello.txt").read_text(encoding="utf-8"), "hello")

    def test_planner_selects_first_satisfactory_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(
                registry=registry,
                policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}),
                planner_config=PlannerConfig(max_risk=RiskLevel.MEDIUM, max_cost=5.0, min_benefit=0.5),
            )
            goal = Goal(
                description="Choose a plan",
                success_criteria=["a candidate is selected"],
                stop_conditions=["selected"],
            )
            proposals = [
                PlanProposal(
                    steps=[ActionStep("safe_file_write", {"path": "x.txt", "content": "x"}, "too costly")],
                    rationale="Too costly",
                    estimated_cost=10.0,
                    expected_benefit=1.0,
                ),
                PlanProposal(
                    steps=[ActionStep("echo", {"message": "hello"}, "low cost")],
                    rationale="Satisfactory",
                    estimated_cost=1.0,
                    expected_benefit=0.75,
                ),
                PlanProposal(
                    steps=[ActionStep("echo", {"message": "later"}, "also acceptable")],
                    rationale="Also satisfactory",
                    estimated_cost=1.0,
                    expected_benefit=1.0,
                ),
            ]

            result = agent.plan(goal, proposals)

            self.assertIs(result.selected, result.candidates[1])
            self.assertFalse(result.candidates[0].score.satisfies)
            self.assertTrue(result.candidates[1].score.satisfies)

    def test_planner_returns_no_selection_without_satisfactory_candidate(self) -> None:
        registry = default_registry()
        agent = AgentKernel(
            registry=registry,
            policy=PolicyEngine(),
            planner_config=PlannerConfig(max_risk=RiskLevel.LOW, max_cost=1.0, min_benefit=2.0),
        )
        goal = Goal(
            description="Choose a plan",
            success_criteria=["a candidate is selected"],
            stop_conditions=["selected"],
        )
        proposals = [
            PlanProposal(
                steps=[ActionStep("echo", {"message": "hello"}, "not enough benefit")],
                rationale="Low benefit",
                estimated_cost=0.5,
                expected_benefit=1.0,
            )
        ]

        result = agent.plan(goal, proposals)

        self.assertIsNone(result.selected)
        self.assertEqual(len(result.candidates), 1)
        self.assertFalse(result.candidates[0].score.satisfies)

    def test_causal_graph_reports_action_consequences_and_counterfactuals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            expected_path = str((Path(tmp) / "x.txt").resolve())
            registry = default_registry(Path(tmp))
            causal = CausalGraph(
                [
                    CausalHypothesis(
                        action_name="safe_file_write",
                        affected_variables=["file_written"],
                        rationale="Writing a file updates file_written",
                        confidence=0.9,
                    )
                ]
            )
            agent = AgentKernel(
                registry=registry,
                policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}),
                causal_model=causal,
            )
            goal = Goal(
                description="Write a file",
                success_criteria=["file exists"],
                stop_conditions=["verified"],
            )
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {"path": "x.txt", "content": "x", "file_written": expected_path},
                        "test",
                    )
                ],
            )

            result = agent.run(plan)
            step = result.steps[0]

            self.assertEqual(step.status, StepStatus.VERIFIED)
            self.assertEqual(step.predictions[0].variable, "file_written")
            self.assertIsNotNone(step.counterfactual_report)
            self.assertEqual(step.counterfactual_report.action_consequences[0].expected_after, expected_path)
            self.assertIsNone(step.counterfactual_report.no_action_consequences[0].expected_after)

    def test_causal_graph_verification_reports_consequence_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            causal = CausalGraph(
                [
                    CausalHypothesis(
                        action_name="safe_file_write",
                        affected_variables=["file_written"],
                        rationale="Writing a file updates file_written",
                        confidence=0.9,
                    )
                ]
            )
            agent = AgentKernel(
                registry=registry,
                policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}),
                causal_model=causal,
            )
            goal = Goal(
                description="Write a file",
                success_criteria=["file exists"],
                stop_conditions=["failed"],
            )
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {"path": "x.txt", "content": "x", "file_written": "wrong-path"},
                        "test",
                    )
                ],
            )

            result = agent.run(plan)

            self.assertEqual(result.steps[0].status, StepStatus.ROLLED_BACK)
            self.assertEqual(agent.state.trust["file_written"], TrustLevel.TOOL_REPORTED)
            failures = [event for event in agent.audit_log.events if event.event_type == "step.verification_failed"]
            self.assertEqual(failures[0].payload["data"]["mismatches"][0]["reason"], "consequence_mismatch")


class CliTests(unittest.TestCase):
    def test_validate_policy_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "valid.json"
            path.write_text(json.dumps({"name": "test", "granted_permissions": ["write_files"]}))
            self.assertEqual(_validate_policy(str(path)), 0)

    def test_validate_policy_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "invalid.json"
            path.write_text(
                json.dumps({"name": "bad", "rules": [{"name": "r", "when": {"tool": "x"}, "decision": "approved"}]})
            )
            self.assertEqual(_validate_policy(str(path)), 1)

    def test_validate_policy_missing_file(self) -> None:
        self.assertEqual(_validate_policy("/tmp/nonexistent_policy_test.json"), 2)

    def test_validate_policy_bad_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("not json")
            self.assertEqual(_validate_policy(str(path)), 2)

    def test_list_tools_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_list_tools(tmp), 0)

    def test_dry_run_echo_ok(self) -> None:
        self.assertEqual(_dry_run("echo", '{"message":"hi"}', ".leos-workspace"), 0)

    def test_dry_run_echo_fail(self) -> None:
        self.assertEqual(_dry_run("echo", "{}", ".leos-workspace"), 1)

    def test_dry_run_unknown_tool(self) -> None:
        self.assertEqual(_dry_run("nonexistent", "{}", ".leos-workspace"), 1)

    def test_dry_run_bad_json(self) -> None:
        self.assertEqual(_dry_run("echo", "not json", ".leos-workspace"), 2)

    def test_replay_valid_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path=path)
            log.record("step.executed", "ok", observed={"key": "val"})
            self.assertEqual(_replay(str(path), verify=True), 0)

    def test_replay_missing_file(self) -> None:
        self.assertEqual(_replay("/tmp/nonexistent_replay_test.jsonl", verify=True), 2)

    def test_replay_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path=path)
            log.record("step.executed", "ok", observed={"key": "val"})
            lines = path.read_text().splitlines()
            record = json.loads(lines[0])
            record["payload"]["observed"]["key"] = "tampered"
            path.write_text(json.dumps(record) + "\n")
            self.assertEqual(_replay(str(path), verify=True), 1)

    def test_run_echo_goal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            goal_path = Path(tmp) / "goal.json"
            goal_path.write_text(
                json.dumps(
                    {
                        "goal": {
                            "description": "Echo test",
                            "success_criteria": ["echo works"],
                            "stop_conditions": ["done"],
                        },
                        "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
                    }
                )
            )
            self.assertEqual(_run(str(goal_path), str(ws), auto_approve=False, profile="developer_local"), 0)

    def test_run_missing_file(self) -> None:
        self.assertEqual(
            _run("/tmp/nonexistent_run_test.json", ".leos-workspace", auto_approve=False, profile="developer_local"), 2
        )

    def test_run_invalid_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            goal_path = Path(tmp) / "goal.json"
            goal_path.write_text(
                json.dumps(
                    {
                        "goal": {
                            "description": "test",
                            "success_criteria": ["x"],
                            "stop_conditions": ["done"],
                        },
                        "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
                    }
                )
            )
            self.assertEqual(
                _run(str(goal_path), ".leos-workspace", auto_approve=False, profile="nonexistent_profile"), 2
            )

    def test_run_production_blocks_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            goal_path = Path(tmp) / "goal.json"
            goal_path.write_text(
                json.dumps(
                    {
                        "goal": {
                            "description": "Write test",
                            "success_criteria": ["file exists"],
                            "stop_conditions": ["blocked or verified"],
                        },
                        "steps": [
                            {
                                "tool_name": "safe_file_write",
                                "arguments": {"path": "x.txt", "content": "x"},
                                "reason": "test",
                            }
                        ],
                    }
                )
            )
            self.assertEqual(_run(str(goal_path), str(ws), auto_approve=False, profile="production"), 1)


class SignedPolicyManifestTests(unittest.TestCase):
    def test_sign_and_verify_valid_secret(self) -> None:
        policy = {"name": "test", "granted_permissions": ["write_files"]}
        manifest = sign_policy(policy, "secret")
        verify_policy_manifest({"policy": manifest.policy, "signature": manifest.signature}, "secret")

    def test_verify_rejects_wrong_secret(self) -> None:
        policy = {"name": "test", "granted_permissions": ["write_files"]}
        manifest = sign_policy(policy, "secret")
        with self.assertRaises(PolicyIntegrityError):
            verify_policy_manifest({"policy": manifest.policy, "signature": manifest.signature}, "wrong")

    def test_verify_rejects_tampered_policy(self) -> None:
        policy = {"name": "test", "granted_permissions": ["write_files"]}
        manifest = sign_policy(policy, "secret")
        tampered_policy = dict(manifest.policy)
        tampered_policy["max_auto_risk"] = "critical"
        with self.assertRaises(PolicyIntegrityError):
            verify_policy_manifest({"policy": tampered_policy, "signature": manifest.signature}, "secret")

    def test_load_policy_from_signed_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            policy = {"name": "locked", "granted_permissions": ["read_files"]}
            manifest = sign_policy(policy, "secret")
            path.write_text(json.dumps({"policy": manifest.policy, "signature": manifest.signature}))
            engine = load_policy_from_file(path, "secret")
            self.assertEqual(engine.profile_name, "locked")
            self.assertIn(Permission.READ_FILES, engine.granted_permissions)

    def test_load_policy_rejects_wrong_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            policy = {"name": "locked", "granted_permissions": ["read_files"]}
            manifest = sign_policy(policy, "secret")
            path.write_text(json.dumps({"policy": manifest.policy, "signature": manifest.signature}))
            with self.assertRaises(PolicyIntegrityError):
                load_policy_from_file(path, "wrong")

    def test_cli_sign_policy_creates_signed_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.json"
            out_path = Path(tmp) / "signed.json"
            policy_path.write_text(json.dumps({"name": "cli_test", "granted_permissions": ["read_files"]}))
            self.assertEqual(_sign_policy(str(policy_path), "secret", str(out_path)), 0)
            manifest = json.loads(out_path.read_text())
            self.assertIn("signature", manifest)
            verify_policy_manifest(manifest, "secret")

    def test_cli_validate_policy_accepts_signed_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "signed.json"
            policy = {"name": "ok", "granted_permissions": ["read_files"]}
            manifest = sign_policy(policy, "secret")
            path.write_text(json.dumps({"policy": manifest.policy, "signature": manifest.signature}))
            self.assertEqual(_validate_policy(str(path), secret="secret"), 0)

    def test_cli_validate_policy_rejects_wrong_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "signed.json"
            policy = {"name": "ok", "granted_permissions": ["read_files"]}
            manifest = sign_policy(policy, "secret")
            path.write_text(json.dumps({"policy": manifest.policy, "signature": manifest.signature}))
            self.assertEqual(_validate_policy(str(path), secret="wrong"), 3)

    def test_cli_run_with_signed_policy_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            manifest_path = Path(tmp) / "manifest.json"
            goal_path = Path(tmp) / "goal.json"
            policy = {"name": "sigrun", "granted_permissions": ["write_files"]}
            manifest = sign_policy(policy, "secret")
            manifest_path.write_text(json.dumps({"policy": manifest.policy, "signature": manifest.signature}))
            goal_path.write_text(
                json.dumps(
                    {
                        "goal": {"description": "t", "success_criteria": ["ok"], "stop_conditions": ["done"]},
                        "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
                    }
                )
            )
            self.assertEqual(
                _run(str(goal_path), str(ws), auto_approve=False, profile=str(manifest_path), secret="secret"), 0
            )


class CapabilityGrantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.write_tool = "safe_file_write"
        self.readonly_tool = "echo"

    def test_grant_applies_when_principal_and_tool_match(self) -> None:
        grant = CapabilityGrant(principal="alice", permissions=["write_files"], tools=["safe_file_write"])
        self.assertTrue(grant.applies_to("alice", "safe_file_write"))
        self.assertFalse(grant.applies_to("alice", "echo"))
        self.assertFalse(grant.applies_to("bob", "safe_file_write"))

    def test_grant_without_tools_applies_to_all_tools(self) -> None:
        grant = CapabilityGrant(principal="alice", permissions=["read_files"])
        self.assertTrue(grant.applies_to("alice", "safe_file_write"))
        self.assertTrue(grant.applies_to("alice", "echo"))

    def test_principal_with_grant_can_use_permitted_tool(self) -> None:
        registry = default_registry()
        policy = PolicyEngine(
            grants=[CapabilityGrant(principal="alice", permissions=["write_files"], tools=["safe_file_write"])],
            principal="alice",
        )
        self.assertIn(Permission.WRITE_FILES, policy.grants[0].permissions)
        agent = AgentKernel(registry=registry, policy=policy)
        goal = Goal(description="t", success_criteria=["ok"], stop_conditions=["done"])
        plan = agent.build_plan(goal, [ActionStep("echo", {"message": "hi"}, "test")])
        result = agent.run(plan)
        self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)

    def test_principal_without_grant_uses_global_fallback(self) -> None:
        default_registry()
        policy = PolicyEngine(
            granted_permissions=[Permission.READ_FILES],
            grants=[CapabilityGrant(principal="alice", permissions=["write_files"])],
            principal="bob",
        )
        self.assertIn(Permission.READ_FILES, policy.granted_permissions)

    def test_grant_can_deny_specific_permission(self) -> None:
        default_registry()
        # EchoTool has no required_permissions, so it doesn't trigger deny
        policy = PolicyEngine(
            grants=[CapabilityGrant(principal="alice", permissions=["write_files"], deny_permissions=["write_files"])],
            principal="alice",
        )
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            r = default_registry(ws)
            agent = AgentKernel(registry=r, policy=policy)
            goal = Goal(description="t", success_criteria=["ok"], stop_conditions=["blocked or verified"])
            plan = agent.build_plan(goal, [ActionStep("safe_file_write", {"path": "x.txt", "content": "x"}, "test")])
            result = agent.run(plan)
            # safe_file_write has WRITE_FILES permission, grant denies it
            self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)

    def test_grant_max_risk_restricts_high_risk_tools(self) -> None:
        registry = ToolRegistry()
        tool = HighRiskTool()
        registry.register(tool)
        policy = PolicyEngine(
            grants=[CapabilityGrant(principal="alice", permissions=[], max_risk=RiskLevel.LOW)],
            principal="alice",
        )
        agent = AgentKernel(registry=registry, policy=policy)
        goal = Goal(description="t", success_criteria=["ok"], stop_conditions=["blocked"])
        plan = agent.build_plan(goal, [ActionStep("high_risk", {}, "test")])
        result = agent.run(plan)
        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)

    def test_cli_run_with_principal_passes_through(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            goal_path = Path(tmp) / "goal.json"
            goal_path.write_text(
                json.dumps(
                    {
                        "goal": {"description": "t", "success_criteria": ["ok"], "stop_conditions": ["done"]},
                        "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
                    }
                )
            )
            self.assertEqual(
                _run(str(goal_path), str(ws), auto_approve=False, profile="developer_local", principal="alice"), 0
            )

    def test_policy_profile_constructor_normalizes_grants(self) -> None:
        profile = PolicyProfile(
            name="granted_profile",
            grants=[
                {"principal": "carol", "permissions": ["read_files"], "tools": ["echo"]},
            ],
        )
        self.assertEqual(len(profile.grants), 1)
        self.assertIsInstance(profile.grants[0], CapabilityGrant)
        self.assertEqual(profile.grants[0].principal, "carol")

    def test_policy_profile_from_mapping_loads_grants(self) -> None:
        profile = PolicyProfile.from_mapping(
            {
                "name": "from_map",
                "grants": [
                    {"principal": "dave", "permissions": ["write_files"], "max_risk": "medium"},
                ],
            }
        )
        self.assertEqual(len(profile.grants), 1)
        self.assertEqual(profile.grants[0].principal, "dave")
        self.assertEqual(profile.grants[0].max_risk, RiskLevel.MEDIUM)


class SecretTests(unittest.TestCase):
    def test_secret_repr_is_redacted(self) -> None:
        s = Secret("my-token")
        self.assertEqual(repr(s), "<secret>")

    def test_secret_unwrap_returns_value(self) -> None:
        s = Secret("my-token")
        self.assertEqual(s.unwrap(), "my-token")

    def test_secret_blocked_for_non_secrets_allowed_tool(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(description="t", success_criteria=["ok"], stop_conditions=["blocked"])
        step = ActionStep("echo", {"message": Secret("secret-msg")}, "test secret boundary")
        plan = agent.build_plan(goal, [step])
        result = agent.run(plan)
        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        blocked = [e for e in agent.audit_log.events if e.event_type == "step.blocked"]
        self.assertEqual(blocked[0].payload["error_type"], "SecretLeakedToUntrustedTool")

    def test_secret_allowed_for_secrets_allowed_tool(self) -> None:
        registry = ToolRegistry()
        tool = SecretAllowedEchoTool()
        registry.register(tool)
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(description="t", success_criteria=["ok"], stop_conditions=["done"])
        step = ActionStep("secret_echo", {"message": Secret("secret-msg")}, "test")
        plan = agent.build_plan(goal, [step])
        result = agent.run(plan)
        self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)
        self.assertEqual(agent.state.facts["last_echo"], "secret-msg")

    def test_cli_run_rejects_secret_for_echo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            goal_path = Path(tmp) / "goal.json"
            goal_path.write_text(
                json.dumps(
                    {
                        "goal": {
                            "description": "t",
                            "success_criteria": ["ok"],
                            "stop_conditions": ["blocked or verified"],
                        },
                        "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
                    }
                )
            )
            self.assertEqual(
                _run(
                    str(goal_path),
                    str(ws),
                    auto_approve=False,
                    profile="developer_local",
                    cli_secrets=["message=mysecret"],
                ),
                1,
            )


class SandboxTests(unittest.TestCase):
    def test_container_policy_blocks_execution(self) -> None:
        tool_spec = ToolSpec(
            name="container_tool",
            description="requires container",
            permissions=(),
            sandbox_policy=SandboxPolicy.CONTAINER,
        )
        self.assertEqual(
            TransactionManager._enforce_sandbox(_FakeTool(tool_spec)),
            "container sandbox not available — requires external container runtime",
        )

    def test_microvm_policy_blocks_execution(self) -> None:
        tool_spec = ToolSpec(
            name="microvm_tool",
            description="requires microvm",
            permissions=(),
            sandbox_policy=SandboxPolicy.MICROVM,
        )
        self.assertEqual(
            TransactionManager._enforce_sandbox(_FakeTool(tool_spec)),
            "microvm sandbox not available — requires external microvm runtime",
        )

    def test_none_policy_allows_execution(self) -> None:
        tool_spec = ToolSpec(
            name="safe_tool",
            description="no sandbox needed",
            permissions=(),
            sandbox_policy=SandboxPolicy.NONE,
        )
        self.assertIsNone(TransactionManager._enforce_sandbox(_FakeTool(tool_spec)))

    def test_network_access_blocked(self) -> None:
        tool_spec = ToolSpec(
            name="network_tool",
            description="needs network",
            permissions=(),
            network_access=True,
        )
        self.assertIsNotNone(TransactionManager._enforce_sandbox(_FakeTool(tool_spec)))

    def test_workspace_sandbox_rejects_no_filesystem_scope(self) -> None:
        tool_spec = ToolSpec(
            name="ws_tool",
            description="workspace sandbox without scope",
            permissions=(),
            sandbox_policy=SandboxPolicy.WORKSPACE,
            filesystem_scope="none",
        )
        self.assertIsNotNone(TransactionManager._enforce_sandbox(_FakeTool(tool_spec)))

    def test_safe_file_write_has_workspace_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            spec = registry.get("safe_file_write").spec
            self.assertEqual(spec.sandbox_policy, SandboxPolicy.WORKSPACE)

    def test_echo_has_no_sandbox(self) -> None:
        spec = default_registry().get("echo").spec
        self.assertEqual(spec.sandbox_policy, SandboxPolicy.NONE)


class LLMTests(unittest.TestCase):
    def test_validate_llm_proposals_accepts_valid_input(self) -> None:
        proposals = validate_llm_proposals(
            [
                {
                    "steps": [{"tool_name": "echo", "arguments": {"message": "hi"}, "reason": "test"}],
                    "rationale": "simple",
                },
            ],
            {"echo"},
        )
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].steps[0].tool_name, "echo")

    def test_validate_llm_proposals_rejects_missing_steps(self) -> None:
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals([{"rationale": "no steps"}], set())

    def test_validate_llm_proposals_rejects_unknown_tool(self) -> None:
        with self.assertRaises(LLMOutputValidationError):
            validate_llm_proposals(
                [
                    {"steps": [{"tool_name": "nonexistent", "arguments": {}, "reason": "x"}], "rationale": "bad"},
                ],
                {"echo"},
            )


class AnomalyTests(unittest.TestCase):
    def _make_events(self, event_types: list[str]) -> list[dict[str, Any]]:
        t = 1000.0
        events = []
        for et in event_types:
            events.append({"event_type": et, "created_at": t, "payload": {}})
            t += 1.0
        return events

    def test_no_anomalies_on_normal_events(self) -> None:
        detector = AuditAnomalyDetector(burst_threshold=5)
        events = self._make_events(["step.executed", "step.verified", "step.executed", "step.verified"])
        self.assertEqual(detector.detect(events), [])

    def test_burst_detected(self) -> None:
        detector = AuditAnomalyDetector(burst_window_seconds=60, burst_threshold=3)
        events = self._make_events(["step.blocked", "step.blocked", "step.blocked"])
        findings = detector.detect(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "burst")

    def test_rollback_loop_detected(self) -> None:
        detector = AuditAnomalyDetector(burst_threshold=99)
        events = self._make_events(["rollback_attempted", "rollback_attempted", "rollback_attempted"])
        for e in events:
            e["payload"]["tool"] = "bad_tool"
        findings = detector.detect(events)
        self.assertTrue(any(f.rule == "rollback_loop" for f in findings))

    def test_high_block_rate_detected(self) -> None:
        detector = AuditAnomalyDetector(burst_threshold=99)
        blocked = ["step.blocked"] * 8
        ok = ["step.verified"] * 2
        events = self._make_events(blocked + ok)
        findings = detector.detect(events)
        self.assertTrue(any("High block rate" in f.message for f in findings))


class ReplayFailureTests(unittest.TestCase):
    def test_replay_excludes_failed_step_state(self) -> None:
        audit = AuditLog()
        audit.record("step.executed", "ok", observed={"safe": "yes"})
        audit.record("step.execution_failed", "fail", data={"bad": "no"})
        result = replay_audit_log(audit)
        self.assertIn("safe", result.state.facts)
        self.assertNotIn("bad", result.state.facts)

    def test_replay_with_rollback_preserves_prior_state(self) -> None:
        audit = AuditLog()
        audit.record("step.executed", "first", observed={"first": "kept"})
        audit.record("step.executed", "second", observed={"second": "gone"})
        audit.record("rollback_attempted", "undo second")
        result = replay_audit_log(audit)
        self.assertIn("first", result.state.facts)

    def test_replay_goal_lifecycle_transitions(self) -> None:
        audit = AuditLog()
        audit.record("goal.status_changed", "created->planning", from_status="created", to_status="planning")
        audit.record("goal.status_changed", "planning->running", from_status="planning", to_status="running")
        audit.record("step.executed", "ok", observed={"result": "ok"})
        audit.record("goal.status_changed", "running->succeeded", from_status="running", to_status="succeeded")
        result = replay_audit_log(audit)
        self.assertTrue(result.ok)
        self.assertIn("result", result.state.facts)

    def test_replay_empty_log_returns_empty_state(self) -> None:
        audit = AuditLog()
        result = replay_audit_log(audit)
        self.assertTrue(result.ok)
        self.assertEqual(result.state.facts, {})

    def test_replay_mixed_success_and_memory(self) -> None:
        audit = AuditLog()
        audit.record("step.executed", "ok", observed={"a": 1})
        audit.record("memory.written", "stored", key="note", value="hello")
        result = replay_audit_log(audit)
        self.assertEqual(result.state.facts.get("a"), 1)
        self.assertEqual(result.state.facts.get("memory:note"), "hello")
        self.assertEqual(result.applied_events, 2)


class RedTeamTests(unittest.TestCase):
    def test_unknown_tool_name_rejected(self) -> None:
        agent = AgentKernel(registry=ToolRegistry(), policy=PolicyEngine())
        goal = Goal(description="t", success_criteria=["fail"], stop_conditions=["exception"])
        plan = agent.build_plan(goal, [ActionStep("../../etc/passwd", {}, "path traversal as tool")])
        with self.assertRaises(KeyError):
            agent.run(plan)

    def test_nested_argument_injection_rejected_by_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(registry=registry, policy=PolicyEngine.from_profile("developer_local"))
            goal = Goal(description="t", success_criteria=["fail"], stop_conditions=["failed"])
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {
                            "path": "x.txt",
                            "__proto__": {"isAdmin": True},
                        },
                        "prototype pollution attempt",
                    ),
                ],
            )
            result = agent.run(plan)
            self.assertEqual(result.steps[0].status, StepStatus.FAILED)

    def test_workspace_escape_via_dot_dot_slash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(registry=registry, policy=PolicyEngine(granted_permissions={Permission.WRITE_FILES}))
            goal = Goal(description="t", success_criteria=["fail"], stop_conditions=["failed"])
            for path in ["../escape.txt", "sub/../../escape.txt", "./../../escape.txt"]:
                plan = agent.build_plan(goal, [ActionStep("safe_file_write", {"path": path, "content": "x"}, "escape")])
                result = agent.run(plan)
                self.assertEqual(result.steps[0].status, StepStatus.FAILED, f"path {path} should fail")

    def test_policy_approve_rule_rejected(self) -> None:
        with self.assertRaises(PolicyConfigurationError):
            PolicyProfile.from_mapping(
                {
                    "name": "bad",
                    "rules": [{"name": "auto_approve", "when": {"risk_at_least": "low"}, "decision": "approved"}],
                }
            )

    def test_budget_exhaustion_attack(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(
            description="budget attack",
            success_criteria=["blocked"],
            stop_conditions=["blocked"],
            budget=ResourceBudget(max_tool_calls=1),
        )
        steps = [ActionStep("echo", {"message": f"msg{i}"}, f"step{i}") for i in range(20)]
        plan = agent.build_plan(goal, steps)
        result = agent.run(plan)
        blocked = sum(1 for s in result.steps if s.status == StepStatus.BLOCKED)
        self.assertGreater(blocked, 0)

    def test_idempotency_key_collision_prevented(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(description="t", success_criteria=["one"], stop_conditions=["blocked"])
        plan = agent.build_plan(
            goal,
            [
                ActionStep("echo", {"message": "first"}, "first", idempotency_key="once"),
                ActionStep("echo", {"message": "second"}, "second", idempotency_key="once"),
            ],
        )
        result = agent.run(plan)
        self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)
        self.assertEqual(result.steps[1].status, StepStatus.BLOCKED)

    def test_audit_log_fake_hash_rejected(self) -> None:
        audit = AuditLog()
        audit.record("step.executed", "ok", observed={"x": 1})
        records = audit.records()
        records.append(
            {
                "event_type": "step.executed",
                "payload": {"observed": {"injected": True}},
                "sequence": 2,
                "previous_hash": records[0]["event_hash"],
                "event_hash": "0" * 64,
            }
        )
        result = AuditLog.verify_event_records(records)
        self.assertFalse(result.ok)

    def test_secret_injection_bypassed_by_tool_name_mismatch(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(description="t", success_criteria=["blocked"], stop_conditions=["blocked"])
        plan = agent.build_plan(
            goal,
            [
                ActionStep("echo", {"token": Secret("injected-token")}, "inject secret to non-secret tool"),
            ],
        )
        result = agent.run(plan)
        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)


class InvariantTests(unittest.TestCase):
    def test_invariant_blocks_when_pre_violated(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(description="t", success_criteria=["blocked"], stop_conditions=["blocked"])
        plan = agent.build_plan(
            goal,
            [
                ActionStep("echo", {"message": "hi"}, "test", invariants=(StateCondition("ready", "equals", True),)),
            ],
        )
        result = agent.run(plan)
        self.assertEqual(result.steps[0].status, StepStatus.BLOCKED)
        pre = [e for e in agent.audit_log.events if e.event_type == "step.precondition_failed"]
        self.assertEqual(len(pre), 1)

    def test_invariant_rolls_back_when_post_violated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = default_registry(Path(tmp))
            agent = AgentKernel(registry=registry, policy=PolicyEngine.from_profile("developer_local"))
            goal = Goal(description="t", success_criteria=["rolled back"], stop_conditions=["failed"])
            plan = agent.build_plan(
                goal,
                [
                    ActionStep(
                        "safe_file_write",
                        {"path": "x.txt", "content": "x"},
                        "test",
                        postconditions=(StateCondition("file_written", "equals", "/dev/null"),),
                    ),
                ],
            )
            result = agent.run(plan)
            self.assertEqual(result.steps[0].status, StepStatus.ROLLED_BACK)

    def test_invariant_with_trust_filter(self) -> None:
        registry = default_registry()
        agent = AgentKernel(registry=registry, policy=PolicyEngine())
        goal = Goal(description="t", success_criteria=["verified"], stop_conditions=["done"])
        plan = agent.build_plan(
            goal,
            [
                ActionStep(
                    "echo",
                    {"message": "hi"},
                    "test",
                    postconditions=(StateCondition("last_echo", "exists", trust_level=TrustLevel.TOOL_REPORTED),),
                ),
            ],
        )
        result = agent.run(plan)
        self.assertEqual(result.steps[0].status, StepStatus.VERIFIED)


class _FakeTool:
    def __init__(self, spec: ToolSpec) -> None:
        self.spec = spec


class SecretAllowedEchoTool:
    spec = ToolSpec(
        name="secret_echo",
        description="Echo that accepts secrets.",
        permissions=(),
        default_risk=RiskLevel.LOW,
        secrets_allowed=True,
    )

    def dry_run(self, arguments, state):
        if "message" not in arguments:
            return ToolResult(False, "Missing message")
        return ToolResult(True, f"Would echo: {arguments['message']}")

    def execute(self, arguments, state):
        msg = str(arguments["message"])
        return ToolResult(True, msg, observed_state_delta={"last_echo": msg})

    def rollback(self, token, state):
        return ToolResult(True, "rolled back")


if __name__ == "__main__":
    unittest.main()
