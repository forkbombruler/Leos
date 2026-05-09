"""Benchmark case definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from leos_agent.goals import Goal
from leos_agent.kernel import AgentKernel
from leos_agent.plans import ActionStep, StateCondition
from leos_agent.policy import PolicyEngine
from leos_agent.tools import ToolRegistry, default_registry


@dataclass
class BenchmarkCase:
    name: str
    description: str
    tags: list[str] = field(default_factory=list)
    build_kernel: Any = None
    build_goal: Any = None
    build_steps: Any = None
    expected_goal_status: str = "succeeded"
    expected_step_statuses: list[str] = field(default_factory=list)


def _registry_with_high_risk() -> ToolRegistry:
    from leos_agent.enums import RiskLevel
    from leos_agent.tools import ToolResult, ToolSpec

    registry = default_registry()

    class _HRT:
        spec = ToolSpec(name="high_risk", description="h", permissions=(), default_risk=RiskLevel.HIGH)

        def dry_run(self, *a, **kw):
            return ToolResult(True, "ok")

        def execute(self, *a, **kw):
            return ToolResult(True, "ok")

        def rollback(self, *a, **kw):
            return ToolResult(True, "ok")

    registry.register(_HRT())
    return registry


def cases() -> list[BenchmarkCase]:
    return [
        BenchmarkCase(
            name="echo_success",
            description="Single echo step completes successfully",
            tags=["smoke"],
            build_goal=lambda **kw: Goal(description="Echo", success_criteria=["ok"], stop_conditions=["done"]),
            build_steps=lambda **kw: [ActionStep("echo", {"message": "hi"}, "test")],
            expected_step_statuses=["verified"],
        ),
        BenchmarkCase(
            name="file_write_requires_policy",
            description="File write blocked without WRITE_FILES grant",
            tags=["policy"],
            build_goal=lambda **kw: Goal(
                description="Write", success_criteria=["blocked"], stop_conditions=["blocked"]
            ),
            build_steps=lambda **kw: [ActionStep("safe_file_write", {"path": "x.txt", "content": "x"}, "test")],
            build_kernel=lambda **kw: AgentKernel(
                registry=default_registry(kw.get("ws", Path("."))), policy=PolicyEngine()
            ),
            expected_goal_status="blocked",
            expected_step_statuses=["blocked"],
        ),
        BenchmarkCase(
            name="path_escape_blocked",
            description="Workspace escape path rejected",
            tags=["security"],
            build_goal=lambda **kw: Goal(description="Escape", success_criteria=["failed"], stop_conditions=["failed"]),
            build_steps=lambda **kw: [ActionStep("safe_file_write", {"path": "../x.txt", "content": "x"}, "escape")],
            build_kernel=lambda **kw: AgentKernel(
                registry=default_registry(kw.get("ws", Path("."))),
                policy=PolicyEngine(granted_permissions={"write_files"}),
            ),
            expected_goal_status="failed",
            expected_step_statuses=["failed"],
        ),
        BenchmarkCase(
            name="duplicate_idempotency_blocks",
            description="Same idempotency key blocks second execution",
            tags=["idempotency"],
            build_goal=lambda **kw: Goal(description="Idem", success_criteria=["one"], stop_conditions=["blocked"]),
            build_steps=lambda **kw: [
                ActionStep("echo", {"message": "first"}, "first", idempotency_key="once"),
                ActionStep("echo", {"message": "second"}, "second", idempotency_key="once"),
            ],
            expected_goal_status="partially_done",
            expected_step_statuses=["verified", "blocked"],
        ),
        BenchmarkCase(
            name="high_risk_blocked",
            description="HIGH risk tool blocked by conservative policy",
            tags=["policy", "risk"],
            build_kernel=lambda **kw: AgentKernel(registry=_registry_with_high_risk(), policy=PolicyEngine()),
            build_goal=lambda **kw: Goal(description="HR", success_criteria=["blocked"], stop_conditions=["blocked"]),
            build_steps=lambda **kw: [ActionStep("high_risk", {}, "high risk")],
            expected_goal_status="blocked",
            expected_step_statuses=["blocked"],
        ),
        BenchmarkCase(
            name="postcondition_failure_rolls_back",
            description="Mismatched postcondition triggers rollback",
            tags=["rollback"],
            build_goal=lambda **kw: Goal(
                description="Post", success_criteria=["rolled back"], stop_conditions=["failed"]
            ),
            build_steps=lambda **kw: [
                ActionStep(
                    "echo",
                    {"message": "hi"},
                    "test",
                    postconditions=(StateCondition("last_echo", "equals", "wrong"),),
                )
            ],
            expected_goal_status="failed",
            expected_step_statuses=["failed"],
        ),
    ]
