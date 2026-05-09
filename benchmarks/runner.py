#!/usr/bin/env python3
"""Lightweight benchmark runner for Leos agent safety invariants."""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import benchmarks.cases as _cases
from leos_agent.causal import CausalHypothesis, CausalWorldModel
from leos_agent.policy import PolicyEngine


@dataclass
class BenchmarkResult:
    case_name: str
    success: bool
    goal_status: str = ""
    step_statuses: list[str] = field(default_factory=list)
    audit_event_count: int = 0
    blocked_count: int = 0
    failed_count: int = 0
    rollback_count: int = 0
    manual_recovery_count: int = 0
    duration_seconds: float = 0.0

    def summary(self) -> str:
        status = "PASS" if self.success else "FAIL"
        return (
            f"[{status}] {self.case_name}: "
            f"goal={self.goal_status} steps={self.step_statuses} "
            f"({self.duration_seconds:.3f}s)"
        )


def run_cases() -> list[BenchmarkResult]:
    results = []
    for case in _cases.cases():
        start = time.monotonic()
        result = BenchmarkResult(case_name=case.name, success=False)
        try:
            ws = Path(tempfile.mkdtemp())
            ws.mkdir(parents=True, exist_ok=True)
            if case.build_kernel:
                kernel = case.build_kernel(ws=ws)
            else:
                from leos_agent.tools import default_registry

                registry = default_registry(ws)
                kernel_params = dict(registry=registry, policy=PolicyEngine())
                if any("rollback" in t for t in case.tags) or any("postcondition" in t for t in case.tags):
                    causal = CausalWorldModel(
                        [
                            CausalHypothesis(
                                action_name="echo",
                                affected_variables=["last_echo"],
                                rationale="Echo sets last_echo",
                                confidence=0.9,
                            )
                        ]
                    )
                    kernel_params["causal_model"] = causal
                from leos_agent.kernel import AgentKernel

                kernel = AgentKernel(**kernel_params)

            goal = case.build_goal()
            steps = case.build_steps(ws=ws)
            plan = kernel.build_plan(goal, steps)
            executed = kernel.run(plan)

            result.goal_status = executed.goal.status.value
            result.step_statuses = [s.status.value for s in executed.steps]
            result.audit_event_count = len(kernel.audit_log.events)
            result.blocked_count = sum(1 for e in kernel.audit_log.events if e.event_type == "step.blocked")
            result.failed_count = sum(
                1 for e in kernel.audit_log.events if e.event_type in {"step.execution_failed", "step.dry_run_failed"}
            )
            result.rollback_count = sum(1 for e in kernel.audit_log.events if "rollback" in e.event_type)
            result.manual_recovery_count = sum(
                1 for e in kernel.audit_log.events if e.event_type == "manual_recovery_required"
            )

            result.success = (
                result.goal_status == case.expected_goal_status and result.step_statuses == case.expected_step_statuses
            )
        except Exception as exc:
            result.goal_status = f"exception: {exc}"
        finally:
            result.duration_seconds = time.monotonic() - start
        results.append(result)
    return results


def main() -> int:
    results = run_cases()
    for r in results:
        print(r.summary())
    failed = [r for r in results if not r.success]
    if failed:
        print(f"\n{len(failed)} / {len(results)} failed")
    else:
        print(f"\n{len(results)} passed")
    return len(failed)


if __name__ == "__main__":
    raise SystemExit(main())
