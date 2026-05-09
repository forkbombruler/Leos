"""Deterministic replay from audit events with rich state reconstruction."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog
from .state import TrustLevel, WorldState


@dataclass
class ReplayResult:
    ok: bool
    state: WorldState
    applied_events: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    goals: dict[str, dict[str, Any]] = field(default_factory=dict)
    tasks: dict[str, dict[str, Any]] = field(default_factory=dict)
    plans: dict[str, dict[str, Any]] = field(default_factory=dict)
    rollbacks: list[dict[str, Any]] = field(default_factory=list)
    policy_decisions: list[dict[str, Any]] = field(default_factory=list)
    budget_events: list[dict[str, Any]] = field(default_factory=list)
    failed_steps: list[dict[str, Any]] = field(default_factory=list)
    blocked_steps: list[dict[str, Any]] = field(default_factory=list)


class AuditReplayer:
    """Reconstructs runtime state from append-only audit events."""

    def replay(self, audit_log: AuditLog, *, verify_integrity: bool = True) -> ReplayResult:
        records = audit_log.records()
        return self.replay_records(records, verify_integrity=verify_integrity)

    def replay_records(self, records: Sequence[Mapping[str, Any]], *, verify_integrity: bool = True) -> ReplayResult:
        if verify_integrity:
            integrity = AuditLog.verify_event_records(records)
            if not integrity.ok:
                return ReplayResult(
                    ok=False,
                    state=WorldState(),
                    errors=list(integrity.data.get("issues", [])),
                )

        result = ReplayResult(ok=True, state=WorldState())
        for record in records:
            event_type = record.get("event_type", "")
            payload = record.get("payload", {})
            if not isinstance(payload, Mapping):
                continue

            # --- step lifecycle ---
            if event_type == "step.executed":
                observed = payload.get("observed", {})
                if isinstance(observed, Mapping):
                    trust = TrustLevel(str(payload.get("observed_trust", TrustLevel.TOOL_REPORTED.value)))
                    result.state.observe(dict(observed), trust_level=trust)
                    result.applied_events += 1
            elif event_type == "step.verified":
                verified = payload.get("verified", ())
                if isinstance(verified, list):
                    trust = TrustLevel(str(payload.get("verified_trust", TrustLevel.VERIFIED.value)))
                    result.state.mark_trust(verified, trust)
            elif event_type == "step.blocked":
                result.blocked_steps.append(dict(payload))
                result.policy_decisions.append(dict(payload))
            elif event_type in {
                "step.precondition_failed",
                "step.postcondition_failed",
                "step.dry_run_failed",
                "step.execution_failed",
                "step.output_schema_failed",
                "step.verification_failed",
            }:
                result.failed_steps.append({"type": event_type, **dict(payload)})
            elif event_type == "step.rollback":
                pass  # handled by rollback_attempted

            # --- goal lifecycle ---
            elif event_type == "goal.created":
                goal_id = payload.get("goal_id", "")
                result.goals[goal_id] = dict(payload)
            elif event_type == "goal.status_changed":
                goal_id = payload.get("goal_id", "")
                if goal_id not in result.goals:
                    result.goals[goal_id] = {}
                result.goals[goal_id]["status"] = payload.get("to_status")
                result.goals[goal_id]["from_status"] = payload.get("from_status")

            # --- plan ---
            elif event_type == "plan.started":
                plan_id = payload.get("plan_id", "")
                result.plans[plan_id] = dict(payload)
            elif event_type == "plan.finished":
                plan_id = payload.get("plan_id", "")
                if plan_id in result.plans:
                    result.plans[plan_id]["goal_status"] = payload.get("goal_status")

            # --- memory ---
            elif event_type == "memory.written":
                key = payload.get("key")
                value = payload.get("value")
                if isinstance(key, str):
                    result.state.set_fact(f"memory:{key}", value, trust_level=TrustLevel.VERIFIED)
                    result.applied_events += 1

            # --- budget ---
            elif event_type in {"budget.checked", "budget.exceeded"}:
                result.budget_events.append(dict(payload))

            # --- rollback ---
            elif event_type == "rollback_attempted":
                result.rollbacks.append({"type": "attempted", **dict(payload)})
            elif event_type == "rollback_succeeded":
                result.rollbacks.append({"type": "succeeded", **dict(payload)})
            elif event_type == "rollback_failed":
                result.rollbacks.append({"type": "failed", **dict(payload)})
            elif event_type == "rollback_partially_completed":
                result.rollbacks.append({"type": "partial", **dict(payload)})
            elif event_type == "manual_recovery_required":
                result.rollbacks.append({"type": "manual_recovery", **dict(payload)})

            # --- task queue ---
            elif event_type == "task.enqueued":
                task_id = payload.get("task_id", "")
                result.tasks[task_id] = {"status": "queued", **dict(payload)}
            elif event_type == "task.claimed":
                task_id = payload.get("task_id", "")
                if task_id in result.tasks:
                    result.tasks[task_id]["status"] = "running"
            elif event_type == "task.completed":
                task_id = payload.get("task_id", "")
                if task_id in result.tasks:
                    result.tasks[task_id]["status"] = "succeeded"
            elif event_type == "task.failed":
                task_id = payload.get("task_id", "")
                if task_id in result.tasks:
                    result.tasks[task_id]["status"] = "failed"
            elif event_type == "task.timed_out":
                task_id = payload.get("task_id", "")
                if task_id in result.tasks:
                    result.tasks[task_id]["status"] = "timed_out"
            elif event_type == "task.cancelled":
                task_id = payload.get("task_id", "")
                if task_id in result.tasks:
                    result.tasks[task_id]["status"] = "cancelled"
            elif event_type == "task.retry_scheduled":
                task_id = payload.get("task_id", "")
                if task_id in result.tasks:
                    result.tasks[task_id]["status"] = "retrying"

            # --- state trust ---
            elif event_type == "state.trust_escalated":
                keys = payload.get("keys", ())
                if isinstance(keys, list):
                    to_trust = TrustLevel(str(payload.get("to_trust", TrustLevel.VERIFIED.value)))
                    result.state.mark_trust(keys, to_trust)

        return result


def replay_audit_log(audit_log: AuditLog, *, verify_integrity: bool = True) -> ReplayResult:
    return AuditReplayer().replay(audit_log, verify_integrity=verify_integrity)
