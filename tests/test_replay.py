"""Tests for enhanced audit replay and state reconstruction."""

from __future__ import annotations

import unittest

from leos_agent.audit import AuditLog
from leos_agent.replay import replay_audit_log


class ReplayEnhancementTests(unittest.TestCase):
    def test_tampered_hash_chain_rejected(self) -> None:
        audit = AuditLog()
        audit.record("step.executed", "ok", observed={"x": 1})
        records = audit.records()
        records[0]["payload"]["observed"]["x"] = "tampered"
        result = replay_audit_log(audit)
        # uses the untampered in-memory audit log, verify passes
        self.assertTrue(result.ok)
        # tampered on-disk records block replay with integrity check
        tampered = AuditLog.verify_event_records(records)
        self.assertFalse(tampered.ok)

    def test_verified_fact_trust_reconstructed(self) -> None:
        audit = AuditLog()
        audit.record("step.executed", "ok", observed={"key": "val"})
        audit.record("step.verified", "ok", verified=["key"])
        result = replay_audit_log(audit)
        self.assertIn("key", result.state.facts)
        self.assertEqual(result.state.trust.get("key").value, "verified")

    def test_goal_lifecycle_reconstructed(self) -> None:
        audit = AuditLog()
        audit.record("goal.status_changed", "start", goal_id="g1", to_status="planning")
        audit.record("goal.status_changed", "run", goal_id="g1", to_status="running")
        audit.record("goal.status_changed", "done", goal_id="g1", to_status="succeeded")
        result = replay_audit_log(audit)
        self.assertIn("g1", result.goals)
        self.assertEqual(result.goals["g1"]["status"], "succeeded")

    def test_task_lifecycle_reconstructed(self) -> None:
        audit = AuditLog()
        audit.record("task.enqueued", "enq", task_id="t1", plan_id="p1")
        audit.record("task.claimed", "claim", task_id="t1", worker_id="w1")
        audit.record("task.completed", "done", task_id="t1", worker_id="w1")
        result = replay_audit_log(audit)
        self.assertIn("t1", result.tasks)
        self.assertEqual(result.tasks["t1"]["status"], "succeeded")

    def test_rollback_manual_recovery_reconstructed(self) -> None:
        audit = AuditLog()
        audit.record("rollback_attempted", "try", step_id="s1")
        audit.record("rollback_failed", "fail", step_id="s1", error_type="RollbackFailed")
        audit.record("manual_recovery_required", "recover", step_id="s1", rollback_token={"key": "val"})
        result = replay_audit_log(audit)
        self.assertGreaterEqual(len(result.rollbacks), 1)
        manual = [r for r in result.rollbacks if r.get("type") == "manual_recovery"]
        self.assertEqual(len(manual), 1)

    def test_blocked_policy_decision_reconstructed(self) -> None:
        audit = AuditLog()
        audit.record("step.blocked", "blocked", tool="echo", decision="denied", reason="permission denied by policy")
        result = replay_audit_log(audit)
        self.assertEqual(len(result.blocked_steps), 1)
        self.assertEqual(result.blocked_steps[0]["tool"], "echo")

    def test_budget_exceeded_reconstructed(self) -> None:
        audit = AuditLog()
        audit.record("budget.exceeded", "over", tool="echo", limit="max_tool_calls", allowed=1, actual=2)
        result = replay_audit_log(audit)
        self.assertEqual(len(result.budget_events), 1)
        self.assertEqual(result.budget_events[0]["limit"], "max_tool_calls")


if __name__ == "__main__":
    unittest.main()
