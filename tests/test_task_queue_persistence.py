"""Tests for SQLite-persistent TaskQueue."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent.enums import TaskStatus
from leos_agent.goals import Goal
from leos_agent.plans import ActionStep, TransactionPlan
from leos_agent.task_queue import (
    TaskQueue,
    TimeoutPolicy,
    Watchdog,
)


def _echo_plan(goal_desc: str = "test") -> TransactionPlan:
    goal = Goal(
        description=goal_desc,
        success_criteria=["ok"],
        stop_conditions=["done"],
    )
    return TransactionPlan(
        goal=goal,
        steps=[ActionStep("echo", {"message": "hi"}, "test")],
    )


class TaskQueuePersistenceTests(unittest.TestCase):
    def test_enqueue_persists_and_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tasks.db"
            queue = TaskQueue(path=db_path)
            task = queue.enqueue(_echo_plan())
            self.assertIsNotNone(task.task_id)

            queue2 = TaskQueue(path=db_path)
            loaded = queue2.get(task.task_id)
            self.assertEqual(loaded.status, TaskStatus.QUEUED)

    def test_idempotency_dedupe_survives_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tasks.db"
            q1 = TaskQueue(path=db_path)
            q1.enqueue(_echo_plan(), idempotency_key="once")
            q2 = TaskQueue(path=db_path)
            dup = q2.enqueue(_echo_plan(), idempotency_key="once")
            self.assertEqual(dup.idempotency_key, "once")

    def test_claim_lock_survives_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tasks.db"
            q1 = TaskQueue(path=db_path)
            q1.enqueue(_echo_plan())
            claimed = q1.claim("w1")
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed.status, TaskStatus.RUNNING)

            q2 = TaskQueue(path=db_path)
            loaded = q2.get(claimed.task_id)
            self.assertEqual(loaded.status, TaskStatus.RUNNING)
            self.assertEqual(loaded.locked_by, "w1")

    def test_heartbeat_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tasks.db"
            q = TaskQueue(path=db_path)
            q.enqueue(_echo_plan())
            claimed = q.claim("w1")
            q.heartbeat(claimed.task_id, "w1", now=999.0)
            q2 = TaskQueue(path=db_path)
            loaded = q2.get(claimed.task_id)
            self.assertEqual(loaded.last_heartbeat_at, 999.0)

    def test_complete_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tasks.db"
            q = TaskQueue(path=db_path)
            q.enqueue(_echo_plan())
            claimed = q.claim("w1")
            q.complete(claimed.task_id, "w1")
            q2 = TaskQueue(path=db_path)
            loaded = q2.get(claimed.task_id)
            self.assertEqual(loaded.status, TaskStatus.SUCCEEDED)

    def test_retry_persists_attempts_and_queued(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tasks.db"
            q = TaskQueue(path=db_path)
            q.enqueue(_echo_plan())
            claimed = q.claim("w1")
            q.retry(claimed.task_id, "w1", "test retry")
            q2 = TaskQueue(path=db_path)
            loaded = q2.get(claimed.task_id)
            self.assertEqual(loaded.status, TaskStatus.QUEUED)
            self.assertEqual(loaded.attempts, 1)

    def test_pause_resume_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tasks.db"
            q = TaskQueue(path=db_path)
            q.enqueue(_echo_plan())
            claimed = q.claim("w1")
            q.pause(claimed.task_id, "w1")
            q.resume(claimed.task_id)
            q2 = TaskQueue(path=db_path)
            loaded = q2.get(claimed.task_id)
            self.assertEqual(loaded.status, TaskStatus.QUEUED)

    def test_watchdog_can_time_out_reloaded_running_task(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tasks.db"
            q = TaskQueue(path=db_path)
            q.enqueue(
                _echo_plan(),
                timeout_policy=TimeoutPolicy(heartbeat_timeout_seconds=1.0),
            )
            q.claim("w1", now=100.0)
            q2 = TaskQueue(path=db_path)
            w = Watchdog(q2)
            timed_out = w.check(now=999.0)
            self.assertEqual(len(timed_out), 1)
            self.assertEqual(timed_out[0].status, TaskStatus.TIMED_OUT)

    def test_task_order_preserved_after_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "tasks.db"
            q = TaskQueue(path=db_path)
            ids = []
            for i in range(3):
                t = q.enqueue(_echo_plan(f"task {i}"))
                ids.append(t.task_id)
            q2 = TaskQueue(path=db_path)
            self.assertEqual([t.task_id for t in q2.tasks()], ids)


if __name__ == "__main__":
    unittest.main()
