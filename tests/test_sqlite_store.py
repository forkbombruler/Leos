from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from leos_agent import ActionStep, Goal, TransactionPlan
from leos_agent.runtime_store import RuntimeStoreError
from leos_agent.sqlite_store import SQLiteRuntimeStore
from leos_agent.tools import Secret


class SQLiteRuntimeStoreTests(unittest.TestCase):
    def test_reopen_restores_goal_plan_events_and_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "runtime.db"
            goal = Goal("demo", ["done"])
            plan = TransactionPlan(goal, [ActionStep("echo", {"message": "hi"}, "echo")])
            store = SQLiteRuntimeStore(db)
            store.save_goal(goal)
            store.save_plan(plan)
            store.append_runtime_event({"goal_id": goal.goal_id, "event_type": "one"})
            store.save_checkpoint("final", {"goal_id": goal.goal_id, "status": "done"})
            store.close()

            reopened = SQLiteRuntimeStore(db)

            self.assertEqual(reopened.load_goal(goal.goal_id).description, "demo")  # type: ignore[union-attr]
            self.assertEqual(reopened.load_plan(plan.plan_id).steps[0].tool_name, "echo")  # type: ignore[union-attr]
            self.assertEqual(reopened.list_runtime_events(goal.goal_id)[0]["event_type"], "one")
            self.assertEqual(reopened.load_checkpoint("final")["status"], "done")  # type: ignore[index]

    def test_checkpoint_upsert_returns_latest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteRuntimeStore(Path(tmp) / "runtime.db")

            store.save_checkpoint("k", {"value": 1})
            store.save_checkpoint("k", {"value": 2})

            self.assertEqual(store.load_checkpoint("k"), {"value": 2})

    def test_events_are_append_only_and_ordered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteRuntimeStore(Path(tmp) / "runtime.db")

            store.append_runtime_event({"goal_id": "g", "event_type": "one"})
            store.append_runtime_event({"goal_id": "g", "event_type": "two"})

            self.assertEqual([event["event_type"] for event in store.list_runtime_events("g")], ["one", "two"])

    def test_secret_like_checkpoint_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteRuntimeStore(Path(tmp) / "runtime.db")

            with self.assertRaises(RuntimeStoreError):
                store.save_checkpoint("k", {"token": Secret("must-not-store")})
            with self.assertRaises(RuntimeStoreError):
                store.save_checkpoint("k", {"token": "ghp_must_not_store"})

    def test_invalid_path_raises_runtime_store_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(RuntimeStoreError):
            SQLiteRuntimeStore(Path(tmp))


if __name__ == "__main__":
    unittest.main()
