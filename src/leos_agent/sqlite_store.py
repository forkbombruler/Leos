"""SQLite-backed runtime store for local durable agent state."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .goals import Goal
from .plans import TransactionPlan
from .runtime_store import RuntimeStoreError, _goal_from_dict, _goal_to_dict
from .sanitization import SanitizationError, assert_no_secrets
from .serialization import SerializationError, deserialize_plan, serialize_plan


class SQLiteRuntimeStore:
    """SQLite development runtime store.

    This is stronger local persistence than JSONL, but it is not a distributed
    production store and does not provide multi-node coordination.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._init_schema()
        except sqlite3.Error as exc:
            raise RuntimeStoreError(f"sqlite runtime store unavailable: {type(exc).__name__}") from exc
        except OSError as exc:
            raise RuntimeStoreError(f"sqlite runtime store path unavailable: {type(exc).__name__}") from exc

    def save_goal(self, goal: Goal) -> None:
        payload = _goal_to_dict(goal)
        _assert_sqlite_safe(payload)
        now = time.time()
        self._execute(
            """
            INSERT INTO goals (goal_id, payload_json, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(goal_id) DO UPDATE SET
              payload_json=excluded.payload_json,
              updated_at=excluded.updated_at
            """,
            (goal.goal_id, json.dumps(payload, ensure_ascii=False), now, now),
        )

    def load_goal(self, goal_id: str) -> Goal | None:
        row = self._fetchone(
            "SELECT payload_json FROM goals WHERE goal_id = ? ORDER BY updated_at DESC, rowid DESC LIMIT 1",
            (goal_id,),
        )
        if row is None:
            return None
        return _goal_from_dict(_loads_object(row["payload_json"], "goal payload"))

    def save_plan(self, plan: TransactionPlan) -> None:
        try:
            payload = json.loads(serialize_plan(plan))
        except (SerializationError, TypeError, ValueError) as exc:
            raise RuntimeStoreError(f"Could not serialize plan: {type(exc).__name__}") from exc
        _assert_sqlite_safe(payload)
        now = time.time()
        self._execute(
            """
            INSERT INTO plans (plan_id, payload_json, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(plan_id) DO UPDATE SET
              payload_json=excluded.payload_json,
              updated_at=excluded.updated_at
            """,
            (plan.plan_id, json.dumps(payload, ensure_ascii=False), now, now),
        )

    def load_plan(self, plan_id: str) -> TransactionPlan | None:
        row = self._fetchone(
            "SELECT payload_json FROM plans WHERE plan_id = ? ORDER BY updated_at DESC, rowid DESC LIMIT 1",
            (plan_id,),
        )
        if row is None:
            return None
        try:
            return deserialize_plan(str(row["payload_json"]))
        except Exception as exc:
            raise RuntimeStoreError(f"Could not deserialize plan: {type(exc).__name__}") from exc

    def append_runtime_event(self, event: Mapping[str, Any]) -> None:
        _assert_sqlite_safe(event)
        now = time.time()
        self._execute(
            "INSERT INTO runtime_events (goal_id, payload_json, created_at) VALUES (?, ?, ?)",
            (event.get("goal_id"), json.dumps(dict(event), ensure_ascii=False), now),
        )

    def list_runtime_events(self, goal_id: str | None = None) -> list[dict[str, Any]]:
        if goal_id is None:
            rows = self._fetchall("SELECT payload_json FROM runtime_events ORDER BY sequence ASC", ())
        else:
            rows = self._fetchall(
                "SELECT payload_json FROM runtime_events WHERE goal_id = ? ORDER BY sequence ASC",
                (goal_id,),
            )
        return [_loads_object(row["payload_json"], "runtime event") for row in rows]

    def save_checkpoint(self, key: str, value: Mapping[str, Any]) -> None:
        _assert_sqlite_safe(value)
        now = time.time()
        self._execute(
            """
            INSERT INTO checkpoints (key, payload_json, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
              payload_json=excluded.payload_json,
              updated_at=excluded.updated_at
            """,
            (key, json.dumps(dict(value), ensure_ascii=False), now, now),
        )

    def load_checkpoint(self, key: str) -> dict[str, Any] | None:
        row = self._fetchone(
            "SELECT payload_json FROM checkpoints WHERE key = ? ORDER BY updated_at DESC, rowid DESC LIMIT 1",
            (key,),
        )
        if row is None:
            return None
        return _loads_object(row["payload_json"], "checkpoint")

    def close(self) -> None:
        self._conn.close()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS goals (
              goal_id TEXT PRIMARY KEY,
              payload_json TEXT NOT NULL,
              created_at REAL NOT NULL,
              updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS plans (
              plan_id TEXT PRIMARY KEY,
              payload_json TEXT NOT NULL,
              created_at REAL NOT NULL,
              updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runtime_events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              goal_id TEXT,
              payload_json TEXT NOT NULL,
              created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
              key TEXT PRIMARY KEY,
              payload_json TEXT NOT NULL,
              created_at REAL NOT NULL,
              updated_at REAL NOT NULL
            );
            """
        )
        self._conn.commit()

    def _execute(self, sql: str, params: tuple[Any, ...]) -> None:
        try:
            with self._conn:
                self._conn.execute(sql, params)
        except sqlite3.Error as exc:
            raise RuntimeStoreError(f"sqlite runtime store write failed: {type(exc).__name__}") from exc

    def _fetchone(self, sql: str, params: tuple[Any, ...]) -> sqlite3.Row | None:
        try:
            row = self._conn.execute(sql, params).fetchone()
            return row if isinstance(row, sqlite3.Row) else None
        except sqlite3.Error as exc:
            raise RuntimeStoreError(f"sqlite runtime store read failed: {type(exc).__name__}") from exc

    def _fetchall(self, sql: str, params: tuple[Any, ...]) -> list[sqlite3.Row]:
        try:
            return list(self._conn.execute(sql, params).fetchall())
        except sqlite3.Error as exc:
            raise RuntimeStoreError(f"sqlite runtime store read failed: {type(exc).__name__}") from exc


def _assert_sqlite_safe(value: Any) -> None:
    try:
        assert_no_secrets(value)
    except SanitizationError as exc:
        raise RuntimeStoreError(f"SQLiteRuntimeStore rejected secret-like value: {exc}") from exc


def _loads_object(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeStoreError(f"Invalid {label} JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeStoreError(f"Invalid {label}: expected object")
    return value
