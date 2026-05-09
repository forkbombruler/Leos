"""Task queue and watchdog primitives for long-running runtime work."""

from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditLog
from .enums import GoalStatus, TaskStatus
from .plans import TransactionPlan
from .serialization import (
    deserialize_plan,
    deserialize_retry_policy,
    deserialize_timeout_policy,
    serialize_plan,
    serialize_retry_policy,
    serialize_timeout_policy,
)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 1

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")


@dataclass(frozen=True)
class TimeoutPolicy:
    heartbeat_timeout_seconds: float | None = 60.0
    runtime_timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        for name in ("heartbeat_timeout_seconds", "runtime_timeout_seconds"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} must be non-negative")


@dataclass
class RuntimeTask:
    plan: TransactionPlan
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: TaskStatus = TaskStatus.QUEUED
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    timeout_policy: TimeoutPolicy = field(default_factory=TimeoutPolicy)
    idempotency_key: str | None = None
    attempts: int = 0
    locked_by: str | None = None
    enqueued_at: float = field(default_factory=time.time)
    started_at: float | None = None
    last_heartbeat_at: float | None = None
    finished_at: float | None = None
    failure_reason: str | None = None

    def __post_init__(self) -> None:
        self.status = TaskStatus(self.status)

    @property
    def active(self) -> bool:
        return self.status in {TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.PAUSED}


class TaskQueue:
    """FIFO task queue with optional SQLite persistence.

    When `path` is None, operates in-memory only (current behavior).
    When `path` is provided, persists all mutations to a SQLite database.
    """

    def __init__(
        self,
        audit_log: AuditLog | None = None,
        path: Path | None = None,
    ) -> None:
        self.audit_log = audit_log or AuditLog()
        self._tasks: dict[str, RuntimeTask] = {}
        self._order: list[str] = []
        self._idempotency_index: dict[str, str] = {}
        self._db_path = path
        self._conn: sqlite3.Connection | None = None
        if self._db_path is not None:
            self._init_db()
            self._load_tasks()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                plan_json TEXT NOT NULL,
                status TEXT NOT NULL,
                retry_policy_json TEXT NOT NULL,
                timeout_policy_json TEXT NOT NULL,
                idempotency_key TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                locked_by TEXT,
                enqueued_at REAL,
                started_at REAL,
                last_heartbeat_at REAL,
                finished_at REAL,
                failure_reason TEXT
            )"""
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS idempotency (
                idempotency_key TEXT PRIMARY KEY,
                task_id TEXT NOT NULL
            )"""
        )
        self._conn.commit()

    def _load_tasks(self) -> None:
        if self._conn is None:
            raise RuntimeError("_load_tasks called without a database connection")
        rows = self._conn.execute("SELECT * FROM tasks ORDER BY enqueued_at").fetchall()
        for row in rows:
            task = RuntimeTask(
                plan=deserialize_plan(row[1]),
                task_id=row[0],
                status=TaskStatus(row[2]),
                retry_policy=deserialize_retry_policy(row[3]),
                timeout_policy=deserialize_timeout_policy(row[4]),
                idempotency_key=row[5],
                attempts=row[6],
                locked_by=None if row[7] == "None" else row[7],
                enqueued_at=row[8] or time.time(),
                started_at=row[9],
                last_heartbeat_at=row[10],
                finished_at=row[11],
                failure_reason=row[12],
            )
            self._tasks[task.task_id] = task
            self._order.append(task.task_id)
        idem_rows = self._conn.execute("SELECT * FROM idempotency").fetchall()
        for row in idem_rows:
            self._idempotency_index[row[0]] = row[1]

    def _persist_enqueue(self, task: RuntimeTask) -> None:
        if self._conn is None:
            return
        self._conn.execute(
            """INSERT INTO tasks (task_id, plan_json, status, retry_policy_json,
               timeout_policy_json, idempotency_key, attempts, locked_by,
               enqueued_at, started_at, last_heartbeat_at, finished_at,
               failure_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task.task_id,
                serialize_plan(task.plan),
                task.status.value,
                serialize_retry_policy(task.retry_policy),
                serialize_timeout_policy(task.timeout_policy),
                task.idempotency_key,
                task.attempts,
                task.locked_by,
                task.enqueued_at,
                task.started_at,
                task.last_heartbeat_at,
                task.finished_at,
                task.failure_reason,
            ),
        )
        if task.idempotency_key:
            self._conn.execute(
                "INSERT INTO idempotency (idempotency_key, task_id) VALUES (?, ?)",
                (task.idempotency_key, task.task_id),
            )
        self._conn.commit()

    def _persist_update(self, task: RuntimeTask) -> None:
        if self._conn is None:
            return
        self._conn.execute(
            """UPDATE tasks SET status=?, attempts=?, locked_by=?,
               started_at=?, last_heartbeat_at=?, finished_at=?,
               failure_reason=?
               WHERE task_id=?""",
            (
                task.status.value,
                task.attempts,
                task.locked_by,
                task.started_at,
                task.last_heartbeat_at,
                task.finished_at,
                task.failure_reason,
                task.task_id,
            ),
        )
        self._conn.commit()

    def enqueue(
        self,
        plan: TransactionPlan,
        *,
        idempotency_key: str | None = None,
        retry_policy: RetryPolicy | None = None,
        timeout_policy: TimeoutPolicy | None = None,
    ) -> RuntimeTask:
        if idempotency_key and idempotency_key in self._idempotency_index:
            existing = self._tasks[self._idempotency_index[idempotency_key]]
            self.audit_log.record(
                "task.deduplicated",
                "Task idempotency key already exists",
                task_id=existing.task_id,
                plan_id=existing.plan.plan_id,
                idempotency_key=idempotency_key,
                status=existing.status.value,
            )
            return existing

        task = RuntimeTask(
            plan=plan,
            retry_policy=retry_policy or RetryPolicy(),
            timeout_policy=timeout_policy or TimeoutPolicy(),
            idempotency_key=idempotency_key,
        )
        self._tasks[task.task_id] = task
        self._order.append(task.task_id)
        if idempotency_key:
            self._idempotency_index[idempotency_key] = task.task_id
        self.audit_log.record(
            "task.enqueued",
            "Task enqueued",
            task_id=task.task_id,
            plan_id=plan.plan_id,
            idempotency_key=idempotency_key,
        )
        self._persist_enqueue(task)
        return task

    def claim(self, worker_id: str, *, now: float | None = None) -> RuntimeTask | None:
        timestamp = time.time() if now is None else now
        for task_id in self._order:
            task = self._tasks[task_id]
            if task.status is not TaskStatus.QUEUED:
                continue
            task.status = TaskStatus.RUNNING
            task.locked_by = worker_id
            task.attempts += 1
            task.started_at = timestamp
            task.last_heartbeat_at = timestamp
            self.audit_log.record(
                "task.claimed",
                "Task claimed by worker",
                task_id=task.task_id,
                plan_id=task.plan.plan_id,
                worker_id=worker_id,
                attempts=task.attempts,
            )
            self._persist_update(task)
            return task
        return None

    def heartbeat(self, task_id: str, worker_id: str, *, now: float | None = None) -> RuntimeTask:
        task = self._require_task(task_id)
        self._require_lock(task, worker_id)
        task.last_heartbeat_at = time.time() if now is None else now
        self.audit_log.record("task.heartbeat", "Task heartbeat recorded", task_id=task.task_id, worker_id=worker_id)
        self._persist_update(task)
        return task

    def complete(self, task_id: str, worker_id: str, *, now: float | None = None) -> RuntimeTask:
        task = self._finish(task_id, worker_id, TaskStatus.SUCCEEDED, now=now)
        self.audit_log.record("task.completed", "Task completed", task_id=task.task_id, worker_id=worker_id)
        self._persist_update(task)
        return task

    def fail(self, task_id: str, worker_id: str, reason: str, *, now: float | None = None) -> RuntimeTask:
        task = self._finish(task_id, worker_id, TaskStatus.FAILED, now=now)
        task.failure_reason = reason
        self.audit_log.record("task.failed", reason, task_id=task.task_id, worker_id=worker_id)
        self._persist_update(task)
        return task

    def retry(self, task_id: str, worker_id: str, reason: str) -> RuntimeTask:
        task = self._require_task(task_id)
        self._require_lock(task, worker_id)
        task.status = TaskStatus.QUEUED
        task.locked_by = None
        task.started_at = None
        task.last_heartbeat_at = None
        task.finished_at = None
        task.failure_reason = reason
        self.audit_log.record(
            "task.retry_scheduled",
            reason,
            task_id=task.task_id,
            worker_id=worker_id,
            attempts=task.attempts,
            max_attempts=task.retry_policy.max_attempts,
        )
        self._persist_update(task)
        return task

    def cancel(self, task_id: str, *, reason: str = "cancelled", now: float | None = None) -> RuntimeTask:
        task = self._require_task(task_id)
        task.status = TaskStatus.CANCELLED
        task.finished_at = time.time() if now is None else now
        task.failure_reason = reason
        task.locked_by = None
        self.audit_log.record("task.cancelled", reason, task_id=task.task_id)
        self._persist_update(task)
        return task

    def pause(self, task_id: str, worker_id: str) -> RuntimeTask:
        task = self._require_task(task_id)
        self._require_lock(task, worker_id)
        task.status = TaskStatus.PAUSED
        task.locked_by = None
        self.audit_log.record("task.paused", "Task paused", task_id=task.task_id, worker_id=worker_id)
        self._persist_update(task)
        return task

    def resume(self, task_id: str) -> RuntimeTask:
        task = self._require_task(task_id)
        if task.status is not TaskStatus.PAUSED:
            raise ValueError("Only paused tasks can be resumed")
        task.status = TaskStatus.QUEUED
        self.audit_log.record("task.resumed", "Task resumed", task_id=task.task_id)
        self._persist_update(task)
        return task

    def get(self, task_id: str) -> RuntimeTask:
        return self._require_task(task_id)

    def tasks(self) -> list[RuntimeTask]:
        return [self._tasks[task_id] for task_id in self._order]

    def _finish(self, task_id: str, worker_id: str, status: TaskStatus, *, now: float | None) -> RuntimeTask:
        task = self._require_task(task_id)
        self._require_lock(task, worker_id)
        task.status = status
        task.finished_at = time.time() if now is None else now
        task.locked_by = None
        return task

    def _require_task(self, task_id: str) -> RuntimeTask:
        if task_id not in self._tasks:
            raise KeyError(f"Unknown task: {task_id}")
        return self._tasks[task_id]

    @staticmethod
    def _require_lock(task: RuntimeTask, worker_id: str) -> None:
        if task.status is not TaskStatus.RUNNING or task.locked_by != worker_id:
            raise PermissionError("Task is not locked by this worker")


class Watchdog:
    """Detects timed-out running tasks using heartbeat/runtime limits."""

    def __init__(self, queue: TaskQueue, audit_log: AuditLog | None = None) -> None:
        self.queue = queue
        self.audit_log = audit_log or queue.audit_log

    def check(self, *, now: float | None = None) -> list[RuntimeTask]:
        timestamp = time.time() if now is None else now
        timed_out = []
        for task in self.queue.tasks():
            if task.status is not TaskStatus.RUNNING:
                continue
            reason = self._timeout_reason(task, timestamp)
            if not reason:
                continue
            task.status = TaskStatus.TIMED_OUT
            task.finished_at = timestamp
            task.failure_reason = reason
            task.locked_by = None
            timed_out.append(task)
            self.audit_log.record(
                "task.timed_out",
                reason,
                task_id=task.task_id,
                plan_id=task.plan.plan_id,
                attempts=task.attempts,
            )
        return timed_out

    @staticmethod
    def _timeout_reason(task: RuntimeTask, now: float) -> str | None:
        heartbeat_timeout = task.timeout_policy.heartbeat_timeout_seconds
        if (
            heartbeat_timeout is not None
            and task.last_heartbeat_at is not None
            and now - task.last_heartbeat_at > heartbeat_timeout
        ):
            return "Task heartbeat timed out"
        runtime_timeout = task.timeout_policy.runtime_timeout_seconds
        if runtime_timeout is not None and task.started_at is not None and now - task.started_at > runtime_timeout:
            return "Task runtime timed out"
        return None


class TaskRunner:
    """Claims queued tasks and executes their plans through an AgentKernel-like object."""

    def __init__(
        self, queue: TaskQueue, kernel: object, *, worker_id: str = "worker", audit_log: AuditLog | None = None
    ) -> None:
        self.queue = queue
        self.kernel = kernel
        self.worker_id = worker_id
        self.audit_log = audit_log or queue.audit_log

    def run_next(self, *, now: float | None = None) -> RuntimeTask | None:
        task = self.queue.claim(self.worker_id, now=now)
        if task is None:
            self.audit_log.record("task.runner_idle", "No queued task available", worker_id=self.worker_id)
            return None

        self.audit_log.record(
            "task.runner_started",
            "Task runner started execution",
            task_id=task.task_id,
            plan_id=task.plan.plan_id,
            worker_id=self.worker_id,
        )
        try:
            self.kernel.run(task.plan)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001 - task runner must capture task-level failures
            return self._handle_failure(task, f"Task execution raised: {exc}", now=now)

        goal_status = task.plan.goal.status
        self.audit_log.record(
            "task.runner_finished",
            "Task runner finished execution",
            task_id=task.task_id,
            plan_id=task.plan.plan_id,
            worker_id=self.worker_id,
            goal_status=goal_status.value,
        )
        if goal_status is GoalStatus.SUCCEEDED:
            return self.queue.complete(task.task_id, self.worker_id, now=now)
        return self._handle_failure(task, f"Goal ended with status {goal_status.value}", now=now)

    def _handle_failure(self, task: RuntimeTask, reason: str, *, now: float | None) -> RuntimeTask:
        if task.attempts < task.retry_policy.max_attempts:
            return self.queue.retry(task.task_id, self.worker_id, reason)
        return self.queue.fail(task.task_id, self.worker_id, reason, now=now)
