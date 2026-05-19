"""Runtime persistence abstractions for goals, plans, events, and checkpoints."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from .enums import GoalStatus
from .errors import LeosError
from .goals import Goal
from .plans import TransactionPlan
from .sanitization import SanitizationError, assert_no_secrets
from .serialization import SerializationError, deserialize_plan, serialize_plan


class RuntimeStoreError(LeosError):
    """Raised when runtime store persistence fails."""


class RuntimeStore(Protocol):
    def save_goal(self, goal: Goal) -> None: ...

    def load_goal(self, goal_id: str) -> Goal | None: ...

    def save_plan(self, plan: TransactionPlan) -> None: ...

    def load_plan(self, plan_id: str) -> TransactionPlan | None: ...

    def append_runtime_event(self, event: Mapping[str, Any]) -> None: ...

    def list_runtime_events(self, goal_id: str | None = None) -> list[dict[str, Any]]: ...

    def save_checkpoint(self, key: str, value: Mapping[str, Any]) -> None: ...

    def load_checkpoint(self, key: str) -> dict[str, Any] | None: ...


class InMemoryRuntimeStore:
    """In-memory runtime store for tests and local demos."""

    def __init__(self) -> None:
        self.goals: dict[str, Goal] = {}
        self.plans: dict[str, TransactionPlan] = {}
        self.events: list[dict[str, Any]] = []
        self.checkpoints: dict[str, dict[str, Any]] = {}

    def save_goal(self, goal: Goal) -> None:
        self.goals[goal.goal_id] = goal

    def load_goal(self, goal_id: str) -> Goal | None:
        return self.goals.get(goal_id)

    def save_plan(self, plan: TransactionPlan) -> None:
        self.plans[plan.plan_id] = plan

    def load_plan(self, plan_id: str) -> TransactionPlan | None:
        return self.plans.get(plan_id)

    def append_runtime_event(self, event: Mapping[str, Any]) -> None:
        _assert_store_safe(event)
        self.events.append(dict(event))

    def list_runtime_events(self, goal_id: str | None = None) -> list[dict[str, Any]]:
        if goal_id is None:
            return [dict(event) for event in self.events]
        return [dict(event) for event in self.events if event.get("goal_id") == goal_id]

    def save_checkpoint(self, key: str, value: Mapping[str, Any]) -> None:
        _assert_store_safe(value)
        self.checkpoints[key] = dict(value)

    def load_checkpoint(self, key: str) -> dict[str, Any] | None:
        value = self.checkpoints.get(key)
        return dict(value) if value is not None else None


class JsonlRuntimeStore:
    """JSONL development store.

    This store restores core goal and plan fields only and is not designed for
    strong concurrent writers or production database semantics.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.goals_path = self.root / "goals.jsonl"
        self.plans_path = self.root / "plans.jsonl"
        self.events_path = self.root / "events.jsonl"
        self.checkpoints_path = self.root / "checkpoints.json"

    def save_goal(self, goal: Goal) -> None:
        self._append_jsonl(self.goals_path, _goal_to_dict(goal))

    def load_goal(self, goal_id: str) -> Goal | None:
        found: Goal | None = None
        for record in self._read_jsonl(self.goals_path):
            if record.get("goal_id") == goal_id:
                found = _goal_from_dict(record)
        return found

    def save_plan(self, plan: TransactionPlan) -> None:
        try:
            payload = json.loads(serialize_plan(plan))
        except (SerializationError, TypeError, ValueError) as exc:
            raise RuntimeStoreError(f"Could not serialize plan: {type(exc).__name__}") from exc
        _assert_store_safe(payload)
        self._append_jsonl(self.plans_path, payload)

    def load_plan(self, plan_id: str) -> TransactionPlan | None:
        found: TransactionPlan | None = None
        for record in self._read_jsonl(self.plans_path):
            if record.get("plan_id") == plan_id:
                try:
                    found = deserialize_plan(json.dumps(record))
                except Exception as exc:
                    raise RuntimeStoreError(f"Could not deserialize plan: {type(exc).__name__}") from exc
        return found

    def append_runtime_event(self, event: Mapping[str, Any]) -> None:
        _assert_store_safe(event)
        self._append_jsonl(self.events_path, dict(event))

    def list_runtime_events(self, goal_id: str | None = None) -> list[dict[str, Any]]:
        events = self._read_jsonl(self.events_path)
        if goal_id is None:
            return events
        return [event for event in events if event.get("goal_id") == goal_id]

    def save_checkpoint(self, key: str, value: Mapping[str, Any]) -> None:
        _assert_store_safe(value)
        checkpoints = self._read_checkpoints()
        checkpoints[key] = dict(value)
        tmp_path = self.checkpoints_path.with_suffix(self.checkpoints_path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(checkpoints, ensure_ascii=False, indent=2))
            handle.flush()
        tmp_path.replace(self.checkpoints_path)

    def load_checkpoint(self, key: str) -> dict[str, Any] | None:
        value = self._read_checkpoints().get(key)
        return dict(value) if isinstance(value, dict) else None

    def _append_jsonl(self, path: Path, record: Mapping[str, Any]) -> None:
        _assert_store_safe(record)
        try:
            encoded = json.dumps(record, ensure_ascii=False)
        except TypeError as exc:
            raise RuntimeStoreError(f"{path.name}: record is not JSON serializable") from exc
        with path.open("a", encoding="utf-8") as handle:
            handle.write(encoded + "\n")
            handle.flush()

    def _read_jsonl(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeStoreError(f"{path.name}:{line_number}: corrupt JSONL") from exc
            if not isinstance(value, dict):
                raise RuntimeStoreError(f"{path.name}:{line_number}: JSONL record is not an object")
            records.append(value)
        return records

    def _read_checkpoints(self) -> dict[str, Any]:
        if not self.checkpoints_path.exists():
            return {}
        try:
            value = json.loads(self.checkpoints_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeStoreError("checkpoints.json: corrupt JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeStoreError("checkpoints.json: root is not an object")
        return value


def _goal_to_dict(goal: Goal) -> dict[str, Any]:
    return {
        "goal_id": goal.goal_id,
        "description": goal.description,
        "success_criteria": list(goal.success_criteria),
        "constraints": list(goal.constraints),
        "stop_conditions": list(goal.stop_conditions),
        "priority": goal.priority,
        "owner": goal.owner,
        "deadline": goal.deadline,
        "status": goal.status.value,
    }


def _goal_from_dict(data: Mapping[str, Any]) -> Goal:
    return Goal(
        description=str(data["description"]),
        success_criteria=tuple(str(value) for value in data.get("success_criteria", ())),
        constraints=tuple(str(value) for value in data.get("constraints", ())),
        stop_conditions=tuple(str(value) for value in data.get("stop_conditions", ())),
        priority=int(data.get("priority", 5)),
        goal_id=str(data["goal_id"]),
        owner=str(data["owner"]) if data.get("owner") is not None else None,
        deadline=float(data["deadline"]) if data.get("deadline") is not None else None,
        status=GoalStatus(str(data.get("status", "created"))),
    )


def _assert_store_safe(value: Any) -> None:
    try:
        assert_no_secrets(value)
    except SanitizationError as exc:
        raise RuntimeStoreError(f"RuntimeStore rejected secret-like value: {exc}") from exc
