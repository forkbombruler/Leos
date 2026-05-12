"""Conflict detection helpers for goals, facts, memory, and plans."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .memory import MemoryRecord
from .plans import ActionStep


@dataclass(frozen=True)
class Conflict:
    conflict_type: str
    summary: str
    evidence: dict[str, Any]
    requires_human: bool = False


class ConflictDetector:
    def goal_policy_conflict(self, goal_constraints: list[str], denied_tools: list[str]) -> list[Conflict]:
        conflicts = []
        for tool in denied_tools:
            for constraint in goal_constraints:
                if tool in constraint:
                    conflicts.append(
                        Conflict(
                            "goal_policy",
                            f"Goal constraint mentions denied tool '{tool}'",
                            {"tool": tool, "constraint": constraint},
                            requires_human=True,
                        )
                    )
        return conflicts

    def memory_fact_conflict(self, memory: MemoryRecord, fact_key: str, fact_value: Any) -> list[Conflict]:
        if memory.key == fact_key and memory.value != fact_value:
            return [
                Conflict(
                    "memory_fact",
                    "Memory conflicts with verified fact",
                    {"key": fact_key, "memory_value": memory.value, "fact_value": fact_value},
                )
            ]
        return []

    def plan_resource_conflicts(self, steps: list[ActionStep]) -> list[Conflict]:
        writers: dict[str, str] = {}
        conflicts = []
        for step in steps:
            path = step.arguments.get("path")
            if not isinstance(path, str):
                continue
            if path in writers and writers[path] != step.step_id:
                conflicts.append(
                    Conflict(
                        "plan_resource",
                        f"Multiple steps write the same path '{path}'",
                        {"path": path, "first_step_id": writers[path], "second_step_id": step.step_id},
                        requires_human=True,
                    )
                )
            writers[path] = step.step_id
        return conflicts


class ConflictResolutionPolicy:
    """Small deterministic conflict policy for common runtime cases."""

    def resolve_memory_fact(self, memory: MemoryRecord, fact_value: Any) -> dict[str, Any]:
        return {
            "action": "prefer_fact",
            "key": memory.key,
            "old_confidence": memory.confidence,
            "new_confidence": max(0.0, memory.confidence - 0.2),
            "value": fact_value,
        }
