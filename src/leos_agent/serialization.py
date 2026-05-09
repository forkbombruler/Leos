"""JSON serialization helpers for Leos domain objects.

Serializes Goal, ResourceBudget, TransactionPlan, ActionStep, StateCondition,
RetryPolicy, TimeoutPolicy, and RuntimeTask to/from JSON-compatible dicts.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .task_queue import RetryPolicy, TimeoutPolicy

from .enums import (
    GoalStatus,
    RiskLevel,
)
from .goals import Goal, ResourceBudget
from .plans import ActionStep, TransactionPlan


class SerializationError(ValueError):
    """Raised when an object cannot be serialized or deserialized."""


def _serialize_goal(goal: Goal) -> dict[str, Any]:
    return {
        "description": goal.description,
        "success_criteria": list(goal.success_criteria),
        "constraints": list(goal.constraints),
        "stop_conditions": list(goal.stop_conditions),
        "priority": goal.priority,
        "goal_id": goal.goal_id,
        "owner": goal.owner,
        "deadline": goal.deadline,
        "budget": _serialize_budget(goal.budget),
        "status": goal.status.value,
    }


def _deserialize_goal(data: dict[str, Any]) -> Goal:
    return Goal(
        description=data["description"],
        success_criteria=tuple(data.get("success_criteria", [])),
        constraints=tuple(data.get("constraints", [])),
        stop_conditions=tuple(data.get("stop_conditions", [])),
        priority=data.get("priority", 5),
        goal_id=data.get("goal_id", ""),
        owner=data.get("owner"),
        deadline=data.get("deadline"),
        budget=_deserialize_budget(data.get("budget", {})),
        status=GoalStatus(data["status"]),
    )


def _serialize_budget(budget: ResourceBudget) -> dict[str, Any]:
    return {
        "max_tokens": budget.max_tokens,
        "max_cost_usd": budget.max_cost_usd,
        "max_runtime_seconds": budget.max_runtime_seconds,
        "max_tool_calls": budget.max_tool_calls,
        "max_retries": budget.max_retries,
        "max_network_requests": budget.max_network_requests,
        "max_file_writes": budget.max_file_writes,
        "max_risk_level": budget.max_risk_level.value,
    }


def _deserialize_budget(data: dict[str, Any]) -> ResourceBudget:
    return ResourceBudget(
        max_tokens=data.get("max_tokens"),
        max_cost_usd=data.get("max_cost_usd"),
        max_runtime_seconds=data.get("max_runtime_seconds"),
        max_tool_calls=data.get("max_tool_calls"),
        max_retries=data.get("max_retries"),
        max_network_requests=data.get("max_network_requests"),
        max_file_writes=data.get("max_file_writes"),
        max_risk_level=RiskLevel(data.get("max_risk_level", RiskLevel.CRITICAL.value)),
    )


def _serialize_step(step: ActionStep) -> dict[str, Any]:
    return {
        "tool_name": step.tool_name,
        "arguments": step.arguments,
        "reason": step.reason,
        "status": step.status.value,
        "risk": step.risk.value,
        "reversibility": step.reversibility.value,
        "compensation_strategy": step.compensation_strategy.value,
        "rollback_reliability": step.rollback_reliability,
        "required_permissions": [p.value for p in step.required_permissions],
        "idempotency_key": step.idempotency_key,
        "step_id": step.step_id,
    }


def _deserialize_step(data: dict[str, Any]) -> ActionStep:
    return ActionStep(
        tool_name=data["tool_name"],
        arguments=dict(data.get("arguments", {})),
        reason=data.get("reason", ""),
        step_id=data.get("step_id", ""),
    )


def serialize_plan(plan: TransactionPlan) -> str:
    data = {
        "goal": _serialize_goal(plan.goal),
        "steps": [_serialize_step(s) for s in plan.steps],
        "plan_id": plan.plan_id,
        "budget": _serialize_budget(plan.budget) if plan.budget else None,
    }
    encoded = json.dumps(data, ensure_ascii=False, default=str)
    return encoded


def deserialize_plan(json_str: str) -> TransactionPlan:
    data = json.loads(json_str)
    goal = _deserialize_goal(data["goal"])
    steps = [_deserialize_step(s) for s in data.get("steps", [])]
    budget = _deserialize_budget(data["budget"]) if data.get("budget") else None
    return TransactionPlan(goal=goal, steps=steps, plan_id=data.get("plan_id", ""), budget=budget)


def serialize_retry_policy(policy: object) -> str:
    return json.dumps({"max_attempts": policy.max_attempts})  # type: ignore[attr-defined]


def deserialize_retry_policy(json_str: str) -> RetryPolicy:
    from .task_queue import RetryPolicy

    data = json.loads(json_str)
    return RetryPolicy(max_attempts=data["max_attempts"])


def serialize_timeout_policy(policy: object) -> str:
    return json.dumps(
        {
            "heartbeat_timeout_seconds": policy.heartbeat_timeout_seconds,  # type: ignore[attr-defined]
            "runtime_timeout_seconds": policy.runtime_timeout_seconds,  # type: ignore[attr-defined]
        }
    )


def deserialize_timeout_policy(json_str: str) -> TimeoutPolicy:
    from .task_queue import TimeoutPolicy

    data = json.loads(json_str)
    return TimeoutPolicy(
        heartbeat_timeout_seconds=data.get("heartbeat_timeout_seconds", 60.0),
        runtime_timeout_seconds=data.get("runtime_timeout_seconds"),
    )
