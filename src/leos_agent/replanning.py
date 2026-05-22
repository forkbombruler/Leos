"""Failure analysis and bounded replan context."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from .audit import AuditLog
from .enums import StepStatus
from .goals import Goal
from .plans import PlanProposal, TransactionPlan
from .state import WorldState
from .tools import ToolRegistry


class FailureType(str, Enum):
    POLICY_DENIED = "policy_denied"
    PRECONDITION_FAILED = "precondition_failed"
    DRY_RUN_FAILED = "dry_run_failed"
    EXECUTION_FAILED = "execution_failed"
    OUTPUT_SCHEMA_FAILED = "output_schema_failed"
    CAUSAL_CONTRACT_FAILED = "causal_contract_failed"
    POSTCONDITION_FAILED = "postcondition_failed"
    GOAL_EVALUATION_FAILED = "goal_evaluation_failed"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    NETWORK_BLOCKED = "network_blocked"
    TIMEOUT = "timeout"
    UNKNOWN_TOOL = "unknown_tool"
    APPROVAL_DENIED = "approval_denied"
    UNKNOWN = "unknown"


class PlanRepairStrategy(str, Enum):
    ASK_APPROVAL = "ask_approval"
    LOWER_RISK_ALTERNATIVE = "lower_risk_alternative"
    OBSERVE_STATE = "observe_state"
    REPAIR_ARGUMENTS = "repair_arguments"
    ROLLBACK_AND_REPLAN = "rollback_and_replan"
    DRY_RUN_ONLY = "dry_run_only"
    STOP = "stop"


@dataclass(frozen=True)
class FailureAnalysis:
    failure_type: FailureType
    root_cause: str
    retryable: bool
    suggested_strategy: str
    evidence: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ReplanContext:
    goal: Goal
    failed_plan: TransactionPlan
    analysis: FailureAnalysis
    replan_attempt: int


class FailureAwareProposalProvider(Protocol):
    def propose_repair(
        self,
        context: ReplanContext,
        goal: Goal,
        state: WorldState,
        registry: ToolRegistry,
    ) -> list[PlanProposal]: ...


class FailureAnalyzer:
    """Classify failed plans into conservative repair strategies."""

    def analyze(self, plan: TransactionPlan, audit_log: AuditLog) -> FailureAnalysis:
        events = list(audit_log.events)
        last = next((event for event in reversed(events) if _is_failure_event(event.event_type)), None)
        failed_step = next(
            (
                step
                for step in plan.steps
                if step.status in {StepStatus.BLOCKED, StepStatus.FAILED, StepStatus.ROLLED_BACK}
            ),
            None,
        )
        if failed_step is None:
            return FailureAnalysis(FailureType.UNKNOWN, "plan did not expose a failed step", False, "stop")
        event_type = last.event_type if last is not None else ""
        reason = str(last.payload.get("reason", "")) if last is not None else ""
        message = last.message if last is not None else failed_step.status.value
        failure_type = _classify(event_type, reason, message)
        retryable = failure_type in {
            FailureType.PRECONDITION_FAILED,
            FailureType.DRY_RUN_FAILED,
            FailureType.EXECUTION_FAILED,
            FailureType.OUTPUT_SCHEMA_FAILED,
            FailureType.CAUSAL_CONTRACT_FAILED,
            FailureType.GOAL_EVALUATION_FAILED,
            FailureType.TIMEOUT,
            FailureType.UNKNOWN_TOOL,
        }
        strategy = _strategy(failure_type)
        return FailureAnalysis(
            failure_type=failure_type,
            root_cause=message,
            retryable=retryable,
            suggested_strategy=strategy,
            evidence={"step_id": failed_step.step_id, "tool": failed_step.tool_name, "event_type": event_type},
        )


def _classify(event_type: str, reason: str, message: str) -> FailureType:
    text = f"{event_type} {reason} {message}".lower()
    if "approval.rejected" in event_type:
        return FailureType.APPROVAL_DENIED
    if "unknown tool" in text:
        return FailureType.UNKNOWN_TOOL
    if "sandbox" in text or "container sandbox not available" in text:
        return FailureType.SANDBOX_UNAVAILABLE
    if "network" in text or "egress" in text:
        return FailureType.NETWORK_BLOCKED
    if "causal_contract" in event_type or "verification" in event_type:
        return FailureType.CAUSAL_CONTRACT_FAILED
    if "output_schema" in event_type:
        return FailureType.OUTPUT_SCHEMA_FAILED
    if "precondition" in event_type:
        return FailureType.PRECONDITION_FAILED
    if "dry_run" in event_type:
        return FailureType.DRY_RUN_FAILED
    if "timeout" in text:
        return FailureType.TIMEOUT
    if "execution" in event_type:
        return FailureType.EXECUTION_FAILED
    if "postcondition" in event_type:
        return FailureType.POSTCONDITION_FAILED
    if "policy" in text or "permission" in text:
        return FailureType.POLICY_DENIED
    return FailureType.UNKNOWN


def _is_failure_event(event_type: str) -> bool:
    return (
        event_type
        in {
            "step.blocked",
            "step.precondition_failed",
            "step.dry_run_failed",
            "step.execution_failed",
            "step.output_schema_failed",
            "step.causal_contract_verification_failed",
            "step.postcondition_failed",
            "step.verification_failed",
            "approval.rejected",
            "policy.blocked",
            "causal_contract.missing",
            "budget.exceeded",
        }
        or "rollback_failed" in event_type
    )


def _strategy(failure_type: FailureType) -> str:
    return {
        FailureType.POLICY_DENIED: "ask approval, choose a lower-risk alternative, or stop",
        FailureType.PRECONDITION_FAILED: "observe missing state or run read-only inspection",
        FailureType.DRY_RUN_FAILED: "repair arguments or choose a safer tool",
        FailureType.EXECUTION_FAILED: "rollback if possible, inspect failure output, and retry within budget",
        FailureType.OUTPUT_SCHEMA_FAILED: "regenerate structured output and do not execute malformed output",
        FailureType.CAUSAL_CONTRACT_FAILED: "rollback, observe state, then replan only if safe",
        FailureType.POSTCONDITION_FAILED: "repair action or add missing verification",
        FailureType.GOAL_EVALUATION_FAILED: "add missing verification or repair previous action",
        FailureType.SANDBOX_UNAVAILABLE: "switch to dry-run-only or stop",
        FailureType.NETWORK_BLOCKED: "use cached/local information or stop",
        FailureType.TIMEOUT: "reduce scope or retry once if idempotent",
        FailureType.UNKNOWN_TOOL: "choose a registered tool",
        FailureType.APPROVAL_DENIED: "stop or ask for narrower approval",
        FailureType.UNKNOWN: "stop",
    }[failure_type]
