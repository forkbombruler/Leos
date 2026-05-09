"""Transactional plan execution."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .audit import AuditLog
from .causal import CausalGraph, CounterfactualReview
from .enums import (
    Decision,
    GoalStatus,
    Permission,
    Reversibility,
    SandboxPolicy,
    StepStatus,
    _risk_value,
)
from .errors import (
    BudgetExceeded,
    DryRunFailed,
    IdempotencyConflict,
    LeosError,
    PolicyDenied,
    PostconditionFailed,
    PreconditionFailed,
    RollbackFailed,
    SandboxViolation,
    SchemaValidationFailed,
    SecretLeakedToUntrustedTool,
)
from .goals import GoalProgress, ResourceBudget
from .plans import ActionStep, StateCondition, TransactionPlan
from .policy import ApprovalGate, PolicyEngine
from .state import TrustLevel, WorldState
from .tools import (
    Secret,
    Tool,
    ToolRegistry,
    ToolResult,
    _contains_secrets,
    _redact_secrets,
)


def _error_type(error: LeosError | None) -> str | None:
    return type(error).__name__ if error else None


class TransactionManager:
    """Executes plan steps as reversible transactions where possible."""

    def __init__(
        self,
        registry: ToolRegistry,
        policy: PolicyEngine,
        causal_model: CausalGraph,
        audit_log: AuditLog,
        approval_gate: ApprovalGate | None = None,
        counterfactual_review: CounterfactualReview | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy
        self.causal_model = causal_model
        self.audit_log = audit_log
        self.approval_gate = approval_gate or ApprovalGate()
        self.counterfactual_review = counterfactual_review or CounterfactualReview(causal_model, audit_log)

    def execute_plan(self, plan: TransactionPlan, state: WorldState) -> TransactionPlan:
        self.audit_log.record(
            "plan.started", "Starting transaction plan", plan_id=plan.plan_id, goal=plan.goal.description
        )
        self._transition_plan_goal(plan, GoalStatus.RUNNING)
        rollback_stack: list[tuple[Tool, dict[str, Any], ActionStep]] = []
        budget = plan.budget or plan.goal.budget
        if self._budget_exceeded(plan, budget):
            self._transition_plan_goal(plan, self._final_goal_status(plan))
            self.audit_log.record(
                "plan.finished",
                "Finished transaction plan",
                plan_id=plan.plan_id,
                goal_status=plan.goal.status.value,
            )
            return plan

        for step in plan.steps:
            tool = self.registry.get(step.tool_name)
            self._hydrate_step_metadata(step, tool)

            sandbox_issue = self._enforce_sandbox(tool)
            if sandbox_issue:
                step.status = StepStatus.BLOCKED
                error: LeosError = SandboxViolation(sandbox_issue)
                self.audit_log.record(
                    "step.blocked",
                    "Step blocked by sandbox policy",
                    step_id=step.step_id,
                    tool=step.tool_name,
                    decision="denied",
                    error_type=type(error).__name__,
                    reason=sandbox_issue,
                )
                self._rollback(rollback_stack, state)
                break

            if _contains_secrets(step.arguments) and not tool.spec.secrets_allowed:
                step.status = StepStatus.BLOCKED
                error = SecretLeakedToUntrustedTool(f"Tool '{step.tool_name}' does not allow secrets")
                self.audit_log.record(
                    "step.blocked",
                    "Step blocked: secrets not allowed",
                    step_id=step.step_id,
                    tool=step.tool_name,
                    decision="denied",
                    error_type=type(error).__name__,
                )
                self._rollback(rollback_stack, state)
                break

            step.predictions = self.causal_model.predict(step, state)
            step.counterfactual_report = self.counterfactual_review.review(step, state, step.predictions)

            if self._idempotency_conflict(step, state):
                self._rollback(rollback_stack, state)
                break

            precondition_issues = self._check_conditions((*step.preconditions, *step.invariants), state)
            if precondition_issues:
                step.status = StepStatus.BLOCKED
                error = PreconditionFailed("Step preconditions failed")
                self.audit_log.record(
                    "step.precondition_failed",
                    "Step preconditions failed",
                    step_id=step.step_id,
                    tool=step.tool_name,
                    issues=precondition_issues,
                    error_type=type(error).__name__,
                )
                self._rollback(rollback_stack, state)
                break

            decision_result = self.policy.decide(step)
            decision = decision_result.decision
            if decision is Decision.NEEDS_HUMAN:
                decision = self.approval_gate.request(step)
            if decision is not Decision.APPROVED:
                step.status = StepStatus.BLOCKED
                error = PolicyDenied(f"Step blocked by policy: {decision.value}")
                self.audit_log.record(
                    "step.blocked",
                    "Step blocked by policy",
                    step_id=step.step_id,
                    tool=step.tool_name,
                    decision=decision.value,
                    reason=decision_result.reason,
                    rule_name=decision_result.rule_name,
                    reversibility=step.reversibility.value,
                    compensation_strategy=step.compensation_strategy.value,
                    error_type=type(error).__name__,
                )
                self._rollback(rollback_stack, state)
                break

            prepared_args = self._prepare_arguments(step.arguments, tool.spec.secrets_allowed)
            dry_run = tool.dry_run(prepared_args, state)
            if not dry_run.ok:
                step.status = StepStatus.FAILED
                error = dry_run.error or DryRunFailed(dry_run.message)
                self.audit_log.record(
                    "step.dry_run_failed",
                    dry_run.message,
                    step_id=step.step_id,
                    data=dry_run.data,
                    error_type=_error_type(error),
                )
                self._rollback(rollback_stack, state)
                break
            step.status = StepStatus.DRY_RUN_OK
            self.audit_log.record("step.dry_run_ok", dry_run.message, step_id=step.step_id, tool=step.tool_name)

            result = tool.execute(prepared_args, state)
            if not result.ok:
                step.status = StepStatus.FAILED
                self.audit_log.record(
                    "step.execution_failed",
                    result.message,
                    step_id=step.step_id,
                    data=result.data,
                    error_type=_error_type(result.error),
                )
                self._rollback(rollback_stack, state)
                break

            step.status = StepStatus.EXECUTED
            if result.rollback_token:
                rollback_stack.append((tool, dict(result.rollback_token), step))

            output_schema_issues = tool.spec.validate_output(result.observed_state_delta)
            if output_schema_issues:
                step.status = StepStatus.FAILED
                error = SchemaValidationFailed("Output schema validation failed")
                self.audit_log.record(
                    "step.output_schema_failed",
                    "Output schema validation failed",
                    step_id=step.step_id,
                    tool=step.tool_name,
                    data={"schema_issues": output_schema_issues},
                    error_type=type(error).__name__,
                )
                self._rollback(rollback_stack, state)
                break

            state.observe(result.observed_state_delta, trust_level=TrustLevel.TOOL_REPORTED)
            self.audit_log.record(
                "step.executed",
                result.message,
                step_id=step.step_id,
                observed=result.observed_state_delta,
                observed_trust=TrustLevel.TOOL_REPORTED.value,
            )

            verification = self.causal_model.verify(step.predictions, result)
            if not verification.ok:
                step.status = StepStatus.FAILED
                self.audit_log.record(
                    "step.verification_failed",
                    verification.message,
                    step_id=step.step_id,
                    data=verification.data,
                    error_type=_error_type(verification.error),
                )
                self._rollback(rollback_stack, state)
                break

            postcondition_issues = self._check_conditions((*step.postconditions, *step.invariants), state)
            if postcondition_issues:
                step.status = StepStatus.FAILED
                error = PostconditionFailed("Step postconditions failed")
                self.audit_log.record(
                    "step.postcondition_failed",
                    "Step postconditions failed",
                    step_id=step.step_id,
                    tool=step.tool_name,
                    issues=postcondition_issues,
                    error_type=type(error).__name__,
                )
                self._rollback(rollback_stack, state)
                break

            state.mark_trust(result.observed_state_delta.keys(), TrustLevel.VERIFIED)
            self._record_grant_use(step)
            self.audit_log.record(
                "state.trust_escalated",
                "Trust escalated for observed state keys",
                step_id=step.step_id,
                keys=list(result.observed_state_delta),
                from_trust=TrustLevel.TOOL_REPORTED.value,
                to_trust=TrustLevel.VERIFIED.value,
            )
            if step.idempotency_key:
                self._record_idempotency_key(step, state)
            step.status = StepStatus.VERIFIED
            self.audit_log.record(
                "step.verified",
                verification.message,
                step_id=step.step_id,
                verified=list(result.observed_state_delta),
                verified_trust=TrustLevel.VERIFIED.value,
            )

        self._transition_plan_goal(plan, self._final_goal_status(plan))
        self.audit_log.record(
            "plan.finished",
            "Finished transaction plan",
            plan_id=plan.plan_id,
            goal_status=plan.goal.status.value,
        )
        return plan

    def _transition_plan_goal(self, plan: TransactionPlan, status: GoalStatus) -> None:
        if plan.goal.status is status:
            return
        if plan.goal.status is GoalStatus.CREATED and status is GoalStatus.RUNNING:
            self._transition_plan_goal(plan, GoalStatus.PLANNING)
        previous = plan.goal.status
        plan.goal = plan.goal.transition(status)
        self.audit_log.record(
            "goal.status_changed",
            "Goal status changed",
            goal_id=plan.goal.goal_id,
            from_status=previous.value,
            to_status=plan.goal.status.value,
        )

    @staticmethod
    def _final_goal_status(plan: TransactionPlan) -> GoalStatus:
        if not plan.steps:
            return GoalStatus.SUCCEEDED
        verified = sum(1 for step in plan.steps if step.status is StepStatus.VERIFIED)
        if verified == len(plan.steps):
            return GoalStatus.SUCCEEDED
        if verified:
            return GoalStatus.PARTIALLY_DONE
        if any(step.status is StepStatus.BLOCKED for step in plan.steps):
            return GoalStatus.BLOCKED
        if any(step.status in {StepStatus.FAILED, StepStatus.ROLLED_BACK} for step in plan.steps):
            return GoalStatus.FAILED
        return GoalStatus.FAILED

    @staticmethod
    def _enforce_sandbox(tool: Tool) -> str | None:
        policy = tool.spec.sandbox_policy
        if policy is SandboxPolicy.CONTAINER:
            return "container sandbox not available — requires external container runtime"
        if policy is SandboxPolicy.MICROVM:
            return "microvm sandbox not available — requires external microvm runtime"
        if tool.spec.network_access:
            return "network access not allowed in default sandbox"
        if policy is SandboxPolicy.WORKSPACE and tool.spec.filesystem_scope == "none":
            return "workspace sandbox requires filesystem_scope"
        return None

    @staticmethod
    def _prepare_arguments(arguments: dict[str, Any], secrets_allowed: bool) -> dict[str, Any]:
        if secrets_allowed:
            return {k: v.unwrap() if isinstance(v, Secret) else v for k, v in arguments.items()}
        return _redact_secrets(arguments)

    def track_progress(self, plan: TransactionPlan) -> GoalProgress:
        progress = GoalProgress(total_steps=len(plan.steps))
        for step in plan.steps:
            if step.status is StepStatus.VERIFIED:
                progress.verified_steps += 1
            elif step.status is StepStatus.BLOCKED:
                progress.blocked_steps += 1
            elif step.status in {StepStatus.FAILED, StepStatus.ROLLED_BACK}:
                if step.status is StepStatus.ROLLED_BACK:
                    progress.rolled_back_steps += 1
                else:
                    progress.failed_steps += 1
        return progress

    def _record_grant_use(self, step: ActionStep) -> None:
        grant = self.policy._matching_grant(step.tool_name)
        if grant is not None:
            grant.record_use()

    def _hydrate_step_metadata(self, step: ActionStep, tool: Tool) -> None:
        step.required_permissions = tuple(tool.spec.permissions)
        step.risk = self.policy.assess(tool, step.arguments)
        step.reversibility = tool.spec.reversibility or Reversibility.IRREVERSIBLE
        step.compensation_strategy = tool.spec.compensation_strategy
        step.rollback_reliability = tool.spec.rollback_reliability

    def _budget_exceeded(self, plan: TransactionPlan, budget: ResourceBudget) -> bool:
        if budget.max_tool_calls is not None and len(plan.steps) > budget.max_tool_calls:
            step = plan.steps[min(budget.max_tool_calls, len(plan.steps) - 1)]
            self._record_budget_exceeded(
                step,
                "Plan exceeds maximum tool calls",
                limit="max_tool_calls",
                allowed=budget.max_tool_calls,
                actual=len(plan.steps),
            )
            return True

        file_writes = 0
        network_requests = 0
        for step in plan.steps:
            tool = self.registry.get(step.tool_name)
            self._hydrate_step_metadata(step, tool)

            if _risk_value(step.risk) > _risk_value(budget.max_risk_level):
                self._record_budget_exceeded(
                    step,
                    "Step exceeds maximum risk level",
                    limit="max_risk_level",
                    allowed=budget.max_risk_level.value,
                    actual=step.risk.value,
                )
                return True

            required = set(step.required_permissions)
            if Permission.WRITE_FILES in required:
                file_writes += 1
                if budget.max_file_writes is not None and file_writes > budget.max_file_writes:
                    self._record_budget_exceeded(
                        step,
                        "Plan exceeds maximum file writes",
                        limit="max_file_writes",
                        allowed=budget.max_file_writes,
                        actual=file_writes,
                    )
                    return True

            if Permission.NETWORK in required:
                network_requests += 1
                if budget.max_network_requests is not None and network_requests > budget.max_network_requests:
                    self._record_budget_exceeded(
                        step,
                        "Plan exceeds maximum network requests",
                        limit="max_network_requests",
                        allowed=budget.max_network_requests,
                        actual=network_requests,
                    )
                    return True

        if (
            hasattr(plan, "metrics")
            and budget.max_retries is not None
            and plan.metrics.retries_used > budget.max_retries
        ):
            if not plan.steps:
                return True
            self._record_budget_exceeded(
                plan.steps[0],
                "Plan exceeds maximum retries",
                limit="max_retries",
                allowed=budget.max_retries,
                actual=plan.metrics.retries_used,
            )
            return True

        self.audit_log.record(
            "budget.checked",
            "Resource budget accepted",
            plan_id=plan.plan_id,
            max_tool_calls=budget.max_tool_calls,
            max_file_writes=budget.max_file_writes,
            max_network_requests=budget.max_network_requests,
            max_risk_level=budget.max_risk_level.value,
        )
        return False

    def _record_budget_exceeded(self, step: ActionStep, message: str, **payload: Any) -> None:
        step.status = StepStatus.BLOCKED
        error = BudgetExceeded(message)
        self.audit_log.record(
            "budget.exceeded",
            message,
            step_id=step.step_id,
            tool=step.tool_name,
            error_type=type(error).__name__,
            **payload,
        )

    def _idempotency_conflict(self, step: ActionStep, state: WorldState) -> bool:
        if not step.idempotency_key:
            return False
        marker = self._idempotency_marker(step.idempotency_key)
        if marker not in state.facts:
            return False
        step.status = StepStatus.BLOCKED
        error = IdempotencyConflict("Step idempotency key was already consumed")
        self.audit_log.record(
            "step.idempotency_duplicate",
            "Step idempotency key was already consumed",
            step_id=step.step_id,
            tool=step.tool_name,
            idempotency_key=step.idempotency_key,
            previous=state.facts[marker],
            error_type=type(error).__name__,
        )
        return True

    def _record_idempotency_key(self, step: ActionStep, state: WorldState) -> None:
        marker = self._idempotency_marker(step.idempotency_key or "")
        record = {"step_id": step.step_id, "tool": step.tool_name}
        state.set_fact(marker, record, trust_level=TrustLevel.VERIFIED)
        self.audit_log.record(
            "step.idempotency_recorded",
            "Step idempotency key recorded",
            step_id=step.step_id,
            tool=step.tool_name,
            idempotency_key=step.idempotency_key,
        )

    @staticmethod
    def _idempotency_marker(idempotency_key: str) -> str:
        return f"idempotency:{idempotency_key}"

    def _check_conditions(self, conditions: Sequence[StateCondition], state: WorldState) -> list[dict[str, Any]]:
        issues = []
        for condition in conditions:
            present = condition.variable in state.facts
            actual = state.facts.get(condition.variable)
            if condition.operator == "exists" and not present:
                issues.append({**condition.describe(), "reason": "missing_fact"})
                continue
            if condition.operator == "not_exists" and present:
                issues.append({**condition.describe(), "reason": "unexpected_fact", "actual": actual})
                continue
            if condition.operator == "equals" and (not present or actual != condition.value):
                issues.append({**condition.describe(), "reason": "value_mismatch", "actual": actual})
                continue
            if condition.trust_level is not None and state.trust.get(condition.variable) != condition.trust_level:
                trust = state.trust.get(condition.variable)
                issues.append(
                    {
                        **condition.describe(),
                        "reason": "trust_mismatch",
                        "actual_trust": trust.value if trust else None,
                    }
                )
        return issues

    def _rollback(self, rollback_stack: list[tuple[Tool, dict[str, Any], ActionStep]], state: WorldState) -> None:
        rollback_succeeded = 0
        rollback_failed = 0
        while rollback_stack:
            tool, token, step = rollback_stack.pop()
            self.audit_log.record(
                "rollback_attempted", "Attempting rollback", step_id=step.step_id, tool=tool.spec.name
            )
            try:
                result = tool.rollback(token, state)
            except Exception as exc:  # noqa: BLE001 - rollback failures must become audit events
                result = ToolResult(False, f"Rollback raised: {exc}", error=RollbackFailed(str(exc)))
            step.status = StepStatus.ROLLED_BACK if result.ok else StepStatus.FAILED
            self.audit_log.record("step.rollback", result.message, step_id=step.step_id, ok=result.ok)
            if result.ok:
                rollback_succeeded += 1
                self.audit_log.record("rollback_succeeded", result.message, step_id=step.step_id, tool=tool.spec.name)
                continue

            rollback_failed += 1
            error = result.error or RollbackFailed(result.message)
            self.audit_log.record(
                "rollback_failed",
                result.message,
                step_id=step.step_id,
                tool=tool.spec.name,
                error_type=_error_type(error),
            )
            self.audit_log.record(
                "manual_recovery_required",
                "Rollback failed; manual recovery is required",
                step_id=step.step_id,
                tool=tool.spec.name,
                rollback_token=token,
                error_type=_error_type(error),
            )
        if rollback_failed and rollback_succeeded:
            self.audit_log.record(
                "rollback_partially_completed",
                "Some rollback steps succeeded and some failed",
                succeeded=rollback_succeeded,
                failed=rollback_failed,
            )
