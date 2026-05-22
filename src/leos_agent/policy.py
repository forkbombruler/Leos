"""Policy and approval gates."""

from __future__ import annotations

import json
import time as _time_module
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .approval import ApprovalDecision, ApprovalDecisionValue, ApprovalPacket, render_approval_packet_markdown
from .egress import EgressPolicy
from .enums import Decision, Permission, Reversibility, RiskLevel, SandboxPolicy, _risk_value
from .errors import PolicyConfigurationError
from .plans import ActionStep
from .tools import Tool


def _permissions(values: Iterable[Permission | str]) -> tuple[Permission, ...]:
    return tuple(Permission(value) for value in values)


@dataclass(frozen=True)
class PolicyRule:
    name: str
    when: Mapping[str, Any]
    decision: Decision

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", Decision(self.decision))
        if self.decision is Decision.APPROVED:
            raise PolicyConfigurationError("Policy-as-code rules cannot directly approve actions")
        if not self.when:
            raise PolicyConfigurationError(f"Policy rule {self.name} must define at least one condition")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> PolicyRule:
        if "name" not in data:
            raise PolicyConfigurationError("Policy rule is missing name")
        if "when" not in data:
            raise PolicyConfigurationError(f"Policy rule {data['name']} is missing when")
        if "decision" not in data:
            raise PolicyConfigurationError(f"Policy rule {data['name']} is missing decision")
        return cls(name=str(data["name"]), when=dict(data["when"]), decision=Decision(str(data["decision"])))

    def matches(self, step: ActionStep, *, profile_name: str) -> bool:
        for key, expected in self.when.items():
            if key == "profile":
                if profile_name != str(expected):
                    return False
                continue
            if key == "tool":
                if step.tool_name != str(expected):
                    return False
                continue
            if key == "permission":
                permissions = {Permission(value) for value in _as_list(expected)}
                if not permissions.intersection(set(step.required_permissions)):
                    return False
                continue
            if key == "risk_at_least":
                if _risk_value(step.risk) < _risk_value(RiskLevel(str(expected))):
                    return False
                continue
            if key == "reversibility":
                if step.reversibility is not Reversibility(str(expected)):
                    return False
                continue
            raise PolicyConfigurationError(f"Unsupported policy rule condition: {key}")
        return True


@dataclass(frozen=True)
class CapabilityGrant:
    """A per-user, per-tool capability grant.

    Restricts which permissions a principal has for specific tools.
    An empty `tools` sequence means the grant applies to all tools.
    """

    principal: str
    permissions: Sequence[Permission]
    tools: Sequence[str] = ()
    max_risk: RiskLevel | None = None
    deny_permissions: Sequence[Permission] = ()
    expires_at: float | None = None
    max_uses: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "permissions", _permissions(self.permissions))
        object.__setattr__(self, "deny_permissions", _permissions(self.deny_permissions))
        if self.max_risk is not None:
            object.__setattr__(self, "max_risk", RiskLevel(self.max_risk))
        object.__setattr__(self, "tools", tuple(self.tools))
        object.__setattr__(self, "_uses", 0)

    def applies_to(self, principal: str, tool_name: str, *, now: float | None = None) -> bool:
        if self.principal != principal:
            return False
        if self.tools and tool_name not in self.tools:
            return False
        if self.expires_at is not None and (_time_module.time() if now is None else now) > self.expires_at:
            return False
        return not (self.max_uses is not None and self._uses >= self.max_uses)  # type: ignore[attr-defined]

    def record_use(self) -> None:
        object.__setattr__(self, "_uses", self._uses + 1)  # type: ignore[attr-defined]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> CapabilityGrant:
        if "principal" not in data:
            raise PolicyConfigurationError("Capability grant is missing principal")
        return cls(
            principal=str(data["principal"]),
            permissions=tuple(data.get("permissions", ())),
            tools=tuple(data.get("tools", ())),
            max_risk=RiskLevel(str(data["max_risk"])) if data.get("max_risk") else None,
            deny_permissions=tuple(data.get("deny_permissions", ())),
        )


@dataclass(frozen=True)
class PolicyProfile:
    name: str
    granted_permissions: Sequence[Permission] = ()
    max_auto_risk: RiskLevel = RiskLevel.MEDIUM
    require_human_for: Sequence[Permission] = ()
    deny_permissions: Sequence[Permission] = ()
    rules: Sequence[PolicyRule] = ()
    grants: Sequence[CapabilityGrant] = ()
    require_strong_sandbox_for_execute: bool = False
    network_default_deny: bool = False
    require_causal_contract_for_medium_risk: bool = False
    require_timeout_for_medium_risk: bool = False
    require_output_schema_for_medium_risk: bool = False
    require_typed_goal_criteria: bool = False
    egress_policy: EgressPolicy | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "granted_permissions", _permissions(self.granted_permissions))
        object.__setattr__(self, "max_auto_risk", RiskLevel(self.max_auto_risk))
        object.__setattr__(self, "require_human_for", _permissions(self.require_human_for))
        object.__setattr__(self, "deny_permissions", _permissions(self.deny_permissions))
        object.__setattr__(
            self,
            "rules",
            tuple(rule if isinstance(rule, PolicyRule) else PolicyRule.from_mapping(rule) for rule in self.rules),
        )
        object.__setattr__(
            self,
            "grants",
            tuple(
                grant if isinstance(grant, CapabilityGrant) else CapabilityGrant.from_mapping(grant)
                for grant in self.grants
            ),
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> PolicyProfile:
        if "name" not in data:
            raise PolicyConfigurationError("Policy profile is missing name")
        return cls(
            name=str(data["name"]),
            granted_permissions=tuple(data.get("granted_permissions", ())),
            max_auto_risk=RiskLevel(str(data.get("max_auto_risk", RiskLevel.MEDIUM.value))),
            require_human_for=tuple(data.get("require_human_for", ())),
            deny_permissions=tuple(data.get("deny_permissions", ())),
            rules=tuple(PolicyRule.from_mapping(rule) for rule in data.get("rules", ())),
            grants=tuple(CapabilityGrant.from_mapping(grant) for grant in data.get("grants", ())),
            require_strong_sandbox_for_execute=bool(data.get("require_strong_sandbox_for_execute", False)),
            network_default_deny=bool(data.get("network_default_deny", False)),
            require_causal_contract_for_medium_risk=bool(data.get("require_causal_contract_for_medium_risk", False)),
            require_timeout_for_medium_risk=bool(data.get("require_timeout_for_medium_risk", False)),
            require_output_schema_for_medium_risk=bool(data.get("require_output_schema_for_medium_risk", False)),
            require_typed_goal_criteria=bool(data.get("require_typed_goal_criteria", False)),
            egress_policy=(
                EgressPolicy(
                    allowed_hosts=tuple(data["egress_policy"].get("allowed_hosts", ())),
                    allowed_methods=tuple(
                        data["egress_policy"].get("allowed_methods", ("GET", "POST", "PATCH", "PUT", "DELETE"))
                    ),
                    max_requests=data["egress_policy"].get("max_requests"),
                    dns_rebind_protection=bool(data["egress_policy"].get("dns_rebind_protection", True)),
                )
                if isinstance(data.get("egress_policy"), Mapping)
                else None
            ),
        )


BUILT_IN_POLICY_PROFILES = {
    "personal_safe": PolicyProfile(
        name="personal_safe",
        max_auto_risk=RiskLevel.LOW,
        require_human_for=(Permission.SEND_MESSAGE, Permission.FINANCIAL, Permission.DELETE, Permission.SYSTEM_CONFIG),
    ),
    "developer_local": PolicyProfile(
        name="developer_local",
        granted_permissions=(Permission.READ_FILES, Permission.WRITE_FILES, Permission.EXECUTE_CODE),
        max_auto_risk=RiskLevel.MEDIUM,
        deny_permissions=(Permission.NETWORK, Permission.FINANCIAL, Permission.DELETE, Permission.SYSTEM_CONFIG),
    ),
    "production": PolicyProfile(
        name="production",
        max_auto_risk=RiskLevel.LOW,
        require_human_for=(
            Permission.WRITE_FILES,
            Permission.SEND_MESSAGE,
            Permission.FINANCIAL,
            Permission.DELETE,
            Permission.EXECUTE_CODE,
            Permission.SYSTEM_CONFIG,
        ),
    ),
    "production_locked_down": PolicyProfile(
        name="production_locked_down",
        max_auto_risk=RiskLevel.LOW,
        require_human_for=(
            Permission.NETWORK,
            Permission.WRITE_FILES,
            Permission.SEND_MESSAGE,
            Permission.EXECUTE_CODE,
            Permission.READ_MEMORY,
            Permission.WRITE_MEMORY,
        ),
        deny_permissions=(Permission.FINANCIAL, Permission.DELETE, Permission.SYSTEM_CONFIG),
        require_strong_sandbox_for_execute=True,
        network_default_deny=True,
        require_causal_contract_for_medium_risk=True,
        require_timeout_for_medium_risk=True,
        require_output_schema_for_medium_risk=True,
        require_typed_goal_criteria=True,
    ),
}


class PolicyEngine:
    """Capability and risk policy.

    The default rule is conservative:
    - LOW actions can run automatically.
    - MEDIUM actions require explicit permission grant.
    - HIGH/CRITICAL actions require human approval.
    - Consequential compensatable/irreversible actions require human approval.
    """

    def __init__(
        self,
        granted_permissions: Iterable[Permission] | None = None,
        *,
        max_auto_risk: RiskLevel = RiskLevel.MEDIUM,
        require_human_for: Iterable[Permission] | None = None,
        deny_permissions: Iterable[Permission] | None = None,
        rules: Iterable[PolicyRule] | None = None,
        grants: Iterable[CapabilityGrant] | None = None,
        principal: str | None = None,
        profile_name: str = "custom",
        egress_policy: EgressPolicy | None = None,
    ) -> None:
        self.granted_permissions = set(granted_permissions or [])
        self.max_auto_risk = max_auto_risk
        self.require_human_for = set(require_human_for or [])
        self.deny_permissions = set(deny_permissions or [])
        self.rules = tuple(rules or ())
        self.grants = tuple(grants or ())
        self.principal = principal
        self.profile_name = profile_name
        self.egress_policy = egress_policy
        self.require_strong_sandbox_for_execute = False
        self.network_default_deny = False
        self.require_causal_contract_for_medium_risk = False
        self.require_timeout_for_medium_risk = False
        self.require_output_schema_for_medium_risk = False
        self.require_typed_goal_criteria = False

    @classmethod
    def from_profile(cls, profile: str | PolicyProfile, *, principal: str | None = None) -> PolicyEngine:
        if isinstance(profile, str):
            if profile not in BUILT_IN_POLICY_PROFILES:
                raise KeyError(f"Unknown policy profile: {profile}")
            profile = BUILT_IN_POLICY_PROFILES[profile]
        engine = cls(
            granted_permissions=profile.granted_permissions,
            max_auto_risk=profile.max_auto_risk,
            require_human_for=profile.require_human_for,
            deny_permissions=profile.deny_permissions,
            rules=profile.rules,
            grants=profile.grants,
            principal=principal,
            profile_name=profile.name,
        )
        engine.require_strong_sandbox_for_execute = profile.require_strong_sandbox_for_execute
        engine.network_default_deny = profile.network_default_deny
        engine.require_causal_contract_for_medium_risk = profile.require_causal_contract_for_medium_risk
        engine.require_timeout_for_medium_risk = profile.require_timeout_for_medium_risk
        engine.require_output_schema_for_medium_risk = profile.require_output_schema_for_medium_risk
        engine.require_typed_goal_criteria = profile.require_typed_goal_criteria
        engine.egress_policy = profile.egress_policy
        return engine

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, principal: str | None = None) -> PolicyEngine:
        return cls.from_profile(PolicyProfile.from_mapping(data), principal=principal)

    def assess(self, tool: Tool, arguments: Mapping[str, Any]) -> RiskLevel:
        risk = tool.spec.default_risk
        if any(
            permission in tool.spec.permissions
            for permission in [Permission.DELETE, Permission.FINANCIAL, Permission.SYSTEM_CONFIG]
        ):
            return RiskLevel.CRITICAL
        if arguments.get("destructive") is True:
            return RiskLevel.HIGH
        return risk

    def production_block_reason(self, step: ActionStep, tool: Tool) -> str | None:
        """Return a non-overridable production profile block reason."""

        if self.profile_name != "production_locked_down":
            return None
        if tool.spec.network_access or Permission.NETWORK in tool.spec.permissions:
            host = str(
                step.arguments.get("host") or step.arguments.get("hostname") or step.arguments.get("domain") or ""
            ) or (tool.spec.egress_host or "")
            methods = _egress_methods_for_step(step, tool)
            if self.egress_policy is None:
                return "production_locked_down forbids network tools without an explicit egress policy"
            if not host:
                return "production_locked_down egress policy does not allow GET <missing-host>"
            if not any(self.egress_policy.allows(host, method) for method in methods):
                target = host or "<missing-host>"
                methods_label = ",".join(method.upper() for method in methods)
                return f"production_locked_down egress policy does not allow {methods_label} {target}"
        if (
            self.require_strong_sandbox_for_execute
            and Permission.EXECUTE_CODE in tool.spec.permissions
            and tool.spec.sandbox_policy is SandboxPolicy.WORKSPACE
        ):
            return "production_locked_down forbids workspace subprocess execution as a production sandbox"
        if _risk_value(step.risk) >= _risk_value(RiskLevel.MEDIUM):
            if self.require_causal_contract_for_medium_risk and tool.spec.causal_contract is None:
                return "production_locked_down requires causal contracts for medium+ tools"
            if self.require_timeout_for_medium_risk and tool.spec.timeout_ms <= 0:
                return "production_locked_down requires timeout_ms for medium+ tools"
            if self.require_output_schema_for_medium_risk and not tool.spec.output_schema:
                return "production_locked_down requires output_schema for medium+ tools"
        return None

    def validate_goal(self, goal: Any) -> None:
        if (
            self.profile_name == "production_locked_down"
            and self.require_typed_goal_criteria
            and not getattr(goal, "criteria", ())
        ):
            from .errors import PolicyDenied

            raise PolicyDenied("production_locked_down requires at least one typed goal criterion")

    def _matching_grant(self, tool_name: str) -> CapabilityGrant | None:
        if not self.principal:
            return None
        for grant in self.grants:
            if grant.applies_to(self.principal, tool_name):
                return grant
        return None

    def decide(self, step: ActionStep) -> DecisionResult:
        configured_decision = self._decide_by_rules(step)
        if configured_decision is not None:
            rule = next((r for r in self.rules if r.matches(step, profile_name=self.profile_name)), None)
            return DecisionResult(
                configured_decision,
                f"matched rule '{rule.name}'" if rule else "matched policy rule",
                rule.name if rule else None,
            )
        required = set(step.required_permissions)
        if required & self.deny_permissions:
            return DecisionResult(Decision.DENIED, "permission denied by policy")

        grant = self._matching_grant(step.tool_name)
        if grant is not None:
            if required & set(grant.deny_permissions):
                return DecisionResult(Decision.DENIED, f"permission denied by grant for '{grant.principal}'")
            if required & self.require_human_for:
                return DecisionResult(Decision.NEEDS_HUMAN, "permission requires human approval")
            missing = required - set(grant.permissions)
            if missing:
                return DecisionResult(Decision.NEEDS_HUMAN, f"missing permissions: {[p.value for p in missing]}")
            max_risk = grant.max_risk if grant.max_risk is not None else self.max_auto_risk
            if _risk_value(step.risk) > _risk_value(max_risk):
                return DecisionResult(Decision.NEEDS_HUMAN, f"risk {step.risk.value} exceeds max {max_risk.value}")
            consequential = bool(step.required_permissions) or _risk_value(step.risk) >= _risk_value(RiskLevel.MEDIUM)
            if consequential and step.reversibility in {Reversibility.COMPENSATABLE, Reversibility.IRREVERSIBLE}:
                return DecisionResult(
                    Decision.NEEDS_HUMAN, f"consequential {step.reversibility.value} action requires human approval"
                )
            return DecisionResult(Decision.APPROVED, f"granted by '{grant.principal}'")

        if required & self.require_human_for:
            return DecisionResult(Decision.NEEDS_HUMAN, "permission requires human approval")
        missing = required - self.granted_permissions
        if missing:
            return DecisionResult(Decision.NEEDS_HUMAN, f"missing permissions: {[p.value for p in missing]}")
        if _risk_value(step.risk) > _risk_value(self.max_auto_risk):
            return DecisionResult(
                Decision.NEEDS_HUMAN, f"risk {step.risk.value} exceeds max {self.max_auto_risk.value}"
            )
        consequential = bool(step.required_permissions) or _risk_value(step.risk) >= _risk_value(RiskLevel.MEDIUM)
        if consequential and step.reversibility in {Reversibility.COMPENSATABLE, Reversibility.IRREVERSIBLE}:
            return DecisionResult(
                Decision.NEEDS_HUMAN, f"consequential {step.reversibility.value} action requires human approval"
            )
        return DecisionResult(Decision.APPROVED, "auto-approved")

    def _decide_by_rules(self, step: ActionStep) -> Decision | None:
        for rule in self.rules:
            if rule.matches(step, profile_name=self.profile_name):
                return rule.decision
        return None


class ApprovalGate:
    """Human-in-the-loop gate for risky steps."""

    def __init__(self, approver: Callable[[ActionStep], bool] | None = None) -> None:
        self.approver = approver

    def request(self, step: ActionStep) -> Decision:
        if not self.approver:
            return Decision.DENIED
        return Decision.APPROVED if self.approver(step) else Decision.DENIED

    def request_packet(self, packet: ApprovalPacket, step: ActionStep) -> ApprovalDecision:
        decision = self.request(step)
        return ApprovalDecision(
            approval_id=packet.approval_id,
            step_hash=packet.step_hash,
            decision=ApprovalDecisionValue.APPROVE if decision is Decision.APPROVED else ApprovalDecisionValue.DENY,
        )


@dataclass(frozen=True)
class ApprovalRequest:
    """Auditable, non-chain-of-thought approval summary for one step."""

    goal: str
    action: str
    impact: str
    risk: str
    reversibility: str
    evidence: list[str]
    alternatives: list[str]
    minimal_permissions: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal,
            "action": self.action,
            "impact": self.impact,
            "risk": self.risk,
            "reversibility": self.reversibility,
            "evidence": list(self.evidence),
            "alternatives": list(self.alternatives),
            "minimal_permissions": list(self.minimal_permissions),
        }


def build_approval_request(step: ActionStep, *, goal: str = "Execute requested step") -> ApprovalRequest:
    path = step.arguments.get("path")
    target = f" target={path}" if isinstance(path, str) else ""
    evidence = [step.reason]
    if step.preconditions:
        evidence.extend(f"precondition:{condition.variable}" for condition in step.preconditions)
    if step.idempotency_key:
        evidence.append(f"idempotency_key:{step.idempotency_key}")
    permissions = sorted({permission.value for permission in step.required_permissions})
    return ApprovalRequest(
        goal=goal,
        action=f"{step.tool_name}{target}",
        impact=_summarize_impact(step),
        risk=f"{step.risk.value}: {step.reason}",
        reversibility=(
            f"{step.reversibility.value}; compensation={step.compensation_strategy.value}; "
            f"rollback_reliability={step.rollback_reliability:.2f}"
        ),
        evidence=evidence,
        alternatives=["deny and leave state unchanged", "request a lower-risk or narrower step"],
        minimal_permissions=permissions,
    )


def _summarize_impact(step: ActionStep) -> str:
    if step.required_permissions:
        permissions = ", ".join(sorted(permission.value for permission in step.required_permissions))
        return f"requires permissions: {permissions}"
    if step.arguments:
        keys = ", ".join(sorted(str(key) for key in step.arguments))
        return f"uses arguments: {keys}"
    return "no external permission declared"


class InteractiveApprovalGate(ApprovalGate):
    """Interactive approval gate that prompts the user on the terminal.

    Displays the step details and waits for a [y/N] response.
    Falls back to DENIED if stdin is not a TTY or on timeout.
    """

    def __init__(self, timeout_seconds: float = 30.0) -> None:
        super().__init__(approver=None)
        self.timeout_seconds = timeout_seconds

    def request(self, step: ActionStep) -> Decision:
        import sys

        if not sys.stdout.isatty():
            return Decision.DENIED

        print("\n--- Approval Required ---")
        request = build_approval_request(step)
        print(f"Goal:       {request.goal}")
        print(f"Action:     {request.action}")
        print(f"Impact:     {request.impact}")
        print(f"Risk:       {request.risk}")
        print(f"Reversible: {request.reversibility}")
        print(f"Evidence:   {json.dumps(request.evidence, ensure_ascii=False)}")
        print(f"Alternates: {json.dumps(request.alternatives, ensure_ascii=False)}")
        print(f"Permissions:{json.dumps(request.minimal_permissions, ensure_ascii=False)}")
        if step.arguments:
            print(f"Arguments: {json.dumps({k: v for k, v in step.arguments.items()}, default=str)}")
        try:
            import select

            print(f"Approve? [y/N] (timeout {self.timeout_seconds:.0f}s): ", end="", flush=True)
            ready, _, _ = select.select([sys.stdin], [], [], self.timeout_seconds)
            if not ready:
                print("\n(timeout)")
                return Decision.DENIED
            response = sys.stdin.readline().strip().lower()
            if response in ("y", "yes"):
                return Decision.APPROVED
            return Decision.DENIED
        except Exception:  # noqa: BLE001
            return Decision.DENIED

    def request_packet(self, packet: ApprovalPacket, step: ActionStep) -> ApprovalDecision:
        import sys

        if not sys.stdout.isatty():
            return ApprovalDecision(packet.approval_id, packet.step_hash, ApprovalDecisionValue.DENY)

        print(render_approval_packet_markdown(packet))
        try:
            import select

            prompt = f"Approve packet? [y/N/dry-run/narrow] (timeout {self.timeout_seconds:.0f}s): "
            print(prompt, end="", flush=True)
            ready, _, _ = select.select([sys.stdin], [], [], self.timeout_seconds)
            if not ready:
                print("\n(timeout)")
                return ApprovalDecision(packet.approval_id, packet.step_hash, ApprovalDecisionValue.DENY)
            response = sys.stdin.readline().strip().lower()
        except Exception:  # noqa: BLE001
            return ApprovalDecision(packet.approval_id, packet.step_hash, ApprovalDecisionValue.DENY)

        if response in {"y", "yes"}:
            decision = ApprovalDecisionValue.APPROVE
        elif response in {"d", "dry-run", "dry_run", "dry_run_only"}:
            decision = ApprovalDecisionValue.DRY_RUN_ONLY
        elif response == "narrow":
            decision = ApprovalDecisionValue.NARROW_SCOPE
        else:
            decision = ApprovalDecisionValue.DENY
        return ApprovalDecision(packet.approval_id, packet.step_hash, decision)


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _egress_methods_for_step(step: ActionStep, tool: Tool) -> tuple[str, ...]:
    if step.arguments.get("method") is not None:
        return (str(step.arguments["method"]).upper(),)
    if tool.spec.egress_methods:
        return tuple(str(method).upper() for method in tool.spec.egress_methods)
    return ("GET",)


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reason: str
    rule_name: str | None = None


def validate_policy_config(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    issues = []
    try:
        PolicyProfile.from_mapping(data)
    except Exception as exc:  # noqa: BLE001 - validation should return structured issues
        issues.append({"reason": "policy_config_invalid", "message": str(exc)})
    return issues
