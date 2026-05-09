"""Backward-compatible public surface for the Leos agent runtime.

The runtime is split across focused modules. Importing from `leos_agent.core`
continues to work for existing callers.
"""

from __future__ import annotations

from .audit import AuditAnomalyDetector, AuditEvent, AuditLog
from .causal import (
    ActionConsequence,
    CausalEffect,
    CausalGraph,
    CausalHypothesis,
    CausalWorldModel,
    CounterfactualReport,
    CounterfactualReview,
    EffectPrediction,
)
from .enums import (
    CompensationStrategy,
    Decision,
    GoalStatus,
    Permission,
    Reversibility,
    RiskLevel,
    StepStatus,
    TaskStatus,
    _max_risk,
    _risk_value,
)
from .errors import (
    BudgetExceeded,
    DryRunFailed,
    IdempotencyConflict,
    InvalidGoalTransition,
    LeosError,
    LLMOutputValidationError,
    PolicyConfigurationError,
    PolicyDenied,
    PolicyError,
    PolicyIntegrityError,
    PostconditionFailed,
    PreconditionFailed,
    RollbackFailed,
    SandboxViolation,
    SchemaValidationFailed,
    SecretBoundaryViolation,
    SecretLeakedToUntrustedTool,
    SecurityError,
    StepFailureError,
    ToolTimeout,
    VerificationFailed,
    WorkspaceEscapeBlocked,
)
from .goals import Goal, ResourceBudget
from .kernel import AgentKernel
from .memory import MemoryRecord, MemorySensitivity, MemoryStore, MemoryType
from .manifest import PLAN_PROPOSAL_SCHEMA, ToolManifest, validate_json_schema
from .planner import LLMPlannerAdapter, Planner, validate_llm_proposals
from .plans import ActionStep, PlanCandidate, PlanProposal, PlanScore, PlannerConfig, PlannerResult, StateCondition, TransactionPlan
from .policy import ApprovalGate, BUILT_IN_POLICY_PROFILES, CapabilityGrant, PolicyEngine, PolicyProfile, PolicyRule, validate_policy_config
from .policy_manifest import SignedPolicyManifest, load_policy_from_file, manifest_to_json, sign_policy, verify_policy_manifest
from .replay import AuditReplayer, ReplayResult, replay_audit_log
from .state import TrustLevel, WorldState
from .task_queue import RetryPolicy, RuntimeTask, TaskQueue, TaskRunner, TimeoutPolicy, Watchdog
from .tools import EchoTool, SafeFileWriteTool, Secret, Tool, ToolRegistry, ToolResult, ToolSpec, default_registry
from .transactions import TransactionManager, _error_type

__all__ = [
    "ActionConsequence",
    "ActionStep",
    "AgentKernel",
    "ApprovalGate",
    "AuditEvent",
    "AuditLog",
    "AuditReplayer",
    "BUILT_IN_POLICY_PROFILES",
    "BudgetExceeded",
    "CapabilityGrant",
    "CausalEffect",
    "CausalGraph",
    "CausalHypothesis",
    "CausalWorldModel",
    "CompensationStrategy",
    "CounterfactualReport",
    "CounterfactualReview",
    "Decision",
    "DryRunFailed",
    "EchoTool",
    "EffectPrediction",
    "Goal",
    "GoalStatus",
    "IdempotencyConflict",
    "InvalidGoalTransition",
    "LeosError",
    "MemoryRecord",
    "MemorySensitivity",
    "MemoryStore",
    "MemoryType",
    "Permission",
    "PlanCandidate",
    "PlanProposal",
    "PlanScore",
    "Planner",
    "PlannerConfig",
    "PlannerResult",
    "PolicyConfigurationError",
    "PolicyDenied",
    "PolicyEngine",
    "PolicyIntegrityError",
    "PolicyProfile",
    "PolicyRule",
    "PostconditionFailed",
    "PreconditionFailed",
    "Reversibility",
    "RiskLevel",
    "ReplayResult",
    "ResourceBudget",
    "RetryPolicy",
    "RollbackFailed",
    "RuntimeTask",
    "SafeFileWriteTool",
    "SchemaValidationFailed",
    "Secret",
    "SecretBoundaryViolation",
    "Secret",
    "SecretLeakedToUntrustedTool",
    "SignedPolicyManifest",
    "StateCondition",
    "StepStatus",
    "TaskQueue",
    "TaskRunner",
    "TaskStatus",
    "Tool",
    "ToolManifest",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "ToolTimeout",
    "TransactionManager",
    "TransactionPlan",
    "TrustLevel",
    "TimeoutPolicy",
    "VerificationFailed",
    "WorkspaceEscapeBlocked",
    "WorldState",
    "Watchdog",
    "default_registry",
    "load_policy_from_file",
    "manifest_to_json",
    "replay_audit_log",
    "sign_policy",
    "validate_policy_config",
    "validate_json_schema",
    "verify_policy_manifest",
]
