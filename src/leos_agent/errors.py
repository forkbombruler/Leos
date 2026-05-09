"""Typed runtime errors for Leos safety boundaries."""

from __future__ import annotations


class LeosError(Exception):
    """Base class for typed Leos runtime failures."""


# -- intermediate grouping layers -------------------------------------------


class StepFailureError(LeosError):
    """Step-level failures: a single action step could not complete safely."""


class PolicyError(LeosError):
    """Policy configuration or enforcement failures."""


class SecurityError(LeosError):
    """Security boundary violations."""


# -- step lifecycle errors -------------------------------------------------


class DryRunFailed(StepFailureError):
    """Raised or recorded when a dry-run check fails."""


class PreconditionFailed(StepFailureError):
    """Raised or recorded when a step precondition is not satisfied."""


class PostconditionFailed(StepFailureError):
    """Raised or recorded when a step postcondition is not satisfied."""


class VerificationFailed(StepFailureError):
    """Raised or recorded when post-action verification fails."""


class SchemaValidationFailed(StepFailureError):
    """Raised or recorded when structured input or output validation fails."""


class RollbackFailed(StepFailureError):
    """Raised or recorded when rollback cannot restore the prior state."""


class LLMOutputValidationError(StepFailureError):
    """Raised when an LLM-generated output fails JSON Schema validation."""


# -- policy errors ---------------------------------------------------------


class PolicyDenied(PolicyError):
    """Raised or recorded when policy blocks an action."""


class PolicyConfigurationError(PolicyError):
    """Raised when policy-as-code configuration is invalid or unsafe."""


class PolicyIntegrityError(PolicyError):
    """Raised when a signed policy manifest fails signature verification."""


# -- security errors -------------------------------------------------------


class SecretBoundaryViolation(SecurityError):
    """Raised when a secret value attempts to cross into memory or audit state."""


class SecretLeakedToUntrustedTool(SecurityError):
    """Raised when a Secret value is passed to a tool without secrets_allowed."""


class SandboxViolation(SecurityError):
    """Raised when a tool violates its sandbox policy."""


class WorkspaceEscapeBlocked(SecurityError):
    """Raised or recorded when a path escapes the configured workspace."""


# -- remaining direct LeosError children -----------------------------------


class ToolTimeout(LeosError):
    """Raised or recorded when a tool exceeds its execution budget."""


class BudgetExceeded(LeosError):
    """Raised or recorded when a goal or plan exceeds its resource budget."""


class IdempotencyConflict(LeosError):
    """Raised or recorded when an idempotency key was already consumed."""


class InvalidGoalTransition(LeosError):
    """Raised when a goal lifecycle transition is not allowed."""
