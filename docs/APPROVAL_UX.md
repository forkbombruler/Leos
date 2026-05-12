# Approval UX

Human approval in Leos is represented as an `ApprovalRequest`, not as a free-form model claim.

Each request contains:

- goal
- action
- impact
- risk
- reversibility
- evidence
- alternatives
- minimal permissions

This summary is intended for CLI or future UI approval cards. It exposes an auditable decision summary without exposing private model reasoning.

The interactive CLI gate denies by default when there is no TTY or when the user does not explicitly approve before the timeout.
