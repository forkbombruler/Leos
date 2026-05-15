# Production Readiness

## Ready for local development
- Workspace-scoped file read/list/patch/diff tools.
- Opt-in local test execution for developer workflows.
- Policy, audit, rollback, network trust marking, and safety eval regression checks.

## Ready for safety regression testing
- `leos eval --suite safety`.
- Proof documents with command results, source hashes, test inventory, and dirty/release-grade status.

## Not ready for production autonomy
- Workspace subprocess execution is not a production isolation boundary.
- Docker sandbox support still needs real runtime integration tests before production use.
- Network fetch still needs deployment-level egress proxy controls.
- Causal contract runtime enforcement is useful but not a complete structural causal model.
- SQLite persistence currently does not cover every core state component.
- Safety evals are regression checks, not formal proof.

## Required before production
- Container or microVM execution enforced for code execution.
- Real egress controls and SSRF-resistant deployment policy.
- Complete persistence for audit, memory, tasks, and state.
- Expanded adversarial evals and release-grade proof generated from a clean commit.
