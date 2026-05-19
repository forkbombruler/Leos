# Threat Model — Leos Agent Runtime

Leos is a bounded, auditable agent runtime. It is not production-ready autonomous infrastructure and this document is not a formal proof.

## Assets
- Secrets and scoped secret references.
- Workspace files and generated patches.
- Audit logs, replay inputs, and proof documents.
- Policy manifests, capability grants, and approval records.
- User intent, task descriptions, and goal constraints.
- External service credentials, including GitHub tokens.

## Trust Boundaries
- LLM output is untrusted until schema validation and policy checks pass.
- Network and browser content is `UNTRUSTED_EXTERNAL` data, never instruction.
- Tool output is tool-reported until verified.
- Filesystem access must stay inside configured workspace roots.
- Subprocess execution is local-dev only unless a container or stronger sandbox is enforced.
- GitHub API data and writes cross an external-service boundary.
- GitHub REST responses are external observations; tokens are scoped `Secret`
  inputs and must not appear in audit, trace, stdout, or exceptions.
- Human approval is a separate gate and cannot be declared by a model or policy file.

## Threats
- Prompt injection: external text asks the agent to ignore policy or reveal secrets.
- Tool injection: tool output attempts to alter planner, policy, or system behavior.
- Secret exfiltration: secret values leak to audit, memory, model prompts, stdout, or tool output.
- Workspace escape: path traversal reads or writes outside the workspace.
- SSRF: network tools attempt localhost, private IPs, or metadata services.
- Policy bypass: policy-as-code or model output attempts to auto-approve actions.
- Rollback failure: a reversible or compensatable action cannot be restored.
- Audit tampering: records are deleted, edited, or reordered.
- Stale memory: old facts or preferences override current user intent.
- Confused deputy: an allowed tool is used to perform a broader action than intended.
- Duplicate external actions: retries create duplicate PRs, messages, or writes.
- GitHub overwrite/confused-deputy risk: a file update targets stale content or
  a cleanup path deletes a protected branch.

## Mitigations Already Implemented
- `PolicyEngine`, `ApprovalGate`, and `TransactionManager` gate all transaction execution.
- Tool schemas validate inputs and observed outputs.
- `Secret` values are denied for tools unless `secrets_allowed=True`.
- Audit logs use append-only hash-chain integrity checks.
- Workspace tools resolve and reject path escapes.
- Network safety policy blocks localhost, private ranges, metadata IPs, and non-HTTP(S) schemes.
- Safety evals cover workspace escape, prompt injection, secret exfiltration, policy bypass, rollback, SSRF, high-risk approval, and output schema violations.
- Docker sandbox command construction uses conservative defaults, but CI does not prove full runtime isolation.
- GitHub tools support idempotency and optimistic file update guards.
- `GitHubRESTClient` uses injectable transports for tests, redacts API errors,
  rejects protected branch deletion, and uses hidden PR idempotency markers.
- GitHub issue-to-PR orchestration uses the same `AgentLoop` and transaction
  path as local tools; the planner provider observes issue/file state before
  proposing write steps and never calls GitHub directly.

## Mitigations Still Missing
- Production-grade container or microVM isolation with integration tests against a real runtime.
- Deployment-level egress proxy and DNS rebinding defenses.
- Complete SQLite persistence for every runtime state component.
- Stronger secret scanning across every stdout/stderr/result path.
- Broader adversarial benchmark coverage for long-running software engineering tasks.
- Real GitHub token scope verification and deployment policy for production use.
- Live GitHub issue-to-PR runs still need deployment policy, least-privilege
  token issuance, and operator approval UX beyond the fake-transport demo.

## Security Invariants
- No high-risk or consequential action executes silently without policy/approval.
- No tool may read or write outside its workspace scope.
- Network and code execution remain opt-in.
- Policy-as-code cannot directly approve actions.
- Secrets must not be written to audit, memory, proof documents, or model prompts.
- GitHub tokens must enter tools as `Secret`; plain strings are rejected before
  network transport is called.
- GitHub file writes must provide `expected_sha` or `expected_previous`.
- GitHub PR creation should use idempotency keys for retry safety.
- Rollback failures must be visible in audit records.
- External observations cannot override system, developer, or policy constraints.

## Non-Goals
- Leos is not an AGI agent or unrestricted automation framework.
- Workspace subprocess execution is not a production sandbox.
- Safety evals and proof documents are audit aids, not mathematical verification.
- The current GitHub tools and REST client are a bounded software-engineering
  tool layer, not full GitHub API coverage or a GitHub App/OAuth system.
