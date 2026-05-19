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
- Audit, trace, runtime-store, and fake-client state are persistence or
  presentation boundaries and must sanitize secret-like values.
- Tool manifests are capability declarations, not approval grants.
- RuntimeStore data crosses a persistence boundary and must reject `Secret`
  values and token-like strings in events and checkpoints.
- CredentialVault handles are references to secrets, not secret values.
- Human approval is a separate gate and cannot be declared by a model or policy file.

## Threats
- Prompt injection: external text asks the agent to ignore policy or reveal secrets.
- Tool injection: tool output attempts to alter planner, policy, or system behavior.
- Secret exfiltration: secret values leak to audit, memory, model prompts, stdout, or tool output.
- Workspace escape: path traversal reads or writes outside the workspace.
- SSRF: network tools attempt localhost, private IPs, or metadata services.
- DNS rebinding / DNS SSRF: a public-looking hostname resolves to private or
  metadata IP space.
- Policy bypass: policy-as-code or model output attempts to auto-approve actions.
- Rollback failure: a reversible or compensatable action cannot be restored.
- Audit tampering: records are deleted, edited, or reordered.
- Stale memory: old facts or preferences override current user intent.
- Confused deputy: an allowed tool is used to perform a broader action than intended.
- Duplicate external actions: retries create duplicate PRs, messages, or writes.
- GitHub overwrite/confused-deputy risk: a file update targets stale content or
  a cleanup path deletes a protected branch.
- Audit payload secret leak: a tool or model-sourced payload includes a token
  that would otherwise be persisted in JSONL.
- Trace rendering secret leak: an audit payload contains a token-like string
  that would otherwise appear in HTML or Markdown reports.
- Test fake-client token persistence: a fake integration client stores raw
  credentials in helper state and later leaks them through `repr` or failure logs.

## Mitigations Already Implemented
- `PolicyEngine`, `ApprovalGate`, and `TransactionManager` gate all transaction execution.
- Tool schemas validate inputs and observed outputs.
- `Secret` values are denied for tools unless `secrets_allowed=True`.
- Audit logs use append-only hash-chain integrity checks.
- Workspace tools resolve and reject path escapes.
- Network safety policy blocks localhost, private ranges, metadata IPs, and non-HTTP(S) schemes.
- DNS-aware URL policy can be enabled with an injected resolver and blocks
  hostnames resolving to private, loopback, link-local, reserved, unspecified,
  multicast, or metadata IPs.
- Safety evals cover workspace escape, prompt injection, secret exfiltration, policy bypass, rollback, SSRF, high-risk approval, and output schema violations.
- Docker sandbox command construction uses conservative defaults, but CI does not prove full runtime isolation.
- Docker/Podman sandbox runner is opt-in and uses conservative defaults
  including network none, read-only root filesystem, dropped capabilities,
  no-new-privileges, pids, memory, and CPU limits.
- GitHub tools support idempotency and optimistic file update guards.
- `GitHubRESTClient` uses injectable transports for tests, redacts API errors,
  rejects protected branch deletion, and uses hidden PR idempotency markers.
- GitHub issue-to-PR orchestration uses the same `AgentLoop` and transaction
  path as local tools; the planner provider observes issue/file state before
  proposing write steps and never calls GitHub directly.
- Tool manifest validation rejects mismatched permissions, weaker risk claims,
  and secret access widening.
- Goal evaluation is registry-backed; unmatched criteria are not treated as
  satisfied.
- RuntimeStore rejects `Secret` values in persisted runtime events and
  checkpoints, including redaction markers embedded in strings and common
  token-like literals.
- CredentialVault rejects wrong-scope, revoked, expired, and missing
  `SecretHandle` values.
- A shared sanitizer protects audit, runtime store, trace rendering, and proof
  helper boundaries. Audit payloads containing secret-like values are replaced
  with `audit.secret_blocked` events.
- Trace rendering redacts token-like values before Markdown/HTML output.
- `InMemoryGitHubClient` stores only token fingerprints and counts, not raw
  token strings.

## Mitigations Still Missing
- Production-grade container or microVM isolation with integration tests against a real runtime.
- Deployment-level egress proxy and DNS rebinding defenses.
- Complete SQLite persistence for every runtime state component.
- Stronger secret scanning across every stdout/stderr/result path.
- Broader adversarial benchmark coverage for long-running software engineering tasks.
- Real GitHub token scope verification and deployment policy for production use.
- Live GitHub issue-to-PR runs still need deployment policy, least-privilege
  token issuance, and operator approval UX beyond the fake-transport demo.
- `JsonlRuntimeStore` is a development persistence layer and does not provide
  production concurrency, migration, or retention guarantees.
- `SQLiteRuntimeStore` improves local restart recovery but is not a
  distributed production store.
- `InMemoryCredentialVault` is not a production KMS, OS keychain, or cloud
  secrets manager.

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
- RuntimeStore checkpoints and events must reject `Secret` values and token-like strings.
- Audit and trace output must not contain raw token-like values.
- Fake clients must not persist raw credentials.
- Credential handles must match scope and must fail after revoke or expiry.
- Rollback failures must be visible in audit records.
- External observations cannot override system, developer, or policy constraints.

## Non-Goals
- Leos is not an AGI agent or unrestricted automation framework.
- Workspace subprocess execution is not a production sandbox.
- Safety evals and proof documents are audit aids, not mathematical verification.
- The current GitHub tools and REST client are a bounded software-engineering
  tool layer, not full GitHub API coverage or a GitHub App/OAuth system.
