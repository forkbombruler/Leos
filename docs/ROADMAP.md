# Leos Roadmap

Leos is a bounded, auditable agent runtime. This roadmap describes engineering
stages, not a claim that the current runtime is production-ready.

## 1. Kernel Reliability

- Keep policy, approval, sandbox, audit, rollback, sanitizer, and replay paths
  deterministic and well tested.
- Expand safety evals for prompt injection, tool injection, secret leakage,
  workspace escape, SSRF, rollback failure, and audit tampering.
- Keep proof generation tied to source/test hashes and reproducible command
  output.

## 2. Software Engineering Agent

- Support safe local software-engineering loops through dev tools, GitHub REST
  dry-runs, trace output, and goal evaluation.
- Keep network and code execution opt-in, with high-risk actions gated by
  `PolicyEngine` and `ApprovalGate`.
- Use Docker/Podman sandboxing for stronger local execution boundaries where
  available, while treating subprocess execution as local-dev only.

## 3. Long-running Organization Agent

- Add production-grade persistence, secret storage, egress controls, operator
  approval UX, and broader red-team benchmarks.
- Move beyond local SQLite and in-memory vaults to deployment-managed databases
  and KMS/keychain-backed credentials.
- Add long-running task operations only after runtime safety evidence remains
  stable under adversarial evaluation.
