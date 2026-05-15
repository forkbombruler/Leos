# Known Limitations

- Proof documents generated from a dirty worktree are not release-grade.
- Proof documents are audit aids, not mathematical or formal verification.
- Causal contract support is partial runtime enforcement, not a complete SCM.
- Docker sandbox command construction is not full isolation proof in CI.
- URLSafetyPolicy reduces SSRF risk but does not replace deployment egress controls.
- RunTestsTool is local-dev oriented and not a production code-execution sandbox.
- Workspace subprocess sandbox is not a production isolation boundary.
- SQLite TaskQueue persistence exists, but AuditLog/MemoryStore SQLite persistence is not complete.
- Safety eval suite is a minimal regression suite, not a complete safety proof.
