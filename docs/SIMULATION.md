# Simulation Environment

Leos includes a small deterministic simulation layer for agent-level safety tests before any real-world integration is used.

Current simulated services:

- `FakeFileSystem`
- `FakeBrowser`
- `FakeEmailServer`
- `FakeCalendar`
- `FakePaymentSystem`
- `FakeShell`
- `FakeGitHubRepo`

The fake browser marks fetched page content as `untrusted_external`, so tests can assert that prompt-injection text from pages remains an observation rather than a policy or system instruction.

The fake payment system requires an `idempotency_key` and deduplicates repeated calls with the same key. This gives CI a safe place to test repeated consequential actions without talking to external services.

This simulation layer is intentionally narrow. It is not a production sandbox; it is a stable target for red-team, benchmark, rollback, idempotency, and long-running task tests.
