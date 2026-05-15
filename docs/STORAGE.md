# Storage

The runtime currently provides an in-memory `TaskQueue` with optional SQLite
persistence for task records and idempotency keys.

Implemented:

- task enqueue/reload
- idempotency key dedupe across queue instances
- claim, heartbeat, completion, retry, pause/resume, and watchdog timeout state

Not complete:

- SQLite-backed `AuditLog`
- SQLite-backed `MemoryStore`
- real concurrent worker stress testing

Use the in-memory backend for short-lived tests and the SQLite task queue for
local development scenarios that need task state to survive process restart.
