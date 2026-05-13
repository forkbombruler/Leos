# Storage

Leos currently supports in-memory and JSONL/JSON file stores plus SQLite-backed `TaskQueue`.

Use in-memory stores for tests and short-lived demos. Use SQLite `TaskQueue(path=...)` for local long-running task persistence.

Known gaps:

- SQLite `AuditLog` is not implemented yet.
- SQLite `MemoryStore` is not implemented yet.
- TaskQueue SQLite concurrency is basic and should receive stronger multi-worker stress tests before production use.

Secrets must never be stored as memory values. Store secret references only.
