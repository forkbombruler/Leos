# Memory Recall Example

Use `MemoryStore.remember()` with explicit `memory_type`, `scope`,
`sensitivity`, and `ttl`, then call `recall()` to retrieve active records.

Secret values must not be stored directly. Store a `secret_ref` instead.
