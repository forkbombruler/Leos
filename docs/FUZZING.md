# Fuzzing

Leos includes a dependency-free fuzz smoke check for parser and safety
boundaries.

## Run

```bash
make fuzz-smoke
```

The smoke check uses a fixed seed so failures are reproducible.

## Current Fuzz Targets

- Task JSON schema validation.
- Policy-as-code configuration validation.
- Workspace file path handling.
- Audit replay with malformed payloads.
- Goal input construction.

## Why This Shape

The first fuzzing layer should find crashes, schema bypasses, and accidental
acceptance of dangerous inputs without requiring external services or long CI
runtime. Broader property-based fuzzing can build on this by expanding the same
targets with Hypothesis strategies.
