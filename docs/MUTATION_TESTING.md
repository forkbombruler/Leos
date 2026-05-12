# Mutation Testing

Leos uses a targeted mutation smoke check for safety-critical boundaries.

The goal is not to maximize a broad mutation score yet. The first goal is to
prove that tests fail when core safety logic is deliberately weakened.

## Run

```bash
make mutation-smoke
```

The script copies the repository to a temporary directory, applies one mutation
at a time, and runs the unit test suite against the mutated copy. The current
working tree is not modified.

## Current Targeted Mutations

- Approval gate inversion in transaction execution.
- Workspace escape check inversion in safe file writes.
- Audit hash mismatch checks being ignored.
- Policy-as-code direct approval being allowed.
- Secret boundary enforcement being disabled for untrusted tools.

Each mutation must be killed by tests. A surviving mutation means the related
safety boundary needs a stronger test before broad mutation testing is useful.

## Why This Shape

Full mutation testing across the entire runtime can be noisy and expensive.
This smoke check keeps the first pass focused on the boundaries that would be
dangerous if silently weakened: approval, workspace isolation, audit integrity,
policy hardening, and secret handling.
