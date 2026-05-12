# Contributing

Leos Agent is an action-safety runtime. Contributions should preserve the
security boundaries before expanding capability.

## Development Checks

Run the fast checks before opening a change:

```bash
make check
make mutation-smoke
make fuzz-smoke
PYTHONPATH=src:. python benchmarks/runner.py
```

## Safety Rules

- Do not weaken approval, policy, rollback, audit, workspace, sandbox, or secret
  boundaries without adding explicit tests.
- Do not expose raw secret values to logs, memory, browser contexts, model
  prompts, or untrusted tools.
- Prefer structured schemas over free-form parsing.
- Add a regression test for every safety bug.

## Pull Request Expectations

- Explain the risk boundary touched by the change.
- Include relevant unit, red-team, benchmark, mutation, or fuzz evidence.
- Keep unrelated refactors out of safety fixes.
