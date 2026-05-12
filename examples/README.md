# Examples

These examples are minimal JSON task files for the `leos run` and
`leos validate-task` commands.

Run validation:

```bash
leos validate-task examples/01_echo/task.json
```

Run a task:

```bash
leos run examples/01_echo/task.json --profile developer_local --auto-approve
```

Examples are intentionally small so they can be used in CI, docs, and manual
runtime smoke tests.
