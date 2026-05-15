# Leos Dev Agent Tools

The dev agent tools are local-development helpers for bounded repository work.
They are workspace-scoped and are not a production code-execution sandbox.

Implemented tools:

- `list_files`: recursively lists workspace files with default excludes for `.git`, `.venv`, `__pycache__`, build outputs, and bytecode.
- `read_file`: reads UTF-8 text files inside the workspace and rejects path escape.
- `patch_file`: performs full-file text replacement with dry-run validation and rollback token support.
- `git_diff`: returns `git diff` from the workspace using argv-only subprocess execution.
- `run_tests`: opt-in high-risk local test runner; it is not registered by default.

`RunTestsTool` uses a controlled environment allowlist: `PATH`, `PYTHONPATH`,
and `VIRTUAL_ENV`. It does not forward secret-like environment variables such as
`TOKEN`, `API_KEY`, `PASSWORD`, or `SECRET`.

Use `default_dev_registry(workspace_root, include_execute=False)` for the safe
default. Pass `include_execute=True` only when local code execution is explicitly
allowed by policy and approval gates.
