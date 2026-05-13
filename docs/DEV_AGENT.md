# Dev Agent Tools

Leos includes an opt-in local developer tool registry for workspace-scoped code maintenance.

Tools:

- `list_files`: recursively lists workspace files and excludes `.git`, `.venv`, `__pycache__`, build outputs, and bytecode.
- `read_file`: reads UTF-8 text files inside the workspace.
- `patch_file`: replaces a workspace text file and returns a rollback token.
- `git_diff`: returns `git diff` from the workspace.
- `run_tests`: runs an argv-only test command.

`default_dev_registry(workspace_root, include_execute=False)` registers read/write/diff tools but does not register `run_tests` unless `include_execute=True`.

Safety boundaries:

- all paths are resolved under the workspace root
- path escape returns `ToolResult(ok=False)`
- patch writes are reversible
- command execution is not shell-based
- `run_tests` is high risk and opt-in only
