# Sandboxing

Leos has three sandbox levels:

- `WorkspaceSubprocessSandboxRunner`: development and testing only. It scopes cwd to a workspace but is not an OS security boundary.
- `DockerSandboxRunner`: initial production-oriented container boundary. It constructs docker/podman argv with network disabled, dropped capabilities, no-new-privileges, resource limits, tmpfs `/tmp`, and a non-root user by default.
- `MicroVMSandboxRunner`: future target for high-risk workloads.

Docker runner defaults:

- image: `python:3.12-slim`
- workspace mount: resolved host path mounted to `/workspace`
- network: `--network none`
- capabilities: `--cap-drop ALL`
- security: `--security-opt no-new-privileges`
- memory/cpu/pids limits enabled
- root filesystem read-only

CI tests validate command construction with mocks and do not require Docker to be installed.
