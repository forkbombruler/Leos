# Sandboxing

Leos currently supports multiple sandbox runner shapes:

- `WorkspaceSubprocessSandboxRunner`: development and test runner scoped to a
  workspace path. It is not a production isolation boundary.
- `DockerSandboxRunner`: initial Docker/podman command builder with hardening
  flags such as `--network none`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, memory/CPU/PID limits, read-only rootfs,
  and `/tmp` tmpfs.
- `MicroVMSandboxRunner`: future high-risk isolation target.

The Docker runner is unit-tested for command construction. CI does not prove full
container isolation because it may not have Docker or podman available.

High-risk code execution must remain opt-in and policy-gated.
