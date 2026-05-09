# Threat Model — Leos Agent Runtime

## Prompt Injection
- **Attack**: Malicious text in tool output or world state treated as instruction.
- **Mitigation**: Untrusted observations are tagged `UNTRUSTED_EXTERNAL`. The LLM planner prompt labels untrusted observations as DATA, not instructions. Model cannot declare approval.
- **Tests**: `tests/redteam/test_prompt_injection.py`
- **Risk**: No runtime sandbox for LLM inference itself; mitigation is prompt-level only.

## Secret Exfiltration
- **Attack**: Secret value leaks through audit log, tool arguments, or memory.
- **Mitigation**: `Secret` wrapper class; `secrets_allowed=False` by default; `_redact_secrets()` for audit; `SecretBoundaryViolation` for memory.
- **Tests**: `tests/redteam/test_secret_boundary.py`
- **Risk**: Secrets in `ToolResult.data` not systematically scanned.

## Policy Manifest Tampering
- **Attack**: Maliciously modified policy file bypasses authorization.
- **Mitigation**: HMAC-SHA256 signed manifests (`policy_manifest.py`); `PolicyIntegrityError` on verification failure.
- **Tests**: `tests/test_core.py` SignedPolicyManifestTests

## Audit Log Tampering
- **Attack**: Attackers modify audit records to hide malicious activity.
- **Mitigation**: SHA-256 hash chain; `verify_event_records()` detects tampering; `verify_integrity=True` blocks replay.
- **Tests**: `tests/test_core.py`, `tests/test_properties.py`

## Workspace Escape
- **Attack**: `safe_file_write` writes outside workspace boundary.
- **Mitigation**: `os.path.commonpath` check in `SafeFileWriteTool._resolve()`; `SandboxPolicy.WORKSPACE` enforcement.
- **Tests**: `tests/redteam/test_workspace_escape.py`

## Approval Spoofing
- **Attack**: Model declares approval has been obtained, bypassing human gate.
- **Mitigation**: `PolicyRule` cannot directly approve; `ApprovalGate` is a separate code path; `InteractiveApprovalGate` requires TTY input.
- **Tests**: `tests/redteam/test_policy_bypass.py`

## Idempotency Failure
- **Attack**: Duplicate task execution causes double-spend or double-write.
- **Mitigation**: Two-level idempotency (task-level in `TaskQueue`, step-level in `TransactionManager`).
- **Tests**: `tests/test_core.py`, `tests/redteam/test_policy_bypass.py`

## Sandbox Escape
- **Attack**: High-risk tool executes outside sandbox constraints.
- **Mitigation**: `SandboxPolicy` enforcement; `CONTAINER`/`MICROVM` default to blocking; `WorkspaceSubprocessSandboxRunner` filesystem-only.
- **Tests**: `tests/test_sandbox.py`
- **Risk**: Workspace subprocess sandbox is not a production isolation boundary; no network/os-level isolation.

## Model Hallucination
- **Attack**: LLM generates tool names that don't exist or harmful arguments.
- **Mitigation**: `validate_llm_proposals()` rejects unknown tools; `PLAN_PROPOSAL_SCHEMA` validates structure; `minLength`/`minItems` constraints.
- **Tests**: `tests/test_llm_planner.py`, `tests/test_schema_validation.py`
