# Test Results

## unit_tests

- Command: `python -m unittest discover -s tests`
- Exit code: `0`
- Status: `passed`
- Duration seconds: `2.0`
- Truncated: `False`

### stdout

```text
safety: 15/15 passed, 0 failed
workspace_escape: passed severity=critical
prompt_injection_untrusted_network: passed severity=high
secret_exfiltration: passed severity=critical
policy_bypass: passed severity=critical
rollback_reliability: passed severity=high
network_ssrf: passed severity=critical
high_risk_requires_approval: passed severity=critical
output_schema_violation: passed severity=high
prompt_injection_policy_override: passed severity=critical
prompt_injection_reveal_secret: <redacted> severity=critical
prompt_injection_grant_permission: passed severity=critical
network_ssrf_dns_private_ip: passed severity=critical
rollback_failure_manual_recovery: passed severity=high
container_without_runner_blocked: passed severity=critical
container_command_hardening: passed severity=high
Integrity: OK
Applied events: 1
Anomalies: none
Facts: 1 key(s)
[
  {
    "name": "echo",
    "version": "0.1.0",
    "permissions": [],
    "risk": "low",
    "reversibility": "irreversible",
    "input_schema": {},
    "output_schema": {},
    "timeout_ms": 3000,
    "network_access": false,
    "egress_host": null,
    "egress_methods": [],
    "filesystem_scope": "none",
    "secrets_allowed": false,
    "sandbox_policy": "none",
    "requires_human_for": [],
    "rollback_reliability": 1.0,
    "compensation_strategy": "none"
  },
  {
    "name": "safe_file_write",
    "version": "0.1.0",
    "permissions": [
      "write_files"
    ],
    "risk": "medium",
    "reversibility": "reversible",
    "input_schema": {
      "type": "object",
      "required": [
        "path",
        "content"
      ],
      "properties": {
        "path": {
          "type": "string"
        },
        "content": {
          "type": "string"
        },
        "file_written": {
          "type": "string"
        }
      },
      "additionalProperties": true
    },
    "output_schema": {
      "type": "object",
      "properties": {
        "file_written": {
          "type": "string"
        }
      },
      "additionalProperties": true
    },
    "timeout_ms": 3000,
    "network_access": false,
    "egress_host": null,
    "egress_methods": [],
    "filesystem_scope": "workspace",
    "secrets_allowed": false,
    "sandbox_policy": "workspace",
    "requires_human_for": [
      "outside_workspace"
    ],
    "rollback_reliability": 1.0,
    "compensation_strategy": "undo"
  }
]
Policy configuration is valid.
proof_status=release_grade release_grade=True
Enqueued: f89e92a3-8554-4a07-b6e8-48b052e5b82e
Status: failed
Task file is valid.
echo: verified risk=low
Progress: 1/1 verified, 0 blocked, 0 failed, 0 rolled-back [complete]
FAIL: Missing required argument: message
OK: Would echo: hi
echo                  risk=low       rev=irreversible  perm=none
  Return a message and record it in observed state.
safe_file_write       risk=medium    rev=reversible    perm=write_files
  Write a UTF-8 file inside the configured workspace root.
Integrity: FAIL (1 issue(s))
  [0] event_hash_mismatch: expected=6fc33fa75f6a06438d25de6b49a63825c38cc027502b3b80c4355f8ef1eacad6 observed=23aa31d73e260a9b618ff709f9d33438e0c3f8e7e9ca7bf6189c8d83bd573dca
Integrity: OK
Applied events: 1
Facts:
  key = 'val'  [TrustLevel.TOOL_REPORTED]
echo: verified risk=low
Progress: 1/1 verified, 0 blocked, 0 failed, 0 rolled-back [complete]
safe_file_write: blocked risk=medium (approval decision is deny)
Progress: 0/1 verified, 1 blocked, 0 failed, 0 rolled-back [blocked]
Policy configuration is valid.
echo: blocked risk=low
Progress: 0/1 verified, 1 blocked, 0 failed, 0 rolled-back [blocked]
echo: verified risk=low
Progress: 1/1 verified, 0 blocked, 0 failed, 0 rolled-back [complete]
Signed manifest written to /tmp/tmp2hv2q8o9/signed.json
Policy configuration is valid. Signature verified.
report.md: pattern=github-classic-token
<redacted> written to /tmp/tmpqg7nayu_/trace.html

```

### stderr

```text
................................................................................Issue: $: 'steps' is a required property
Issue: /goal: 'not_an_object' is not of type 'object'
.Unknown tool: nonexistent
..............................................................................Error: invalid --args JSON: Expecting value: line 1 column 1 (char 0)
...Error: unknown tool 'nonexistent'. Available: echo, safe_file_write
...Error: file not found: /tmp/nonexistent_replay_test.jsonl
...Error: invalid profile 'nonexistent_profile': 'Unknown policy profile: nonexistent_profile'
.Error: file not found: /tmp/nonexistent_run_test.json
..Error: invalid JSON: Expecting value: line 1 column 1 (char 0)
.Issue: policy_config_invalid: Policy-as-code rules cannot directly approve actions
.Error: file not found: /tmp/nonexistent_policy_test.json
....................................Signature verification failed: Policy signature verification failed — manifest may have been tampered
...........................................................................................................................................................................................................................................................................................................................................................................................................................
----------------------------------------------------------------------
Ran 620 tests in 1.732s

OK

```
