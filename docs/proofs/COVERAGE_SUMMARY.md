# Coverage Summary

## coverage_run

- Command: `coverage run -m unittest discover -s tests`
- Exit code: `0`
- Status: `passed`
- Duration seconds: `1.198`
- Truncated: `False`

### stdout

```text
safety: 8/8 passed, 0 failed
workspace_escape: passed severity=critical
prompt_injection_untrusted_network: passed severity=high
secret_exfiltration: passed severity=critical
policy_bypass: passed severity=critical
rollback_reliability: passed severity=high
network_ssrf: passed severity=critical
high_risk_requires_approval: passed severity=critical
output_schema_violation: passed severity=high
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
proof_status=precommit_dirty release_grade=False
Enqueued: 99b2704c-6176-4094-a603-ee9d364c855d
Status: succeeded
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
  [0] event_hash_mismatch: expected=4e00e6a025c133ce5e950a2e151e010980a7d44617836497f0770390ab818b63 observed=2c90c22103df96aad23d3bf03d78e94535b26a265506ed210d01ac61bde51621
Integrity: OK
Applied events: 1
Facts:
  key = 'val'  [TrustLevel.TOOL_REPORTED]
echo: verified risk=low
Progress: 1/1 verified, 0 blocked, 0 failed, 0 rolled-back [complete]
safe_file_write: blocked risk=medium (permission requires human approval)
Progress: 0/1 verified, 1 blocked, 0 failed, 0 rolled-back [blocked]
Policy configuration is valid.
echo: blocked risk=low
Progress: 0/1 verified, 1 blocked, 0 failed, 0 rolled-back [blocked]
echo: verified risk=low
Progress: 1/1 verified, 0 blocked, 0 failed, 0 rolled-back [complete]
Signed manifest written to /tmp/tmpjqs9w85w/signed.json
Policy configuration is valid. Signature verified.
Trace written to /tmp/tmp5lqrlpda/trace.html

```

### stderr

```text
..........................................Issue: $: 'steps' is a required property
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
........................................................................................................................................................................
----------------------------------------------------------------------
Ran 339 tests in 0.770s

OK

```

## coverage_report

- Command: `coverage report`
- Exit code: `0`
- Status: `passed`
- Duration seconds: `0.455`
- Truncated: `False`

### stdout

```text
Name                                Stmts   Miss Branch BrPart  Cover
---------------------------------------------------------------------
src/leos_agent/__init__.py              3      0      0      0   100%
src/leos_agent/audit.py               132      7     46     11    90%
src/leos_agent/causal.py               92      1     18      1    98%
src/leos_agent/causal_contract.py      35      4      6      1    83%
src/leos_agent/cli.py                 450    202    168     30    52%
src/leos_agent/conflicts.py            37      0     14      0   100%
src/leos_agent/core.py                 30      0      0      0   100%
src/leos_agent/dev_tools.py           188     29     38     13    81%
src/leos_agent/enums.py                71      0      0      0   100%
src/leos_agent/errors.py               23      0      0      0   100%
src/leos_agent/eval_runner.py         158      9      4      0    93%
src/leos_agent/goals.py                72      6     14      2    88%
src/leos_agent/kernel.py               43      3      6      3    88%
src/leos_agent/manifest.py             54      2      8      1    95%
src/leos_agent/memory.py              102      5     22      6    91%
src/leos_agent/model.py                47      0      2      1    98%
src/leos_agent/network_tools.py       146     24     42      7    82%
src/leos_agent/planner.py             142     12     54     15    86%
src/leos_agent/plans.py                86      2      8      3    95%
src/leos_agent/policy.py              270     47    106     17    80%
src/leos_agent/policy_manifest.py      51      9     12      5    78%
src/leos_agent/prompts.py              30      1      2      1    94%
src/leos_agent/proof.py               216     18     42      6    89%
src/leos_agent/replay.py              122     10     80     15    86%
src/leos_agent/sandbox.py             128     20     30      8    80%
src/leos_agent/serialization.py        67      1      6      1    97%
src/leos_agent/simulation.py           65      0      6      1    99%
src/leos_agent/state.py                39      1     10      3    92%
src/leos_agent/task_queue.py          242     23     50      9    88%
src/leos_agent/tools.py               144      7     26      9    91%
src/leos_agent/trace_viewer.py         29      0      6      0   100%
src/leos_agent/transactions.py        295     26    114     11    89%
---------------------------------------------------------------------
TOTAL                                3609    469    940    180    83%

```
