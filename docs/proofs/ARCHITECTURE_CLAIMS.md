# Architecture Claims

| Claim | Code path | Test path | Proof status |
|---|---|---|---|
| Workspace path escape is blocked | `src/leos_agent/dev_tools.py` | `tests/test_dev_tools.py` | covered by tests |
| High risk actions require approval | `src/leos_agent/policy.py` | `tests/evals` / safety eval | covered by eval |
| Secrets are not leaked to untrusted tools | `src/leos_agent/tools.py` | safety eval | covered by eval |
| Network observations are untrusted | `src/leos_agent/network_tools.py` | network tests | covered by tests |
| Audit logs have hash-chain integrity | `src/leos_agent/audit.py` | `tests/test_replay.py` | covered by tests |
