# Architecture Claims

| Claim | Code paths | Test paths | Proof evidence | Status |
|---|---|---|---|---|
| Workspace path escape is blocked | `src/leos_agent/dev_tools.py`, `src/leos_agent/tools.py` | `tests/test_dev_tools.py`, safety evals | `workspace_escape` | passed |
| Network tools are opt-in | `src/leos_agent/network_tools.py`, `src/leos_agent/transactions.py` | `tests/test_network_tools.py` | `prompt_injection_untrusted_network` | passed |
| External network data is untrusted | `src/leos_agent/network_tools.py` | `tests/test_network_tools.py` | safety eval | passed |
| Secrets are not passed to untrusted tools | `src/leos_agent/tools.py`, `src/leos_agent/transactions.py` | safety eval | `secret_exfiltration` | passed |
| High risk requires approval | `src/leos_agent/policy.py`, `src/leos_agent/transactions.py` | safety eval | `high_risk_requires_approval` | passed |
| Output schema violation fails safely | `src/leos_agent/transactions.py`, `src/leos_agent/tools.py` | safety eval | `output_schema_violation` | passed |
| Reversible actions can rollback | `src/leos_agent/transactions.py`, `src/leos_agent/dev_tools.py` | `tests/test_dev_tools.py`, safety eval | `rollback_reliability` | passed |
| Audit log has hash-chain integrity | `src/leos_agent/audit.py` | `tests/test_core.py`, `tests/test_replay.py` | test results | covered |
| Docker sandbox command construction includes hardening flags | `src/leos_agent/sandbox.py` | `tests/test_sandbox.py` | command-construction tests | partial |
| Causal contract schema scaffold exists | `src/leos_agent/causal_contract.py` | `tests/test_causal_contract.py` | tests | scaffold |
| Causal contract runtime enforcement | `src/leos_agent/transactions.py`, `src/leos_agent/causal.py` | `tests/test_causal_contract.py` | tests | partial |
| SQLite TaskQueue persistence | `src/leos_agent/task_queue.py` | `tests/test_task_queue_persistence.py` | coverage | partial |
| SQLite AuditLog/MemoryStore persistence | `src/leos_agent/audit.py`, `src/leos_agent/memory.py` | none | known limitations | not_complete |
