# Causal Contracts

Causal contracts are tool-level declarations of expected action consequences.
They complement JSON schemas: schemas validate shape, while causal contracts
describe expected state effects and required observations.

The built-in `safe_file_write` contract declares:

```yaml
tool_name: safe_file_write
sets:
  - file_written
may_change:
  - disk_usage
side_effects:
  - filesystem_modified
rollback_effects:
  - restores_previous_file_content
required_observations:
  - file_written
without_action:
  file_written: target_file_unchanged
confidence: 0.9
```

Runtime behavior:

- `CausalGraph.predict_for_tool(step, state, tool=tool)` uses
  `tool.spec.causal_contract` when present.
- Legacy `CausalHypothesis` prediction remains supported for older tools.
- `TransactionManager` checks contract `required_observations` after execution.
- Missing required observations fail the step, create an audit event, and trigger
  rollback when a rollback token is available.

This is partial runtime enforcement, not a full structural causal model.
