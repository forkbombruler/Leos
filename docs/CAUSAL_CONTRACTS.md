# Causal Contracts

Causal contracts are tool-level metadata describing expected action consequences. They complement JSON Schema: schemas validate shapes, while causal contracts describe state effects and verification requirements.

```yaml
tool_name: safe_file_write
sets: [file_written]
may_change: [disk_usage]
side_effects: [filesystem_modified]
rollback_effects: [restores_previous_file_content]
required_observations: [file_written]
without_action: target_file_unchanged
confidence: 0.9
```

Current status:

- `CausalContract` can generate `ActionConsequence` predictions.
- `safe_file_write_causal_contract()` provides the built-in example contract.
- Existing `CausalGraph` and `CausalHypothesis` APIs remain compatible.

Future work includes automatic `ToolSpec.causal_contract` prediction generation and policy profile enforcement for medium+ risk tools.
