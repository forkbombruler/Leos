# Tool Manifests

Leos can validate and load JSON tool manifests with:

- `validate_tool_manifest(data)`
- `tool_manifest_from_mapping(data)`
- `load_tool_manifest_file(path)`

The manifest schema requires:

- name
- version
- permissions
- risk
- reversibility
- input_schema

Optional fields cover output schema, timeout, network access, filesystem scope, secret handling, sandbox policy, human approval triggers, rollback reliability, and compensation strategy.

Manifest loading creates metadata only. It does not dynamically import or execute plugin code, and it does not register tools in the runtime. Tool execution still requires an explicit trusted adapter and policy approval.
