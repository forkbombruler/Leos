# Leos Agent Architecture

## Design target

Leos Agent is designed for reliable autonomy rather than maximal apparent capability. The intended direction is a narrow-domain, auditable agent runtime that can be trusted with bounded tasks before it is expanded toward broader autonomy.

## Seven required subsystems

### 1. Goal system

A goal must declare:

- description
- success criteria
- constraints
- stop conditions
- priority

This forces the agent to reason under bounded rationality: it can decide when a result is good enough and when to stop.

### 2. World model

The world state separates:

- verified facts
- assumptions
- uncertainty estimates

This prevents the agent from treating guesses as ground truth.

### 3. Causal model

Before action, each step receives action-consequence predictions such as:

```text
safe_file_write -> file_written should become /workspace/file.txt
no safe_file_write -> file_written should remain unchanged
```

Counterfactual review compares the action path with the no-action path before execution. After execution, observed state deltas are compared against predicted consequences. Missing or mismatched observations fail verification.

Current implementation supports both legacy `CausalHypothesis` predictions and
tool-level causal contracts. Contract enforcement is partial runtime support:
required observations are checked and missing observations trigger rollback, but
this is not a complete structural causal model.

### 4. Planning and search

The current implementation includes a deterministic planner that accepts explicit `PlanProposal` candidates, scores each candidate by risk, cost, and benefit, and selects the first satisfactory plan. The intended next layer is an LLM planner adapter that must output the same typed proposal schema rather than free-form text. The runtime should remain independent from any one model vendor.

### 5. Tool/action system

Each tool declares:

- name
- description
- permissions
- default risk
- reversibility
- sandbox policy
- filesystem/network scope
- optional causal contract

Each tool must support:

- `dry_run`
- `execute`
- `rollback`

Developer tools are available through `default_dev_registry()`. High-risk tools such as test execution and network fetch are opt-in and remain subject to policy and approval.

### 6. Memory and learning

Memory records contain:

- key
- value
- confidence
- provenance
- timestamp

This creates a basis for learning while preserving traceability.

### 7. Audit and human collaboration

Every consequential step emits an audit event. Risky or under-authorized actions require approval. This supports Engelbart-style augmentation: the agent helps humans reason about work rather than silently replacing human judgment.

## Transaction protocol

```text
for each step:
  resolve tool
  assign permissions and risk
  predict causal effects
  review action consequences against no-action counterfactuals
  ask policy engine
  request human approval if needed
  dry run
  execute
  update observed world state
  verify causal predictions
  continue or rollback
```

## Safety invariants

1. Unknown tools cannot execute.
2. Missing permissions block execution unless approved by a human gate.
3. High and critical risk actions require approval by default.
4. File writes are constrained to a workspace root.
5. Dry-run failure prevents execution.
6. Verification failure triggers rollback for reversible prior actions.
7. Audit events are append-only.

## Production hardening checklist

- Replace in-memory policy with signed policy manifests.
- Add per-user and per-tool capability grants.
- Add secure secret handling and never expose secrets to untrusted tools.
- Run high-risk tools in containers or microVMs.
- Generate proof documents before release review.
- Run `leos eval --suite safety` for safety regressions.
- Use structured LLM outputs with JSON schema validation.
- Add anomaly detection over audit logs.
- Add replay tests for known failures.
- Add external red-team suites for prompt injection and tool injection.

## Current readiness boundaries

- Implemented: local dev tools, network trust boundaries, safety evals, proof generation, task queue persistence.
- Partial: causal contract runtime enforcement, Docker/podman command construction.
- Not complete: production autonomy, full SQLite persistence for all state, formal safety proof, deployment egress controls.
