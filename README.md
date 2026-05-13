# Leos Agent

Leos is not a general autonomous agent. It is a safety-first runtime kernel for
bounded, auditable agent actions.

Leos Agent is a safety-first autonomous-agent kernel designed around the requirements discussed in the Hamming / Simon / Pearl / Engelbart / Brooks roundtable:

- **Hamming:** every action should be checked, logged, verified, and recoverable where possible.
- **Simon:** goals must include success criteria, constraints, and stop conditions so the agent can seek satisfactory solutions instead of looping forever.
- **Pearl:** actions need causal predictions before execution and verification after execution.
- **Engelbart:** the agent should augment humans through transparency, memory, and approval gates instead of hiding consequential decisions.
- **Brooks:** the system should be small, testable, modular, auditable, and explicitly engineered rather than a magical monolith.

This repository starts with a minimal Python runtime that can be extended with LLM planners, browser tools, code tools, messaging tools, or domain-specific workflows.

## Core architecture

```text
User Goal
  -> Goal Manager
  -> Planner
  -> Policy Engine
  -> Causal Model
  -> Approval Gate
  -> Tool Runtime
  -> Verifier
  -> Memory
  -> Audit Log
```

The initial implementation includes:

- Goal objects with success criteria, constraints, and stop conditions.
- Explicit world state split into verified facts and assumptions.
- A causal graph for action-effect predictions, counterfactual review, and post-action verification.
- A capability-based policy engine.
- Human approval gates for risky or under-authorized actions.
- Transactional plan execution with rollback support.
- JSON/JSONL memory and audit primitives.
- A sandboxed reversible file-write tool.
- Unit tests covering execution, blocking, verification, and workspace escape rejection.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m unittest discover -s tests
leos eval --suite safety
python scripts/generate_proofs.py
```

Run the demo:

```bash
leos-agent --auto-approve
```

Without `--auto-approve`, the file-writing action is denied because it lacks a write-file grant and requires explicit approval.

## Current Capability Matrix

| Area | Status |
| --- | --- |
| Policy / approval gates | Implemented |
| Audit hash-chain | Implemented |
| Rollback for reversible writes | Implemented |
| Dev agent workspace tools | Implemented, opt-in |
| Network/browser tools | Implemented, opt-in, default blocked |
| Code execution | Opt-in only |
| Docker sandbox | Initial command-construction runner |
| Safety evals | Implemented minimum suite |
| Proof documents | Generated under `docs/proofs/` |
| SQLite persistence | TaskQueue only |

## Dev Agent Example

```python
from pathlib import Path
from leos_agent import default_dev_registry

registry = default_dev_registry(Path("."), include_execute=False)
```

`include_execute=False` keeps `run_tests` out of the registry. Enabling it adds a high-risk `EXECUTE_CODE` tool that still goes through policy and approval.

## Safety And Proofs

```bash
leos eval --suite safety
leos trace --audit logs/latest.jsonl --format markdown
python scripts/generate_proofs.py
```

Proof documents record command, exit code, environment, git metadata, output excerpts, and known limitations. They are audit aids, not formal security proofs.

## Sandbox Threat Model

`WorkspaceSubprocessSandboxRunner` is for dev/test only and is not a production isolation boundary. High-risk command execution should use `DockerSandboxRunner` or a future microVM runner plus deployment-level network and secret controls.

## Production Readiness Checklist

- high-risk tools disabled by default
- network disabled by default
- code execution disabled by default
- external observations marked `UNTRUSTED_EXTERNAL`
- proof documents regenerated for release candidates
- Docker/microVM sandbox selected for production code execution
- egress proxy configured for network tools
- secret manager integrated; no raw secrets in memory or audit logs

## Why this is not just another chatbot wrapper

Most agent prototypes look like this:

```text
Prompt -> LLM -> Tool call -> Result -> Repeat
```

Leos Agent instead makes the action boundary explicit:

1. **What goal are we serving?**
2. **What state do we believe is true?**
3. **What causal effect do we predict?**
4. **What permission does this action require?**
5. **Can we dry-run it?**
6. **Can we verify it?**
7. **Can we roll it back?**
8. **What should be audited for humans?**

## Extension points

Add tools by implementing the `Tool` protocol:

```python
class MyTool:
    spec = ToolSpec(
        name="my_tool",
        description="Do a bounded action",
        permissions=(Permission.READ_FILES,),
        default_risk=RiskLevel.LOW,
        reversible=False,
    )

    def dry_run(self, arguments, state): ...
    def execute(self, arguments, state): ...
    def rollback(self, token, state): ...
```

Then register it:

```python
registry = ToolRegistry()
registry.register(MyTool())
```

## Roadmap

- Deterministic planner with candidate generation, risk/cost/benefit scoring, and satisficing selection.
- LLM planner adapter with deterministic plan schemas.
- Typed permission manifest per tool.
- Counterfactual review policy gates for high-impact actions.
- Persistent task queue and watchdog.
- Web/browser tool sandbox.
- ReAct-style trace viewer for human review.
- Policy profiles for personal, team, and production deployments.
