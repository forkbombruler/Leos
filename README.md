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
  -> Goal Evaluator
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
- Deterministic goal evaluation that checks explicit success criteria after action verification.
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

For development and audit checks:

```bash
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src
coverage run -m unittest discover -s tests
coverage report --fail-under=83
bandit -r src
leos eval --suite safety
python scripts/generate_proofs.py --output docs/proofs --allow-dirty
```

Run the demo:

```bash
leos-agent --auto-approve
```

Without `--auto-approve`, the file-writing action is denied because it lacks a write-file grant and requires explicit approval.

Run the local software-engineering loop demo:

```bash
python examples/software_engineering_agent/run_demo.py
```

The demo creates a temporary Python project, fixes a failing test through the
agent loop, writes an audit log, replays it, and renders a trace without using
network access or external APIs.

## Current capability matrix

| Capability | Status |
|---|---|
| Workspace-scoped read/list/patch/diff tools | implemented |
| Local test runner | opt-in, local-dev only |
| Network fetch/browser observations | opt-in, marked `UNTRUSTED_EXTERNAL` |
| URL SSRF checks | implemented regression guard |
| DNS-aware SSRF checks | opt-in resolver checks |
| Docker sandbox runner | opt-in Docker/Podman command runner |
| Agent loop | implemented minimal observe-plan-act-verify loop |
| Goal evaluation | deterministic success-criteria evaluator |
| Tool manifest registry | implemented |
| Evaluator registry | implemented |
| Runtime store | in-memory and JSONL development store |
| SQLite runtime store | stronger local persistence, not distributed production storage |
| Credential vault | in-memory SecretHandle abstraction |
| Secret sanitization | implemented for audit/store/trace/runtime boundaries |
| GitHub software-engineering tools | in-memory dry-run-first tool layer |
| GitHub REST client | implemented with fake-transport tests; real writes gated |
| GitHub issue-to-PR orchestration | AgentLoop dry-run path with fake REST transport |
| Local software engineering demo | implemented, no network/API token required |
| Safety benchmark fixtures | implemented for regression loading |
| Safety eval suite | implemented regression suite |
| Proof documents | generated audit aids, not formal proof |
| Causal contracts | partial runtime enforcement |
| Production autonomy | not ready |

High-risk tools are not enabled by default. Network tools and code execution
must be explicitly registered and policy-gated. The workspace subprocess sandbox
is not a production isolation boundary.
Docker/Podman sandboxing is opt-in and requires a local container runtime.
DNS-aware SSRF checks reduce domain-to-private-IP risk when enabled, but
production deployments still need egress firewall controls.

Run the GitHub REST dry-run demo:

```bash
python examples/github_rest_agent/run_dry_run.py
```

The demo uses `InMemoryGitHubClient` by default and performs no real GitHub
write. `GitHubRESTClient` is available for real API integration, but write
operations must still run through the tool layer, `PolicyEngine`,
`ApprovalGate`, and `TransactionManager`. GitHub tokens must be passed as
`Secret` values; plain string tokens are rejected by the tools. File updates
require `expected_sha` or `expected_previous`, PR creation supports a hidden
Leos idempotency marker, and protected branches such as `main` and `master` are
not deleted by cleanup logic.
Audit, trace rendering, runtime events, and checkpoints share a sanitization
boundary that rejects or redacts `Secret`, `SecretHandle`-unsafe payloads, and
common token-like strings. `InMemoryGitHubClient` keeps only token fingerprints
and counts for test evidence, never raw token strings.

Run the end-to-end GitHub issue orchestration demo:

```bash
python examples/github_rest_agent/run_orchestration.py
```

This demo uses `GitHubRESTClient` with an in-process fake transport and goes
through `AgentLoop -> PlanProposal -> TransactionManager -> GitHub tools`.
It first observes the issue and target file, then replans to create a branch,
update the file with `expected_previous`, and open an idempotent PR. It performs
no real GitHub write.

## Proof documents

Proof documents under `docs/proofs/` bind command results to source and test file
hashes. Dirty worktree proofs are marked `precommit_dirty` and are useful for
local review only. After committing, generate release-grade evidence with:

```bash
python scripts/generate_proofs.py --output docs/proofs --require-clean
```

Proof documents and safety evals are audit aids and regression evidence, not
formal verification or a complete external red-team assessment.

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
7. **Did the verified action actually satisfy the goal criteria?**
8. **Can we roll it back?**
9. **What should be audited for humans?**

Transaction verification and goal evaluation are intentionally separate.
Transaction verification checks whether an action produced its predicted effect.
`GoalEvaluator` checks whether the user's explicit success criteria are actually
satisfied, such as `tests_ok=True` for a "tests pass" goal.

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
