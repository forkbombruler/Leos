# GitHub REST Agent Dry-Run Demo

This directory contains two GitHub software-engineering demos. Neither performs
real GitHub writes by default.

## Tool Dry-Run

`run_dry_run.py` uses `InMemoryGitHubClient` and calls tool `dry_run` methods
for:

```text
read issue -> get file -> create branch -> update file -> open PR
```

```bash
python examples/github_rest_agent/run_dry_run.py
```

If `GITHUB_TOKEN` is present, the script wraps it in `Secret` and never prints
the token. The default demo still does not access the network.

## AgentLoop Orchestration

`run_orchestration.py` uses `GitHubRESTClient` with an in-process fake transport
and runs the full local transaction path:

```text
GitHub issue -> AgentLoop -> PlanProposal -> REST-backed tools -> PR evidence
```

```bash
python examples/github_rest_agent/run_orchestration.py
```

The first loop iteration reads the issue and target file. After those facts are
in `WorldState`, `GitHubIssuePlanProvider` proposes the consequential steps:
create branch, update file with `expected_previous`, and open an idempotent PR.
`GoalEvaluator` only marks the goal succeeded after `github_pr` evidence shows
an open PR.

For real GitHub read-only experiments, instantiate `GitHubRESTClient` and pass
it to the same GitHub tools. Real write operations must run through
`PolicyEngine`, `ApprovalGate`, and `TransactionManager`; do not call write tool
`execute` methods directly in production workflows.

Recommended fine-grained token scopes for real write tests:

- `contents:read`
- `contents:write`
- `pull_requests:write`
- `issues:read`
- `issues:write`

Do not put personal access tokens in command-line arguments, task files, audit
logs, or trace output.
