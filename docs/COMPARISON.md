# Why Leos Is Not LangChain, AutoGPT, Or CrewAI

Leos is not an orchestration convenience layer.

Leos is an action-safety kernel for bounded, auditable agent actions.

| Project type | Primary focus |
| --- | --- |
| General agent framework | Connect models and tools quickly |
| Workflow/orchestration layer | Compose chains, agents, tools, and callbacks |
| Leos Agent | Enforce action boundaries, permissions, verification, rollback, and audit |

## Positioning

Leos assumes tool calls can be consequential. Its core value is not making tool
calling easier; it is making tool calling safer to review, replay, constrain,
and recover.

## Consequences

- Tools declare permissions, schemas, risk, reversibility, and sandbox policy.
- Policy can block or require approval before execution.
- Dry-run, execution, verification, and rollback are separate phases.
- Audit logs are hash chained and replayable.
- Untrusted observations, model output, and tool output cannot override policy.
