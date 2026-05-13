# Known Limitations

- Workspace subprocess sandbox is not a production isolation boundary.
- Docker sandbox support is initial and command-construction focused.
- Causal model is not a full structural causal model.
- LLM planner quality depends on the configured model.
- Network fetch requires deployment egress controls before production use.
- TaskQueue has SQLite persistence; AuditLog and MemoryStore SQLite backends remain future work.
- Safety eval suite is a minimum regression suite, not a formal proof.
