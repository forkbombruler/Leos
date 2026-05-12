# Conflict Handling

Leos provides deterministic conflict helpers for common runtime cases:

- goal constraints that mention tools denied by policy
- memory records that disagree with newer verified facts
- plan steps that target the same resource path

The default memory conflict policy prefers the newer fact and lowers confidence in the conflicting memory record. This keeps current user instructions and verified observations above stale memory without silently deleting the older record.

Resource conflicts require human review because two steps writing the same path may be intentional, destructive, or order-dependent.

The helpers are deliberately small and testable. They create auditable conflict records but do not execute resolution automatically for high-impact cases.
