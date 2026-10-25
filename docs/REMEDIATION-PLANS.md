# Design note: suggest-only remediation plans (future)

Status: proposal for a later epic. Nothing here is implemented. `junction check` is read-only and its
remediation is text only (#27).

## Idea

A failing check could also emit the exact Junction operation and input that would fix it, collected
into a plan file an operator reviews and then runs with `junction batch --approve`. The plan is a
suggestion: Junction never applies it on its own.

```json
{
  "plan_version": 1,
  "source_run_id": "20261025t000000-...",
  "tenant_id": "00000000-0000-4000-8000-000000000001",
  "items": [
    {
      "check": "identity.legacy_auth_blocked",
      "operation": "graph.identity.conditional_access.policies.create",
      "input": {"body": {"displayName": "Block legacy authentication", "state": "enabledForReportingButNotEnforced"}},
      "why": "No Conditional Access policy blocks legacy client apps.",
      "risk": "privileged",
      "rollback": "Delete the created policy (graph.identity.conditional_access.policies.delete)."
    }
  ]
}
```

## Principles

- **Never automatic.** Plans are written to a file. Running one is a separate, explicit
  `junction batch --input-file plan.json --approve`, and every privileged or destructive item needs
  the existing terminal approval (see [APPROVALS.md](APPROVALS.md)). MCP and HTTP hosts cannot
  generate and run a plan in one step.
- **Report-only first.** Where Microsoft supports it (Conditional Access `enabledForReportingButNotEnforced`,
  ASR audit mode), the suggested change starts in report or audit mode.
- **Reviewable.** Each item names the check, the reason, the operation's risk class and a rollback.
- **Least privilege.** Generating a plan needs only the read permissions checks already use. Running
  it needs write permissions, granted separately and only for the operations in the plan.

## Open questions

- Which checks have a safe, generic fix (many depend on tenant design and should stay advice).
- How to bind a plan to the run that produced it so a stale plan is refused.
- Whether plans belong in `junction-check` or a separate crate with its own review.

Agree this note before any code is written.
