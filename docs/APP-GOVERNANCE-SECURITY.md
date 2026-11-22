# Connected-app governance: permissions, writes and approvals

> Junction is independent and not affiliated with or endorsed by Microsoft. Use of Microsoft services is governed by Microsoft's terms; the software is provided as is, without warranty or liability. See [DISCLAIMER.md](../DISCLAIMER.md).

This page covers the security design of [`junction apps`](APP-GOVERNANCE.md): which Microsoft Graph
permissions it needs and why, application versus delegated access, what it writes and where, and
how approvals work. The permission tables below are generated from the code (`junction check
docs`), and a CI check fails if they drift.

## Principles

- **Read-only by default.** `inventory`, `flags`, `permissions`, `baseline`, `diff`, `export` and
  `plan` only read Microsoft Graph. They run under Junction's read-only policy whatever policy the
  context uses, so a mutation cannot be sent even by mistake.
- **One write path.** `junction apps apply` is the only command that changes the tenant. It is CLI
  only, and every item needs operator approval on the controlling terminal.
- **Least privilege, split by job.** Grant the read permissions to one identity and the write
  permissions, only when needed, to another.
- **Missing access is reported, not guessed.** A refused read becomes a recorded gap with the
  permission to grant, never a false "unused" or "ownerless".

## Read permissions

These are **application** permissions on Microsoft Graph, granted with admin consent to a dedicated
read-only app registration (see [CHECKS-PERMISSIONS.md](CHECKS-PERMISSIONS.md) for registration and
certificate set-up). `junction apps permissions` prints the same list.

<!-- generated:app-read-permissions:start (junction check docs) -->
| Permission | Type | Used for | Operations | If not granted |
|---|---|---|---|---|
| `Application.Read.All` | Microsoft Graph application | Service principals, app registrations, application permissions and owners | `graph.service_principals.list`, `graph.applications.list`, `graph.service_principals.app_role_assigned_to.list`, `graph.applications.owners.list`, `graph.service_principals.owners.list` | No inventory (service principals and registrations are required); owners recorded as not read |
| `AuditLog.Read.All` | Microsoft Graph application | Service principal sign-in activity (Entra ID P1 or P2) | `graph.reports.service_principal_sign_in_activities.list` | `sign_in_data` is `unavailable`; `unused` and `privileged_no_recent_sign_in` not evaluated |
| `DelegatedPermissionGrant.Read.All` | Microsoft Graph application | Admin and per-user delegated consent grants | `graph.oauth2permission_grants.list` | No inventory (grants are required) |
| `IdentityRiskyServicePrincipal.Read.All` | Microsoft Graph application | Workload identity risk (Workload Identities Premium) | `graph.identity_protection.risky_service_principals.list` | `risky_service_principal` not evaluated |
| `User.Read.All` | Microsoft Graph application | Which users are guests, for guest consent | `graph.users.list` | `guest_consented` not evaluated |
<!-- generated:app-read-permissions:end -->

`Application.Read.All` and `DelegatedPermissionGrant.Read.All` are enough for a useful inventory.
The other three add guest detection, sign-in recency and workload identity risk.

Nothing in this set can change the tenant, and none of it reads mail, files, chats or secret
values. Credential metadata (type, key id, name, dates) is read from the application and service
principal objects; secret values, hints and key identifiers are dropped and never stored.

### Application or delegated access

Application permissions are the recommended model. They give a complete, repeatable inventory, they
do not depend on a person's role assignments, and they work from a scheduled job.

Delegated access (`junction auth login` as a person) also works for reads, with Junction acting as
that user. The user then needs a directory role that can read applications and consent grants, such
as **Global Reader**, plus the same delegated scopes. Some reports, notably service principal
sign-in activity, may not be available to delegated callers; those reads become recorded gaps.
Prefer application access for evidence that an assessor will rely on.

## Write permissions

Only `junction apps apply` uses these. Grant them to a **separate** identity that is not used for
the inventory, ideally only when a change is planned:

<!-- generated:app-write-permissions:start (junction check docs) -->
| Operation | Method and path | Risk (after review) | Permission |
|---|---|---|---|
| `graph.oauth2permission_grants.delete` | `DELETE /oauth2PermissionGrants/{oAuth2PermissionGrant-id}` | destructive | `DelegatedPermissionGrant.ReadWrite.All` |
| `graph.oauth2permission_grants.update` | `PATCH /oauth2PermissionGrants/{oAuth2PermissionGrant-id}` | privileged | `DelegatedPermissionGrant.ReadWrite.All` |
| `graph.service_principals.app_role_assigned_to.delete` | `DELETE /servicePrincipals/{servicePrincipal-id}/appRoleAssignedTo/{appRoleAssignment-id}` | privileged | `AppRoleAssignment.ReadWrite.All` |
| `graph.service_principals.update` | `PATCH /servicePrincipals/{servicePrincipal-id}` | privileged | `Application.ReadWrite.All` |
<!-- generated:app-write-permissions:end -->

- `AppRoleAssignment.ReadWrite.All` can grant any app any permission, so it is as sensitive as a
  Global Administrator. Prefer delegated access by a person who activates **Cloud Application
  Administrator** through PIM for the change window, or a short-lived application credential that
  you remove afterwards.
- Grant only the permissions for the actions you plan. A missing permission makes that item fail
  with a 403 and stops the run; nothing else is affected.
- The write identity does not need any read permission beyond those above. `apply` re-reads the
  tenant with the same context before sending anything.

## What is written, and where

| Command | Writes to the tenant | Writes locally |
|---|---|---|
| `inventory` | Nothing | The report file with `--output` |
| `baseline save` | Nothing | The baseline file |
| `diff` | Nothing | The drift report with `--output` |
| `export` | Nothing | The evidence directory |
| `plan` | Nothing | The plan file |
| `apply --dry-run` | Nothing | Nothing (prints what would be sent) |
| `apply` | Only the approved items in the plan, using the operations above | Nothing (prints one outcome per item) |

Local files can hold tenant data: app names, ids, owner user principal names and permission
details, but never credential values. Store them like any other security evidence. Output files are
written atomically into place, and no tokens, request bodies or secrets are written to them.

## How approvals work

`apply` reuses Junction's existing approval machinery ([APPROVALS.md](APPROVALS.md)). For each item,
in order:

1. **Plan validation.** The plan file is parsed strictly. Each item's input must match its action
   exactly. A grant update may only set `scope`. A service principal update may only set
   `accountEnabled` to `false`. Anything else is refused before the tenant is contacted.
2. **Policy.** Apply runs under your `--policy` (or the default), with its deny rules, tenant
   allow-list and limits kept, upgraded to safe-write only so items qualify for approval. If a deny
   rule matches any operation in the plan, or the tenant is not allowed, apply stops before reading
   the tenant. A deny rule can never be approved away.
3. **Freshness.** The tenant is read again. Items whose target changed or no longer exists are
   refused. Plans for another tenant, or older than 24 hours, are refused as a whole.
4. **Terminal confirmation.** Each remaining item is shown on the controlling terminal: operation,
   risk, why, rollback, request, tenant, cloud, endpoint, audience, credential profile and the exact
   input. You retype the operation id and a fresh one-time code. The prompt reads from `/dev/tty`
   (`CONIN$` on Windows), never from stdin or arguments, so piped input cannot approve it.
5. **Single-use grant.** Only after confirmation is an approval grant issued. It is bound to that
   exact operation, input, tenant, endpoint, audience, credential profile and policy, lasts at most
   five minutes and is consumed by `Executor::execute_with_approval`, which re-checks every binding
   and the token before sending.
6. **Stop on decline or failure.** A declined or failed item ends the run, so you can review before
   anything else changes.

### Why every item needs approval

Writes run through a dedicated registry
([`apps-write.json`](../crates/junction-check/data/apps-write.json)) that holds only the four
operations above, so no policy can authorise any other write through this path. Upstream Graph
classifies the two PATCH operations as `write`, which a safe-write policy would allow without
approval. Narrowing a grant or disabling an app changes who can reach tenant data, so reviewed
overrides
([`apps-write-risk-overrides.toml`](../crates/junction-check/data/apps-write-risk-overrides.toml))
raise both to `privileged`. Every item therefore needs approval, even under a `full` policy. A test
enforces this.

### Agents cannot apply

MCP and HTTP expose only the read-only inventory (`junction_apps_inventory`, `GET
/v1/apps/inventory`). There is no plan, apply or revoke tool or route, and tests assert that. Durable
approvals (`junction approvals issue`) do not cover `apply`.

## Limits and threats

- **The operator terminal is the trust boundary.** A process that controls your pseudo-terminal can
  type into it. Do not run agents with access to the terminal where you approve changes (see
  [APPROVALS.md](APPROVALS.md)).
- **Plan files are untrusted input.** Anyone who can edit a plan can change what you are asked to
  approve. Apply re-validates every item and shows the exact input, but read the prompt, not the
  file name. Keep plans in a directory only you can write to.
- **Freshness is checked at the start.** Apply compares the plan with the tenant once, before the
  first item. A change made by someone else during the run is not detected item by item.
- **Revoking access is not a security investigation.** If an app is suspected compromised, also
  review its sign-in and audit logs and rotate any credentials it may have held.
- **Disabling keeps grants.** `disable` stops sign-in but leaves permissions in place, so enabling
  the app again restores its access. Remove grants as well when the app is retired.
