# Connected-app governance (`junction apps`)

> Junction is independent and not affiliated with or endorsed by Microsoft. Use of Microsoft services is governed by Microsoft's terms; the software is provided as is, without warranty or liability. See [DISCLAIMER.md](../DISCLAIMER.md).

`junction apps` answers one question for an Entra ID and Microsoft 365 tenant: **what is connected
to this tenant, and what can it do?** It lists every enterprise application and service principal,
every app registration (OAuth client), every application permission and delegated consent grant,
and who owns each one. Each app is flagged where the Graph data shows a real risk: over-broad
scopes, privileged apps nobody uses, unverified external publishers, guest owners and more. You can
compare the tenant with an approved baseline, export an evidence pack, and, as a separate and
human-approved step, revoke or restrict access.

Everything except `junction apps apply` is **read-only** and runs under Junction's read-only
policy, whatever policy the context uses. `apply` is CLI only, and every item it sends is approved
on the controlling terminal. Junction never revokes anything on its own. See
[APP-GOVERNANCE-SECURITY.md](APP-GOVERNANCE-SECURITY.md) for permissions, what is written and how
approvals work.

Scope is Entra ID and Microsoft 365. SharePoint, GitHub, Salesforce and other SaaS connectors are
not part of this.

## Quick start

1. Register a read-only app and grant the read permissions in
   [APP-GOVERNANCE-SECURITY.md](APP-GOVERNANCE-SECURITY.md#read-permissions). `junction apps
   permissions` prints the same list.
2. Add a cloud context for it (see [CHECKS-PERMISSIONS.md](CHECKS-PERMISSIONS.md#1-register-an-application)).
3. Run the inventory:

```sh
junction apps inventory --context contoso                       # table, most severe first
junction apps inventory --context contoso --flagged-only --min-severity high
junction apps inventory --context contoso --format json --output apps.json
junction apps inventory --context contoso --format html --output apps.html
junction apps inventory --context contoso --fail-on critical     # exit 1 in CI if anything is critical
```

The table hides Microsoft first-party apps that have no flags; add `--include-microsoft` to show
them. JSON always includes every app.

## What the inventory contains

For each service principal (`apps[]`):

| Field | Meaning |
|---|---|
| `service_principal_id`, `app_id`, `display_name`, `service_principal_type`, `enabled` | Identity and state of the enterprise application. |
| `owner_tenant` | `home` (registered here), `external` (another organisation), `microsoft` (first party) or `unknown` (for example managed identities). |
| `publisher` | `microsoft`, `verified` (with the publisher name) or `unverified`. |
| `sign_in_audience`, `assignment_required` | Who can sign in, and whether users must be assigned. |
| `credentials` | Secrets and certificates on the app registration and on the service principal: type, key id, name, end date, expired. **Never the value**, hint or key identifier. |
| `owners`, `owners_unread` | Owners of the app registration and of the service principal, with guests marked. `owners_unread` names a lookup that failed for this app. |
| `application_permissions` | App roles granted to the app (for example `Mail.Read` on Microsoft Graph), resolved to names for every resource, with the assignment id. |
| `delegated_grants` | Consent grants: `AllPrincipals` (admin consent for everyone) or `Principal` (one user), scopes, and whether the consenting user is a guest. |
| `last_sign_in`, `sign_in_data` | Last sign-in in any role, and whether it was `recorded`, `none_recorded` or `unavailable` (report not readable). |
| `risk` | Identity Protection workload identity risk level and state, where licensed. |
| `flags` | Risk flags with severity, summary and the evidence that triggered them. |

`registrations_without_service_principal[]` lists app registrations in this tenant that have no
service principal here (for example a multi-tenant app offered to other organisations), with their
owners and credential metadata. `gaps[]` lists any read that was refused, with the permission to
grant.

### Missing data is never a finding

If a read is refused, the inventory records the gap and does not evaluate the flags that need it:

- Service principals, app registrations, application permissions and delegated grants are required.
  If one is refused, the inventory fails and names the permission to grant.
- No sign-in data means `sign_in_data: "unavailable"`, never "unused".
- A failed owner lookup for one app is recorded against that app. Owners read for other apps, and
  guest owners read from the other lookup, are kept. `ownerless` needs that app's registration-owner
  lookup to have succeeded.
- An app is only called unused when its age is known (local creation date or earliest permission
  grant). External apps with neither are not flagged as unused.

## Risk flags

Permission impact comes from a reviewed file,
[`graph-permission-tiers.yaml`](../crates/junction-check/data/graph-permission-tiers.yaml), which gives
each permission a tier (`critical`, `high` or `medium`), a reason and, where one exists, a narrower
alternative. Permissions not in the file are `unclassified`, never assumed to be low. Microsoft
first-party apps are inventoried but never flagged as unused or for their publisher.

Thresholds go in a TOML file passed with `--config`:

```toml
[packs.governance]
unused_days = 90   # default
```

`junction apps flags` prints this table on the terminal.

<!-- generated:app-flags:start (junction check docs) -->
| Flag | Severity | Reads | Why it matters | Suggested fix |
|---|---|---|---|---|
| `critical_permission` | critical | Application permissions (app role assignments) and tenant-wide delegated grants, classified with data/graph-permission-tiers.yaml. | Critical permissions let the app take over the directory or roles, or read and change every mailbox, file or site, without a user present. | Remove the permission, or replace it with the narrower alternative shown, then confirm an owner and a business reason for anything that stays. |
| `high_permission` | high | Application permissions and tenant-wide delegated grants in the high tier. | High-impact permissions read every mailbox, file or chat, or change a broad class of objects. | Confirm the app needs it, scope it where the API allows (Exchange RBAC for Applications, Sites.Selected), or remove it. |
| `overbroad_scope` | medium | Each held permission against the `narrower` alternative recorded in the tier file. | A tenant-wide permission where a selected or read-only variant would do widens the damage if the app or its credential is compromised. | Move the app to the narrower permission shown, then remove the broad one. |
| `tenant_wide_delegated` | high | Delegated grants with consentType AllPrincipals and a high or critical scope. | Admin consent lets the app act as any user who signs in to it, up to that user's own rights, without each user agreeing. | Revoke the tenant-wide grant and require user assignment, or replace it with per-user consent for the people who need the app. |
| `privileged_no_recent_sign_in` | high | Service principal sign-in activity (Entra ID P1 or P2) for apps holding high or critical permissions. | A privileged app nobody uses is pure risk: its credentials and grants stay valid for an attacker while nobody notices activity. | Confirm with the owner whether it is still needed; if not, disable the service principal, then remove its grants. |
| `unused` | low | Service principal sign-in activity for enabled, non-Microsoft apps older than the unused period. | Unused apps accumulate grants and credentials that nobody reviews. | Disable apps that are no longer needed and remove their grants; delete them once the owner confirms. |
| `unverified_publisher_external` | high | Owning organisation, verifiedPublisher and held permissions. | Consent phishing uses unverified multi-tenant apps; high-impact permissions on one is a strong signal. | Confirm the vendor and the business need; if unknown, revoke its grants and disable it. |
| `guest_owned` | medium | Owners of the app registration and the service principal, and whether each is a guest. | An owner can add credentials and act as the app. Guests are outside the organisation's joiner and leaver process. | Replace guest owners with members of the organisation. |
| `guest_consented` | medium | Per-user delegated grants and whether the consenting user is a guest. | Guests consenting apps in the tenant bypass internal review and can expose tenant data to an outside app. | Review and revoke the guest's consent, and restrict user consent for guests. |
| `ownerless` | low | Owners of app registrations in this tenant. | Nobody is accountable for its credentials, permissions or retirement. | Assign at least two owners who are members of the organisation. |
| `credential_on_service_principal` | medium | passwordCredentials on the service principal (not the app registration). | These secrets do not appear on the app registration and are often missed in reviews; it is a known persistence technique. | Remove the secret from the service principal and use a certificate or federated credential on the app registration. |
| `expired_credentials_only` | low | Credential end dates on the app registration and service principal of apps in this tenant. | The app is probably dead, but its grants stay live and a new credential brings them straight back. | Confirm with the owner and disable or remove the app, or rotate the credential if it is still needed. |
| `risky_service_principal` | high | Risky service principals (Workload Identities Premium). | Microsoft has seen suspicious sign-ins or leaked credentials for the app. | Investigate the risk detections, rotate credentials, and disable the service principal if compromise is confirmed. |
<!-- generated:app-flags:end -->

## Baselines and drift

Save what you have reviewed and accepted, then check for changes later:

```sh
junction apps baseline save --context contoso --output contoso-baseline.json
junction apps diff --context contoso --baseline contoso-baseline.json             # Markdown
junction apps diff --context contoso --baseline contoso-baseline.json --format json
junction apps diff --context contoso --baseline contoso-baseline.json --fail-on-drift
```

A baseline records, per app: identity, publisher, audience, enabled state, owners, application
permissions and admin and per-user delegated scopes. It leaves out sign-in times, credential expiry,
risk and flags, so drift shows **access changes, not activity**. Drift lists added, removed and
changed apps. `--fail-on-drift` exits 1 when apps were added or gained permissions, scopes or
owners.

Apps are matched by service principal object id. An app deleted and re-created under the same name
shows as one removed and one added. The baseline file carries a SHA-256 of its content: an edited
file, or a baseline from another tenant, is refused. An inventory whose owners could not be read
cannot become a baseline.

## Evidence pack

```sh
junction apps export --context contoso --baseline contoso-baseline.json --output evidence/
```

The directory suits an assessment bundle, for example IRAP evidence for ISM controls on application
control and privileged access:

| File | Contents |
|---|---|
| `README.md` | Summary, flag counts, method, the permissions used, gaps and limits, drift summary. |
| `inventory.json` | The full inventory. |
| `apps.csv`, `permissions.csv`, `grants.csv`, `flags.csv` | Flat tables for spreadsheets. `permissions.csv` includes each permission's impact tier. |
| `drift.json`, `drift.md` | Drift against the baseline, when one is given. |
| `manifest.json` | SHA-256 and size of every file. |

CSV cells that start with `=`, `+`, `-` or `@` get a leading quote, so a hostile display name cannot
run as a spreadsheet formula. The pack is not signed; sign or archive it with your own tooling.
Results indicate alignment; they are not a formal IRAP assessment.

## Revoke or restrict (human approved)

Changes are two separate steps. Planning only reads; applying is the one write, and every item is
approved on the terminal.

```sh
# 1. Plan: read-only, writes a local file you can review.
junction apps plan --context contoso --app <service-principal-or-app-id> \
  --action narrow-delegated --action remove-app-role --output plan.json

# 2. Check it against the tenant without sending anything.
junction apps apply --context contoso-admin --plan plan.json --dry-run

# 3. Apply: each item is shown on the terminal and needs your confirmation.
junction apps apply --context contoso-admin --plan plan.json --policy operator-policy.toml
```

| Action | What it does | Rollback |
|---|---|---|
| `revoke-delegated` | Deletes the app's delegated consent grants. | Grant consent again. |
| `narrow-delegated` | Removes high and critical scopes from each grant and keeps the rest. A grant with nothing high impact is left alone. | Set the grant's scope back (the plan records the original). |
| `remove-app-role` | Removes application permissions (app role assignments). | Grant the permission again (the plan records the app role id). |
| `disable` | Sets `accountEnabled` to `false` on the service principal, so the app can no longer sign in. Grants stay in place. | Enable the enterprise application again. |

Each plan item records the exact operation and input, its risk class, why it was suggested (the
app's flags), a rollback note and the state it expects. `apply` refuses:

- any item whose target changed since the plan was made, or no longer exists;
- a plan for another tenant, or more than 24 hours old;
- any operation your `--policy` deny rules or tenant allow-list forbid. These are checked before the
  tenant is read and cannot be approved away.

A declined or failed item stops the run. Microsoft first-party apps are never planned. Use a
separate context, with the write permissions in
[APP-GOVERNANCE-SECURITY.md](APP-GOVERNANCE-SECURITY.md#write-permissions), for `apply`.

## MCP and HTTP

Agents can read the inventory, never change it:

- MCP tool `junction_apps_inventory` (`context`, `flagged_only`, `min_severity`)
- HTTP `GET /v1/apps/inventory` with the same query parameters

Both return exactly what `--format json` prints. They follow the same context rules as checks:
without `--allow-check-contexts`, agents can only read the host's own context. There is no plan,
apply or revoke tool or route.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done. |
| 1 | `--fail-on` severity reached, or `--fail-on-drift` and access widened. |
| 2 | Error: bad arguments, unreadable required data, invalid or refused plan or baseline, or a policy refusal. |
| 3 | `apply`: some items were refused, declined or failed. |
