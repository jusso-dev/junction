# Junction archive security model

This document covers what `junction archive` can access, where it writes, how
records are protected and who can see them. Read it with
[ARCHIVE.md](ARCHIVE.md).

## Principles

- **Read-only against the tenant.** Every tenant permission is a read-only
  application permission. The archive never changes tenant configuration and
  never starts audit subscriptions.
- **One write path.** The archive creates objects in storage you own. The only
  other write is the optional forward of high-value events to your own Sentinel
  workspace or Bower collector, which runs only when you invoke it.
- **The storage service enforces immutability.** Junction cannot shorten or
  remove retention. A compromised collector host can add objects but cannot
  rewrite or delete archived ones.
- **No secrets in configuration.** The configuration file refuses unknown
  keys, so a key cannot be pasted into it, and `account_url` refuses SAS or
  query strings. Credentials come from the environment or the OS credential
  store, and are never logged.

## Tenant permissions

| Permission | Resource | Used for | Cannot |
| --- | --- | --- | --- |
| `ActivityFeed.Read` | Office 365 Management APIs | Reading the four Unified Audit Log content types | Read mail, files or chat content; change settings; start subscriptions (the archive never calls `subscriptions/start`) |
| `AuditLog.Read.All` | Microsoft Graph | Entra ID directory audits and sign-ins | Sign in as users, reset passwords or change the directory |
| `SecurityAlert.Read.All` | Microsoft Graph | Defender XDR alerts (opt-in) | Update, classify or resolve alerts |
| `SecurityIncident.Read.All` | Microsoft Graph | Defender XDR incidents (opt-in) | Update, assign or resolve incidents |

Grant only the permissions for the sources you enable. A missing permission is
reported by name and pauses that source until the daily re-test; other sources
keep running.

## Storage isolation

- **One container or bucket per tenant**, in a subscription or account you
  control, in the region your data residency needs. Do not share it with other
  workloads.
- **Azure**: shared keys disabled, no public access, TLS 1.2, version-level
  immutability on the account and container. Restrict network access to the
  collector's network or a private endpoint.
- **R2**: one bucket, API tokens scoped to that bucket only, bucket lock rules
  on `v1/` and `holds/`.
- **Local directory**: for trials only. It is create-only and read-only on
  disk but **not immutable**; `doctor` reports it as failing.

## Identities and who can do what

Use separate identities so no single credential can collect, read and hold.

| Identity | Azure Blob | Cloudflare R2 | Can | Cannot |
| --- | --- | --- | --- | --- |
| Collector | Custom role with `blobs/read` and `blobs/add/action` on the container (in `archive-storage.bicep`) | Object Read & Write token for the bucket | Create new objects and read them back | Overwrite, delete, change retention or set legal holds |
| Searcher | Storage Blob Data Reader on the container | Object Read token | `search` and `export` | Write, delete or hold |
| Hold administrator | Storage Blob Data Contributor on the container | Object Read & Write token | `hold create` and `hold release` | Delete or overwrite objects under retention |
| Storage administrator | Owner of the account | Admin Read & Write token | Set and extend retention, lock policies, change lock rules | Shorten a locked Azure policy (the service refuses it) |

Junction never uses the storage administrator identity. Keep it with the
people who own retention, not on the collector host.

Search and export output is redacted by default; `--full` asks for a
confirmation. Treat `--full` access as access to personal data and limit the
searcher identity to the people who need it.

## Immutability

- **Azure**: `archive-storage.bicep` sets a time-based immutability policy on
  the container (365 days by default) with version-level immutability. Each
  blob version is protected from modification and deletion until its retention
  ends. Lock the policy once testing is done; a locked policy can only be
  extended. Every collector write uses `If-None-Match: *`, and the collector
  role has no `blobs/write` (overwrite) or `blobs/delete` action.
- **R2**: bucket lock rules block overwrites and deletes of matching objects,
  including by lifecycle rules, for the rule's age or indefinitely.
- **Manifests** are create-only objects under the same retention and are
  chained by hash, so a missing or altered manifest shows up as a broken chain.

`junction archive doctor` checks the store refuses a second write to the same
key and refuses deletion, and that Azure reports retention covering
`retention_days`.

## Retention and expiry

Retention defaults to 365 days and is extended on the storage, never in
Junction. When retention ends, records remain until you delete them or a
lifecycle rule you configure removes them. Junction has no delete command.

## Legal hold

- A hold manifest records who placed the hold (`JUNCTION_ARCHIVE_OPERATOR`, or
  the OS user), when, why, the query, and every covered record id with its raw
  hash.
- Azure holds set the per-blob legal hold flag; the blob cannot be deleted
  while it is set, regardless of time-based retention.
- R2 holds copy the objects under `holds/`, protected by an indefinite lock
  rule that only a storage administrator can change.
- Creation fails closed, and releases are recorded and never delete.
- Every hold, release and export writes an audit entry under `audit/` in the
  store.

## Personal data

- Audit records contain names, UPNs, IP addresses, file names and mailbox
  details. The archive stores them as Microsoft delivered them, so the archive
  itself is personal data and must be protected as such.
- Defender alerts are reduced before storage: command lines, file paths,
  registry values, analyst comments and long vendor text are dropped.
- Default search and export output pseudonymises actors and truncates IPs.
- Forwarded events carry pseudonyms, IP networks and the raw hash only, never
  the raw record.
- Audit content is attacker-influenced. It is size-bounded, stripped of control
  and bidirectional-override characters, and never interpreted.

## Network and residency

The collector contacts `login.microsoftonline.com`, `graph.microsoft.com`,
`manage.office.com`, and your storage endpoint. Forwarding adds your Logs
Ingestion endpoint or Bower collector. Sovereign clouds use their documented
equivalents. Where Microsoft stores the tenant's audit data is governed by the
tenant's Microsoft data residency; where the archive stores it is the storage
region you chose.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
