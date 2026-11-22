# Junction M365 audit and evidence archive

`junction archive` continuously copies Microsoft 365 audit streams into storage
you own, keeps them immutable for as long as you need, and lets you search
them, place legal holds and export hashed evidence bundles for IRAP
assessments or incident reviews.

Status: **implementation candidate, live tenant and live storage validation
still required**. Everything below is covered by fixture tests with synthetic
data. Nothing has yet been run against a real tenant, Azure storage account or
R2 bucket.

It is an archive and evidence tool. It is not a SIEM and does not replace
Sentinel. If you run Sentinel, the archive can forward only a short list of
high-value events to it, so ingestion stays small.

## Why

Unified Audit Log retention defaults to 90 or 180 days, depending on the
workload and licence. Longer retention needs Purview Audit (Premium), which is
included in Microsoft 365 E5 or Purview Suite (US$12 per user per month on top
of E3, as listed on 22 November 2026), and 10-year retention is a further
add-on listed at around €2 per user per month. Sending every audit record to
Sentinel is a separate, often larger, ingestion bill.

The archive keeps the same records in a storage account or bucket you already
pay for, at storage prices, for as long as your retention policy says.

## How it works

```
Microsoft 365, Entra ID, Defender
        │  read-only application permissions
        ▼
junction archive collect ──▶ create-only objects ──▶ your Azure Blob container
        │                                            or Cloudflare R2 bucket
        │                                            (immutable by policy)
        ├─ junction archive search    (read-only)
        ├─ junction archive hold      (legal hold)
        ├─ junction archive export    (evidence bundle)
        └─ junction archive forward   (optional, high-value only)
```

- **One tenant per configuration.** The configuration, checkpoint and every
  record name the tenant. Records naming another organisation are refused.
- **Storage enforces immutability.** Junction only creates objects
  (`If-None-Match: *`). Retention is set on the container or bucket by an
  administrator. Junction never sets, shortens or removes it, so a
  compromised collector host cannot rewrite the archive either.
- **Schedule it.** Run `junction archive collect` every 15 to 60 minutes from
  cron, a systemd timer, launchd or a scheduled container. The Management
  Activity API keeps content for 7 days, so the collector must run at least
  weekly; longer outages become recorded gaps.

## Sources and permissions

`junction archive permissions` prints this table with the storage roles.

| Source | API | Application permission | Default | Notes |
| --- | --- | --- | --- | --- |
| `o365:Audit.AzureActiveDirectory` | Office 365 Management Activity API | `ActivityFeed.Read` | on | Purview Audit (Standard). The feed subscription must be started. |
| `o365:Audit.Exchange` | Office 365 Management Activity API | `ActivityFeed.Read` | on | |
| `o365:Audit.SharePoint` | Office 365 Management Activity API | `ActivityFeed.Read` | on | |
| `o365:Audit.General` | Office 365 Management Activity API | `ActivityFeed.Read` | on | Teams, Defender, Purview and every other workload. |
| `graph:directoryAudits` | Microsoft Graph | `AuditLog.Read.All` | on | All Entra ID editions. |
| `graph:signIns` | Microsoft Graph | `AuditLog.Read.All` | on | Needs Entra ID P1 or P2; skipped as `requires_licence` otherwise. |
| `graph:alerts_v2` | Microsoft Graph security API | `SecurityAlert.Read.All` | opt-in | Defender XDR alerts, each update a new version. |
| `graph:incidents` | Microsoft Graph security API | `SecurityIncident.Read.All` | opt-in | Defender XDR incidents, each update a new version. |

Every permission is a read-only application permission. The archive never
starts audit subscriptions; use `junction watch subscribe` once, or your
existing feed.

### Why only two Defender resources

Alerts and incidents are the investigation record: what was detected, how
severe it was, how it was classified and how it was resolved. They are low
volume. Advanced hunting tables are not collected (high volume, better kept in
Sentinel or Defender), nor is Defender for Cloud Apps activity (Bower owns it),
nor device inventory or vulnerabilities (posture, covered by `junction check`).
Alert evidence is reduced to an allow-list: process command lines, file paths,
registry values, analyst comments and long vendor text are dropped.

### Not collected here

Intune, Power Platform, Power Automate, Dataverse, Defender for Cloud Apps,
Purview eDiscovery, Entra provisioning and Teams admin are collected and
normalised by Bower. See [the Bower contract](archive/BOWER-CONTRACT.md) for
how the two fit together.

## Setting up

1. **Create the storage.** Deploy `examples/archive/archive-storage.bicep`
   (Azure) or create an R2 bucket with `examples/archive/r2-lock-rules.json`.
   See [examples/archive](../examples/archive/README.md).
2. **Write the configuration** (secret-free, mode 0600):
   ```sh
   junction archive init --tenant-id <directory-guid>
   ```
   Then edit the `[storage]` section. It must never contain a key or SAS token.
3. **Grant the tenant permissions** in the table above to the collector app
   registration, and give admin consent.
4. **Set the credential environment.** Tenant access uses Junction's
   environment credentials (certificate by default):
   ```sh
   export AZURE_TENANT_ID=<directory-guid> AZURE_CLIENT_ID=<application-guid>
   export AZURE_CLIENT_CERTIFICATE_PATH=/secure/cert.der
   export AZURE_CLIENT_PRIVATE_KEY_PATH=/secure/key.der
   ```
   Azure storage uses the storage identity's flow from `[storage] auth` with
   the same variables. For R2, also set `JUNCTION_ARCHIVE_R2_ACCESS_KEY_ID`
   and `JUNCTION_ARCHIVE_R2_SECRET_ACCESS_KEY` from your secret manager.
5. **Check the store:**
   ```sh
   junction archive doctor
   ```
   It writes a canary object and confirms a second write cannot replace it,
   that deletion is refused, and (on Azure) that the reported retention covers
   `retention_days`. A store that allows deletion fails `doctor`.
6. **Collect on a schedule:**
   ```sh
   junction archive collect
   junction archive status
   ```

## Storage layout

```
v1/tenant=<id>/source=<source>/date=YYYY-MM-DD/hour=HH/<sha256>.ndjson.gz   records
v1/tenant=<id>/manifests/source=<source>/date=YYYY-MM-DD/<start>-<sha256>.json   window manifests
v1/tenant=<id>/holds/<hold-id>/...                                            hold manifests
holds/<hold-id>/v1/...                                                        R2 and local hold copies
v1/tenant=<id>/audit/date=YYYY-MM-DD/...                                      hold and export audit entries
```

Each record object is gzip-compressed NDJSON of `junction.archive.record/1`
envelopes: stable record id, tenant, source, Microsoft id, version (Defender
only), event and ingest time, operation, result, actor, target, IP, correlation
id, the SHA-256 of the record as received, and the record itself. Objects are
named by the SHA-256 of their content, so retrying a batch names the same
object.

## Exactness

Delivery into storage is **at least once**. Search, export, hold and forward
all **deduplicate on the record id**, so duplicates never reach a result.

- A window's objects and manifest are stored before its checkpoint moves. A
  crash in between replays the window: nothing is skipped, and some records
  may be stored twice.
- Management Activity content blobs are remembered by id for eight days, so
  the one-hour listing overlap never fetches an archived blob again.
- Graph windows overlap the previous one by two hours, and record ids seen in
  the overlap are remembered.
- Microsoft documents that the same audit record can appear in more than one
  content blob. Those copies are kept and removed on read.

The checkpoint lives in `state_directory` (one private JSON file per tenant,
written atomically). It is not evidence; losing it causes a replay, not a gap
and not data loss.

## Gaps

Every committed window writes a manifest, including empty windows, listing its
objects, record counts and gaps. Gaps are recorded when:

- the collector was offline longer than the 7-day Management Activity content
  window, or longer than the 7-day Graph start window;
- a content blob was refused by Microsoft or failed three runs in a row
  (quarantined);
- listing entries or records were malformed, out of window or named another
  organisation.

Manifests for a source are chained by hash (`previousManifestSha256`) and are
create-only objects under the same retention as the records.

Evidence bundles report two kinds of gap for their range:

- **recorded**: gaps the collector wrote into manifests (read from 8 days
  before the range to 8 days after it, because an offline gap is filed with
  the window that resumed collection);
- **uncovered**: any part of the range that no complete collection window
  covers, because the collector was not running, has not reached it yet, or
  the source was never collected.

A bundle with no gaps therefore means every part of the range was collected
by a complete window and nothing was rejected or quarantined.

`junction archive status` shows watermarks, paused sources and why a source is
unavailable; the gaps themselves are in the manifests and bundles.

## Search

```sh
junction archive search --from 2026-11-01T00:00:00Z --to 2026-11-08T00:00:00Z \
  --operation New-InboxRule
junction archive search --from ... --to ... --actor person@example.org --full
```

Filters: `--source`, `--operation` (exact, case-insensitive), `--actor` (UPN),
`--ip` (exact), `--contains` (case-insensitive text in the record id, raw hash,
Microsoft id, operation, target, result, correlation id, actor, IP or raw
record).
All given filters must match. A range may cover at most 3660 days.

Default output is redacted: the actor is a `sha256:` pseudonym, IPv4 is
truncated to /24 and IPv6 to /48, and raw records are not shown. The query is
echoed redacted too (actor and IP filters as pseudonym and network, free text
as a hash), so the output cannot be used to reverse its own pseudonyms. `--full`
shows everything and asks for confirmation (`--yes` when not at a terminal).
The pseudonym is not a secret mapping: anyone with the archive can hash a
known UPN to find its records. It keeps identities out of casual output and
screen shares.

Only date partitions inside the range are listed. Objects that cannot be read
or whose content does not match their name are reported under `problems`.

## Legal hold

```sh
junction archive hold create --name matter-2026-17 --reason "Legal matter 2026-17" \
  --from 2026-10-01T00:00:00Z --to 2026-11-01T00:00:00Z --actor person@example.org
junction archive hold list
junction archive hold release --name matter-2026-17 --reason "Matter closed"
```

A hold first writes an intent manifest naming every object it will protect,
then protects each object holding a matching record, then writes the hold
manifest (who, when, why, the query, every covered record id with its raw
hash, and each object held):

- **Azure**: `Set Blob Legal Hold` on the object. Needs the hold
  administrator identity (Storage Blob Data Contributor).
- **R2 and local**: a copy under `holds/<hold-id>/`, protected by the
  indefinite `holds/` lock rule.

Creation fails closed: it refuses when an object in range cannot be read, and
names every object that could not be held. Release is recorded and never
deletes anything. On Azure the flag is cleared only on objects no other
unreleased hold covers, and a release refuses to run if any other hold's
manifests cannot be read. A release that fails part-way is shown as
`release_incomplete` and can be run again. On R2 the copies stay until an
administrator changes the lock rule.

## Evidence bundles

```sh
junction archive export --from 2026-11-01T00:00:00Z --to 2026-11-08T00:00:00Z \
  --purpose "IRAP assessment 2026, ISM-0580 evidence" --output ./bundle-2026-11
junction archive verify ./bundle-2026-11
```

The bundle directory holds:

- `records.ndjson`: matching records, deduplicated, ordered by event time then
  record id, redacted unless `--full`.
- `manifest.json`: tool version, who exported it and why, tenant, storage,
  range, query and its hash (the query is redacted in a redacted bundle),
  sources, record count, duplicates removed, the SHA-256 of `records.ndjson`,
  the result-set hash, the storage objects read, recorded and uncovered gaps,
  and any read problems.
- `README.txt`: how to verify it by hand.

The **result-set hash** is the SHA-256 of the sorted `recordId rawSha256`
lines. It does not depend on order or redaction, so a redacted bundle for an
assessor and a full bundle for investigators of the same query share it.

Bundles are evidence of what the archive holds, with its recorded gaps. They
are not a certified chain of custody on their own; keep the bundle with your
case records, and record its hashes in your case notes.

## Forwarding high-value events

```sh
junction archive forward --list
junction archive forward --to sentinel --from ... --until ... \
  --push-sentinel --dce <endpoint> --dcr <dcr-...> --stream Custom-JunctionArchive_CL \
  --push-context <context> --approve-push
junction archive forward --to bower --endpoint https://collector.example.org --from ... --until ...
```

Only the sources a selected rule can match are read, and only events matching
the built-in selector are forwarded: role grants, app
consent, app credentials, mailbox forwarding and rules, mailbox permissions,
audit logging reduced, high-severity Defender alerts and risky sign-in
success. `--only` narrows the list; it cannot be widened.

- **Sentinel** uses the same policy-checked Logs Ingestion path as
  `junction check run --push-sentinel`, and sends redacted summary columns to
  `JunctionArchive_CL` (`examples/archive/archive-forward-table.bicep`).
- **Bower** receives Bower security event envelopes 1.0.0 on its existing
  `/v1/events`, with a producer token from `JUNCTION_BOWER_INGEST_TOKEN`. See
  [the Bower contract](archive/BOWER-CONTRACT.md).

Defender alerts and incidents are forwarded by their update time: an alert
raised up to 30 days before the range and escalated or resolved inside it is
forwarded. Raw records are never forwarded. A cursor per destination (kept for
400 days) means an accepted event is not sent again.

## Retention

The default is 365 days, set on the storage (`retentionDays` in the Bicep, or
the `v1/` R2 lock rule). To keep records longer, extend it on the storage and
raise `retention_days` in the configuration so `doctor` checks the new value.
See [examples/archive](../examples/archive/README.md#extending-retention).
When retention ends, the storage service lets records expire or be deleted by
a lifecycle rule you choose; Junction does not delete anything. Records under a
legal hold stay.

## Security

See [ARCHIVE-SECURITY.md](ARCHIVE-SECURITY.md).

## Known limits

- No live validation yet: tenant, Azure storage and R2 have only been
  exercised with fixtures.
- A run reads up to 5,000 content blobs per Management Activity feed; larger
  backlogs continue on the next run.
- Graph sign-ins and audits start at most 7 days back; earlier history is not
  backfilled.
- Search scans objects; it is not indexed. It suits investigations and
  evidence exports, not interactive dashboards.
- Holds and exports cover at most 1,000,000 records per query.
- One run per tenant at a time: the state file is locked, and an overlapping
  `collect` or `forward` exits with a message instead of sharing it.
- A Graph day with more than 2,000 pages is split into smaller windows over
  following runs (down to five minutes) rather than completed in one run.
- Storage identities must be in the same Entra tenant as the archived tenant.
