# Junction archive and Bower: hand-off contract

Junction and Bower split the work like this:

| Junction archive owns | Bower owns |
| --- | --- |
| Long-term retention in customer-owned immutable storage | Collecting and normalising hard-to-export Microsoft sources (Intune, Power Platform, Dataverse, Defender for Cloud Apps, Purview, Entra provisioning, Teams admin and others) |
| Search, legal hold and evidence bundles | Redaction, policy and arrival proof on its ingest path |
| Collecting the Unified Audit Log, Entra ID sign-in and audit logs, and Defender alerts and incidents | Shipping events into Sentinel or Log Analytics |

Junction does not implement Bower sources, change Bower's collector code or copy
its redaction engine. This document is the whole contract between them. Any
change Bower needs is listed under [Requests for the Bower project](#requests-for-the-bower-project)
for the Bower maintainers to pick up; nothing here changes Bower.

## 1. Junction forwards high-value events to Bower (implemented)

`junction archive forward --to bower --endpoint <collector URL>` sends each
selected event to Bower's existing collector endpoint:

- **Endpoint**: `POST {collector}/v1/events`, one JSON envelope per request.
  HTTPS is required except for a loopback collector.
- **Authentication**: `Authorization: Bearer <producer token>`. The token is
  read from `JUNCTION_BOWER_INGEST_TOKEN` and never logged or stored.
- **Envelope**: Bower security event envelope `schemaVersion` `1.0.0`
  (`schemas/envelope/security-event.schema.json` in the Bower repository). A
  copy is vendored at `crates/junction-archive/data/bower-security-event-1.0.0.schema.json`
  (Bower is MIT licensed) and every envelope Junction builds is validated
  against it in the tests.
- **Responses handled**: `202` accepted, `200` duplicate (both count as
  delivered); `429` and `503` retried with backoff; `401`, `403`, `409` and
  `422` stop the forward with an explanation.
- **Exactness**: at least once. Junction keeps a per-destination cursor of
  forwarded record ids. Bower deduplicates on `eventId`, which is stable for
  a given archived record.

### Envelope mapping

| Envelope field | Value |
| --- | --- |
| `eventId` | `junction-archive-<recordId>` (stable per archived record and version) |
| `eventOriginalId` | Microsoft's record id |
| `timeGenerated` | Event time from Microsoft |
| `timeObserved` | When Junction archived the record |
| `eventCategory` | From the selector rule (`authorisation`, `identity-management`, `administrative-activity`, `authentication`, `application-security`) |
| `eventType` | `m365_<rule id>`, for example `m365_role_assignment_added` |
| `eventAction` | Microsoft operation, for example `Add member to role` |
| `eventResult` | `success`, `failure` or `unknown` |
| `eventSeverity` | From the selector rule |
| `application` | `name: junction-archive`, the Junction version, `environment` from `--environment`, and the Entra tenant id |
| `actor.userId` | `sha256:` pseudonym of the UPN or object id (never the UPN) |
| `target` | `type: m365_object`, `id` a pseudonym |
| `source.ipAddress` | The IP truncated to /24 (IPv4) or /48 (IPv6) |
| `request.correlationId` | Microsoft correlation id |
| `labels` | `junction.source`, `junction.rule`, `junction.selector_version`, `junction.raw_sha256` |

The raw record is never sent. `junction.raw_sha256` lets an analyst find the
full record in the archive (`junction archive search --contains <hash>` or by
record id) under the archive's own access controls.

### Event types

| `eventType` | Rule | Why |
| --- | --- | --- |
| `m365_role_assignment_added` | `role-assignment-added` | Privileged role grants are the usual persistence step after account takeover. |
| `m365_app_consent_granted` | `app-consent-granted` | Illicit consent grants give durable access without a password. |
| `m365_app_credential_added` | `app-credential-added` | A new secret or certificate on an app is a classic backdoor. |
| `m365_mailbox_forwarding_or_rule` | `mailbox-forwarding-or-rule` | Forwarding and inbox rules hide and exfiltrate mail. |
| `m365_mailbox_permission_added` | `mailbox-permission-added` | Full Access and Send As let one account read or impersonate another. |
| `m365_audit_logging_reduced` | `audit-logging-reduced` | Defence evasion that also degrades the archive. |
| `m365_defender_high_severity_alert` | `defender-high-severity-alert` | The alerts a SOC acts on. |
| `m365_risky_sign_in_success` | `risky-sign-in-success` | A successful medium or high risk sign-in is likely compromise. |

`junction archive forward --list` prints the selector with its version.

### What the Bower operator configures

1. Issue a per-producer ingest token for Junction (`BOWER_INGEST_TOKENS_FILE`).
2. Add a producer scope for that producer with
   `application.name = "junction-archive"`, the chosen `environment`, and the
   Entra tenant id as `application.tenantId`. Without it Bower answers `403`,
   which Junction reports.
3. Keep Bower's privacy profile in place. Junction already pseudonymises
   identifiers, but Bower's policy remains the authority on what reaches
   Sentinel.

## 2. Bower-normalised feeds into the archive (proposed, not implemented)

Bower can produce NDJSON objects of redacted envelopes (`BOWER_OUTPUT=s3`, or
the `http` output with `ndjson`). A future Junction issue can archive those
alongside Microsoft sources, so evidence bundles cover Intune, Power Platform
and the other Bower sources too. Proposed shape:

- **Source id**: `bower:<eventCategory>` in the archive, for example
  `bower:administrative-activity`.
- **Record id**: `event_id(tenant, "bower", collectorId + ":" + eventId)`,
  matching Sentinel's deduplication key `(CollectorId, EventId)`.
- **Event time**: `timeGenerated`.
- **Raw**: the redacted envelope as Bower delivered it. Junction never sees the
  pre-redaction payload.
- **Intake**: Junction reads Bower's NDJSON objects from a customer bucket
  (read-only credentials) or accepts `POST`ed NDJSON on a loopback listener.
  It would not run a public ingest endpoint.
- **Integrity**: if Bower's arrival proof (ledger hash) is present in the
  envelope's `collector` object, Junction stores it unchanged so an evidence
  bundle can cite it.

This needs no Bower change if the S3 output is used. It is tracked as a
follow-up to epic #51.

## Requests for the Bower project

None are required for section 1. For section 2, two optional additions would
help, and are for the Bower maintainers to decide:

- A documented, stable object layout for the NDJSON outputs (prefix, naming
  and whether objects are ever rewritten), so Junction can list them
  incrementally.
- An arrival-proof field in the delivered envelope (`collector.ledgerHash` or
  similar), so archived copies can be tied back to Bower's ledger.
