# M365 Watchdog implementation plan

## Repository discovery

Junction is an edition-2024 Rust Cargo workspace, not a Cloudflare application.
The `junction` binary exposes CLI commands, `junction-server` exposes a bounded
local HTTP API, `junction-mcp` exposes agent tools, and `junction-tui` provides a
terminal UI. API catalog discovery/generation lives in `junction-discovery`,
`junction-generator`, `junction-schema`, `junction-registry` and `junction-types`.
These catalog modules do not need a second security monitoring implementation.

The existing `junction-watch` crate already contains Phase 1: certificate-backed
onboarding, capability probes, Management Activity ingestion, checkpoint recovery,
event normalisation, tenant-bound SQLite, and an Axum/Maud loopback dashboard.
Its local Argon2 accounts have viewer/analyst/admin roles, expiring hashed sessions,
CSRF protection and a chained operator audit trail. The organisation boundary is
one tenant per database/process, not a multi-tenant SaaS. A second organisation
requires a separate store, credentials and listener. OS administrators remain
trusted; database binding does not protect against an administrator of the host.

Authentication and Microsoft transport reuse `junction-auth`, `junction-http`,
`junction-policy` and `junction-core` cloud endpoints. Credentials are environment
or OS-store supplied, never stored in watch SQLite. The daemon uses Tokio and
wall-clock scheduling; launchd is documented. Releases are native binaries through
GitHub Actions. Existing Rust tests use scripted HTTP doubles and Axum requests;
CI runs formatting, Clippy, workspace tests and release-script checks on three OSes.
There is no existing outbound notification provider or object-storage service.

## Phased module mapping and gates

1. **Foundation:** verify `config`, `probe`, `capability`, `activity`, `store`,
   `auth`, `web` tests before extending. Keep capability uncertainty explicit.
2. **High-value detections:** add Graph audit ingestion through `upstream` and
   `backoff`; extend `event`; add versioned deterministic rules and durable alerts
   to the same SQLite store. Add an independent external notification outbox.
   Gate: positive/negative rule fixtures, Graph retry/pagination/failure tests,
   deduplication and capability gating.
3. **Investigation:** extend the existing Maud navigation with alerts/activity/
   changes; reuse role/session/CSRF checks. Add approved, complete snapshots and
   deterministic comparison; support optional read-only Exchange PowerShell
   exports. Add encrypted evidence and audited retrieval. Gate: incomplete data
   never deletes resources, reordered/missing fields produce no false drift,
   unauthorised routes reject, untrusted payloads remain escaped.
4. **Operations:** add daily/weekly reports, bounded recovery, retention/quota
   controls, suppression and maintenance handling. Extend `watch` CLI and existing
   run loop. Gate: restart/idempotency, retention safety and full local CI checks.

## Deployment and honest coverage

Use the existing native host and SQLite; no D1/R2/Queues or separate application.
FileVault or equivalent disk encryption remains required for normalised telemetry.
Raw evidence requires a separately supplied encryption key. Host location and
backup destination determine local data residency; Microsoft processing and any
external email provider must be disclosed separately. No sovereignty claim.

Sign-in retrieval remains conditional on a successful Graph capability probe and
normally requires Entra P1/P2. Directory and unified audit events stay distinct.
Missing permissions, licences, partial collection and unknown event coverage must
remain visible. Synthetic tests prove logic, not a tenant's entitlement or event
completeness. Live validation must be explicitly invoked with operator credentials.

The submitted acceptance list ends after item 2; this plan uses the complete
requirements in sections 1–12 as the implementation scope.

## Local verification (25 October 2026)

- Workspace: 428 passing tests across 71 suites; Watchdog: 96 passing tests,
  including positive and negative fixtures for all 20 rule IDs.
- Formatting, whitespace checks and strict workspace Clippy passed. Nine existing
  lifetime warnings remain in vendored ratatui.
- Four release/catalog script suites and mocked PowerShell Exchange contracts
  passed. The runner was also checked for PowerShell syntax errors.
- Synthetic dashboard smoke checks covered desktop and 375-pixel mobile layouts,
  login, incident evidence, activity filters, settings and readable reports.
- Compatible TLS/runtime dependency updates removed six vulnerability advisories.
  The final audit reported zero vulnerability advisories, with existing
  unmaintained, unsound and yanked-package warnings still outstanding.

These checks used synthetic data and mocked Microsoft responses. They did not
contact a live tenant, rotate a live certificate, verify Exchange role assignments
or deliver real email. Reports are available in the dashboard, not automatically
emailed. Production acceptance requires the opt-in tenant validator and a pilot
that verifies collection coverage, runner scope, recovery and independent inbox
delivery on the intended deployment host.


## Council review and remediation

One independent Claude/Codex round returned **SHIP WITH CHANGES** from both
reviewers. Their strongest shared objection was that actorless events loaded
unbounded tenant history, stopping subsequent detections and queued notifications.
The implementation now scopes history, defers oversized evaluations durably with
visible gaps, and permits notification delivery after detector failure. A
60,000-event regression verifies actorless snapshot detection and email handoff.

Other confirmed findings were fixed with regressions: unknown/null observations
preserve last-known baseline fields; unconfirmed deletions no longer repeat
unrelated changes; enabling an existing dangerous inbox rule evaluates its effective
actions; correlation requires independent successful records, retains both evidence
IDs and deduplicates the same pair; change timestamps use canonical UTC.

Additional review concerns led to visible rejection of malformed Graph records and
a six-hour collection overlap. Late publication beyond that overlap remains a gap.
Exchange audit and runner identifiers must match exactly for rule correlation;
we deliberately do not guess identity equivalence. Pilot validation must check
those identifiers. Reviewers did not independently run tests or validate a live
tenant; remediation was verified locally by the lead, without claiming reviewer
re-approval or production acceptance.
