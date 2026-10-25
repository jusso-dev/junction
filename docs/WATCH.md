# Junction M365 Security Watchdog

`junction watch` monitors a Microsoft 365 tenant for signs of account and data compromise. It is built for small, volunteer-run organisations (for example community sporting clubs) on free or donated Microsoft 365 plans such as Business Basic or Office 365 E1, and it does not need Defender, Sentinel, Entra ID P1/P2 or a SIEM.

Status: **implementation candidate, live tenant validation still required**. Foundation, deterministic detections, incident investigation and operational reporting are implemented in the existing native Junction process. Local synthetic tests do not establish a tenant's licence entitlements, event completeness, Exchange role scope or successful external email delivery.

## How it works

```
Microsoft 365 ──(read-only app permissions)──▶ junction watch run ──▶ SQLite on this machine ──▶ dashboard on 127.0.0.1
```

- **One tenant, one machine.** The store is bound to one tenant ID when it is created and refuses any other.
- **Runs on the operator's laptop.** It collects every 15 minutes while the machine is awake. Microsoft keeps audit content available to the API for **7 days**, so the laptop must be on and collecting at least weekly. Anything older than that becomes a recorded *gap* on the Coverage page. Those events stay searchable in Microsoft Purview (180 days on Audit Standard); they are only missing from this tool.
- **Licence-aware.** Every data source is checked with a real read-only API call. The result is one of `AVAILABLE`, `AVAILABLE_WITH_LIMITATIONS`, `REQUIRES_PERMISSION`, `REQUIRES_LICENCE`, `NOT_ENABLED`, `UNSUPPORTED`, `TEMPORARILY_UNAVAILABLE` or `UNKNOWN`, with the cause beside it. A 403 is classified by its error code, never assumed to mean "needs a licence". Subscription names are shown for context but never decide coverage.
- **Known-unavailable sources are not polled.** If a source needs a permission or licence the tenant lacks, collection skips it until an admin presses *Re-test* (or the daily re-probe runs).

## What it reads

| Source | API | Needs | Free-plan reality |
|---|---|---|---|
| Exchange, SharePoint/OneDrive, Entra ID and other audit feeds | Office 365 Management Activity API | `ActivityFeed.Read` | Included with Purview Audit (Standard) on Business Basic/Standard/Premium and E1/E3. **Auditing is off by default on Business plans**; turn it on in the Purview portal. |
| Entra ID directory audit log | Graph `auditLogs/directoryAudits` | `AuditLog.Read.All` | Available on Entra ID Free (7-day retention). |
| Entra ID sign-in log | Graph `auditLogs/signIns` | `AuditLog.Read.All` | **Needs Entra ID P1/P2.** Seeing sign-ins in the admin portal on Free does not make the API available. Without it, the sign-in detection is switched off and shown as a gap. |
| Organisation, domains, subscriptions | Graph `organization`, `subscribedSkus` | `Organization.Read.All` | All plans. |
| SharePoint sharing settings | Graph `admin/sharepoint/settings` | `SharePointTenantSettings.Read.All` | All plans with SharePoint. |

`junction watch permissions` explains every permission in plain English, including what it *cannot* do. The default integration requests only the four permissions above. `--include-optional` adds the optional Exchange runner permission. Audit-based identity detection needs no additional directory write permissions. Grant Exchange.ManageAsApp only to the separate optional runner with a custom read-only, recipient-scoped role. No unused Graph inventory permissions are requested. Default permissions are read-only; the optional Exchange application permission relies on separately scoped read-only Exchange roles. The watchdog never reads email or file contents, and it does not request `Directory.ReadWrite.All`, `Mail.Read`, `Sites.Read.All` or similar broad permissions.

The only change the watchdog ever makes to a tenant is starting the audit feed subscription (`junction watch subscribe` or *Start audit feeds* on the dashboard). That turns on delivery of audit data Microsoft already records. It is audited and limited to one attempt per feed every 15 minutes, as Microsoft asks.

## Onboarding

1. **Create the app registration.** Entra ID > App registrations > New, single tenant, named for example "Junction Watchdog". Do not create a client secret.
2. **Create a certificate** on the laptop and upload only the public part:
   ```sh
   mkdir -p ~/.junction-watch && chmod 700 ~/.junction-watch && cd ~/.junction-watch
   openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes -subj "/CN=Junction Watchdog" \
     -keyout key.pem -out cert.pem
   openssl x509 -in cert.pem -outform der -out cert.der
   openssl pkcs8 -topk8 -nocrypt -in key.pem -outform der -out key.der
   chmod 600 key.der key.pem
   ```
   Upload `cert.pem` under *Certificates & secrets > Certificates*. Put a calendar reminder for renewal before it expires.
3. **Write the configuration** (secret-free, created with mode 0600):
   ```sh
   junction watch init --tenant-id <directory-guid> --domain club.org.au --client-id <application-guid>
   ```
   The output lists the remaining steps and an admin consent link.
4. **Add the permissions** from `junction watch permissions` (or paste `junction watch permissions --manifest` into the app manifest's `requiredResourceAccess`), then press **Grant admin consent**. Admin consent is given interactively by a Global Administrator in Microsoft's own portal; the watchdog never asks for an administrator password and never bypasses MFA.
5. **Turn on auditing** if it is off: Microsoft Purview portal > Audit. It can take up to an hour to start.
6. **Set the environment** (paths only, no secret values):
   ```sh
   export AZURE_TENANT_ID=<directory-guid> AZURE_CLIENT_ID=<application-guid>
   export AZURE_CLIENT_CERTIFICATE_PATH=~/.junction-watch/cert.der
   export AZURE_CLIENT_PRIVATE_KEY_PATH=~/.junction-watch/key.der
   ```
7. **Check what can be monitored, then start the feeds:**
   ```sh
   junction watch probe
   junction watch subscribe      # first content can take up to 12 hours
   ```
8. **Create a dashboard account** (the password is prompted for, never a command-line argument) and run:
   ```sh
   junction watch user add treasurer --role admin
   junction watch run            # collects every 15 minutes and serves http://127.0.0.1:8787/
   ```

### Opt-in live validation

`junction watch validate` probes every source, samples the last two hours of each enabled feed (at most five content blobs per feed) into a throwaway in-memory store, and reports granted roles, capability states, which detections could run, and the event types actually observed. It never starts subscriptions and never changes the tenant.

### Running in the background on macOS

Save as `~/Library/LaunchAgents/au.org.club.junction-watch.plist`, adjust paths, then `launchctl load` it. The plist holds file paths only.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>au.org.club.junction-watch</string>
  <key>WorkingDirectory</key><string>/Users/you/junction-watch</string>
  <key>ProgramArguments</key><array>
    <string>/Users/you/junction/junction</string><string>watch</string><string>run</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>AZURE_TENANT_ID</key><string>DIRECTORY-GUID</string>
    <key>AZURE_CLIENT_ID</key><string>APPLICATION-GUID</string>
    <key>AZURE_CLIENT_CERTIFICATE_PATH</key><string>/Users/you/.junction-watch/cert.der</string>
    <key>AZURE_CLIENT_PRIVATE_KEY_PATH</key><string>/Users/you/.junction-watch/key.der</string>
  </dict>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Users/you/junction-watch/watch.log</string>
</dict></plist>
```

The run loop schedules from the wall clock, so it collects promptly after the laptop wakes rather than waiting out a timer that paused during sleep.

## Collection details

- **Windows and checkpoints.** The Management Activity API lists content by when Microsoft made it available (`contentCreated`), not when the event happened, in windows of at most 24 hours and no more than 7 days back. The collector keeps a watermark per feed, re-lists a one-hour overlap to catch late listings, and advances the watermark only after a whole window is stored.
- **Deduplication.** Each content blob is recorded once it is stored, in the same transaction as its events, so an interrupted run either fully records a blob or retries it. Events are unique on tenant, source and Microsoft record ID; Microsoft documents duplicate delivery.
- **Retries.** Junction's transport retries briefly; collectors add exponential backoff with jitter and honour `Retry-After`. The Management Activity API throttles with HTTP 403 `AF429`, which is treated as throttling, not as a permission failure. When Junction's own per-minute request budget is spent, requests wait for a free slot instead of failing, and the feed that has gone longest without a successful run is collected first next time.
- **Feeds are independent.** A failure in one feed, including a local database error, is reported for that feed and the others still run. Every run is closed with its result.
- **Bad content is skipped visibly, never silently.** A content blob Microsoft refuses for a reason that will not change (expired, missing, not a JSON array), or that fails in three consecutive runs, is quarantined: recorded as a gap and skipped so it cannot stall the feed. Authentication and permission errors never cause content to be skipped; they stop the run and are retried. Listing entries with an unexpected link, and records that cannot be normalised or name another organisation, are rejected and counted. Any of these marks the run `ok_with_warnings` and adds a gap on the Coverage page.
- **Untrusted content.** Audit records are attacker-influenced (rule names, file names). They are size-bounded, stripped of control and bidirectional-override characters, reduced to an allow-list of fields (message subjects and item lists are dropped), never interpreted, and rendered only through auto-escaping templates. Blob links are followed only on the feed's own origin under this tenant's `/activity/feed/audit/` path, and page links only on this tenant's content-listing endpoint, so a crafted listing cannot send the access token elsewhere or skip pages. A listing that is not a JSON array, or a page link that leaves the listing endpoint, fails the window without moving the checkpoint.
- **Coverage is about collected data.** "Detections with data available" counts only sources this release actually collects and can currently read. A successful probe of a source that is not yet collected (organisation/subscription enrichment) is shown on Coverage but does not make a detection look covered.
- **Evidence integrity.** Each stored event keeps the SHA-256 of the JSON record before normalisation (re-serialised JSON, not the HTTP wire bytes).

## Rotating and revoking credentials

**Rotate the certificate** before it expires (or straight away if the laptop may have been compromised):

1. Create a new key and certificate as in onboarding step 2, with new file names.
2. Upload the new `cert.pem` to the app registration. Both certificates now work.
3. Point `AZURE_CLIENT_CERTIFICATE_PATH` and `AZURE_CLIENT_PRIVATE_KEY_PATH` at the new files (and in the launchd plist), restart `junction watch run`, and run `junction watch probe` to confirm access.
4. Delete the old certificate from the app registration, then delete the old key file.

**Revoke access** at any time, without touching the laptop: in Entra ID remove the certificate from the app registration (stops new tokens), or remove admin consent / delete the enterprise application (removes all permissions). Existing access tokens expire within about an hour. Stop the feed subscriptions too if the watchdog will not be used again (`subscriptions/stop` in the Management Activity API, or deleting the app).

**Dashboard accounts:** `junction watch user disable <name>` ends that account's sessions immediately.

## Security and privacy

- **Credentials.** The certificate key stays on the laptop (mode 0600). Tokens live in memory only. Nothing secret is written to the configuration file, the database or logs.
- **Dashboard.** Bound to loopback only (the configuration refuses anything else). The Host header is pinned against DNS rebinding. Sessions use 256-bit random tokens stored only as hashes, HttpOnly and SameSite=Strict cookies, per-form CSRF tokens and same-origin checks. A strict Content-Security-Policy allows no script. Failed sign-ins lock an account for 15 minutes after five attempts, and passwords are Argon2id hashes. Roles: `viewer` (overview and coverage), `analyst` (adds activity, evidence and incident handling) and `admin` (adds re-tests, feed subscriptions and accounts).
- **Audit trail.** Operator actions (sign-ins, re-tests, subscription starts, account changes) are written to a hash-chained trail. `junction watch verify-trail` detects tampering.
- **Storage.** The SQLite file and its directory are private to the operator account. SQLite `secure_delete` is on. Use FileVault for encryption at rest. Optional raw evidence uses AES-256-GCM with tenant/event authenticated data; see the operations section below.
- **No AI or product analytics.** Collection contacts Microsoft's APIs. When configured, minimal alert notifications are handed to the operator's independently secured mail service; raw evidence is never sent to AI providers.

### Data residency

With the default laptop deployment, collected telemetry is stored on that laptop. Collection traffic uses Microsoft's endpoints (`login.microsoftonline.com`, `graph.microsoft.com`, `manage.office.com`). Configured alert delivery also uses the operator's mail service and external destination; assess their processing and storage locations separately. Where Microsoft stores and processes the tenant's audit data is governed by the tenant's own Microsoft data residency, not by this tool. If the dashboard is ever put behind a remote reverse proxy, or the store is backed up to cloud storage, the residency of those services must be assessed separately.

## Known limits

- The laptop must collect at least once every 7 days. Longer gaps are recorded and shown, not hidden.
- Sign-in telemetry needs Entra ID P1/P2. Without it there is no sign-in risk detection, and the watchdog does not imitate one from other events.
- Exchange configuration snapshots (current forwarding, delegation and transport rules) need the optional PowerShell runner. Changes are still caught from the audit feed as they happen.
- Management Activity probes alone cannot prove audit configuration. The optional Exchange runner reads Get-AdminAuditLogConfig and reports inaccessible cmdlets as partial collection.
- Nonprofit editions are not named in Microsoft's Purview service description; Audit (Standard) is assumed to follow the commercial plan it is based on. The live probe is what counts.

## Detection and investigation

`junction watch rules` prints all 20 versioned rule definitions, their required
sources, permissions, thresholds, confidence and investigation guidance.
`junction watch detect` processes pending events without contacting Microsoft.
Each rule has positive and negative synthetic fixtures. Supported operation
spellings and structured values are deliberately conservative; an unrecognised
Microsoft event is retained for investigation, not guessed into a detection.

Graph directory audits are collected separately from unified audit records.
Graph sign-ins are collected only after a positive capability probe; risk fields
can require additional entitlements and `hidden` never counts as evidence.
Graph uses seven days as a conservative initial recovery bound, not a claim about
premium searchable retention. Each pass drains one day with six hours of overlap. Records published more than six hours late may still be missed; overlap is not a guarantee of complete delivery. Malformed or foreign-tenant Graph records are rejected with visible gaps and rejection counts, allowing valid records and later pages to continue.
Management Activity collection still uses its own content-created windows.

The existing dashboard now includes Alerts, Activity, Changes, Reports and
Settings. Viewer accounts cannot inspect personal telemetry. Analysts can inspect
and update incidents; administrators additionally approve baselines and settings.
Incident transitions follow NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED; a resolved
incident can be reopened for investigation. Resolution requires a note and a
remediated, false-positive or accepted-risk disposition. Evidence reads, settings,
exceptions and incident actions are audited. The hash chain detects interior
modification; it is not an externally anchored guarantee against a host
administrator rewriting or truncating the entire database.

Bulk download/deletion rules compare distinct events per user/site within an hour
against recent hourly activity and a configurable minimum. Cold starts use the
minimum; they are anomaly indicators, never confirmed exfiltration. Events from a
busy hour group into one incident per rule/user/site. External sharing alerts
track domains absent from the approved list and record their first observation.
Mailbox rule correlation requires both a successful audit event and a distinct matching snapshot, retaining both evidence records. Matching currently requires the exact same resource ID. Exchange audit ObjectId and runner mailbox/rule-name identifiers can differ; validate their correspondence during the pilot. Mismatches cannot be correlated and are not guessed; individual audit and snapshot detections continue. Missing snapshot coverage remains visible.

## Configuration snapshots

The optional [Exchange runner](../scripts/watch/collect-exchange.ps1) uses supported
ExchangeOnlineManagement PowerShell on a separate supported host or Azure
Automation. It does not run in Workers, fetch messages or execute event content.
Supply a certificate object from the host certificate store or an Automation
certificate asset. Protect the output directory with OS ACLs and schedule the
runner at the desired interval. Pin and maintain the Exchange module on that host.
Test every cmdlet with the intended scoped role; the script does not grant roles.

The runner collects inbox rules (including hidden rules where allowed), forwarding,
Full Access/Send As/Send on Behalf, transport rules, accepted/remote domains,
outbound anti-spam forwarding policy and audit/bypass settings. A cmdlet or mailbox
failure marks its collection partial. Unknown or missing API fields remain unknown.
Named forwarding recipients are resolved through read-only Get-Recipient calls.
An inaccessible recipient marks collection partial instead of guessing its domain.

Set `snapshot_directory` in the top-level TOML to the protected export directory,
or import an individual export:

```sh
junction watch import-snapshot /protected/exports/mailboxes.json
junction watch approve-baseline <snapshot-id>
```

Review complete initial snapshots in Changes before approval. No existing object
is treated as newly suspicious before an approved baseline. Arrays are canonical
sets; omitted/null properties do not prove deletion. Incomplete collections never
replace baselines. Complete snapshots retain last-known comparison values for omitted/null properties while preserving the original observed payload and hash. Object deletion needs two complete observations; unrelated changes advance independently without duplicate alerts. Changing the
runner's recipient scope requires explicit baseline review. The SharePoint tenant
sharing-settings API uses the same approved snapshot path. No file-reading Graph
permissions are requested. The audit feed provides site activity; the product does
not imply that a site-scoped Graph grant supplies tenant-wide visibility.

## Evidence, notifications and operations

Raw audit retention is **off by default**. Inject a base64-encoded 32-byte random
key through `JUNCTION_WATCH_EVIDENCE_KEY` using the host secret manager to enable
it. Never put the key in TOML, command arguments, SQLite, source control or logs.
Key fingerprints identify the required version; retain the corresponding old key
securely while its evidence remains retained. Changing the active key affects new
evidence. Old evidence cannot be decrypted with a different key. Normalised events
and configuration remain protected by host disk encryption and private filesystem
permissions. Backups require their own encryption and expiry policy.

Settings configures poll interval, thresholds, approved external domains, sensitive
sites, retention, quotas and external email. Settings saved in the dashboard take
precedence over TOML detection/notification defaults. Polling defaults to 15
minutes, event retention to 90 days, raw evidence to 30 days, and quotas to one
million events / 1 GiB encrypted evidence. Quota failure rolls back collection and
retains its checkpoint. Open unsuppressed incidents pin their supporting events;
resolve them before that data can expire. This may stop collection at quota and
must be monitored. Secure deletion and WAL checkpointing cannot erase independent
backups or guarantee physical erasure on an unencrypted SSD.

Critical/high alert emails use the host's `/usr/sbin/sendmail` interface and a
persistent retry outbox. Configure a separately secured MTA and a destination
outside **all** verified tenant domains, then attest to that independence in
Settings. The application cannot independently verify who controls the external
mailbox or mail relay. Windows hosts need an external supported delivery host;
there is no native Windows MTA adapter. Mail handoff success is not proof of inbox
delivery. Test the complete external delivery path before relying on it. Messages
contain only severity, rule and incident ID, not account/document names or raw
records. Unresolved critical alerts are re-queued daily after a successful handoff.

Daily and weekly reports are stored automatically by the collection scheduler and
available in Reports. They explain changes, unresolved work, recorded actions and
coverage without personal details. Period boundaries use UTC. Browser printing
supports PDF export without a second rendering service. Reports are not emailed
automatically. Reports and notification queues survive restart. History-dependent detection is scoped by source and actor/site or target. Evaluations over 50,000 relevant records are deferred for hourly retry with a visible coverage gap; single-event rules and notification delivery continue. Detector failures do not stop delivery of already queued alerts.

```sh
junction watch report daily
junction watch report weekly
junction watch retain
junction watch backfill --days 6
junction watch verify-trail
```

Backfill re-lists recent available content without rewinding normal checkpoints;
it cannot recover expired API content. It does not confuse API availability with
Purview's searchable retention. The scheduled daemon must remain running on a
reliable host; a sleeping volunteer laptop is not an always-on monitoring service.

## Validation and release limits

Run `cargo test -p junction-watch --locked`, workspace formatting/Clippy/tests,
PowerShell syntax validation and `cargo audit`. The dependency-audit workflow also
runs weekly. Opt-in `junction watch validate` uses operator credentials and does
not create tenant changes. Real tenant licence coverage, actual Exchange cmdlet
permissions, credential rotation and inbox delivery require a pilot deployment.
Do not describe synthetic tests as that live verification.

The sample `cargo run -p junction-watch --example dashboard-preview` serves only
synthetic in-memory records at 127.0.0.1:18787. Its public fixture account is
`preview` / `synthetic-preview-only`; it has no Microsoft connection or mail sender.
Never adapt this fixture into a production account bootstrap.
