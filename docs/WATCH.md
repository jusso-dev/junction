# Junction M365 Security Watchdog

`junction watch` monitors a Microsoft 365 tenant for signs of account and data compromise. It is built for small, volunteer-run organisations (for example community sporting clubs) on free or donated Microsoft 365 plans such as Business Basic or Office 365 E1, and it does not need Defender, Sentinel, Entra ID P1/P2 or a SIEM.

Status: **Phase 1 (foundation)**. Onboarding, licence and capability discovery, audit collection, storage, coverage reporting and the health dashboard work. Detections and alerts arrive in Phase 2. Until then the dashboard says so; it never shows "no alerts" as if that meant "safe".

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

`junction watch permissions` explains every permission in plain English, including what it *cannot* do. Phase 1 requests only the four permissions above. `--include-optional` lists the extra read-only permissions that later phases need (role assignments, app registrations, user list, inbox rules, policies, and the Exchange runner); do not grant them until those phases ship. All are read-only application permissions. The watchdog never reads email or file contents, and it does not request `Directory.ReadWrite.All`, `Mail.Read`, `Sites.Read.All` or similar broad permissions.

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
- **Coverage is about collected data.** "Detections with data available" counts only sources this release actually collects and can currently read. A successful probe of a source that is not yet collected (for example the Graph directory audit log) is shown on Coverage but does not make a detection look covered.
- **Evidence integrity.** Each stored event keeps the SHA-256 of the raw record as received.

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
- **Dashboard.** Bound to loopback only (the configuration refuses anything else). The Host header is pinned against DNS rebinding. Sessions use 256-bit random tokens stored only as hashes, HttpOnly and SameSite=Strict cookies, per-form CSRF tokens and same-origin checks. A strict Content-Security-Policy allows no script. Failed sign-ins lock an account for 15 minutes after five attempts, and passwords are Argon2id hashes. Roles: `viewer` (overview and coverage), `analyst` (adds activity and evidence, from Phase 3) and `admin` (adds re-tests, feed subscriptions and accounts).
- **Audit trail.** Operator actions (sign-ins, re-tests, subscription starts, account changes) are written to a hash-chained trail. `junction watch verify-trail` detects tampering.
- **Storage.** The SQLite file and its directory are private to the operator account. SQLite `secure_delete` is on. Use FileVault for encryption at rest. Field-level encryption of raw evidence arrives with evidence storage in Phase 3.
- **No AI and no telemetry.** Nothing is sent anywhere except Microsoft's own APIs.

### Data residency

With the default laptop deployment, all collected telemetry stays on that laptop. The only network traffic is between the laptop and Microsoft (`login.microsoftonline.com`, `graph.microsoft.com`, `manage.office.com`). Where Microsoft stores and processes the tenant's audit data is governed by the tenant's own Microsoft data residency, not by this tool. If the dashboard is ever put behind a remote reverse proxy, or the store is backed up to cloud storage, the residency of those services must be assessed separately.

## Known limits

- The laptop must collect at least once every 7 days. Longer gaps are recorded and shown, not hidden.
- Sign-in telemetry needs Entra ID P1/P2. Without it there is no sign-in risk detection, and the watchdog does not imitate one from other events.
- Exchange configuration snapshots (current forwarding, delegation and transport rules) need the optional PowerShell runner (Phase 2). Changes are still caught from the audit feed as they happen.
- Microsoft offers no API to read whether unified auditing is on. The watchdog infers it from the Management Activity API's documented "tenant does not exist" response and says so.
- Nonprofit editions are not named in Microsoft's Purview service description; Audit (Standard) is assumed to follow the commercial plan it is based on. The live probe is what counts.

## Roadmap

| Phase | Scope |
|---|---|
| 1 Foundation (this release) | Onboarding, capability probes, Management Activity collector, storage, checkpoints, gaps, coverage and health dashboard |
| 2 High-value detections | Exchange forwarding, inbox rules, mailbox delegation, SharePoint external sharing, privileged roles, OAuth consent, directory audit collector, alert notifications to an email address outside the tenant, optional Exchange runner |
| 3 Investigation | Activity explorer, correlation, incident workflow, encrypted evidence storage, configuration drift dashboard |
| 4 Operational maturity | Daily digest and weekly plain-English committee report, retention controls, backfill tooling, further detectors |
