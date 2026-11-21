# Security posture checks (`junction check`)

`junction check` assesses one or many Microsoft 365 tenants (Entra ID, Defender for Endpoint, attack
surface reduction rules, Intune, email, Microsoft Sentinel and backups) and reports a score, the
quick wins to fix first, and findings mapped to the ASD Essential Eight, the ISM, CIS benchmarks,
NIST CSF 2.0 and MITRE ATT&CK.

It is **read-only**. Every call goes through Junction's catalogue, registry and read-only policy,
whatever policy a context is configured with, so a check cannot change a tenant even by mistake.
Remediation is suggestion text only. The one optional write is sending results to your own Log
Analytics workspace ([Pushing results to Sentinel](#pushing-results-to-sentinel)).

Results are honest about what they could not see: a missing licence gives `not_applicable`, a
missing permission gives `unknown` with the permission to grant, and neither is ever reported as a
pass or a fail.

Related pages: [CHECKS-PERMISSIONS.md](CHECKS-PERMISSIONS.md) (app registration and least-privilege
permissions), [ESSENTIAL-EIGHT-COVERAGE.md](ESSENTIAL-EIGHT-COVERAGE.md) (coverage matrix),
[WRITING-A-CHECK.md](WRITING-A-CHECK.md) (adding checks), [check-result.schema.json](check-result.schema.json)
(JSON result schema) and [REMEDIATION-PLANS.md](REMEDIATION-PLANS.md) (future design note).

> Junction is independent of Microsoft and ASD. Results indicate alignment with the frameworks named
> here; they are not a formal Essential Eight, IRAP or CIS assessment. See [DISCLAIMER.md](../DISCLAIMER.md).

## Quick start

1. Register an app with the read-only permissions in [CHECKS-PERMISSIONS.md](CHECKS-PERMISSIONS.md)
   and add a cloud context for the tenant:

   ```sh
   junction context add contoso --file contoso.json   # cloud, tenant, credential_profile, flow
   ```

2. Run every pack and read the table:

   ```sh
   junction check run --context contoso
   ```

3. Produce a report for leadership and fail a pipeline on high-severity findings:

   ```sh
   junction check run --context contoso --format html --output posture.html \
     --organisation "Contoso" --fail-on high
   ```

## Commands

| Command | What it does |
|---|---|
| `junction check run` | Run checks against the selected tenants. |
| `junction check list [--pack ...] [--tag ...]` | List checks with severity, tags and permissions. |
| `junction check permissions [--pack ...]` | The least-privilege permissions the selected checks need. |
| `junction check explain <id>` | What a check reads, why, and how to fix a failure. |
| `junction check attest <id> --answer yes --note ...` | Record a person's answer to a manual check. |
| `junction check attest --pending` | List (and on a terminal, answer) manual checks without a current answer. |
| `junction check history` | Stored runs with scores. |
| `junction check diff [--since run-id\|YYYY-MM-DD]` | What changed since a previous run. |

### Selecting checks

| Flag | Meaning |
|---|---|
| `--pack identity,endpoint` | Packs: `identity`, `endpoint`, `intune`, `email`, `backup`, `sentinel`, `apps`, `collaboration`, `azure`. |
| `--check <id>` | Only these checks (repeatable). Unknown ids are an error. |
| `--exclude <id>` | Skip these checks (repeatable). |
| `--tag <selector>` | Checks carrying a framework tag (repeatable, any match): `e8`, `e8:ml1`, `e8:mfa`, `e8:mfa:ml2`, `ism:ISM-1504`, `cis:1.1.3`, `cisv8:6.5`, `nist:PR.AA-03`, `mitre:T1078`. |
| `--config checks.toml` | Thresholds and pack settings (below). |

### Selecting tenants

| Flag | Meaning |
|---|---|
| `--context <name>` | A named context (repeatable for several tenants). |
| `--all-contexts` | Every named context. |
| `--tenants customers.toml` | A list of tenant ids, each with the context whose credential reaches it and a label. |
| `--parallel 4` | Tenants assessed at once (1 to 32). |
| `--per-host 4` | Concurrent requests per Microsoft API host within a tenant. `Retry-After` is always honoured. |

A tenants file:

```toml
[[tenant]]
id = "00000000-0000-4000-8000-000000000001"
context = "partner"          # optional when exactly one --context is given
label = "Customer A"

[[tenant]]
id = "00000000-0000-4000-8000-000000000002"
label = "Customer B"
```

Two multi-tenant models are supported:

- **Per-tenant app consent.** One multi-tenant app registration, consented in each customer tenant
  with the permissions in [CHECKS-PERMISSIONS.md](CHECKS-PERMISSIONS.md). App-only flows (client
  certificate, client secret, workload identity) request a token for each tenant id, so one context
  covers every tenant in the file. This is the recommended model.
- **Delegated partner access (GDAP).** A partner identity holds read roles (for example Global Reader,
  Security Reader) in customer tenants through granular delegated admin privileges. Use an
  interactive context (`junction auth login`) and sign in for each customer tenant id; checks that
  need application-only permissions report `unknown` with the reason where delegated roles do not
  reach. Junction does not create or manage GDAP relationships.

Each tenant runs independently: a tenant that fails to authenticate is reported with the reason and
the others continue. Licences are read once per tenant (`subscribedSkus`) and shared by every check,
so a tenant without, say, Defender for Endpoint gets `not_applicable` for those checks without any
further calls. Tokens, refresh tokens and client secrets never appear in output or logs.

### Output

| Flag | Meaning |
|---|---|
| `--format table` | Terminal table, at most 100 columns, failures and warnings first in quick-win order (`--show-passes` adds passes). |
| `--format json` | The full result; validates against [check-result.schema.json](check-result.schema.json). |
| `--format markdown` | Summary, pack scores, top 10 quick wins, findings by pack, changes since the last run. |
| `--format html` | One self-contained file: executive summary, Essential Eight maturity estimate, technical appendix. Print it to PDF from a browser. |
| `--format m365-secure-json` | M365-Secure schema 1.1, for existing crownguard imports. |
| `--output <path>` | Write to a file instead of standard output. |
| `--split` | One file per tenant in the `--output` directory (markdown, html, json). |
| `--title`, `--organisation`, `--logo <png\|jpg\|svg>` | Report branding. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every selected tenant was assessed and no threshold was breached. |
| `1` | A threshold was breached: a failed check at or above `--fail-on <severity>`, a tenant score below `--min-score <n>`, or a regression with `--fail-on-regression`. |
| `2` | Run error: invalid flags, selection or configuration, or no tenant could be assessed (for example authentication failed for every tenant). |
| `3` | Partial: some tenants or checks could not run (failed tenant, `unknown` because of a permission or service error). Pass `--allow-partial` to treat this as success. Manual checks awaiting an answer do not count. |

When a threshold is breached and the run is also partial, the exit code is `1`.

## Statuses, scoring and quick wins

| Status | Meaning |
|---|---|
| `pass` | The control is in place. |
| `fail` | The control is missing or weaker than the threshold. |
| `warn` | Partly in place, report-only, audit mode, or a heuristic concern. |
| `unknown` | The check could not decide. The reason says why and, for permissions, what to grant. |
| `not_applicable` | The tenant cannot have this control (no licence or workload). The reason says why. |

**Score.** Each check is weighted by severity (critical 10, high 6, medium 3, low 1, info 0). A pass
earns the full weight, a warn half and a fail nothing; the score is `100 × earned ÷ possible`, rounded
to one decimal. `unknown` and `not_applicable` results are excluded from both sides but counted and
shown. Pack scores use the pack's checks; the overall score uses every check. With nothing to score
the score is empty.

**Quick wins.** Failures first, then warnings; within each, higher impact, then lower effort, then
higher severity, then pack order (identity, endpoint, Intune patching and admin rights, email,
backups, Sentinel, then the rest), then check id.

### Thresholds and settings

```toml
[checks."identity.mfa_coverage"]
users_percent = 95
admins_percent = 100

[checks."endpoint.stale_sensors"]
days = 7

[packs.sentinel]
subscriptions = ["00000000-0000-4000-8000-000000000001"]
price_per_gb = 5.22
```

`junction check explain <id>` names each check's settings and defaults.

## History and drift

Each run is stored per tenant in `.junction/check-history/<tenant-id>.sqlite` (change with
`--history-dir`, opt out with `--no-history`). A database belongs to one tenant: it is bound at
creation and checked on every open, so a mis-pointed directory can never mix tenants. Files are
created readable by the owner only, store no credentials, and carry a tamper-evident audit trail.
Runs older than `--retention-days` (default 365) are removed; the latest run is always kept.

- `junction check history --context contoso` lists runs with scores.
- `junction check diff --context contoso [--since <run-id>|YYYY-MM-DD]` shows new failures, fixed
  checks, other status changes, checks added or removed between versions, and the score change.
- Markdown and HTML reports include the changes since the previous run.
- `--fail-on-regression` exits `1` when anything got worse.

## Manual and attested checks

Some controls have no API: an offline backup copy, a recent test restore, whether break-glass
sign-ins are monitored, Exchange Online settings only reachable through PowerShell. These are manual
checks. Answer them once per tenant:

```sh
junction check attest backup.restore_tested --answer yes \
  --note "Restored a mailbox and a file share on 2026-09-30" --context contoso
junction check attest --pending --context contoso     # list, or answer interactively on a terminal
```

Answers (`yes`, `no`, `partial`, `not_applicable`) are stored with the author, time and expiry
(default 180 days, `--expires-days`). Expired answers become `unknown` again. Results from answers
are marked `attested` in every output format. Over MCP and HTTP, agents can read pending
attestations but cannot submit them unless the operator starts the host with `--allow-attest`.

<!-- generated:manual-checks:start (junction check docs) -->
| Check | Question | Why manual |
|---|---|---|
| `identity.break_glass_monitored` | Does every sign-in by an emergency access (break-glass) account raise an alert that someone responds to? | Alert rules can live in Azure Monitor, Sentinel, Defender XDR or a third-party SIEM; no single API shows whether break-glass sign-ins reach a person. |
| `endpoint.air_level` | Is Automated Investigation turned on, and is every Defender for Endpoint device group (including Ungrouped devices) set to Full or Semi automation? | Microsoft publishes no API (Defender for Endpoint, Defender XDR or Microsoft Graph) that reads the device group automation level or the Automated Investigation toggle. |
| `email.preset_policies` | Is the Standard or Strict preset security policy turned on and applied to all recipients, for Exchange Online Protection and (when licensed) Defender for Office 365? | This setting is only exposed by Exchange Online PowerShell (or its admin API), which is not in Junction's read-only operation catalogue. |
| `email.external_sender_tag` | Is external sender identification (the External tag in Outlook) turned on? | This setting is only exposed by Exchange Online PowerShell (or its admin API), which is not in Junction's read-only operation catalogue. |
| `email.auto_forward_blocked` | Does the outbound spam policy block automatic forwarding to external recipients, with no mail flow rule that forwards externally? | This setting is only exposed by Exchange Online PowerShell (or its admin API), which is not in Junction's read-only operation catalogue. |
| `email.mailbox_audit` | Is mailbox auditing on by default for the organisation (AuditDisabled is False), with no mailbox bypassing it? | This setting is only exposed by Exchange Online PowerShell (or its admin API), which is not in Junction's read-only operation catalogue. |
| `backup.offline_copy` | Is at least one copy of your important data, software and settings held offline, or in storage that cannot be changed or deleted during its retention period (immutable), separate from production credentials? | Offline media and third-party storage are not visible to Microsoft APIs. |
| `backup.restore_tested` | Was a restore of data, applications and settings from backup tested, to a common point in time, within the last six months? | Restore exercises are not recorded in any Microsoft API. |
| `backup.admin_separation` | Are backups administered by dedicated accounts that are not used for production administration, and can production administrators not modify or delete backups? | Backup product roles and third-party consoles are outside Microsoft APIs, and separation is an organisational control. |
<!-- generated:manual-checks:end -->

## MCP and HTTP

`junction mcp serve` and `junction serve` expose the same execution as the CLI (the JSON is identical
to `junction check run --format json`):

| MCP tool | HTTP route | Purpose |
|---|---|---|
| `junction_check_list` | `GET /v1/checks?pack=&tag=&check=` | List checks. |
| `junction_check_run` | `POST /v1/checks/run` | Run checks against named contexts; `background: true` returns a run id. |
| `junction_check_run_status` | `GET /v1/checks/runs/{id}?context=` | Progress and result of a background run, or a stored run from history. |
| `junction_check_attestations` | `GET`/`POST /v1/checks/attestations` | Pending manual checks; submitting needs `--allow-attest`. |

Checks run read-only regardless of the host's `--policy` mode; the host policy's `deny.operations`
rules and `allow.tenants` list still apply. By default agents can only assess the host's own context
(`--context` or `--context-file`); the operator allows other saved contexts with
`--allow-check-contexts`. Errors are structured and secret-free.

## Pushing results to Sentinel

`--push-sentinel` sends one row per check (run id, tenant, check id, pack, status, severity, scores,
tags, a one-line summary; never raw tenant data) to a Log Analytics custom table through the Logs
Ingestion API, so drift alerts and workbooks can live in Sentinel:

```sh
junction check run --all-contexts --push-sentinel \
  --dce https://contoso-dce.australiaeast-1.ingest.monitor.azure.com \
  --dcr dcr-00000000000000000000000000000000 --stream Custom-JunctionCheck_CL \
  --push-context monitoring --approve-push
```

It is off unless the flag is set, writes only to your own workspace, and needs either
`--approve-push` (confirmation on the controlling terminal) or `--push-policy` with a policy that
allows `azure.monitor.logs_ingestion.upload` (see [APPROVALS.md](APPROVALS.md)). A `--push-policy`
deny rule cannot be approved away. The report is written before the push, so a failed push (exit
`2`) never loses it. The only role
needed is Monitoring Metrics Publisher on the data collection rule. A Bicep template for the table,
DCE and DCR, a sample workbook and two analytics rules are in
[examples/sentinel](../examples/sentinel/).

## CI and self-hosted runners

The `check-fixtures` CI job runs every check test from recorded, synthetic fixtures with
`JUNCTION_CHECK_OFFLINE=1`, which makes any live Microsoft call or DNS lookup fail before a token is
requested. No CI job calls a tenant.

Runner labels come from repository variables, so CI moves to self-hosted runners without editing the
workflows:

| Variable | Example | Default |
|---|---|---|
| `CI_RUNNER_LINUX` | `["self-hosted","linux","x64"]` | `"ubuntu-latest"` |
| `CI_NATIVE_RUNNERS` | `[["self-hosted","macos"],["self-hosted","windows"]]` | `["macos-latest","windows-latest"]` |

To register a runner: repository **Settings > Actions > Runners > New self-hosted runner**, follow
the download and `./config.sh --url https://github.com/jusso-dev/junction --token <token> --labels
linux,x64` steps, run it as a service, then set the variables above (**Settings > Secrets and
variables > Actions > Variables**). Runners need Rust (stable, with rustfmt and clippy), `bash`, `jq`
and PowerShell 7 for the Exchange runner contract test. The daily release workflow is unchanged.

## Check catalogue

<!-- generated:checks:start (junction check docs) -->
| Id | Title | Pack | Severity | Kind | Licences | Permissions |
|---|---|---|---|---|---|---|
| `identity.baseline` | Security Defaults or a Conditional Access baseline is enforced | identity | critical | automated | none | `Policy.Read.All` |
| `identity.break_glass` | An emergency access account is excluded from Conditional Access | identity | medium | automated | `entra_id_p1` | `GroupMember.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory` |
| `identity.break_glass_monitored` | Break-glass account sign-ins raise an alert | identity | medium | manual | none | none |
| `identity.global_admin_count` | Between two and four Global Administrators | identity | high | automated | none | `RoleManagement.Read.Directory` |
| `identity.legacy_auth_blocked` | Legacy authentication is blocked | identity | high | automated | none | `Policy.Read.All` |
| `identity.mfa_admins` | Every privileged role holder is MFA capable | identity | critical | automated | none | `AuditLog.Read.All`, `GroupMember.Read.All`, `RoleManagement.Read.Directory`, `UserAuthenticationMethod.Read.All` |
| `identity.mfa_coverage` | Enabled users are registered for MFA | identity | high | automated | `entra_id_p1` | `AuditLog.Read.All`, `User.Read.All` |
| `identity.phishing_resistant_admins` | Admins use phishing-resistant MFA, enforced by Conditional Access | identity | high | automated | `entra_id_p1` | `AuditLog.Read.All`, `GroupMember.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory` |
| `identity.pim_used` | Privileged roles are eligible through PIM, not permanent | identity | high | automated | `entra_id_p2` | `RoleAssignmentSchedule.Read.Directory`, `RoleEligibilitySchedule.Read.Directory` |
| `identity.separate_admin_accounts` | Admin accounts have no mailbox or Office apps | identity | medium | automated | none | `GroupMember.Read.All`, `LicenseAssignment.Read.All`, `RoleManagement.Read.Directory`, `User.Read.All` |
| `endpoint.air_level` | Automated investigation and remediation runs at Full or Semi automation | endpoint | medium | manual | `defender_endpoint_p2` | none |
| `endpoint.asr_audit_noise` | No attack surface reduction rules left in audit mode | endpoint | low | automated | `defender_endpoint`, `defender_xdr_hunting` | `AdvancedHunting.Read.All`, `ThreatHunting.Read.All` |
| `endpoint.asr_quick_wins` | Quick-win attack surface reduction rules are in block mode | endpoint | high | automated | none | `AdvancedHunting.Read.All`, `DeviceManagementConfiguration.Read.All`, `ThreatHunting.Read.All` |
| `endpoint.asr_rule_state` | Attack surface reduction rules are in block mode | endpoint | medium | automated | none | `AdvancedHunting.Read.All`, `DeviceManagementConfiguration.Read.All`, `ThreatHunting.Read.All` |
| `endpoint.av_definition_age` | Antivirus security intelligence is no more than three days old | endpoint | high | automated | `defender_endpoint`, `defender_vulnerability_management`, `defender_xdr_hunting` | `AdvancedHunting.Read.All`, `ThreatHunting.Read.All` |
| `endpoint.av_mode` | Defender Antivirus is active, or another antivirus is declared | endpoint | high | automated | `defender_endpoint`, `defender_vulnerability_management`, `defender_xdr_hunting` | `AdvancedHunting.Read.All`, `ThreatHunting.Read.All` |
| `endpoint.cloud_protection` | Cloud-delivered protection is on for every onboarded device | endpoint | high | automated | `defender_endpoint`, `defender_vulnerability_management` | `Vulnerability.Read.All` |
| `endpoint.edr_block_mode` | EDR in block mode covers devices where Defender Antivirus is passive | endpoint | medium | automated | `defender_endpoint_p2`, `defender_vulnerability_management`, `defender_xdr_hunting` | `AdvancedHunting.Read.All`, `ThreatHunting.Read.All` |
| `endpoint.linux_macos_health` | Linux and macOS Defender sensors are active | endpoint | medium | automated | `defender_endpoint` | `Machine.Read.All` |
| `endpoint.network_protection` | Network protection is on in block mode | endpoint | medium | automated | `defender_endpoint`, `defender_vulnerability_management`, `defender_xdr_hunting` | `AdvancedHunting.Read.All`, `ThreatHunting.Read.All`, `Vulnerability.Read.All` |
| `endpoint.onboarding_coverage` | Every active device is onboarded to Defender for Endpoint | endpoint | high | automated | `defender_endpoint` | `Device.Read.All`, `DeviceManagementManagedDevices.Read.All`, `Machine.Read.All` |
| `endpoint.realtime_protection` | Real-time protection is on for every onboarded device | endpoint | high | automated | `defender_endpoint`, `defender_vulnerability_management` | `Vulnerability.Read.All` |
| `endpoint.servers_covered` | Azure VMs and Arc servers are onboarded to Defender for Endpoint | endpoint | high | automated | `defender_endpoint` | `Machine.Read.All`, `Reader` |
| `endpoint.stale_sensors` | Defender for Endpoint sensors are active and reporting | endpoint | medium | automated | `defender_endpoint` | `Machine.Read.All` |
| `endpoint.tamper_protection` | Tamper protection is on for every onboarded device | endpoint | high | automated | `defender_endpoint`, `defender_vulnerability_management` | `Vulnerability.Read.All` |
| `endpoint.unsupported_os` | Onboarded devices run a supported operating system | endpoint | high | automated | `defender_endpoint` | `Machine.Read.All` |
| `intune.bitlocker_escrow` | Encrypted Windows devices have their BitLocker recovery key in Entra ID | intune | medium | automated | none | `BitlockerKey.ReadBasic.All`, `DeviceManagementManagedDevices.Read.All` |
| `intune.browser_updates` | Edge and Chrome are up to date on every device | intune | medium | automated | `defender_vulnerability_management` | `Software.Read.All` |
| `intune.compliance_policy` | Every platform has a compliance policy and Conditional Access requires compliant devices | intune | high | automated | none | `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `Policy.Read.All` |
| `intune.laps` | Windows LAPS manages local administrator passwords and backs them up to Entra ID | intune | high | automated | none | `DeviceLocalCredential.ReadBasic.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All` |
| `intune.local_admin` | Users are not made local administrators of their devices | intune | high | automated | none | `DeviceManagementConfiguration.Read.All`, `Policy.Read.DeviceConfiguration` |
| `intune.office_macros` | Office blocks internet macros and only runs trusted or signed macros | intune | high | automated | none | `DeviceManagementConfiguration.Read.All` |
| `intune.patch_age` | Windows devices have security updates within Essential Eight timeframes | intune | high | automated | none | `DeviceManagementManagedDevices.Read.All`, `Machine.Read.All`, `Vulnerability.Read.All` |
| `intune.update_rings` | Windows update rings install quality updates within a week | intune | high | automated | none | `DeviceManagementConfiguration.Read.All` |
| `email.auto_forward_blocked` | Automatic forwarding to external recipients is blocked | email | high | manual | `exchange_online` | none |
| `email.dkim` | DKIM selector CNAMEs are published for every Exchange Online domain | email | medium | automated | `exchange_online` | `Domain.Read.All` |
| `email.dmarc` | Every mail domain enforces DMARC with reporting | email | high | automated | `exchange_online` | `Domain.Read.All` |
| `email.external_sender_tag` | Mail from outside the organisation is tagged External in Outlook | email | medium | manual | `exchange_online` | none |
| `email.mailbox_audit` | Mailbox auditing is on by default for every mailbox | email | high | manual | `exchange_online` | none |
| `email.preset_policies` | Standard or Strict preset security policy applies to all recipients | email | high | manual | `exchange_online` | none |
| `email.spf` | Every mail domain publishes one strict SPF record | email | high | automated | `exchange_online` | `Domain.Read.All` |
| `backup.admin_separation` | Backup administrator accounts are separate from production administrators | backup | medium | manual | none | none |
| `backup.azure_vaults` | Azure Backup vaults are immutable, soft-delete protected and cover critical VMs | backup | high | automated | none | `Reader` |
| `backup.m365_backup` | Microsoft 365 Backup protects Exchange, OneDrive and SharePoint | backup | high | automated | none | `BackupRestore-Configuration.Read.All` |
| `backup.offline_copy` | An offline or immutable copy of backups exists | backup | high | manual | none | none |
| `backup.restore_tested` | A test restore was done in the last six months | backup | high | manual | none | none |
| `backup.third_party_app` | A third-party Microsoft 365 backup app has consent | backup | info | automated | none | `Application.Read.All` |
| `sentinel.automation` | High severity incidents are routed to a person automatically | sentinel | low | automated | none | `Microsoft Sentinel Reader`, `Reader` |
| `sentinel.connectors` | Entra ID, Defender XDR, Office 365 and Azure Activity data reach Sentinel | sentinel | high | automated | none | `Log Analytics Reader`, `Microsoft Sentinel Reader`, `Reader` |
| `sentinel.health_auditing` | Sentinel health and audit monitoring is enabled | sentinel | medium | automated | none | `Log Analytics Reader`, `Microsoft Sentinel Reader`, `Reader` |
| `sentinel.incidents_stale` | Open Sentinel incidents are assigned and worked within 48 hours | sentinel | medium | automated | none | `Microsoft Sentinel Reader`, `Reader` |
| `sentinel.ingestion_cost` | Sentinel ingestion cost is known and noisy tables use cheaper log plans | sentinel | low | automated | none | `Log Analytics Reader`, `Microsoft Sentinel Reader`, `Reader` |
| `sentinel.retention` | Sentinel workspaces keep data for at least 90 days | sentinel | medium | automated | none | `Log Analytics Reader`, `Microsoft Sentinel Reader`, `Reader` |
| `sentinel.rules_enabled` | At least ten analytics rules are enabled in Sentinel | sentinel | high | automated | none | `Log Analytics Reader`, `Microsoft Sentinel Reader`, `Reader` |
| `sentinel.workspace` | Microsoft Sentinel is onboarded to a Log Analytics workspace | sentinel | high | automated | none | `Microsoft Sentinel Reader`, `Reader` |
| `apps.admin_consent_workflow` | The admin consent workflow is on with at least one reviewer | apps | medium | automated | none | `Policy.Read.All` |
| `apps.app_management_policy` | The tenant app management policy blocks or caps client secrets | apps | medium | automated | none | `Policy.Read.All` |
| `apps.assignment_required` | Third-party enterprise applications require user assignment | apps | low | automated | none | `Application.Read.All` |
| `apps.credential_expiry` | No app registration has an expired or soon-expiring secret or certificate | apps | medium | automated | none | `Application.Read.All` |
| `apps.high_privilege_permissions` | Third-party applications hold no unreviewed high-impact permissions | apps | high | automated | none | `Application.Read.All`, `DelegatedPermissionGrant.Read.All` |
| `apps.multi_tenant_apps` | App registrations are single-tenant unless they need to be multi-tenant | apps | low | automated | none | `Application.Read.All` |
| `apps.privileged_app_secrets` | App registrations with high-impact application permissions do not use client secrets | apps | high | automated | none | `Application.Read.All` |
| `apps.secret_lifetime` | App registration client secrets are valid for a year or less | apps | low | automated | none | `Application.Read.All` |
| `apps.sp_password_credentials` | Third-party service principals carry no client secrets of their own | apps | medium | automated | none | `Application.Read.All` |
| `apps.user_consent_restricted` | Users cannot consent to applications (or only to verified publishers for low-impact permissions) | apps | critical | automated | none | `Policy.Read.All` |
| `apps.users_cannot_register_apps` | Non-admin users cannot register applications | apps | medium | automated | none | `Policy.Read.All` |
| `collaboration.email_verified_join_blocked` | Email-verified users cannot self-join the organisation | collaboration | medium | automated | none | `Policy.Read.All` |
| `collaboration.external_resharing_blocked` | Guests cannot reshare items they do not own | collaboration | medium | automated | `sharepoint_online` | `SharePointTenantSettings.Read.All` |
| `collaboration.group_creation_restricted` | Users cannot create security groups, and Microsoft 365 group creation is limited | collaboration | low | automated | none | `GroupSettings.Read.All`, `Policy.Read.All` |
| `collaboration.guest_access_restricted` | Guest users have the most restricted directory access | collaboration | medium | automated | none | `Policy.Read.All` |
| `collaboration.guest_invites_restricted` | Only admins and Guest Inviters can invite guests | collaboration | medium | automated | none | `Policy.Read.All` |
| `collaboration.idle_session_signout` | Idle SharePoint sessions on unmanaged devices sign out within 3 hours | collaboration | medium | automated | `sharepoint_online` | `SharePointTenantSettings.Read.All` |
| `collaboration.sharepoint_external_sharing` | SharePoint external sharing is 'New and existing guests' or stricter | collaboration | high | automated | `sharepoint_online` | `SharePointTenantSettings.Read.All` |
| `collaboration.sharepoint_legacy_auth_blocked` | SharePoint requires modern authentication | collaboration | high | automated | `sharepoint_online` | `SharePointTenantSettings.Read.All` |
| `collaboration.sharing_domain_restriction` | SharePoint external sharing is limited to an allow list of domains | collaboration | medium | automated | `sharepoint_online` | `SharePointTenantSettings.Read.All` |
| `collaboration.unmanaged_sync_restricted` | OneDrive sync is restricted to managed devices | collaboration | medium | automated | `sharepoint_online` | `SharePointTenantSettings.Read.All` |
| `azure.defender_plans` | Defender for Cloud plans are on wherever matching resources exist | azure | high | automated | none | `Reader`, `Security Reader` |
| `azure.key_vault_protection` | Key vaults use Azure RBAC, purge protection and restricted networking | azure | high | automated | none | `Reader` |
| `azure.public_network_exposure` | Storage and PaaS data services are closed to anonymous and public network access | azure | high | automated | none | `Reader` |
<!-- generated:checks:end -->
