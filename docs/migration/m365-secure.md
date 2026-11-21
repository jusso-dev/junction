# Migrating M365-Secure to Junction check packs

This page maps every M365-Secure check (`m365-assess`, controls registry schema 2.0.0, data version 2026-10-08) to a
Junction check, and sets out how M365-Secure is slimmed down to a wrapper and then retired. Issue: jusso-dev/junction#23
(epic #28).

## Summary

M365-Secure defines 306 check ids: `controls/registry.json` plus `controls/registry.d/*.json`. Every id the source
emits (`src/**`) is in the registry; 60 registry ids have no automated logic (`hasAutomatedCheck: false`). Each id has
exactly one disposition:

| Disposition | Count | Meaning |
|---|---|---|
| new | 25 | Ported in this change to the `apps`, `collaboration` or `azure` pack (23 Junction checks). |
| merged | 46 | Covered by a check in the identity, endpoint, intune, email, Sentinel or backup pack tickets (#11 to #18). Ids marked "planned" export as soon as that pack lands. |
| follow-up | 193 | Needs an API Junction's catalogue does not carry, or is catalogue-ready but outside this ticket. Grouped into the follow-up tickets below. |
| dropped | 42 | Inventory, informational, value-opportunity, SOC 2 roll-up or retired ids. Not security checks. |

`apps.secret_lifetime` is a Junction-only check with no M365-Secure equivalent.

## Ported checks and golden tests

Each ported check has fixture cases under `crates/junction-check/tests/fixtures/{apps,collaboration,azure}/` and tests
in `crates/junction-check/tests/{apps,collaboration,azure}.rs`. Every case's expected status is the one M365-Secure's
code produces for the same synthetic input, and the test names the M365-Secure id next to it. Where the two differ by
design, the difference is Junction's no-false-result rule:

- A missing setting is `unknown` with reason `not_returned` (M365-Secure sometimes defaulted it: `ENTRA-APPS-001` gave
  Warning, `ENTRA-GUEST-003` gave Pass).
- A failed call is `unknown` with the permission to grant, or `not_applicable` when a licence is missing. M365-Secure
  ignored a failed delegated-grant read in `ENTRA-ENTAPP-004`; Junction reports `unknown`.
- M365-Secure's Info for "nothing to check" (no key vaults, no storage) is `not_applicable` with reason `no_resources`.
- SharePoint checks read Graph `admin/sharepoint/settings` only. M365-Secure prefers the SharePoint admin CSOM API,
  which Junction does not catalogue; the golden cases reproduce M365-Secure's Graph-only behaviour. For
  `SPO-SHARING-001` that means 'Anyone' sharing is a fail (the warning branch needs Anyone-link expiry from CSOM).

Operations added to `crates/junction-check/data/operations.txt`: `graph.policies.default_app_management_policy.get` and
`graph.service_principals.app_role_assigned_to.list` (both read-only). Azure checks use Resource Graph
(`azure.resource_graph.resources.post`) and `defender.cloud.pricings.list`, scoped to `[packs.azure] subscriptions` when
set and otherwise to every subscription the identity can read.

## Plan for M365-Secure

**Recommended: thin wrapper, then retire.**

1. Junction ships the packs and `junction check run --format m365-secure-json`. The exporter
   (`crates/junction-check/src/report/m365_secure.rs`) writes M365-Secure's JSON output schema 1.1
   (`schema_version`, `tool`, `summary.tenant`, `findings[]`, `compliance`) and maps Junction results back to
   M365-Secure ids with `crates/junction-check/data/m365-secure-map.yaml`. Statuses use M365-Secure's vocabulary:
   pass, fail, warning, unknown, `review` for a manual check awaiting an answer, `notlicensed` for a missing licence and
   `info` for other not-applicable results. Results without a mapping are skipped.
2. M365-Secure becomes a thin wrapper: `m365-assess` runs `junction check run --format m365-secure-json` and writes the
   output as `_Assessment-Results_<domain>.json`, one file per tenant. crownguard's importer
   (`content/imports/m365-secure.yaml`, `src/imports/m365Secure.ts`) keeps working unchanged because it only reads
   `summary.timestamp`, `summary.tenant.{display_name, primary_domain, license_skus[].sku_part_number}` and
   `findings[].{check_id, status, setting, current_value, expected_value}`.
3. As follow-up groups land, their ids move from follow-up to new in this table and in the map file, so crownguard
   questions fill in again without importer changes.
4. crownguard's mapping refers to 102 M365-Secure ids: 14 are new here, 33 merged into other packs and 55 follow-up
   (in FU-1 to FU-13). When those follow-up groups are done, publish a final M365-Secure release with the deprecation
   notice below, and add a native Junction importer to crownguard.

The alternative, a deprecation notice with a final release now, would leave crownguard without the 193 follow-up
checks until they are ported, so it is not recommended.

Changes to M365-Secure (wrapper, README link, deprecation notice, final release) and to crownguard (native importer) are
tracked in those repositories. This change does not edit them.

### Deprecation notice (draft for the M365-Secure README)

> **M365-Secure is moving into Junction.** New checks are written as Junction check packs
> (`junction check run`), which call Microsoft APIs through Junction's catalogue and read-only policy, report
> unknown or not applicable with a reason instead of guessing, and tag each result with Essential Eight, ISM, CIS and
> MITRE ATT&CK ids. From release X.Y, `m365-assess` is a wrapper around
> `junction check run --format m365-secure-json`; its JSON output keeps schema 1.1, so crownguard imports keep working.
> Check ids are unchanged in that file. See Junction's `docs/migration/m365-secure.md` for where each check went.
> After the final release, M365-Secure receives security fixes only, and the repository will be archived once crownguard
> imports Junction results directly.

## Proposed follow-up tickets

| Group | Ticket | Ids | Why it is not ported here |
|---|---|---|---|
| FU-1 | Exchange Online and Defender for Office 365 policies | 31 | Needs the Exchange Online admin API (`adminapi/beta/{tenant}/InvokeCommand`, Exchange.ManageAsApp with a view-only role), not in the catalogue. Shares the transport with the email pack's optional Exchange reads (#15). |
| FU-2 | SharePoint admin tenant properties | 13 | Default link type and permission, Anyone-link expiry, guest expiry, reauthentication, OneDrive sharing, B2B integration, infected files, custom script and restricted access control are only in the SharePoint Online admin CSOM API, not in Graph `sharepointSettings` or the catalogue. |
| FU-3 | Teams admin policies | 20 | Teams meeting, external access, client and app policies come from the Skype/Teams policy configuration API (`api.interfaces.records.teams.microsoft.com`), not in the catalogue. `TEAMS-APPS-001` can use the catalogued `graph.teamwork.teams_app_settings.get@beta`. |
| FU-4 | Power BI and Power Platform tenant settings | 15 | Catalogue-ready (`fabric.admin.tenants.list_tenant_settings`, `power_platform.*`) but needs the Fabric and Power Platform audiences and admin roles designed and tested. |
| FU-5 | Purview: DLP, labels, retention, alert policies, audit | 12 | DLP, alert, communication compliance and audit log configuration need Security & Compliance PowerShell (not catalogued); sensitivity and retention labels are catalogue-ready (`graph.security.labels.retention_labels.list`, information protection labels). |
| FU-6 | Conditional Access depth | 11 | Catalogue-ready (`graph.identity.conditional_access.policies.list`); extends the identity pack (#11) with device, device-code, PAW, sign-in frequency, exclusion and anti-pattern checks. |
| FU-7 | Entra identity depth | 27 | Catalogue-ready Graph reads (authentication methods policy, group settings for password protection, users with signInActivity, device registration policy, organisation and domains, branding); extends the identity pack. |
| FU-8 | PIM role settings and access reviews | 9 | Catalogue-ready (`graph.policies.role_management_policy_assignments.list`, `graph.identity_governance.access_reviews.definitions.list`); needs Entra ID P2 gating. |
| FU-9 | Applications depth | 19 | Catalogue-ready (owners, managed identities, directory roles, sign-in activity via `graph.reports.service_principal_sign_in_activities.list@beta`, redirect URIs); per-app owner calls need a call budget. |
| FU-10 | Collaboration depth: cross-tenant access, groups, Teams ownership, Forms | 13 | Catalogue-ready (`graph.policies.cross_tenant_access_policy.*`, `graph.groups.list`, `graph.admin.forms.get@beta`). |
| FU-11 | Intune depth | 7 | Catalogue-ready Graph beta (enrolment restrictions, multi-admin approval, role scope tags, App Control for Business); application control is an Essential Eight strategy not yet covered. |
| FU-12 | Azure depth | 6 | `AZ-RBAC-*` need Microsoft.Authorization role assignments and `AZ-KV-002`/`LOG-DIAG-001` need Microsoft.Insights and aadiam diagnostic settings, none catalogued; `AZ-DEFENDER-002` and `AZ-MI-001` are catalogue-ready (Resource Graph, `defender.cloud.secure_scores.list`). |
| FU-13 | Defender for Identity and Defender for Cloud Apps | 2 | Catalogue-ready (`graph.security.identities.sensors.list@beta`, `defender.cloud_apps.*`); needs licence gating for Defender for Identity and Cloud Apps. |
| FU-14 | Manual attestations | 7 | No API exposes these settings (LinkedIn connections, invitation domain list, Microsoft 365 org settings, data access governance reports, Sway). Port as manual checks with `junction check attest`. |
| FU-15 | Activity signals | 1 | Mass device wipe is an activity detection, better placed in `junction watch` detections than in a posture check. |

## Mapping table

Names are M365-Secure's registry names, verbatim. "planned" marks a Junction id proposed by another pack ticket and
not yet built.

| M365-Secure id | Name | Disposition | Junction check / group | Notes |
|---|---|---|---|---|
| `AZ-ACCESS-001` | Azure subscriptions readable by the assessment | dropped |  | Access probe, not a control. Junction reports each Azure check as unknown with the missing role instead. |
| `AZ-BACKUP-001` | Azure Backup vaults have always-on soft delete, locked immutability and multi-user authorisation | merged | `backup.azure_vaults` (planned) |  |
| `AZ-DEFENDER-001` | Defender for Cloud plans enabled where matching resources exist | new | `azure.defender_plans` |  |
| `AZ-DEFENDER-002` | Defender for Cloud secure score and unhealthy high-severity recommendations | follow-up | FU-12 |  |
| `AZ-KV-001` | Key vaults use Azure RBAC, purge protection and restricted networking | new | `azure.key_vault_protection` | No vaults gives not_applicable (M365-Secure: Info). |
| `AZ-KV-002` | Key vaults send diagnostic logs to a destination | follow-up | FU-12 |  |
| `AZ-MI-001` | Workloads use managed identities and storage disallows Shared Key access | follow-up | FU-12 |  |
| `AZ-PUBLIC-001` | Storage and PaaS data services closed to anonymous and public network access | new | `azure.public_network_exposure` | Nothing to check gives not_applicable (M365-Secure: Info). |
| `AZ-RBAC-001` | No standing Owner or User Access Administrator for users at subscription or management-group scope | follow-up | FU-12 |  |
| `AZ-RBAC-002` | No User Access Administrator assignment at root scope | follow-up | FU-12 |  |
| `BCK-M365-001` | Microsoft 365 Backup protection policies active for Exchange, SharePoint and OneDrive | merged | `backup.m365_backup` (planned) |  |
| `CA-DEVICE-001` | Ensure a managed device is required for authentication | follow-up | FU-6 |  |
| `CA-DEVICE-002` | Ensure a managed device is required to register security information | follow-up | FU-6 |  |
| `CA-DEVICE-003` | Ensure an app protection policy is required on iOS and Android | follow-up | FU-6 |  |
| `CA-DEVICECODE-001` | Ensure the device code sign-in flow is blocked | follow-up | FU-6 |  |
| `CA-EXCLUSION-001` | Ensure Conditional Access exclusions are limited to emergency access and documented groups | follow-up | FU-6 |  |
| `CA-INTUNE-001` | Ensure sign-in frequency for Intune Enrollment is set to 'Every time' | follow-up | FU-6 |  |
| `CA-LEGACYAUTH-001` | Ensure Conditional Access blocks legacy authentication for all users | merged | `identity.legacy_auth_blocked` (planned) |  |
| `CA-MFA-ADMIN-001` | Ensure administrative roles require phishing-resistant MFA (plain MFA is partial) | merged | `identity.phishing_resistant_admins` (planned) |  |
| `CA-MFA-ALL-001` | Ensure multifactor authentication is required for all users and all resources | merged | `identity.baseline` (planned) |  |
| `CA-PAW-001` | Ensure privileged roles can sign in only from filtered or compliant devices (PAW) | follow-up | FU-6 |  |
| `CA-PHISHRES-001` | Ensure 'Phishing-resistant MFA strength' is required for Administrators | merged | `identity.phishing_resistant_admins` (planned) |  |
| `CA-PHISHRES-002` | Ensure phishing-resistant MFA strength is required for all users | follow-up | FU-6 |  |
| `CA-RISKPOLICY-001` | CA policy combines sign-in risk and user risk (anti-pattern) | follow-up | FU-6 |  |
| `CA-ROLECOVERAGE-001` | Ensure every Tier-0 and Tier-1 role is covered by an MFA Conditional Access policy | merged | `identity.mfa_admins` (planned) |  |
| `CA-SIGNIN-FREQ-001` | Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users | follow-up | FU-6 |  |
| `CA-SIGNINRISK-001` | Enable Identity Protection sign-in risk policies | merged | `identity.baseline` (planned) |  |
| `CA-SIGNINRISK-002` | Ensure 'sign-in risk' is blocked for medium and high risk | merged | `identity.baseline` (planned) | Manual in M365-Secure; covered by the risky sign-in leg of the baseline. |
| `CA-USERRISK-001` | Enable Identity Protection user risk policies | merged | `identity.baseline` (planned) |  |
| `COMPLIANCE-ALERTPOLICY-001` | Security Alert Policies Configuration | follow-up | FU-5 |  |
| `COMPLIANCE-AUDIT-001` | Ensure Microsoft 365 audit log search is Enabled (retired: replaced by PURVIEW-AUDIT-001) | dropped |  | Retired in M365-Secure (replaced by PURVIEW-AUDIT-001). |
| `COMPLIANCE-COMMS-001` | Communication Compliance Policies Enabled | follow-up | FU-5 |  |
| `COMPLIANCE-DLP-001` | Ensure DLP policies are enabled | follow-up | FU-5 |  |
| `COMPLIANCE-DLP-002` | DLP policies cover standard sensitive information types (PII, PCI, PHI) | follow-up | FU-5 |  |
| `COMPLIANCE-DLP-003` | DLP policies cover Teams and SharePoint content | follow-up | FU-5 |  |
| `COMPLIANCE-LABELS-001` | Ensure Information Protection sensitivity label policies are published | follow-up | FU-5 |  |
| `COMPLIANCE-LABELS-002` | Ensure a default sensitivity label is set in the label policy | follow-up | FU-5 |  |
| `DEFENDER-ANTIMALWARE-001` | Ensure the Common Attachment Types Filter is enabled | follow-up | FU-1 |  |
| `DEFENDER-ANTIMALWARE-002` | Dangerous executable file types are blocked in mail flow | follow-up | FU-1 |  |
| `DEFENDER-ANTIPHISH-001` | Ensure that an anti-phishing policy has been created | follow-up | FU-1 |  |
| `DEFENDER-ANTISPAM-001` | Anti-spam policies and filters are configured | follow-up | FU-1 |  |
| `DEFENDER-ANTISPAM-002` | Outbound spam notifications alert administrators (retired: replaced by EXO-ANTISPAM-ALLOW-001) | dropped |  | Retired in M365-Secure (replaced by EXO-ANTISPAM-ALLOW-001). |
| `DEFENDER-CLOUDAPPS-001` | Ensure Microsoft Defender for Cloud Apps is enabled and configured | follow-up | FU-13 |  |
| `DEFENDER-MALWARE-002` | Detected malware is quarantined with admin notification | follow-up | FU-1 |  |
| `DEFENDER-OUTBOUND-001` | Ensure outbound anti-spam message limits are in place | follow-up | FU-1 |  |
| `DEFENDER-PRESET-001` | Ensure the Standard preset security policy is enabled for all recipients | merged | `email.preset_policies` (planned) |  |
| `DEFENDER-PRESET-002` | Ensure the Strict preset or impersonation protection covers high-value users | merged | `email.preset_policies` (planned) |  |
| `DEFENDER-PRIORITY-001` | Ensure Priority account protection is enabled and configured | follow-up | FU-1 |  |
| `DEFENDER-PRIORITY-002` | Priority account monitoring and enhanced alerting is enabled | follow-up | FU-1 |  |
| `DEFENDER-PRIORITY-003` | Ensure high-value users are tagged as priority accounts | follow-up | FU-1 |  |
| `DEFENDER-SAFEATTACH-001` | Ensure Safe Attachments policy is enabled | follow-up | FU-1 |  |
| `DEFENDER-SAFEATTACH-002` | Ensure Safe Attachments for SharePoint OneDrive and Microsoft Teams is Enabled | follow-up | FU-1 |  |
| `DEFENDER-SAFELINKS-001` | Ensure Safe Links for Office Applications is Enabled | follow-up | FU-1 |  |
| `DEFENDER-SECURESCORE-001` | Microsoft Secure Score (informational) | dropped |  | Informational Secure Score readout, not a pass/fail control; Junction has its own score. |
| `DEFENDER-ZAP-001` | Zero-hour auto purge is enabled for phishing, spam and malware in email | follow-up | FU-1 |  |
| `DNS-DKIM-001` | Ensure that DKIM is enabled for all Exchange Online Domains | merged | `email.dkim` (planned) |  |
| `DNS-DMARC-001` | Ensure DMARC Records for all Exchange Online domains are published | merged | `email.dmarc` (planned) |  |
| `DNS-SPF-001` | Ensure that SPF records are published for all Exchange Domains | merged | `email.spf` (planned) |  |
| `ENTRA-ADMIN-001` | Ensure that between two and four global admins are designated | merged | `identity.global_admin_count` |  |
| `ENTRA-ADMIN-002` | Privileged role inventory | dropped |  | Privileged role inventory (Info only). |
| `ENTRA-ADMIN-003` | Ensure admin accounts are dedicated (no account holds 3 or more privileged roles) | merged | `identity.separate_admin_accounts` (planned) |  |
| `ENTRA-ADMIN-004` | Ensure privileged accounts inactive for 45 days are removed | follow-up | FU-7 |  |
| `ENTRA-APPREG-001` | App registration inventory | dropped |  | App registration inventory (Info only). |
| `ENTRA-APPREG-002` | Ensure app registration secrets and certificates are not expired | new | `apps.credential_expiry` |  |
| `ENTRA-APPREG-003` | App registrations requesting more than 10 Microsoft Graph permissions | follow-up | FU-9 |  |
| `ENTRA-APPREG-004` | Apps with wildcard redirect URIs (open redirect risk) | follow-up | FU-9 |  |
| `ENTRA-APPREG-005` | Ensure app registrations with high-impact application permissions do not use client secrets | new | `apps.privileged_app_secrets` |  |
| `ENTRA-APPREG-006` | Ensure the default app management policy restricts password credentials | new | `apps.app_management_policy` |  |
| `ENTRA-APPS-001` | Ensure third party integrated applications are not allowed | new | `apps.users_cannot_register_apps` | Missing field gives unknown (M365-Secure: Warning). |
| `ENTRA-APPS-002` | App registrations with dangerous Intune write permissions | follow-up | FU-9 |  |
| `ENTRA-AUTHMETHOD-001` | Ensure weak authentication methods are disabled | follow-up | FU-7 |  |
| `ENTRA-AUTHMETHOD-002` | Ensure the email OTP authentication method is disabled | follow-up | FU-7 |  |
| `ENTRA-AUTHMETHOD-003` | Ensure Microsoft Authenticator is configured to protect against MFA fatigue | follow-up | FU-7 |  |
| `ENTRA-AUTHMETHOD-004` | Ensure system-preferred multifactor authentication is enabled | follow-up | FU-7 |  |
| `ENTRA-AUTHMETHOD-005` | Ensure the authentication methods policy migration is complete | follow-up | FU-7 |  |
| `ENTRA-BREAKGLASS-001` | Ensure two cloud-only emergency access accounts use FIDO2 or certificate authentication | merged | `identity.break_glass` (planned) |  |
| `ENTRA-CA-001` | Ensure at least one enabled Conditional Access policy requires MFA | merged | `identity.baseline` (planned) |  |
| `ENTRA-CA-002` | Ensure at least one enabled Conditional Access policy targets All users | merged | `identity.baseline` (planned) |  |
| `ENTRA-CA-003` | Ensure no enabled Conditional Access policy has more than 5 exclusions | follow-up | FU-6 |  |
| `ENTRA-CLOUDADMIN-001` | Ensure administrative accounts are cloud-only | follow-up | FU-7 |  |
| `ENTRA-CLOUDADMIN-002` | Ensure administrative accounts use licenses with a reduced application footprint | merged | `identity.separate_admin_accounts` (planned) | Licence footprint heuristic. |
| `ENTRA-CONSENT-001` | Ensure user consent to apps accessing company data on their behalf is not allowed | new | `apps.user_consent_restricted` |  |
| `ENTRA-CONSENT-002` | Ensure the admin consent workflow is enabled | new | `apps.admin_consent_workflow` |  |
| `ENTRA-CONSENT-003` | User consent restricted to verified publishers only | new | `apps.user_consent_restricted` | Same setting as ENTRA-CONSENT-001 (verified publishers, low impact passes). |
| `ENTRA-CONSENT-004` | Tenant-wide admin consent grants to third-party apps | follow-up | FU-9 |  |
| `ENTRA-DAP-001` | Ensure no partner holds directory roles through legacy delegated admin privileges (DAP) | follow-up | FU-7 |  |
| `ENTRA-DEVICE-001` | Ensure the ability to join devices to Entra is restricted | follow-up | FU-7 |  |
| `ENTRA-DEVICE-002` | Ensure the maximum number of devices per user is limited | follow-up | FU-7 |  |
| `ENTRA-DEVICE-003` | Ensure the GA role is not added as a local administrator during Entra join | merged | `intune.local_admin` (planned) |  |
| `ENTRA-DEVICE-004` | Ensure local administrator assignment is limited during Entra join | merged | `intune.local_admin` (planned) |  |
| `ENTRA-DEVICE-005` | Ensure Local Administrator Password Solution is enabled | merged | `intune.laps` (planned) |  |
| `ENTRA-DEVICE-006` | Ensure users are restricted from recovering BitLocker keys | follow-up | FU-7 |  |
| `ENTRA-ENTAPP-001` | Enterprise application inventory | dropped |  | Enterprise application inventory (Info only). |
| `ENTRA-ENTAPP-002` | Disabled enterprise applications still present | dropped |  | Disabled service principals still present: hygiene note (Pass or Info only). |
| `ENTRA-ENTAPP-003` | Third-party enterprise applications without 'Assignment required' | new | `apps.assignment_required` |  |
| `ENTRA-ENTAPP-004` | Third-party applications granted high-impact permissions | new | `apps.high_privilege_permissions` |  |
| `ENTRA-ENTAPP-005` | Service principals carrying password credentials | new | `apps.sp_password_credentials` |  |
| `ENTRA-ENTAPP-006` | Apps with excessive permission count (>10 application permissions) | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-007` | App instance property lock not enabled | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-008` | Managed identities with dangerous application permissions | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-009` | Managed identities with Entra directory roles | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-010` | Internal apps with Tier 0 application permissions (Global Admin escalation paths) | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-011` | Foreign apps with Tier 1 data access permissions (Mail, Files, Sites) | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-012` | Apps using client secrets instead of certificates | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-013` | Apps with expired credentials still present | new | `apps.credential_expiry` | Expired credentials are the fail branch of apps.credential_expiry. |
| `ENTRA-ENTAPP-014` | Apps with both secret and certificate credentials (dual credential types) | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-015` | Service principals with client secret and permanent privileged directory role | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-016` | Tier 0 permission apps with owners assigned (owner can impersonate) | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-017` | Apps with directory roles that have owners assigned | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-018` | Credentialed apps with no owners (orphaned) | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-019` | Tier 0 apps with no sign-in activity (unused privileged permissions) | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-020` | Foreign apps impersonating Microsoft product display names | follow-up | FU-9 |  |
| `ENTRA-ENTAPP-021` | Multi-tenant app registrations (AzureADMultipleOrgs) | new | `apps.multi_tenant_apps` | Registry-only in M365-Secure (no automated logic); new Junction logic. |
| `ENTRA-ENTAPP-022` | High-privilege service principals without an owner or without a sign-in in 90 days | follow-up | FU-9 |  |
| `ENTRA-GROUP-001` | Ensure users cannot create security groups | new | `collaboration.group_creation_restricted` | Registry-only in M365-Secure; Junction also warns when Microsoft 365 group creation is open. |
| `ENTRA-GROUP-002` | Ensure a dynamic group for guest users is created | follow-up | FU-10 |  |
| `ENTRA-GROUP-003` | Ensure that only organizationally managed/approved public groups exist | follow-up | FU-10 |  |
| `ENTRA-GROUP-004` | Dynamic groups with user-controllable membership rules in privileged contexts | follow-up | FU-10 |  |
| `ENTRA-GROUP-005` | Sensitive groups not protected with role-assignable flag | follow-up | FU-10 |  |
| `ENTRA-GROUP-006` | Public M365 groups count | dropped |  | Count of public Microsoft 365 groups (inventory). |
| `ENTRA-GUEST-001` | Ensure that guest user access is restricted | new | `collaboration.guest_access_restricted` |  |
| `ENTRA-GUEST-002` | Ensure guest user invitations are limited to the Guest Inviter role | new | `collaboration.guest_invites_restricted` |  |
| `ENTRA-GUEST-003` | Ensure email-verified users cannot self-join the organisation | new | `collaboration.email_verified_join_blocked` | Missing field gives unknown (M365-Secure: Pass). |
| `ENTRA-GUEST-004` | Ensure that collaboration invitations are sent to allowed domains only | follow-up | FU-14 |  |
| `ENTRA-HYBRID-001` | Directory synchronisation completed within the last 6 hours | follow-up | FU-7 |  |
| `ENTRA-HYBRID-002` | On-premises synced users holding Tier-0/1 Entra roles | follow-up | FU-7 |  |
| `ENTRA-HYBRID-003` | Ensure all verified domains use managed authentication with password hash sync | follow-up | FU-7 |  |
| `ENTRA-LINKEDIN-001` | Ensure 'LinkedIn account connections' is disabled | follow-up | FU-14 |  |
| `ENTRA-MFA-001` | Ensure all member users are 'MFA capable' | merged | `identity.mfa_coverage` (planned) |  |
| `ENTRA-MFA-002` | Percentage of users without MFA method registered | merged | `identity.mfa_coverage` (planned) |  |
| `ENTRA-ORGSETTING-001` | Ensure 'User owned apps and services' is restricted | follow-up | FU-14 |  |
| `ENTRA-ORGSETTING-002` | Ensure internal phishing protection for Forms is enabled | follow-up | FU-10 |  |
| `ENTRA-ORGSETTING-003` | Ensure 'third-party storage services' are restricted in 'Microsoft 365 on the web' | follow-up | FU-14 |  |
| `ENTRA-ORGSETTING-004` | Ensure shared bookings pages are restricted to select users | follow-up | FU-14 |  |
| `ENTRA-PASSWORD-001` | Ensure a passwordless authentication method is enabled | follow-up | FU-7 |  |
| `ENTRA-PASSWORD-002` | Ensure custom banned passwords lists are used | follow-up | FU-7 |  |
| `ENTRA-PASSWORD-003` | Smart Lockout Threshold | follow-up | FU-7 |  |
| `ENTRA-PASSWORD-004` | Custom Banned Password Count | follow-up | FU-7 |  |
| `ENTRA-PASSWORD-005` | Ensure password protection is enabled for on-prem Active Directory | follow-up | FU-7 |  |
| `ENTRA-PERUSER-001` | Ensure 'Per-user MFA' is disabled | follow-up | FU-7 |  |
| `ENTRA-PIM-001` | Ensure 'Privileged Identity Management' is used to manage roles | merged | `identity.pim_used` (planned) |  |
| `ENTRA-PIM-002` | Ensure 'Access reviews' for Guest Users are configured | follow-up | FU-8 |  |
| `ENTRA-PIM-003` | Ensure 'Access reviews' for privileged roles are configured | follow-up | FU-8 |  |
| `ENTRA-PIM-004` | Ensure approval is required for Global Administrator role activation | follow-up | FU-8 |  |
| `ENTRA-PIM-005` | Ensure approval is required for Privileged Role Administrator activation | follow-up | FU-8 |  |
| `ENTRA-PIM-006` | Ensure Tier-0 role activation is limited to 8 hours or less | follow-up | FU-8 |  |
| `ENTRA-PIM-007` | Justification not required on Tier-0 role activation | follow-up | FU-8 |  |
| `ENTRA-PIM-008` | MFA not required on Tier-0 role activation | follow-up | FU-8 |  |
| `ENTRA-PIM-009` | Permanent eligible assignments allowed for Tier-0 roles | follow-up | FU-8 |  |
| `ENTRA-PIM-010` | No admin notification on Tier-0 role activation | follow-up | FU-8 |  |
| `ENTRA-ROLEGROUP-001` | Unprotected groups in privileged role assignments | follow-up | FU-7 |  |
| `ENTRA-SECDEFAULT-001` | Ensure Security Defaults are enabled or replaced by an all-users MFA policy | merged | `identity.baseline` (planned) |  |
| `ENTRA-SECDEFAULT-002` | Security Defaults Gap Analysis (CA Coverage) | merged | `identity.baseline` (planned) | Manual gap analysis in M365-Secure. |
| `ENTRA-SESSION-001` | Ensure the option to remain signed in is hidden | follow-up | FU-7 |  |
| `ENTRA-SSPR-001` | Ensure 'Self service password reset enabled' is set to 'All' | follow-up | FU-7 |  |
| `ENTRA-SSPR-002` | SSPR enabled for admin accounts | follow-up | FU-7 |  |
| `ENTRA-STALEADMIN-001` | Admin accounts inactive for more than 90 days | follow-up | FU-7 |  |
| `ENTRA-SYNCADMIN-001` | On-premises synced admin accounts (compromise path) | follow-up | FU-7 |  |
| `ENTRA-TENANT-001` | Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes' | follow-up | FU-7 |  |
| `ENTRA-XTAP-001` | Ensure default inbound cross-tenant B2B collaboration is restricted | follow-up | FU-10 |  |
| `EXO-ADDINS-001` | Ensure users installing Outlook add-ins is not allowed | follow-up | FU-1 |  |
| `EXO-ANTIPHISH-001` | Anti-Phishing Policy Configuration | follow-up | FU-1 |  |
| `EXO-ANTISPAM-001` | Anti-Spam Policy Configuration | follow-up | FU-1 |  |
| `EXO-ANTISPAM-ALLOW-001` | Ensure inbound anti-spam policies do not contain allowed sender domains | follow-up | FU-1 |  |
| `EXO-APPRBAC-001` | Ensure applications with mailbox application permissions are scoped by an application access policy or RBAC for Applications | follow-up | FU-1 |  |
| `EXO-AUDIT-001` | Ensure 'AuditDisabled' organizationally is set to 'False' | merged | `email.mailbox_audit` (planned) |  |
| `EXO-AUDIT-002` | Ensure 'AuditBypassEnabled' is not enabled on mailboxes | merged | `email.mailbox_audit` (planned) |  |
| `EXO-AUDIT-003` | Ensure mailbox audit actions are configured | merged | `email.mailbox_audit` (planned) |  |
| `EXO-AUTH-001` | Ensure modern authentication for Exchange Online is enabled | follow-up | FU-1 |  |
| `EXO-AUTH-002` | Ensure SMTP AUTH is disabled | follow-up | FU-1 |  |
| `EXO-CONNFILTER-001` | Ensure the connection filter IP allow list is not used | follow-up | FU-1 |  |
| `EXO-CONNFILTER-002` | Ensure the connection filter safe list is off | follow-up | FU-1 |  |
| `EXO-DIRECTSEND-001` | Ensure Direct Send is not allowed for unauthorized relay | follow-up | FU-1 |  |
| `EXO-EXTTAG-001` | Ensure email from external senders is identified | merged | `email.external_sender_tag` (planned) |  |
| `EXO-FORWARD-001` | Ensure all forms of mail forwarding are blocked and/or disabled | merged | `email.auto_forward_blocked` (planned) |  |
| `EXO-HIDDEN-001` | Ensure no user mailboxes are hidden from the Global Address List | follow-up | FU-1 |  |
| `EXO-LOCKBOX-001` | Ensure the customer lockbox feature is enabled | follow-up | FU-1 |  |
| `EXO-MAILTIPS-001` | Ensure MailTips are enabled for end users | follow-up | FU-1 |  |
| `EXO-MALWARE-001` | Malware Filter Policy Configuration | follow-up | FU-1 |  |
| `EXO-OWA-001` | Ensure additional storage providers are restricted in Outlook on the web | follow-up | FU-1 |  |
| `EXO-SHAREDMBX-001` | Ensure sign-in to shared mailboxes is blocked | follow-up | FU-1 |  |
| `EXO-SHARING-001` | Ensure 'External sharing' of calendars is not available | follow-up | FU-1 |  |
| `EXO-TRANSPORT-001` | Ensure mail transport rules do not whitelist specific domains | follow-up | FU-1 |  |
| `EXO-TRANSPORT-002` | Transport Rule Configuration for External Forwarding | merged | `email.auto_forward_blocked` (planned) | Manual in M365-Secure; the transport rule leg of auto-forwarding. |
| `FORMS-CONFIG-001` | Ensure external users cannot respond to Microsoft Forms | follow-up | FU-10 |  |
| `FORMS-CONFIG-002` | Ensure external users cannot collaborate on Microsoft Forms | follow-up | FU-10 |  |
| `FORMS-CONFIG-003` | Ensure respondent identity recording is enabled by default in Forms | follow-up | FU-10 |  |
| `FORMS-CONFIG-004` | Ensure Microsoft Forms phishing protection is enabled | follow-up | FU-10 |  |
| `FORMS-CONFIG-005` | Ensure Bing image and video search is disabled in Forms | follow-up | FU-10 |  |
| `FORMS-CONFIG-006` | Ensure Forms survey sharing defaults to internal-only | follow-up | FU-10 |  |
| `INTUNE-ASR-001` | Ensure attack surface reduction rules are in block mode on Windows devices | merged | `endpoint.asr_quick_wins` (planned) |  |
| `INTUNE-COMPLIANCE-001` | Ensure every platform in use has an assigned device compliance policy | merged | `intune.compliance_policy` (planned) |  |
| `INTUNE-COMPLIANCE-002` | Ensure devices without a compliance policy are marked 'not compliant' | merged | `intune.compliance_policy` (planned) |  |
| `INTUNE-CONFIG-001` | Device configuration profile inventory | dropped |  | Configuration profile inventory (Info only). |
| `INTUNE-DEVICES-001` | Intune managed device inventory | dropped |  | Managed device inventory (Info only). |
| `INTUNE-ENCRYPTION-001` | Ensure BitLocker and FileVault disk encryption policies are assigned | merged | `intune.bitlocker_escrow` (planned) | Partial: escrow implies an encryption policy; policy assignment itself is not checked. |
| `INTUNE-ENROLL-001` | Device enrollment restrictions are configured beyond the defaults | follow-up | FU-11 |  |
| `INTUNE-ENROLLMENT-001` | Device Enrollment Restrictions | follow-up | FU-11 |  |
| `INTUNE-MACRO-001` | Ensure Office macros are blocked from the internet and disabled without notification via Intune | merged | `intune.office_macros` (planned) |  |
| `INTUNE-MULTIAPPROVAL-001` | Ensure multi-admin approval covers device wipe, retire, delete, scripts and apps | follow-up | FU-11 |  |
| `INTUNE-RBAC-001` | Ensure Intune role assignments use custom scope tags | follow-up | FU-11 |  |
| `INTUNE-SCOPETAGS-001` | RBAC scope tags are used to segment Intune management | follow-up | FU-11 |  |
| `INTUNE-SECURITY-001` | Ensure an antivirus policy or security baseline and an ASR policy are assigned | follow-up | FU-11 |  |
| `INTUNE-SETTINGS-001` | Settings Catalog policy inventory | dropped |  | Settings Catalog inventory (Info only). |
| `INTUNE-UPDATE-001` | Ensure Windows update rings install quality updates within a month (or Windows Autopatch) | merged | `intune.update_rings` (planned) |  |
| `INTUNE-WDAC-001` | Ensure App Control for Business (or AppLocker) is enforced on workstations | follow-up | FU-11 |  |
| `INTUNE-WIPAUDIT-001` | Mass device wipe activity detected (attack indicator) | follow-up | FU-15 |  |
| `INV-GROUPS-001` | Group inventory by type | dropped |  | Inventory report. |
| `INV-SITES-001` | SharePoint site inventory | dropped |  | Inventory report. |
| `INV-TEAMS-001` | Teams inventory | dropped |  | Inventory report. |
| `INV-USERS-001` | User account inventory | dropped |  | Inventory report. |
| `LIC-OVERALLOC-001` | No license SKU has more consumed than prepaid seats | dropped |  | Licence seat accounting, not a security control. |
| `LIC-SUMMARY-001` | Subscribed license SKU summary | dropped |  | Licence inventory. |
| `LIC-TIER-001` | Premium license tier detection (E5 / P2 / Defender plans) | dropped |  | Licence tier detection; Junction's licence pre-flight (data/licensing.yaml) replaces it. |
| `LOG-DETECT-001` | Enabled detection rules across Sentinel and Defender XDR | merged | `sentinel.rules_enabled` (planned) |  |
| `LOG-DIAG-001` | Entra ID sign-in and audit logs exported through diagnostic settings | follow-up | FU-12 |  |
| `LOG-RETENTION-001` | Log Analytics workspaces receiving Entra logs retain for at least 12 months | merged | `sentinel.retention` (planned) |  |
| `LOG-SENTINEL-001` | Microsoft Sentinel ingests Microsoft 365 data and runs enabled analytics rules | merged | `sentinel.connectors` (planned) |  |
| `MDE-ONBOARD-001` | Ensure managed endpoints are onboarded to Defender for Endpoint and active | merged | `endpoint.onboarding_coverage` (planned) |  |
| `MDE-TAMPER-001` | Ensure tamper protection is enabled on Defender for Endpoint devices | merged | `endpoint.tamper_protection` (planned) |  |
| `MDI-SENSOR-001` | Ensure Defender for Identity sensors are deployed and healthy | follow-up | FU-13 |  |
| `POWERBI-AUTH-001` | Ensure service principal use of Power BI APIs is restricted to security groups | follow-up | FU-4 |  |
| `POWERBI-AUTH-002` | Ensure Power BI API access is controlled (ResourceKey authentication blocked) | follow-up | FU-4 |  |
| `POWERBI-AUTH-003` | Ensure Power BI content certification is enabled with designated certifiers | follow-up | FU-4 |  |
| `POWERBI-GUEST-001` | Ensure guest user access is restricted in Power BI | follow-up | FU-4 |  |
| `POWERBI-GUEST-002` | Ensure guest users cannot edit and manage content in Power BI | follow-up | FU-4 |  |
| `POWERBI-GUEST-003` | Ensure guest users cannot browse Power BI content | follow-up | FU-4 |  |
| `POWERBI-INFOPROT-001` | Ensure 'Allow users to apply sensitivity labels for content' is 'Enabled' in Power BI | follow-up | FU-4 |  |
| `POWERBI-SHARING-001` | Ensure guest users cannot share Power BI content with external users | follow-up | FU-4 |  |
| `POWERBI-SHARING-002` | Ensure 'Publish to web' is restricted in Power BI | follow-up | FU-4 |  |
| `POWERBI-SHARING-003` | Ensure copying visuals as images is controlled in Power BI | follow-up | FU-4 |  |
| `POWERBI-SHARING-004` | Ensure enabling of external data sharing is restricted in Power BI | follow-up | FU-4 |  |
| `POWERBI-TENANT-001` | Power BI External Sharing Configuration | follow-up | FU-4 |  |
| `POWERBI-TENANT-002` | Power BI Publish to Web Configuration | follow-up | FU-4 |  |
| `POWERBI-TENANT-003` | Power BI Guest Access Configuration | follow-up | FU-4 |  |
| `PP-GOVERNANCE-001` | Power Platform rule-based data policies govern connectors for agents and flows | follow-up | FU-4 |  |
| `PURVIEW-AUDIT-001` | Unified Audit Logging Enabled | follow-up | FU-5 |  |
| `PURVIEW-RETENTION-001` | Retention labels are defined | follow-up | FU-5 |  |
| `PURVIEW-RETENTION-002` | Retention labels have retention durations configured | follow-up | FU-5 |  |
| `PURVIEW-RETENTION-003` | Retention labels are published or auto-applied | follow-up | FU-5 |  |
| `PURVIEW-RETENTION-004` | Event-based retention event types are configured | follow-up | FU-5 |  |
| `PURVIEW-RETENTION-005` | Overall retention configuration readiness (labels and event types) | dropped |  | Roll-up of PURVIEW-RETENTION-001 to 004, no data of its own. |
| `SOC2-AUDIT-001` | Unified audit logging is enabled and accessible (SOC 2 evidence) | dropped |  | SOC 2 roll-up that restates other checks; Junction expresses frameworks as tags, not extra checks. |
| `SOC2-C1-001` | C1.1 Confidential information is identified and classified | dropped |  | SOC 2 roll-up that restates other checks; Junction expresses frameworks as tags, not extra checks. |
| `SOC2-C2-001` | C2.1 Confidential information is disposed of securely | dropped |  | SOC 2 roll-up that restates other checks; Junction expresses frameworks as tags, not extra checks. |
| `SOC2-CC6-001` | CC6.1 Logical access security controls for user authentication | dropped |  | SOC 2 roll-up that restates other checks; Junction expresses frameworks as tags, not extra checks. |
| `SOC2-CC6-002` | CC6.3 Controls over privileged access and administrative accounts | dropped |  | SOC 2 roll-up that restates other checks; Junction expresses frameworks as tags, not extra checks. |
| `SOC2-CC7-001` | CC7.2 Monitoring of system components for anomalies and security events | dropped |  | SOC 2 roll-up that restates other checks; Junction expresses frameworks as tags, not extra checks. |
| `SOC2-CC7-002` | CC7.4 Incident response procedures and notification | dropped |  | SOC 2 roll-up that restates other checks; Junction expresses frameworks as tags, not extra checks. |
| `SOC2-CC8-001` | CC8.1 Changes to infrastructure and software are authorized and managed | dropped |  | SOC 2 roll-up that restates other checks; Junction expresses frameworks as tags, not extra checks. |
| `SOC2-CC9-001` | CC9.2 Risk assessment and management of third-party service providers | dropped |  | SOC 2 roll-up that restates other checks; Junction expresses frameworks as tags, not extra checks. |
| `SOC2-MANUAL-001` | Security awareness training is conducted annually (manual evidence) | dropped |  | Organisational process evidence (training, HR, BCP, risk), outside a tenant posture tool. |
| `SOC2-MANUAL-002` | Background checks are performed for staff with sensitive access (manual evidence) | dropped |  | Organisational process evidence (training, HR, BCP, risk), outside a tenant posture tool. |
| `SOC2-MANUAL-003` | Business continuity and disaster recovery plan exists and is tested annually (manual evidence) | dropped |  | Organisational process evidence (training, HR, BCP, risk), outside a tenant posture tool. |
| `SOC2-MANUAL-004` | Formal risk assessment is performed annually (manual evidence) | dropped |  | Organisational process evidence (training, HR, BCP, risk), outside a tenant posture tool. |
| `SOC2-MANUAL-005` | Acceptable use policy exists and is acknowledged by all staff (manual evidence) | dropped |  | Organisational process evidence (training, HR, BCP, risk), outside a tenant posture tool. |
| `SPO-AUTH-001` | Ensure modern authentication for SharePoint applications is required | new | `collaboration.sharepoint_legacy_auth_blocked` |  |
| `SPO-B2B-001` | Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled | follow-up | FU-2 |  |
| `SPO-DAG-001` | Ensure data access governance (oversharing) reports are run at least quarterly | follow-up | FU-14 |  |
| `SPO-LOOP-001` | Loop Components Enabled | dropped |  | Posture note (Info only). |
| `SPO-LOOP-002` | OneDrive Loop Sharing | follow-up | FU-2 |  |
| `SPO-MALWARE-002` | Ensure Office 365 SharePoint infected files are disallowed for download | follow-up | FU-2 |  |
| `SPO-OD-001` | Ensure OneDrive content sharing is restricted | follow-up | FU-2 |  |
| `SPO-RCD-001` | Ensure SharePoint restricted access control is enabled (SharePoint Advanced Management) | follow-up | FU-2 |  |
| `SPO-SCRIPT-001` | Ensure custom script execution is restricted on personal sites | follow-up | FU-2 |  |
| `SPO-SCRIPT-002` | Ensure custom script execution is restricted on site collections | follow-up | FU-2 |  |
| `SPO-SESSION-001` | Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices | new | `collaboration.idle_session_signout` |  |
| `SPO-SHARING-001` | Ensure external content sharing is restricted | new | `collaboration.sharepoint_external_sharing` | Graph sharepointSettings only: 'Anyone' is a fail (M365-Secure's warn branch needs CSOM link expiry). |
| `SPO-SHARING-002` | Ensure that SharePoint guest users cannot share items they don't own | new | `collaboration.external_resharing_blocked` |  |
| `SPO-SHARING-003` | Ensure SharePoint external sharing is managed through domain whitelist/blacklists | new | `collaboration.sharing_domain_restriction` |  |
| `SPO-SHARING-004` | Ensure link sharing is restricted in SharePoint and OneDrive | follow-up | FU-2 |  |
| `SPO-SHARING-005` | Ensure guest access to a site or OneDrive will expire automatically | follow-up | FU-2 |  |
| `SPO-SHARING-006` | Ensure reauthentication with verification code is restricted | follow-up | FU-2 |  |
| `SPO-SHARING-007` | Ensure the SharePoint default sharing link permission is set | follow-up | FU-2 |  |
| `SPO-SHARING-008` | Ensure external sharing is restricted by security group | follow-up | FU-2 |  |
| `SPO-SHARING-009` | Ensure Anyone links expire within 30 days and are view-only | follow-up | FU-2 |  |
| `SPO-SWAY-001` | Ensure that Sways cannot be shared with people outside of your organization | follow-up | FU-14 |  |
| `SPO-SYNC-001` | Ensure OneDrive sync is restricted for unmanaged devices | new | `collaboration.unmanaged_sync_restricted` |  |
| `SPO-SYNC-002` | Mac Sync App Enabled | dropped |  | Posture note (Info only). |
| `TEAMS-APPS-001` | Chat Resource-Specific Consent Enabled | follow-up | FU-3 |  |
| `TEAMS-APPS-002` | Ensure app permission policies are configured | follow-up | FU-3 |  |
| `TEAMS-APPS-003` | Ensure users cannot upload custom apps (sideloading) in the Global app setup policy | follow-up | FU-3 |  |
| `TEAMS-CLIENT-001` | Ensure external file sharing in Teams is enabled for only approved cloud storage services | follow-up | FU-3 |  |
| `TEAMS-CLIENT-002` | Ensure users can't send emails to a channel email address | follow-up | FU-3 |  |
| `TEAMS-EXTACCESS-001` | Ensure communication with unmanaged Teams users is disabled | follow-up | FU-3 |  |
| `TEAMS-EXTACCESS-002` | Ensure external Teams users cannot initiate conversations | follow-up | FU-3 |  |
| `TEAMS-EXTACCESS-003` | Ensure external domains are restricted in the Teams admin center | follow-up | FU-3 |  |
| `TEAMS-EXTACCESS-004` | Ensure communication with Skype users is disabled | follow-up | FU-3 |  |
| `TEAMS-GUEST-001` | Guest Access to Teams | follow-up | FU-3 |  |
| `TEAMS-INFO-001` | Teams Workload Active | dropped |  | Workload-active note (Info only). |
| `TEAMS-MEETING-001` | Ensure anonymous users can't join a meeting | follow-up | FU-3 |  |
| `TEAMS-MEETING-002` | Ensure anonymous users and dial-in callers can't start a meeting | follow-up | FU-3 |  |
| `TEAMS-MEETING-003` | Ensure only people in my org can bypass the lobby | follow-up | FU-3 |  |
| `TEAMS-MEETING-004` | Ensure users dialing in can't bypass the lobby | follow-up | FU-3 |  |
| `TEAMS-MEETING-005` | Ensure external participants can't give or request control | follow-up | FU-3 |  |
| `TEAMS-MEETING-006` | Ensure meeting chat does not allow anonymous users | follow-up | FU-3 |  |
| `TEAMS-MEETING-007` | Ensure only organizers and co-organizers can present | follow-up | FU-3 |  |
| `TEAMS-MEETING-008` | Ensure external meeting chat is off | follow-up | FU-3 |  |
| `TEAMS-MEETING-009` | Ensure meeting recording is off by default | follow-up | FU-3 |  |
| `TEAMS-PRIVATE-001` | Ensure every team has at least two owners; public teams and teams with guests are reviewed | follow-up | FU-10 |  |
| `TEAMS-REPORTING-001` | Ensure users can report security concerns in Teams | follow-up | FU-3 |  |
| `VALUE-ADOPT-001` | Licensed security features are actively in use | dropped |  | Value-opportunity (licence adoption and utilisation) report, not a security check. |
| `VALUE-READY-001` | Licensed security features not yet deployed | dropped |  | Value-opportunity (licence adoption and utilisation) report, not a security check. |
| `VALUE-READY-002` | Security features available via license upgrade | dropped |  | Value-opportunity (licence adoption and utilisation) report, not a security check. |
| `VALUE-UTIL-001` | License SKUs below 50% utilisation | dropped |  | Value-opportunity (licence adoption and utilisation) report, not a security check. |
| `VALUE-UTIL-002` | License SKUs with consumed seats above prepaid seats | dropped |  | Value-opportunity (licence adoption and utilisation) report, not a security check. |
