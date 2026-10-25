# Security posture report

Prepared for Contoso Group.

Run run-20261025 from 2026-10-25T01:00:00Z to 2026-10-25T01:02:00Z with junction 0.0.0-test.

> Read-only assessment of the configuration Microsoft APIs reported at the time of the run. Remediation text is a suggestion only. Junction is not affiliated with or endorsed by Microsoft or the Australian Signals Directorate.

## Tenants

| Tenant | Status | Score | Fail | Warn | Unknown | Not applicable |
|---|---|---:|---:|---:|---:|---:|
| Contoso (00000000-0000-4000-8000-000000000001) | partial (some checks could not run) | 45.3 | 2 | 1 | 1 | 1 |
| Fabrikam (00000000-0000-4000-8000-000000000002) | failed | not assessed | 0 | 0 | 0 | 0 |

## Contoso (00000000-0000-4000-8000-000000000001)

### Summary

- **Status:** partial (some checks could not run)
- **Overall score:** 45.3 (7 checks scored, 2 excluded as unknown or not applicable)
- **Results:** 4 pass, 2 fail, 1 warn, 1 unknown, 1 not applicable
- **Licence features detected:** entra_id_p1, intune

### Score by pack

| Pack | Score | Pass | Fail | Warn | Unknown | Not applicable |
|---|---:|---:|---:|---:|---:|---:|
| Identity | 47.4 | 2 | 1 | 0 | 0 | 0 |
| Endpoint (Defender for Endpoint and ASR) | 16.7 | 0 | 1 | 1 | 0 | 0 |
| Intune, patching and admin rights | 100.0 | 1 | 0 | 0 | 1 | 0 |
| Email | 100.0 | 1 | 0 | 0 | 0 | 0 |
| Backups | not scored | 0 | 0 | 0 | 0 | 1 |

### Top quick wins

1. **Administrators register phishing-resistant MFA** (`identity.mfa_admins`; critical severity, low effort, high impact): 25 of 30 administrators have no phishing-resistant method registered.
2. **No critical application vulnerabilities older than two weeks** (`endpoint.app_vulnerabilities`; high severity, high effort, high impact): 4 devices run applications with critical vulnerabilities.
3. **ASR blocks Office macros from creating executables** (`endpoint.asr_office_macros`; medium severity, low effort, medium impact): The rule is in audit mode on 12 devices.

### Changes since last run

Compared with run run-20260918 (finished 2026-09-18T01:00:00Z).

- **New failures:** `endpoint.app_vulnerabilities`
- **Fixed:** `identity.global_admin_count`
- **New checks:** `backup.m365_backup`
- **No longer run:** `identity.legacy_check`
- **Other status changes:** `endpoint.asr_office_macros` (Pass to Warning)
- **Score change:** down 4.2 points

### Findings

#### Identity

##### Fail: Administrators register phishing-resistant MFA

- **Id:** `identity.mfa_admins`
- **Status:** Fail; **severity:** critical; **effort:** low; **impact:** high
- **Evidence:** 25 of 30 administrators have no phishing-resistant method registered.
- **Affected (25):** admin01@contoso.example, admin02@contoso.example, admin03@contoso.example, admin04@contoso.example, admin05@contoso.example, admin06@contoso.example, admin07@contoso.example, admin08@contoso.example, admin09@contoso.example, admin10@contoso.example, admin11@contoso.example, admin12@contoso.example, admin13@contoso.example, admin14@contoso.example, admin15@contoso.example, admin16@contoso.example, admin17@contoso.example, admin18@contoso.example, admin19@contoso.example, admin20@contoso.example and 5 more
- **Remediation:** Suggested fix for Administrators register phishing-resistant MFA.
- **Links:** <https://learn.microsoft.com/entra/identity/>
- **Frameworks:** E8 mfa ML1/ML2/ML3; ISM-1504; CIS v8 5.4
- **References:** CIS M365 1.1.1

##### Pass: Between two and four Global Administrators

- **Id:** `identity.global_admin_count`
- **Status:** Pass; **severity:** high; **effort:** low; **impact:** high
- **Evidence:** 3 Global Administrators.
- **Frameworks:** E8 restrict-admin-privileges ML1/ML2/ML3; ISM-1507; CIS v8 5.4

##### Pass: Break-glass sign-ins raise an alert

- **Id:** `identity.break_glass_monitored`
- **Status:** Pass; **severity:** medium; **effort:** low; **impact:** medium
- **Evidence:** Attested 'yes' by secops@contoso.example on 2026-10-01.
- **Attested:** yes by secops@contoso.example on 2026-10-01T00:00:00Z, expires 2027-04-01T00:00:00Z. Note: Sentinel rule BG-01 alerts the on-call engineer.
- **Frameworks:** E8 restrict-admin-privileges ML2/ML3; CIS v8 5.4

#### Endpoint (Defender for Endpoint and ASR)

##### Fail: No critical application vulnerabilities older than two weeks

- **Id:** `endpoint.app_vulnerabilities`
- **Status:** Fail; **severity:** high; **effort:** high; **impact:** high
- **Evidence:** 4 devices run applications with critical vulnerabilities.
- **Remediation:** Suggested fix for No critical application vulnerabilities older than two weeks.
- **Links:** <https://learn.microsoft.com/entra/identity/>
- **Frameworks:** E8 patch-applications ML2/ML3; CIS v8 5.4

##### Warning: ASR blocks Office macros from creating executables

- **Id:** `endpoint.asr_office_macros`
- **Status:** Warning; **severity:** medium; **effort:** low; **impact:** medium
- **Evidence:** The rule is in audit mode on 12 devices.
- **Remediation:** Suggested fix for ASR blocks Office macros from creating executables.
- **Links:** <https://learn.microsoft.com/entra/identity/>
- **Frameworks:** E8 office-macros ML1/ML2/ML3; CIS v8 5.4

#### Intune, patching and admin rights

##### Unknown: Windows quality updates install within two weeks

- **Id:** `intune.os_update_rings`
- **Status:** Unknown; **severity:** high; **effort:** medium; **impact:** high
- **Evidence:** Could not read Windows update rings.
- **Reason:** missing_permission: Microsoft Graph returned 403 for update rings. (grant: DeviceManagementConfiguration.Read.All)
- **Frameworks:** E8 patch-operating-systems ML1/ML2/ML3; ISM-1877; CIS v8 5.4

##### Pass: Microsoft 365 Apps update automatically

- **Id:** `intune.app_update_policy`
- **Status:** Pass; **severity:** medium; **effort:** low; **impact:** medium
- **Evidence:** Monthly Enterprise Channel with automatic updates.
- **Frameworks:** E8 patch-applications ML1; CIS v8 5.4

#### Email

##### Pass: DMARC policy is reject or quarantine

- **Id:** `email.dmarc_reject`
- **Status:** Pass; **severity:** low; **effort:** low; **impact:** medium
- **Evidence:** contoso.example publishes p=reject.
- **Frameworks:** CIS v8 5.4

#### Backups

##### Not applicable: Microsoft 365 Backup protects mailboxes and sites

- **Id:** `backup.m365_backup`
- **Status:** Not applicable; **severity:** medium; **effort:** medium; **impact:** medium
- **Evidence:** Microsoft 365 Backup is not licensed.
- **Reason:** missing_licence: Microsoft 365 Backup is not licensed.
- **Frameworks:** E8 regular-backups ML1/ML2/ML3; CIS v8 5.4

## Fabrikam (00000000-0000-4000-8000-000000000002)

### Summary

- **Status:** failed
- **Error:** authentication_failed: The app registration has no consent in this tenant.

This tenant could not be assessed, so it has no score or findings.

