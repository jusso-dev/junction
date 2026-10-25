# Essential Eight coverage

How `junction check` maps to the ASD Essential Eight Maturity Model. The matrix is generated from
the checks' framework tags (`junction check docs`) and a test fails if it is stale.

- **Requirements** are the ISM controls ASD tags with Essential Eight maturity levels. They are synced
  one way from crownguard (`scripts/sync-frameworks.sh`); the strategy each requirement sits under is
  Junction's mapping in `scripts/sync-frameworks.py`.
- **Automated** checks read Microsoft APIs. **Manual** checks are answered by a person with
  `junction check attest` and expire.
- **Gaps** are requirements no check is tagged with. Many are outside what Microsoft 365 APIs can
  show (for example application control on servers, or patching third-party applications without
  Defender Vulnerability Management), and need other evidence.

The maturity estimate in HTML and Markdown reports uses the lowest level fully met per strategy: a
level counts as met only when at least one check is tagged at that level and every check tagged at or
below it passed. It is an **estimate, not an assessment**: the Essential Eight was designed for
Windows-based networks, many requirements need evidence no API exposes, and a formal assessment
follows ASD's Essential Eight Assessment Process Guide.

<!-- generated:coverage:start (junction check docs) -->
## Matrix

| Strategy | ML1 | ML2 | ML3 |
|---|---|---|---|
| Patch applications | `intune.browser_updates`<br>`intune.patch_age` | `intune.browser_updates`<br>`intune.patch_age` | `intune.browser_updates`<br>`intune.patch_age` |
| Patch operating systems | `endpoint.unsupported_os`<br>`intune.patch_age`<br>`intune.update_rings` | `endpoint.unsupported_os`<br>`intune.patch_age`<br>`intune.update_rings` | `endpoint.unsupported_os`<br>`intune.patch_age`<br>`intune.update_rings` |
| Multi-factor authentication | `identity.baseline`<br>`identity.legacy_auth_blocked`<br>`identity.mfa_admins`<br>`identity.mfa_coverage` | `identity.baseline`<br>`identity.legacy_auth_blocked`<br>`identity.mfa_admins`<br>`identity.mfa_coverage`<br>`identity.phishing_resistant_admins`<br>`sentinel.connectors`<br>`sentinel.incidents_stale`<br>`sentinel.rules_enabled`<br>`sentinel.workspace` | `identity.baseline`<br>`identity.legacy_auth_blocked`<br>`identity.mfa_admins`<br>`identity.mfa_coverage`<br>`identity.phishing_resistant_admins`<br>`sentinel.connectors`<br>`sentinel.incidents_stale`<br>`sentinel.rules_enabled`<br>`sentinel.workspace` |
| Restrict administrative privileges | `identity.global_admin_count`<br>`identity.separate_admin_accounts`<br>`intune.local_admin` | `identity.break_glass_monitored` (manual)<br>`identity.global_admin_count`<br>`identity.separate_admin_accounts`<br>`intune.laps`<br>`intune.local_admin`<br>`sentinel.connectors`<br>`sentinel.incidents_stale`<br>`sentinel.rules_enabled`<br>`sentinel.workspace` | `identity.break_glass_monitored` (manual)<br>`identity.global_admin_count`<br>`identity.pim_used`<br>`identity.separate_admin_accounts`<br>`intune.laps`<br>`intune.local_admin`<br>`sentinel.connectors`<br>`sentinel.incidents_stale`<br>`sentinel.rules_enabled`<br>`sentinel.workspace` |
| Application control | none | `sentinel.incidents_stale`<br>`sentinel.rules_enabled` | `sentinel.incidents_stale`<br>`sentinel.rules_enabled` |
| Restrict Microsoft Office macros | `intune.office_macros` | `endpoint.asr_quick_wins`<br>`endpoint.asr_rule_state`<br>`intune.office_macros` | `endpoint.asr_quick_wins`<br>`endpoint.asr_rule_state`<br>`intune.office_macros` |
| User application hardening | none | `endpoint.asr_quick_wins`<br>`endpoint.asr_rule_state`<br>`sentinel.incidents_stale`<br>`sentinel.rules_enabled` | `endpoint.asr_quick_wins`<br>`endpoint.asr_rule_state`<br>`sentinel.incidents_stale`<br>`sentinel.rules_enabled` |
| Regular backups | `backup.azure_vaults`<br>`backup.m365_backup`<br>`backup.offline_copy` (manual)<br>`backup.restore_tested` (manual)<br>`backup.third_party_app` | `backup.admin_separation` (manual)<br>`backup.azure_vaults`<br>`backup.m365_backup`<br>`backup.offline_copy` (manual)<br>`backup.restore_tested` (manual)<br>`backup.third_party_app` | `backup.admin_separation` (manual)<br>`backup.azure_vaults`<br>`backup.m365_backup`<br>`backup.offline_copy` (manual)<br>`backup.restore_tested` (manual)<br>`backup.third_party_app` |

(manual) marks a check answered by attestation rather than an API.

## Requirements by strategy

| Strategy | Requirements | Tagged by a check | Gaps |
|---|---:|---:|---:|
| Patch applications | 14 | 4 | 10 |
| Patch operating systems | 21 | 5 | 16 |
| Multi-factor authentication | 24 | 11 | 13 |
| Restrict administrative privileges | 28 | 13 | 15 |
| Application control | 19 | 5 | 14 |
| Restrict Microsoft Office macros | 10 | 5 | 5 |
| User application hardening | 29 | 9 | 20 |
| Regular backups | 11 | 9 | 2 |

## Gaps

Requirements with no check tagged with the same ISM control.

### Patch applications

| Requirement | Levels | Control |
|---|---|---|
| ISM-1876 | ML1, ML2, ML3 | Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within 48 hours of release when… |
| ISM-1690 | ML1, ML2, ML3 | Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within two weeks of release when… |
| ISM-1901 | ML3 | Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email… |
| ISM-1905 | ML1, ML2, ML3 | Online services that are no longer supported by vendors are removed |
| ISM-1704 | ML1, ML2, ML3 | Office productivity suites, web browsers and their extensions, email clients, PDF applications, Adobe Flash Player, and security products… |
| ISM-0304 | ML3 | Applications other than office productivity suites, web browsers and their extensions, email clients, PDF applications, Adobe Flash… |
| ISM-1807 | ML1, ML2, ML3 | An automated method of asset discovery is used at least fortnightly to support the detection of assets for subsequent vulnerability… |
| ISM-1808 | ML1, ML2, ML3 | A vulnerability scanner with an up-to-date vulnerability database is used for vulnerability scanning activities |
| ISM-1698 | ML1, ML2, ML3 | A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in online services |
| ISM-1700 | ML2, ML3 | A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in applications other than… |

### Patch operating systems

| Requirement | Levels | Control |
|---|---|---|
| ISM-1407 | ML3 | The latest release, or the previous release, of operating systems are used |
| ISM-1876 | ML1, ML2, ML3 | Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within 48 hours of release when… |
| ISM-1690 | ML1, ML2, ML3 | Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within two weeks of release when… |
| ISM-1877 | ML1, ML2, ML3 | Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing servers and internet-facing… |
| ISM-1694 | ML1, ML2, ML3 | Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing servers and internet-facing… |
| ISM-1879 | ML3 | Patches, updates or other vendor mitigations for vulnerabilities in drivers are applied within 48 hours of release when vulnerabilities… |
| ISM-1697 | ML3 | Patches, updates or other vendor mitigations for vulnerabilities in drivers are applied within one month of release when vulnerabilities… |
| ISM-1903 | ML3 | Patches, updates or other vendor mitigations for vulnerabilities in firmware are applied within 48 hours of release when vulnerabilities… |
| ISM-1904 | ML3 | Patches, updates or other vendor mitigations for vulnerabilities in firmware are applied within one month of release when vulnerabilities… |
| ISM-1905 | ML1, ML2, ML3 | Online services that are no longer supported by vendors are removed |
| ISM-1807 | ML1, ML2, ML3 | An automated method of asset discovery is used at least fortnightly to support the detection of assets for subsequent vulnerability… |
| ISM-1808 | ML1, ML2, ML3 | A vulnerability scanner with an up-to-date vulnerability database is used for vulnerability scanning activities |
| ISM-1698 | ML1, ML2, ML3 | A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in online services |
| ISM-1701 | ML1, ML2, ML3 | A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in operating systems of… |
| ISM-1703 | ML3 | A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in drivers |
| ISM-1900 | ML3 | A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in firmware |

### Multi-factor authentication

| Requirement | Levels | Control |
|---|---|---|
| ISM-0140 | ML2, ML3 | Cyber security incidents are reported to ASD as soon as possible after they occur or are discovered |
| ISM-1679 | ML1, ML2, ML3 | Multi-factor authentication is used to authenticate human users to third-party online services that process, store or communicate their… |
| ISM-1680 | ML1, ML2, ML3 | Multi-factor authentication (where available) is used to authenticate human users to third-party online services that process, store or… |
| ISM-1892 | ML1, ML2, ML3 | Multi-factor authentication is used to authenticate human users to their organisation’s online customer services that process, store or… |
| ISM-1893 | ML1, ML2, ML3 | Multi-factor authentication is used to authenticate human users to third-party online customer services that process, store or communicate… |
| ISM-1681 | ML1, ML2, ML3 | Multi-factor authentication is used to authenticate customers to online customer services that process, store or communicate sensitive… |
| ISM-1505 | ML3 | Multi-factor authentication is used to authenticate human users of data repositories |
| ISM-1401 | ML1, ML2, ML3 | Multi-factor authentication uses either: something people have and something people know, or something people have that is unlocked by… |
| ISM-1873 | ML2 | Multi-factor authentication used for authenticating customers of online customer services provides a phishing-resistant option |
| ISM-1874 | ML3 | Multi-factor authentication used for authenticating customers of online customer services is phishing-resistant |
| ISM-1894 | ML3 | Multi-factor authentication used for authenticating human users of data repositories is phishing-resistant |
| ISM-1907 | ML3 | Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events |
| ISM-0109 | ML3 | Event logs from workstations are analysed in a timely manner to detect cyber security events |

### Restrict administrative privileges

| Requirement | Levels | Control |
|---|---|---|
| ISM-0140 | ML2, ML3 | Cyber security incidents are reported to ASD as soon as possible after they occur or are discovered |
| ISM-1883 | ML1, ML2, ML3 | Privileged user accounts explicitly authorised to access online services are strictly limited to only what is required for users to… |
| ISM-1648 | ML2, ML3 | Privileged access to systems and their resources are disabled after 45 days of inactivity |
| ISM-1647 | ML2, ML3 | Privileged access to systems and their resources are disabled after 12 months unless revalidated |
| ISM-1861 | ML3 | Local Security Authority protection functionality is enabled |
| ISM-1686 | ML3 | Credential Guard functionality is enabled |
| ISM-1897 | ML3 | Remote Credential Guard functionality is enabled |
| ISM-1898 | ML3 | Secure Admin Workstations are used in the performance of administrative activities |
| ISM-1380 | ML1, ML2, ML3 | Privileged human users use separate privileged and unprivileged operating environments |
| ISM-1687 | ML2, ML3 | Privileged operating environments are not virtualised within unprivileged operating environments |
| ISM-1688 | ML1, ML2, ML3 | Unprivileged user accounts cannot be used to log on to privileged operating environments |
| ISM-1689 | ML1, ML2, ML3 | Privileged user accounts (excluding local administrator accounts) cannot be used to log on to unprivileged operating environments |
| ISM-1387 | ML2, ML3 | Administrative activities are conducted through jump servers |
| ISM-1907 | ML3 | Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events |
| ISM-0109 | ML3 | Event logs from workstations are analysed in a timely manner to detect cyber security events |

### Application control

| Requirement | Levels | Control |
|---|---|---|
| ISM-0140 | ML2, ML3 | Cyber security incidents are reported to ASD as soon as possible after they occur or are discovered |
| ISM-0843 | ML1, ML2, ML3 | Application control is implemented on workstations |
| ISM-1490 | ML2, ML3 | Application control is implemented on internet-facing servers |
| ISM-1656 | ML3 | Application control is implemented on non-internet-facing servers |
| ISM-1870 | ML1, ML2, ML3 | Application control is applied to user profiles and temporary folders used by operating systems, web browsers and email clients |
| ISM-1871 | ML2, ML3 | Application control is applied to all locations other than user profiles and temporary folders used by operating systems, web browsers and… |
| ISM-1657 | ML1, ML2, ML3 | Application control restricts the execution of executables, libraries, scripts, installers, compiled HTML, HTML applications and control… |
| ISM-1658 | ML3 | Application control restricts the execution of drivers to an organisation-approved set |
| ISM-1544 | ML2, ML3 | Microsoft’s recommended application blocklist is implemented |
| ISM-1659 | ML3 | Microsoft’s vulnerable driver blocklist is implemented |
| ISM-1582 | ML2, ML3 | Application control rulesets are validated at least annually |
| ISM-1660 | ML2, ML3 | Allowed and blocked application control events are centrally logged |
| ISM-1907 | ML3 | Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events |
| ISM-0109 | ML3 | Event logs from workstations are analysed in a timely manner to detect cyber security events |

### Restrict Microsoft Office macros

| Requirement | Levels | Control |
|---|---|---|
| ISM-1672 | ML1, ML2, ML3 | Microsoft Office macro antivirus scanning is enabled |
| ISM-1890 | ML3 | Microsoft Office macros are checked to ensure they are free of malicious code before being digitally signed or placed within Trusted… |
| ISM-1487 | ML3 | Only privileged human users responsible for checking that Microsoft Office macros are free of malicious code can write to and modify… |
| ISM-1891 | ML3 | Microsoft Office macros digitally signed by signatures other than V3 signatures cannot be enabled via the Message Bar or Backstage View |
| ISM-1489 | ML1, ML2, ML3 | Microsoft Office macro security settings cannot be changed by human users |

### User application hardening

| Requirement | Levels | Control |
|---|---|---|
| ISM-0140 | ML2, ML3 | Cyber security incidents are reported to ASD as soon as possible after they occur or are discovered |
| ISM-1654 | ML1, ML2, ML3 | Internet Explorer 11 is disabled or removed |
| ISM-1655 | ML3 | .NET Framework 3.5 (includes .NET 2.0 and 3.0) is disabled or removed |
| ISM-1896 | ML3 | Memory integrity functionality is enabled |
| ISM-1889 | ML2, ML3 | Command line process creation events are centrally logged |
| ISM-1621 | ML3 | Windows PowerShell 2.0 is disabled or removed |
| ISM-1622 | ML3 | PowerShell is configured to use Constrained Language Mode |
| ISM-1623 | ML2, ML3 | PowerShell module logging, script block logging and transcription events are centrally logged |
| ISM-1859 | ML2, ML3 | Office productivity suites are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when… |
| ISM-1542 | ML2, ML3 | Microsoft Office is configured to prevent activation of Object Linking and Embedding packages |
| ISM-1823 | ML2, ML3 | Office productivity suite security settings cannot be changed by human users |
| ISM-1676 | ML3 | Microsoft Office’s list of trusted publishers is validated at least annually |
| ISM-1860 | ML2, ML3 | PDF applications are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts… |
| ISM-1824 | ML2, ML3 | PDF application security settings cannot be changed by human users |
| ISM-1486 | ML1, ML2, ML3 | Web browsers do not process Java from the internet |
| ISM-1485 | ML1, ML2, ML3 | Web browsers do not process web advertisements from the internet |
| ISM-1412 | ML2, ML3 | Web browsers are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur |
| ISM-1585 | ML1, ML2, ML3 | Web browser security settings cannot be changed by human users |
| ISM-1907 | ML3 | Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events |
| ISM-0109 | ML3 | Event logs from workstations are analysed in a timely manner to detect cyber security events |

### Regular backups

| Requirement | Levels | Control |
|---|---|---|
| ISM-1812 | ML1, ML2, ML3 | Unprivileged user accounts cannot access backups belonging to other user accounts |
| ISM-1813 | ML3 | Unprivileged user accounts cannot access their own backups |
<!-- generated:coverage:end -->
