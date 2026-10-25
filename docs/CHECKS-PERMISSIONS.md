# Permissions for `junction check`

Checks only read. This page shows how to give Junction least-privilege, read-only access for
[`junction check`](CHECKS.md), and what each permission is used for. The tables below are generated
from the checks' own declarations (`junction check docs`), so they always match the code; a test
fails if they drift. To print the permissions for just the packs you run:

```sh
junction check permissions --pack identity,endpoint
```

A permission you leave out is not an error: the checks that need it report `unknown` with the
permission to grant, and everything else still runs.

## 1. Register an application

1. In the Microsoft Entra admin centre, open **Identity > Applications > App registrations > New
   registration**. Name it (for example `junction-check-readonly`). Choose **Accounts in this
   organisational directory only**, or **any organisational directory** if you will consent it in
   several customer tenants. No redirect URI is needed for app-only use.
2. Under **Certificates & secrets**, upload a certificate (preferred) or create a short-lived client
   secret. See [CERTIFICATE-AUTHENTICATION.md](CERTIFICATE-AUTHENTICATION.md) and
   [AUTHENTICATION.md](AUTHENTICATION.md) for how Junction loads it without storing it in a context.
3. Under **API permissions > Add a permission**, add the **application** permissions from the tables
   below:
   - **Microsoft Graph** for identity, Intune, email domains, applications, collaboration and backup.
   - **WindowsDefenderATP** (APIs my organisation uses) for Defender for Endpoint permissions such as
     `Machine.Read.All`, `SecurityConfiguration.Read.All` and `Vulnerability.Read.All`.
   - **Microsoft Threat Protection** for `AdvancedHunting.Read.All` (Defender XDR advanced hunting).
     Graph `ThreatHunting.Read.All` is an alternative; checks fall back to Graph hunting when the
     Defender API is not granted.
4. Select **Grant admin consent**.
5. For Azure, Sentinel and Log Analytics checks, assign Azure roles (not app permissions) to the app's
   service principal at the subscription or resource group scope: **Reader** (Resource Graph
   discovery, Arc machines, vault settings), **Microsoft Sentinel Reader** (data connectors, rules,
   incidents, automation), **Log Analytics Reader** (workspace tables and queries) and **Backup
   Reader** (protected items).
6. Add a context:

   ```json
   {
     "cloud": "public",
     "tenant": "00000000-0000-4000-8000-000000000001",
     "service": "graph",
     "credential_profile": "checks",
     "flow": "certificate"
   }
   ```

   `junction context add contoso --file contoso.json`. Checks use the context's tenant, cloud and
   credential, and request a token for each Microsoft API audience they call (Graph, Defender for
   Endpoint, Defender XDR, Azure Resource Manager, Log Analytics); the context's `service` is not
   used by checks.

Nothing here grants write access. Checks also never request secret values: LAPS and BitLocker
checks read metadata only (`DeviceLocalCredential.ReadBasic.All`, `BitlockerKey.ReadBasic.All`), and
a test asserts no password or recovery key is requested.

## 2. Delegated partner access

With granular delegated admin privileges (GDAP), a partner identity can hold read-only roles such as
**Global Reader**, **Security Reader** and **Intune Read-only Administrator** in customer tenants.
Use an interactive context, sign in once per customer tenant (`junction auth login`), and list the
tenants in a `--tenants` file (see [CHECKS.md](CHECKS.md#selecting-tenants)). Delegated roles do not
reach every API: Defender for Endpoint and some reports need application permissions, and those
checks report `unknown` with the reason. Per-tenant app consent (step 1, multi-tenant app) is the
more complete model. Junction does not create or manage GDAP relationships.

## 3. What each permission is used for

`junction check explain <id>` shows exactly which operations a check reads, why, and the
permission for each. The generated tables follow: one per pack, then the union for every pack.

<!-- generated:permissions:start (junction check docs) -->
### Identity (`identity`)

| Permission | Type | Checks | Operations |
|---|---|---|---|
| `AuditLog.Read.All` | Microsoft Graph application | `identity.mfa_admins`, `identity.mfa_coverage`, `identity.phishing_resistant_admins` | `graph.reports.authentication_methods.user_registration_details.list` |
| `GroupMember.Read.All` | Microsoft Graph application | `identity.break_glass`, `identity.mfa_admins`, `identity.phishing_resistant_admins`, `identity.separate_admin_accounts` | `graph.groups.transitive_members.list`, `graph.users.transitive_member_of.list` |
| `LicenseAssignment.Read.All` | Microsoft Graph application | `identity.separate_admin_accounts` | `graph.subscribed_skus.list` |
| `Policy.Read.All` | Microsoft Graph application | `identity.baseline`, `identity.break_glass`, `identity.legacy_auth_blocked`, `identity.phishing_resistant_admins` | `graph.identity.conditional_access.policies.list`, `graph.policies.authentication_strength_policies.list`, `graph.policies.identity_security_defaults_enforcement_policy.get` |
| `RoleAssignmentSchedule.Read.Directory` | Microsoft Graph application | `identity.pim_used` | `graph.role_management.directory.role_assignment_schedules.list` |
| `RoleEligibilitySchedule.Read.Directory` | Microsoft Graph application | `identity.pim_used` | `graph.role_management.directory.role_eligibility_schedules.list` |
| `RoleManagement.Read.Directory` | Microsoft Graph application | `identity.break_glass`, `identity.global_admin_count`, `identity.mfa_admins`, `identity.phishing_resistant_admins`, `identity.separate_admin_accounts` | `graph.role_management.directory.role_assignments.list` |
| `User.Read.All` | Microsoft Graph application | `identity.mfa_coverage`, `identity.separate_admin_accounts` | `graph.users.list` |
| `UserAuthenticationMethod.Read.All` | Microsoft Graph application | `identity.mfa_admins` | `graph.users.authentication.methods.list` |

### Endpoint (Defender for Endpoint and ASR) (`endpoint`)

| Permission | Type | Checks | Operations |
|---|---|---|---|
| `Device.Read.All` | Microsoft Graph application | `endpoint.onboarding_coverage` | `graph.devices.list` |
| `DeviceManagementManagedDevices.Read.All` | Microsoft Graph application | `endpoint.onboarding_coverage` | `graph.device_management.managed_devices.list` |
| `ThreatHunting.Read.All` | Microsoft Graph application | `endpoint.av_definition_age`, `endpoint.av_mode`, `endpoint.edr_block_mode`, `endpoint.network_protection` | `graph.security.run_hunting_query` |
| `Machine.Read.All` | Defender for Endpoint application | `endpoint.linux_macos_health`, `endpoint.onboarding_coverage`, `endpoint.servers_covered`, `endpoint.stale_sensors`, `endpoint.unsupported_os` | `defender.endpoint.machines.list` |
| `Vulnerability.Read.All` | Defender for Endpoint application | `endpoint.cloud_protection`, `endpoint.network_protection`, `endpoint.realtime_protection`, `endpoint.tamper_protection` | `defender.endpoint.machines.list_secure_configurations_assessment_by_machine` |
| `AdvancedHunting.Read.All` | Defender XDR application | `endpoint.av_definition_age`, `endpoint.av_mode`, `endpoint.edr_block_mode`, `endpoint.network_protection` | `defender.xdr.advancedhunting.run` |
| `Reader` | Azure RBAC role | `endpoint.servers_covered` | `azure.arc.machines.list_by_subscription`, `azure.resource_graph.resources.post` |

### Email (`email`)

| Permission | Type | Checks | Operations |
|---|---|---|---|
| `Domain.Read.All` | Microsoft Graph application | `email.dkim`, `email.dmarc`, `email.spf` | `graph.domains.list` |

### Backups (`backup`)

| Permission | Type | Checks | Operations |
|---|---|---|---|
| `Application.Read.All` | Microsoft Graph application | `backup.third_party_app` | `graph.service_principals.list` |
| `BackupRestore-Configuration.Read.All` | Microsoft Graph application | `backup.m365_backup` | `graph.solutions.backup_restore.exchange_protection_policies.list`, `graph.solutions.backup_restore.get`, `graph.solutions.backup_restore.one_drive_for_business_protection_policies.list`, `graph.solutions.backup_restore.share_point_protection_policies.list` |
| `Reader` | Azure RBAC role | `backup.azure_vaults` | `azure.resource_graph.resources.post` |

### Microsoft Sentinel (`sentinel`)

| Permission | Type | Checks | Operations |
|---|---|---|---|
| `Log Analytics Reader` | Azure RBAC role | `sentinel.connectors`, `sentinel.health_auditing`, `sentinel.ingestion_cost`, `sentinel.retention`, `sentinel.rules_enabled` | `azure.log_analytics.tables.list_by_workspace`, `azure.log_analytics_query.query.execute` |
| `Microsoft Sentinel Reader` | Azure RBAC role | `sentinel.automation`, `sentinel.connectors`, `sentinel.health_auditing`, `sentinel.incidents_stale`, `sentinel.ingestion_cost`, `sentinel.retention`, `sentinel.rules_enabled`, `sentinel.workspace` | `sentinel.securityinsights.alert_rules.list`, `sentinel.securityinsights.automation_rules.list`, `sentinel.securityinsights.data_connectors.list`, `sentinel.securityinsights.incidents.list`, `sentinel.securityinsights.sentinel_onboarding_states.list` |
| `Reader` | Azure RBAC role | `sentinel.automation`, `sentinel.connectors`, `sentinel.health_auditing`, `sentinel.incidents_stale`, `sentinel.ingestion_cost`, `sentinel.retention`, `sentinel.rules_enabled`, `sentinel.workspace` | `azure.resource_graph.resources.post` |

### Every pack

| Permission | Type | Checks | Operations |
|---|---|---|---|
| `Application.Read.All` | Microsoft Graph application | `backup.third_party_app` | `graph.service_principals.list` |
| `AuditLog.Read.All` | Microsoft Graph application | `identity.mfa_admins`, `identity.mfa_coverage`, `identity.phishing_resistant_admins` | `graph.reports.authentication_methods.user_registration_details.list` |
| `BackupRestore-Configuration.Read.All` | Microsoft Graph application | `backup.m365_backup` | `graph.solutions.backup_restore.exchange_protection_policies.list`, `graph.solutions.backup_restore.get`, `graph.solutions.backup_restore.one_drive_for_business_protection_policies.list`, `graph.solutions.backup_restore.share_point_protection_policies.list` |
| `Device.Read.All` | Microsoft Graph application | `endpoint.onboarding_coverage` | `graph.devices.list` |
| `DeviceManagementManagedDevices.Read.All` | Microsoft Graph application | `endpoint.onboarding_coverage` | `graph.device_management.managed_devices.list` |
| `Domain.Read.All` | Microsoft Graph application | `email.dkim`, `email.dmarc`, `email.spf` | `graph.domains.list` |
| `GroupMember.Read.All` | Microsoft Graph application | `identity.break_glass`, `identity.mfa_admins`, `identity.phishing_resistant_admins`, `identity.separate_admin_accounts` | `graph.groups.transitive_members.list`, `graph.users.transitive_member_of.list` |
| `LicenseAssignment.Read.All` | Microsoft Graph application | `identity.separate_admin_accounts` | `graph.subscribed_skus.list` |
| `Policy.Read.All` | Microsoft Graph application | `identity.baseline`, `identity.break_glass`, `identity.legacy_auth_blocked`, `identity.phishing_resistant_admins` | `graph.identity.conditional_access.policies.list`, `graph.policies.authentication_strength_policies.list`, `graph.policies.identity_security_defaults_enforcement_policy.get` |
| `RoleAssignmentSchedule.Read.Directory` | Microsoft Graph application | `identity.pim_used` | `graph.role_management.directory.role_assignment_schedules.list` |
| `RoleEligibilitySchedule.Read.Directory` | Microsoft Graph application | `identity.pim_used` | `graph.role_management.directory.role_eligibility_schedules.list` |
| `RoleManagement.Read.Directory` | Microsoft Graph application | `identity.break_glass`, `identity.global_admin_count`, `identity.mfa_admins`, `identity.phishing_resistant_admins`, `identity.separate_admin_accounts` | `graph.role_management.directory.role_assignments.list` |
| `ThreatHunting.Read.All` | Microsoft Graph application | `endpoint.av_definition_age`, `endpoint.av_mode`, `endpoint.edr_block_mode`, `endpoint.network_protection` | `graph.security.run_hunting_query` |
| `User.Read.All` | Microsoft Graph application | `identity.mfa_coverage`, `identity.separate_admin_accounts` | `graph.users.list` |
| `UserAuthenticationMethod.Read.All` | Microsoft Graph application | `identity.mfa_admins` | `graph.users.authentication.methods.list` |
| `Machine.Read.All` | Defender for Endpoint application | `endpoint.linux_macos_health`, `endpoint.onboarding_coverage`, `endpoint.servers_covered`, `endpoint.stale_sensors`, `endpoint.unsupported_os` | `defender.endpoint.machines.list` |
| `Vulnerability.Read.All` | Defender for Endpoint application | `endpoint.cloud_protection`, `endpoint.network_protection`, `endpoint.realtime_protection`, `endpoint.tamper_protection` | `defender.endpoint.machines.list_secure_configurations_assessment_by_machine` |
| `AdvancedHunting.Read.All` | Defender XDR application | `endpoint.av_definition_age`, `endpoint.av_mode`, `endpoint.edr_block_mode`, `endpoint.network_protection` | `defender.xdr.advancedhunting.run` |
| `Log Analytics Reader` | Azure RBAC role | `sentinel.connectors`, `sentinel.health_auditing`, `sentinel.ingestion_cost`, `sentinel.retention`, `sentinel.rules_enabled` | `azure.log_analytics.tables.list_by_workspace`, `azure.log_analytics_query.query.execute` |
| `Microsoft Sentinel Reader` | Azure RBAC role | `sentinel.automation`, `sentinel.connectors`, `sentinel.health_auditing`, `sentinel.incidents_stale`, `sentinel.ingestion_cost`, `sentinel.retention`, `sentinel.rules_enabled`, `sentinel.workspace` | `sentinel.securityinsights.alert_rules.list`, `sentinel.securityinsights.automation_rules.list`, `sentinel.securityinsights.data_connectors.list`, `sentinel.securityinsights.incidents.list`, `sentinel.securityinsights.sentinel_onboarding_states.list` |
| `Reader` | Azure RBAC role | `backup.azure_vaults`, `endpoint.servers_covered`, `sentinel.automation`, `sentinel.connectors`, `sentinel.health_auditing`, `sentinel.incidents_stale`, `sentinel.ingestion_cost`, `sentinel.retention`, `sentinel.rules_enabled`, `sentinel.workspace` | `azure.arc.machines.list_by_subscription`, `azure.resource_graph.resources.post` |
<!-- generated:permissions:end -->
