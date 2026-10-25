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
<!-- generated:permissions:end -->
