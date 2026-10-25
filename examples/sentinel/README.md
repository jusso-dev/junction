# Push `junction check` results to Microsoft Sentinel

`junction check run --push-sentinel` can send each run's results to a Log
Analytics custom table, `JunctionCheck_CL`, so drift alerts and dashboards live
in Sentinel. This folder has everything needed on the Azure side:

| File | What it is |
| --- | --- |
| `junction-check-table.bicep` | The `JunctionCheck_CL` table, a data collection endpoint (DCE) and a data collection rule (DCR) with stream `Custom-JunctionCheck_CL`. Optionally grants the push role. |
| `workbook.json` | Azure Monitor workbook: score over time per tenant, failing checks by tenant, latest status table. |
| `analytic-rules/score-drop.json` | Scheduled analytics rule: a tenant's score fell 5 or more points since its previous run. |
| `analytic-rules/new-critical-fail.json` | Scheduled analytics rule: a critical check fails that did not fail in the previous run. |

Junction never creates these resources itself. You deploy them once.

## What is written, and nothing else

Pushing is the only write in `junction check`. It writes to your own Log
Analytics workspace, never to tenant configuration, and only through one
operation: `azure.monitor.logs_ingestion.upload`
(`POST {dce}/dataCollectionRules/{dcrImmutableId}/streams/{stream}?api-version=2023-01-01`).
The push runs through Junction's runtime with a registry that contains only that
operation, so no policy can authorise any other write on this path.

Each row is one (tenant, check) result with these columns, and nothing more:

| Column | Type | Content |
| --- | --- | --- |
| `TimeGenerated` | datetime | When the run finished |
| `RunId` | string | Run id (same for every row of a run) |
| `EntraTenantId` | string | Assessed tenant id (`TenantId` is reserved by Log Analytics) |
| `TenantLabel` | string | Your label for the tenant, if set |
| `CheckId` | string | Check id, or `_tenant` for a tenant that could not be assessed |
| `Pack` | string | Pack, for example `identity` |
| `Status` | string | `pass`, `fail`, `warn`, `unknown`, `not_applicable`, or `failed` on a `_tenant` row |
| `Severity` | string | `critical`, `high`, `medium`, `low` or `info` |
| `Score` | real | The tenant's overall score for the run (0 to 100) |
| `PackScore` | real | The tenant's score for the check's pack |
| `Tags` | dynamic | Framework tags, for example `["e8:mfa:ml1","ism:ISM-1504","mitre:T1078"]` |
| `Summary` | string | The evidence summary, at most 1024 characters; on a `_tenant` row, the error code |
| `Attested` | boolean | The status came from a person's attestation |

Raw evidence data, affected-resource lists (user names, devices, domains) and
remediation text are never sent.

## Permissions

The only role needed for pushing is **Monitoring Metrics Publisher on the DCR**,
granted to the identity that runs `junction check`. It needs no role on the
workspace, the table, or any tenant being checked. Junction requests a token for
the audience `https://monitor.azure.com` in the workspace's tenant.

Deploying the template needs rights to create the table, DCE and DCR (for
example Contributor on the workspace's resource group) and, if you pass
`pusherPrincipalId`, rights to create role assignments on the DCR. That is a one
time operator action, not something Junction does.

## Deploy

1. Deploy into the resource group that holds the workspace, in the workspace's
   region:

   ```sh
   az deployment group create \
     --resource-group <workspace-resource-group> \
     --template-file examples/sentinel/junction-check-table.bicep \
     --parameters workspaceResourceId=<workspace-resource-id> \
                  pusherPrincipalId=<object-id-of-the-pushing-identity>
   ```

   Leave out `pusherPrincipalId` to grant the role yourself:

   ```sh
   az role assignment create \
     --assignee <object-id-of-the-pushing-identity> \
     --role "Monitoring Metrics Publisher" \
     --scope <dcr-resource-id>
   ```

   Role assignments can take up to 30 minutes to apply.

2. Read the outputs: `logsIngestionEndpoint` (pass as `--dce`), `dcrImmutableId`
   (pass as `--dcr`) and `stream` (pass as `--stream`).

3. Allow the push. The operation is classified `write`, so the default
   read-only policy refuses it. Either use a policy in `safe-write` (or `full`)
   mode that does not deny `azure.monitor.logs_ingestion.upload`:

   ```toml
   [agent]
   mode = "safe-write"
   ```

   or approve the push interactively when prompted, in which case Junction uses
   a safe-write policy for this one operation and keeps your deny rules (a deny
   rule cannot be approved away). See `docs/APPROVALS.md`.

4. Run:

   ```sh
   junction check run --push-sentinel \
     --dce https://<dce-name>.<region>-1.ingest.monitor.azure.com \
     --dcr dcr-<32 hex digits> \
     --stream Custom-JunctionCheck_CL
   ```

   Without `--push-sentinel` nothing is sent.

Rows are sent in batches of at most about 900 kB of JSON (the API accepts 1 MB
per call). Throttling (HTTP 429) and server errors are retried, honouring
`Retry-After`. Any other failure stops the push and says which batch failed; a
403 means the role above is missing on the DCR.

## Workbook

In the Azure portal open **Monitor > Workbooks > New**, choose **Advanced
Editor**, paste `workbook.json`, apply, and save it to the workspace's resource
group. Pick the workspace as the resource when prompted.

## Analytics rules

Deploy each rule into the Sentinel workspace:

```sh
az deployment group create \
  --resource-group <workspace-resource-group> \
  --template-file examples/sentinel/analytic-rules/score-drop.json \
  --parameters workspace=<workspace-name>
```

Both rules run daily over the last 14 days and only alert on a tenant's latest
run from the last day. Pass the same `ruleId` again to update a rule instead of
creating a second copy. Adjust `threshold` in `score-drop.json` to taste.

## API versions

- `Microsoft.OperationalInsights/workspaces` and `.../tables`: `2022-10-01`
- `Microsoft.Insights/dataCollectionEndpoints` and `dataCollectionRules`: `2022-06-01`
- `Microsoft.Authorization/roleAssignments`: `2022-04-01`
- `Microsoft.SecurityInsights` alert rules: `2023-02-01`
- Logs Ingestion API: `2023-01-01`
