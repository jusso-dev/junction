# Storage for `junction archive`

`junction archive` writes to storage you own. Junction never creates the
storage, sets its retention or changes it. You deploy one of the options below,
then point the archive configuration at it.

| File | What it is |
| --- | --- |
| `archive-storage.bicep` | Azure storage account and container with version-level immutability, a 365-day default retention, shared keys disabled, and separate role assignments for the collector, searcher and hold administrator. |
| `r2-lock-rules.json` | Cloudflare R2 bucket lock rules: 365 days for `v1/` (archived records) and indefinite for `holds/` (legal hold copies). |

## Azure Blob

```sh
az deployment group create --resource-group <rg> \
  --template-file examples/archive/archive-storage.bicep \
  --parameters storageAccountName=<name> location=australiaeast \
               collectorPrincipalId=<object id> searcherPrincipalId=<object id>
```

Test with `junction archive doctor`. Once it passes, lock the container
policy with the command in the deployment's `lockCommand` output. A locked
policy can be extended but never shortened or removed, so do this only when
the retention is right.

The collector gets a custom role with only `blobs/read` and `blobs/add/action`.
It can create objects and read them back. It cannot overwrite, delete or touch
retention, so a compromised collector host cannot rewrite the archive.

## Cloudflare R2

```sh
cf r2 buckets create junction-archive
cf r2 buckets locks update junction-archive --rules @examples/archive/r2-lock-rules.json
```

Create an R2 API token with **Object Read & Write** scoped to the one bucket for
the collector, and a separate **Object Read** token for searchers. Bucket lock
rules need an Admin token, so keep that away from the collector.

## Extending retention

Retention is 365 days by default. To keep records longer:

- **Azure**: raise `retentionDays` and redeploy, or run
  `az storage container immutability-policy extend`. A locked policy can only
  be extended. Set `retention_days` in the archive configuration to match, so
  `doctor` checks the new value.
- **R2**: raise `maxAgeSeconds` on the `v1/` rule and run
  `cf r2 buckets locks update` again. Set `retention_days` to match.

Records under a legal hold are kept regardless of these values. See
`docs/ARCHIVE.md`.
