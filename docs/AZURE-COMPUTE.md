# Azure Compute discovery

`sources/azure-compute.toml` registers the official Azure REST specification
repository and scopes inventory to
`specification/compute/resource-manager/Microsoft.Compute/Compute`.
This includes the current Compute API definitions without inventorying unrelated
Azure providers. The source is enabled and appears in `junction sources`.

The upstream contains a virtual machine definition at
[Compute stable 2024-07-01](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/virtualMachine.json).
This is an example path, not a claim that this version is the latest.
Discover the scoped inventory, retain its immutable revision, and select a stable
virtualMachine.json path from that inventory before refreshing:

```sh
junction discover azure-compute --output compute-inventory.json
junction refresh azure-compute --revision <inventory-commit-sha> \
  --path specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/virtualMachine.json \
  --service compute --max-documents 256 --output compute-registry.json
junction --registry compute-registry.json search 'virtual machines'
```

Refresh resolves referenced schema documents within the official repository,
normalizes operations, and records source receipts using the existing ingestion
pipeline. Preview selection still requires explicit runtime opt-in.

The source configuration passes local source validation. The daily updater now
pins Compute to the same Azure repository commit as Resources, selects the latest
stable date-versioned virtualMachine.json from the scoped inventory, validates
its refresh receipt, and merges its operations into the staged default registry.
Preview and example documents are excluded from version selection. Missing stable
definitions, failed refresh, empty catalogs, and mismatched provenance abort before
publication. Mock orchestration tests cover these cases and preserve prior catalogs.

Live inventory and refresh remain unverified in this environment. The local
default registry and existing release archive still contain only Graph; the next
successful hosted daily refresh is required to produce the expanded catalog.

An offline ingestion regression now checks representative official VM List,
Start and Restart metadata: canonical names match the spec, API versions and
required subscription parameters survive ingestion, List retains nextLink paging,
and Start/Restart retain write risk and long-running metadata. Repeated ingestion
produces identical manifests. This uses a representative local document, not a
live complete upstream bundle. All 24 ingestion tests pass.
