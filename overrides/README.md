# Operator risk overrides

Pass `--risk-overrides /trusted/path/risks.toml` to apply exact canonical IDs to all API versions. Files are operator configuration, never agent input. Example:

```toml
[[operations]]
operation = "graph.users.list"
risk = "privileged"
reason = "Operator-reviewed sensitive directory query"
```

Values are read_only, write, destructive, or privileged. A nonempty review reason is required. Duplicate entries, unknown IDs, unsupported fields, and excessive sizes fail closed. Search, describe, policy checks, execution, and batch share the corrected registry. Policy checks, execution, and batch also share an independent HTTP method floor: mutations are rejected in read-only mode, and DELETE requires approval even if an override marks it read_only. Overrides do not grant permissions or approve operations. Catalog change reports compare upstream manifests independently of local overrides.
