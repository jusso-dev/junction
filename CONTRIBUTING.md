# Contributing

Junction is licensed under MIT. Contributions are welcome through issues and pull requests in the intended public repository, `jusso-dev/junction`, once publication is complete.

Use Rust 1.89 or newer. Before submitting a change, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Describe the problem, the resulting behavior, and how you verified the change. Keep credentials, access tokens, tenant data, and API response data out of issues, fixtures, and logs. Use synthetic examples for authentication and execution tests.

Endpoint imports must come from official Microsoft sources and retain revision and digest receipts. Review the [specification](docs/SPECIFICATION.md) and [implementation status](docs/IMPLEMENTATION.md) before adding an adapter. Generated registry JSON is excluded from source control; the daily release workflow builds and packages it from upstream specifications.

See [automated releases](docs/RELEASING.md) for catalog refresh, versioning, binary packaging, and repository configuration. Release versions are allocated by the workflow; do not manually reuse an existing tag.

Junction is independent of Microsoft. Contributions must not imply Microsoft affiliation or endorsement and must keep the [disclaimer](DISCLAIMER.md) intact.
