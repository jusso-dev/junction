# Ratatui compatibility patch

`ratatui/` is the official MIT-licensed Ratatui 0.29.0 crates.io source archive.
Its LICENSE is retained. Junction changes only the unicode-width dependency
constraint from `=0.2.0` to `0.2.2` in Cargo.toml and Cargo.toml.orig. This resolves
its dependency conflict with serde-saphyr/annotate-snippets, which require
unicode-width 0.2.2. Ratatui rendering is tested through TestBackend in
junction-tui, including different terminal sizes. Widget implementation is
unchanged. Replace this patch with an upstream release once compatible packages
are available and verified.
