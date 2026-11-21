# Security Policy

## Supported versions

Junction is currently in prerelease (`0.1.x`), with automated daily builds published from the `main` branch. Security fixes are applied to `main` and shipped in the next release; older prereleases are not backported.

| Version | Supported |
| --- | --- |
| Latest `0.1.x` release (`main`) | Yes |
| Earlier `0.1.x` prereleases | No |

## Reporting a vulnerability

Please do **not** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

Report vulnerabilities privately using [GitHub private vulnerability reporting](https://github.com/jusso-dev/junction/security/advisories/new) on `jusso-dev/junction`.

To help with triage and reproduction, please include:

- the affected crate, command, workflow, or component;
- the version or commit SHA where the issue was observed;
- clear steps to reproduce or a minimal proof of concept;
- the expected security impact and any suggested mitigation.

Do **not** include real credentials, access tokens, certificates, tenant IDs, subscription IDs, or real tenant API responses in your report. Use synthetic or redacted examples instead.

## Expected response times

This is an independently maintained open-source project. Best-effort response targets are:

- **Initial acknowledgement**: within 3 business days
- **Triage and severity assessment**: within 7 business days
- **Remediation and disclosure**: prioritised by severity and complexity, with fixes published in a new release and documented in a GitHub Security Advisory where appropriate

If you need to coordinate a disclosure timeline, note that in your advisory submission.

## Scope

### In scope

- All Rust crates in the workspace (`crates/*`), including the CLI (`junction`), authentication and credential-store handling (`junction-auth`), policy enforcement and operator approvals (`junction-policy`, `junction-runtime`), HTTP execution and secret redaction (`junction-http`), local HTTP API (`junction-server`), MCP server (`junction-mcp`), terminal UI (`junction-tui`), security checks and watchdog (`junction-check`, `junction-watch`), and registry, schema, discovery, and generator crates
- Build, catalogue refresh, and release scripts (`scripts/`) and GitHub Actions workflows (`.github/workflows/`)
- Vulnerability classes including credential or token leakage in logs, errors, or state files; policy or approval bypasses; unauthorised host routing or SSRF; command, argument, or path injection; and unsafe handling of untrusted API responses or inputs

### Out of scope

- Vulnerabilities in Microsoft cloud services or upstream Microsoft API specifications; report those directly to the [Microsoft Security Response Center](https://msrc.microsoft.com/)
- Misconfigurations, excessive permissions, or destructive actions performed using valid credentials supplied by the operator or their agents (see [DISCLAIMER.md](DISCLAIMER.md))
- Vulnerabilities in third-party Rust dependencies that do not have a Junction-specific exploit path; report those upstream to the crate maintainers or RustSec (Junction runs `cargo audit` on dependency changes and on a weekly schedule)
- Attacks requiring an already-compromised local host or OS credential store
