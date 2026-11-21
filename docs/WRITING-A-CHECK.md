# Writing a check

A check is read-only Rust code in `crates/junction-check/src/packs/` plus data: framework tags in
`crates/junction-check/data/tags/<pack>.yaml` and recorded, synthetic fixtures under
`crates/junction-check/tests/fixtures/<pack>/<case>/`. This page covers the trait, tags, fixtures,
recording and scrubbing, and the review checklist. [CHECKS.md](CHECKS.md) covers running checks.

## The contract

- **Read-only.** Checks call catalogue operations through `CheckContext` (`ctx.get`, `ctx.list`,
  `ctx.list_with`, `ctx.hunt`, `ctx.log_query`). Every call goes through Junction's registry and the
  read-only policy, so a mutation cannot be sent even by mistake. Remediation is text only.
- **No false passes or fails.** If an API call fails, return the error with `?`. The runner turns it
  into `unknown` (missing permission, with the permission to grant) or `not_applicable` (missing
  licence). Never guess a status from an empty or partial response; return `Finding::unknown` with a
  reason code instead.
- **Least privilege.** Declare every operation with the least-privileged application permission (or
  Azure RBAC role) that reads it. `junction check permissions` and `docs/CHECKS-PERMISSIONS.md` are
  generated from these declarations.
- **No secrets in evidence.** Evidence holds counts, identifiers (UPNs, device names, domains) and
  setting values. Never tokens, passwords, LAPS passwords, BitLocker keys or raw API payloads.

## Anatomy

```rust
use crate::check::{ApiRequirement, Check, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::CheckContext;
use crate::model::{CheckKind, Level, Pack, Severity};
use serde_json::json;

const ROLE_ASSIGNMENTS: ApiRequirement = ApiRequirement {
    operation: "graph.role_management.directory.role_assignments.list",
    permissions: &["RoleManagement.Read.Directory"],
};

pub const GLOBAL_ADMIN_COUNT: CheckMeta = CheckMeta {
    id: "identity.global_admin_count",       // <pack>.<snake_case>, stable forever
    title: "Between two and four Global Administrators",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::High,                 // score weight
    effort: Level::Low,                       // effort to fix (quick-win order)
    impact: Level::High,                      // risk reduced by fixing
    description: "What it reads and why it matters (shown by `junction check explain`).",
    requires: Requirements { apis: &[ROLE_ASSIGNMENTS], licences: &[] },
    remediation: "How to fix a failure, as a suggestion.",
    links: &["https://learn.microsoft.com/..."],
    references: &["CIS M365 1.1.3"],
    manual: None,
};

crate::check!(GlobalAdminCount, &GLOBAL_ADMIN_COUNT, global_admin_count);

async fn global_admin_count(ctx: &CheckContext) -> Evaluation {
    let max: usize = ctx.setting(GLOBAL_ADMIN_COUNT.id, "max", 4); // configurable threshold
    let rows = ctx
        .list_with(ROLE_ASSIGNMENTS.operation, json!({"$expand": ["principal"]}))
        .await?;                                                   // failures become unknown
    let finding = if rows.len() > max { Finding::fail("Too many.") } else { Finding::pass("OK.") };
    Ok(finding.data(json!({"count": rows.len()})).affected(vec!["admin@contoso.example"]))
}
```

Add the check to the pack's `checks()` list. `crates/junction-check/examples/stub_check.rs` is a
complete, runnable example.

### Statuses

| Status | Use when |
|---|---|
| `pass` | The control is in place. |
| `fail` | The control is missing or weaker than the threshold. |
| `warn` | Partly in place, report-only, audit mode, or a heuristic concern. Scores half. |
| `unknown` | The check could not decide (API refused, data missing). Always with a reason. Excluded from the score. |
| `not_applicable` | The tenant cannot have this control (no licence, no such workload). Always with a reason. Excluded from the score. |

Licence gating is declared, not coded: put feature names from `data/licensing.yaml` in
`requires.licences` and the runner returns `not_applicable` without calling the API when the tenant
lacks them. When licences are unreadable, the check runs and reports what the API says.

### Manual and hybrid checks

When no API can answer, declare a manual check with `CheckMeta::manual(id, title, pack, ManualSpec
{ question, guidance, why_manual })` and register `ManualCheck(&META)`. Operators answer with
`junction check attest <id>`; answers expire (default 180 days) and expired answers are `unknown`.
A hybrid check reads the API when it can and otherwise uses `ctx.attestation(id)` with
`Finding::from_attestation`.

### Calling APIs

- Operation ids must be listed in `crates/junction-check/data/operations.txt`. To add one, edit the
  list and run `scripts/check-catalog.py <registry dir>` with a release bundle's `generated/registry`
  folder. Graph beta-only settings use `id@beta`.
- Input is the operation envelope: `{"parameters": {...}, "body": {...}}`. OData `$select`,
  `$expand` and `$orderby` are arrays (`{"$select": ["id", "displayName"]}`); `$top` is an integer.
  The fixture harness rejects inputs the catalogue schema does not allow, exactly as the live path does.
- `ctx.list` follows declared paging up to the run's limits; `Listing::truncated` says when more
  existed. Calls are memoised per tenant run, so packs share the same device or policy listings.
- Advanced hunting: `ctx.hunt(kql)` (Defender XDR API, falling back to Graph `runHuntingQuery`). Keep
  queries bounded (`summarize` per device, `take`). Put queries in `crates/junction-check/queries/`
  and load them with `include_str!`.
- Settings: `ctx.setting(check_id, key, default)` reads `[checks."<id>"]` from the `--config` TOML;
  `ctx.pack_setting(pack, key, default)` reads `[packs.<pack>]`.

## Tags

Tags are data. Add an entry to `crates/junction-check/data/tags/<pack>.yaml`:

```yaml
identity.global_admin_count:
  essential_eight:
    - strategy: restrict-admin-privileges   # ids from data/frameworks/essential-eight.yaml
      levels: [1, 2, 3]
  ism: [ISM-1507, ISM-1508]
  cis_m365: ["1.1.3"]
  cis_v8: ["5.4"]
  nist_csf: [PR.AA-05]
  mitre: [T1078.004, T1098]
```

Every id must exist in `crates/junction-check/data/frameworks/`. Those files are synced one way from
crownguard with `scripts/sync-frameworks.sh`; ATT&CK techniques and CIS Controls v8 ids are kept in
this repository. Every check needs at least one tag; the registry test fails otherwise.

## Fixtures

Each case is a directory of JSON files. A file holds one entry or an array:

```json
{"operation": "graph.users.list",
 "match": {"parameters": {"$filter": "accountEnabled eq true"}},
 "responses": [{"status": 200, "body": {"value": [], "@odata.nextLink": "fixture:users-2"}}]}
```

- `match` (optional) must be a subset of the call's input; the most specific entry wins.
- `{"url": "fixture:users-2", ...}` answers a page link.
- Errors: `{"status": 403, "error": {"code": "Authorization_RequestDenied", "message": "..."}}`.
  Throttling: `{"status": 429, "retry_after": 0}` followed by the real response.
- `case.toml` (optional) sets `licences`, `now`, `config`, `attestations` and `dns` records.

Cover at least pass, fail, `unknown` on 403, `not_applicable` on a missing licence and paging
across two pages. Test with `testkit::run_case`, `assert_status` and `assert_snapshot` (writes
`expected.snap` when run with `UPDATE_SNAPSHOTS=1`; review the file before committing).

### Recording and scrubbing

Fixtures must be synthetic. `scripts/record-check-fixture.sh` runs one read operation against a test
tenant you control and pipes it through `junction check scrub-fixture`, which replaces GUIDs, UPNs,
e-mail addresses, domains, IP addresses, names and tokens with consistent synthetic values. It is off
by default (set `JUNCTION_RECORD_FIXTURES=1`) and never runs in CI. Always read the result before
committing: the scrubber is a safety net, not a guarantee.

Only `contoso.example`, `fabrikam.example`, `example.org` style names are allowed. A test fails if
any fixture contains a `eyJ` JWT prefix or a real domain.

## Review checklist

- [ ] Id is `<pack>.<snake_case>`, stable, and the title reads as the desired state.
- [ ] Every API call is declared in `requires.apis` with the least-privileged permission.
- [ ] Licence-dependent checks declare `requires.licences`.
- [ ] Failures use `?`; no status is guessed from missing data.
- [ ] Evidence has counts and identifiers only; affected lists are identifiers.
- [ ] Remediation is specific, suggest-only, and links to Microsoft Learn.
- [ ] Tags exist in the framework data; Essential Eight levels are honest.
- [ ] Fixtures cover pass, fail, unknown (403), not applicable (licence) and paging.
- [ ] `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings` and
      `cargo test --workspace --locked` pass.
