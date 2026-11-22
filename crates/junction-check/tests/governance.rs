//! Fixture tests for `junction apps` (connected-app governance). The synthetic
//! tenant in `tests/fixtures/governance/tenant` holds one app per risk pattern;
//! the other cases refuse one read to prove missing data never becomes a flag.
use junction_check::governance::{flags, inventory::Inventory};
use junction_check::testkit::{FixtureGateway, TENANT, fixtures_root, scan_fixture_tree};
use junction_watch::clock::Instant;
use std::collections::BTreeSet;
use std::sync::Arc;

const NOW: &str = "2026-10-25T00:00:00.000Z";

async fn inventory(case: &str) -> Result<Inventory, String> {
    let dir = fixtures_root().join("governance").join(case);
    let gateway = Arc::new(FixtureGateway::load(TENANT, &dir).unwrap());
    junction_check::governance::run(
        gateway,
        Some("Contoso (synthetic)".into()),
        Arc::new(Default::default()),
        Instant::parse(NOW).unwrap(),
        4,
    )
    .await
    .map_err(|e| e.to_string())
}

fn flag_ids(inventory: &Inventory, app: &str) -> BTreeSet<String> {
    inventory
        .apps
        .iter()
        .find(|a| a.display_name == app)
        .unwrap_or_else(|| panic!("{app} not inventoried"))
        .flags
        .iter()
        .map(|f| f.id.clone())
        .collect()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| (*s).to_owned()).collect()
}

#[tokio::test]
async fn inventory_joins_permissions_grants_owners_and_sign_ins() {
    let inv = inventory("tenant").await.unwrap();
    assert_eq!(inv.schema_version, 1);
    assert!(inv.gaps.is_empty(), "{:?}", inv.gaps);
    assert_eq!(inv.summary.apps, 13);
    assert_eq!(
        (
            inv.summary.home_tenant,
            inv.summary.external,
            inv.summary.microsoft
        ),
        (4, 5, 3)
    );

    // Application permissions are resolved to names across a paged listing,
    // and user assignments are not mistaken for app permissions.
    let mail = inv.app("00000000-0000-4000-a000-000000000002").unwrap();
    assert_eq!(mail.application_permissions.len(), 1);
    assert_eq!(mail.application_permissions[0].permission, "Mail.Read");
    assert_eq!(
        mail.application_permissions[0].resource_name,
        "Microsoft Graph"
    );
    let hr = inv.app("00000000-0000-4000-a000-000000000105").unwrap();
    assert_eq!(hr.application_permissions[0].permission, "User.Read.All");
    let total: usize = inv
        .apps
        .iter()
        .map(|a| a.application_permissions.len())
        .sum();
    // Graph: Mail.Read, Directory.ReadWrite.All, two User.Read.All; Exchange: IMAP.AccessAsApp.
    assert_eq!(total, 5);

    // Delegated grants: tenant-wide and per-user, with guest consenters marked.
    let pdf = inv.app("00000000-0000-4000-a000-000000000003").unwrap();
    assert_eq!(pdf.delegated_grants[0].consent_type, "AllPrincipals");
    assert!(
        pdf.delegated_grants[0]
            .scopes
            .contains(&"Files.ReadWrite.All".to_owned())
    );
    let cal = inv.app("00000000-0000-4000-a000-000000000007").unwrap();
    let guests: Vec<_> = cal
        .delegated_grants
        .iter()
        .map(|g| g.principal_guest)
        .collect();
    assert_eq!(guests, vec![Some(true), Some(false)]);

    // Owners of the app registration, guest detection and sign-in recency.
    let legacy = inv.app("00000000-0000-4000-a000-000000000104").unwrap();
    assert_eq!(legacy.owners.len(), 1);
    assert_eq!(legacy.owners[0].guest, Some(true));
    assert_eq!(legacy.owners[0].of, "application");
    assert_eq!(legacy.last_sign_in.as_deref(), Some("2026-03-01T08:00:00Z"));
    assert_eq!(legacy.credentials.len(), 2);
}

#[tokio::test]
async fn every_flag_fires_on_the_app_built_for_it() {
    let inv = inventory("tenant").await.unwrap();
    // External, delegated grants only: its age is unknown, so no sign-in
    // recency flag even though no sign-in is recorded. Files.ReadWrite.All is
    // delegated here, so the application-only advice (Sites.Selected) does
    // not apply and no overbroad_scope flag is raised.
    assert_eq!(
        flag_ids(&inv, "Free PDF Helper"),
        set(&[
            "critical_permission",
            "tenant_wide_delegated",
            "unverified_publisher_external"
        ])
    );
    assert_eq!(
        flag_ids(&inv, "Legacy Provisioning Script"),
        set(&[
            "critical_permission",
            "overbroad_scope",
            "privileged_no_recent_sign_in",
            "credential_on_service_principal",
            "guest_owned"
        ])
    );
    assert_eq!(
        flag_ids(&inv, "Old HR Sync"),
        set(&[
            "overbroad_scope",
            "expired_credentials_only",
            "ownerless",
            "unused"
        ])
    );
    assert_eq!(
        flag_ids(&inv, "Fabrikam Mail Archive"),
        set(&["high_permission", "overbroad_scope"])
    );
    assert_eq!(
        flag_ids(&inv, "Contoso Calendar Sync"),
        set(&["risky_service_principal", "guest_consented"])
    );
    // IMAP.AccessAsApp is classified; the confirmed-safe risk is not a flag.
    assert_eq!(
        flag_ids(&inv, "Mail Migration Tool"),
        set(&["critical_permission", "overbroad_scope"])
    );
    // Federated credentials and recent sign-ins: expired leftovers are not a flag.
    assert_eq!(flag_ids(&inv, "CI Deployer"), set(&["overbroad_scope"]));
    // Disabled, Microsoft first-party and recently used apps stay clean.
    for clean in [
        "Retired Reporting App",
        "Office 365 Exchange Online",
        "Office 365 Exchange Online API",
        "Microsoft Graph",
        "mi-backup-runner",
        "Northwind HR Portal",
    ] {
        assert!(flag_ids(&inv, clean).is_empty(), "{clean}");
    }
    let fired: BTreeSet<String> = flags::counts(&inv).into_keys().collect();
    let documented: BTreeSet<String> = flags::FLAGS.iter().map(|f| f.id.to_owned()).collect();
    assert_eq!(
        fired, documented,
        "every documented flag has a triggering fixture"
    );
}

#[tokio::test]
async fn unavailable_sign_in_data_never_reads_as_unused() {
    let inv = inventory("sign_in_forbidden").await.unwrap();
    let gap = inv
        .gaps
        .iter()
        .find(|g| g.area == "sign_in_activity")
        .expect("gap recorded");
    assert_eq!(gap.reason.code, "missing_permission");
    assert_eq!(gap.reason.missing_permissions, ["AuditLog.Read.All"]);
    let fired = flags::counts(&inv);
    assert!(!fired.contains_key("unused"));
    assert!(!fired.contains_key("privileged_no_recent_sign_in"));
    assert!(inv.apps.iter().all(|a| a.last_sign_in.is_none()));
    // Everything else still completes.
    assert!(fired.contains_key("critical_permission"));
}

#[tokio::test]
async fn unreadable_owners_never_read_as_ownerless() {
    let inv = inventory("owners_forbidden").await.unwrap();
    assert!(inv.gap("owners"));
    let fired = flags::counts(&inv);
    assert!(!fired.contains_key("ownerless"));
    assert!(!fired.contains_key("guest_owned"));
    assert!(inv.apps.iter().all(|a| a.owners.is_empty()));
}

#[tokio::test]
async fn a_refused_core_listing_fails_the_inventory() {
    let error = inventory("core_forbidden").await.unwrap_err();
    assert!(error.contains("Application.Read.All"), "{error}");
}

#[tokio::test]
async fn inventory_json_carries_no_secret_material() {
    let inv = inventory("tenant").await.unwrap();
    let text = serde_json::to_string(&inv).unwrap();
    // Fixture hints and certificate key identifiers must not be copied.
    for secret in ["Zx9", "Ab1", "QUJD", "\"hint\"", "customKeyIdentifier"] {
        assert!(!text.contains(secret), "{secret} leaked into the inventory");
    }
}

#[test]
fn governance_fixtures_are_synthetic() {
    let problems = scan_fixture_tree(&fixtures_root().join("governance"));
    assert!(problems.is_empty(), "{problems:#?}");
}

// --- review follow-ups on #59 ------------------------------------------------------

#[tokio::test]
async fn sign_in_state_is_explicit_in_json() {
    use junction_check::governance::inventory::SignInData;
    let read = inventory("tenant").await.unwrap();
    let pdf = read.app("00000000-0000-4000-a000-000000000003").unwrap();
    assert_eq!(pdf.sign_in_data, SignInData::NoneRecorded);
    let legacy = read.app("00000000-0000-4000-a000-000000000104").unwrap();
    assert_eq!(legacy.sign_in_data, SignInData::Recorded);

    let refused = inventory("sign_in_forbidden").await.unwrap();
    let json = serde_json::to_value(&refused).unwrap();
    for app in json["apps"].as_array().unwrap() {
        assert!(
            app.get("last_sign_in")
                .is_some_and(serde_json::Value::is_null),
            "{app}"
        );
        assert_eq!(app["sign_in_data"], "unavailable");
    }
    let json = serde_json::to_value(&read).unwrap();
    let pdf = json["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["display_name"] == "Free PDF Helper")
        .unwrap();
    assert!(pdf["last_sign_in"].is_null());
    assert_eq!(pdf["sign_in_data"], "none_recorded");
}

#[tokio::test]
async fn one_failed_owner_lookup_keeps_owners_read_elsewhere() {
    let inv = inventory("owners_partial").await.unwrap();
    assert!(inv.gap("owners"));
    let hr = inv.app("00000000-0000-4000-a000-000000000105").unwrap();
    assert_eq!(hr.owners_unread, ["application"]);
    // The guest owner read from the service principal is still evidence...
    assert!(
        hr.owners
            .iter()
            .any(|o| o.guest == Some(true) && o.of == "service_principal")
    );
    let ids = flag_ids(&inv, "Old HR Sync");
    assert!(ids.contains("guest_owned"), "{ids:?}");
    // ...but with its registration owners unread it is never called ownerless.
    assert!(!ids.contains("ownerless"), "{ids:?}");
    // Other apps' owners survive the failure.
    let legacy = inv.app("00000000-0000-4000-a000-000000000104").unwrap();
    assert!(legacy.owners_unread.is_empty());
    assert!(flag_ids(&inv, "Legacy Provisioning Script").contains("guest_owned"));
}

#[tokio::test]
async fn microsoft_service_principal_owners_are_collected() {
    let inv = inventory("tenant").await.unwrap();
    let exo = inv.app("00000000-0000-4000-a000-000000000108").unwrap();
    assert!(exo.is_microsoft());
    assert_eq!(exo.owners.len(), 1);
    assert_eq!(exo.owners[0].of, "service_principal");
}

#[tokio::test]
async fn risk_joins_by_object_id_without_app_id() {
    let inv = inventory("tenant").await.unwrap();
    let cal = inv.app("00000000-0000-4000-a000-000000000007").unwrap();
    let risk = cal.risk.as_ref().expect("risk kept without appId");
    assert_eq!(
        (risk.level.as_str(), risk.state.as_str()),
        ("high", "atRisk")
    );
}

#[tokio::test]
async fn registrations_without_a_service_principal_are_inventoried() {
    let inv = inventory("tenant").await.unwrap();
    assert_eq!(inv.summary.registrations_without_service_principal, 1);
    let reg = &inv.registrations_without_service_principal[0];
    assert_eq!(reg.display_name, "Partner Portal Connector");
    assert_eq!(reg.application_id, "00000000-0000-4000-a000-000000000212");
    assert_eq!(reg.sign_in_audience.as_deref(), Some("AzureADMultipleOrgs"));
    assert_eq!(reg.owners.len(), 1);
    assert_eq!(reg.credentials.len(), 1);
    // Not invented as a service principal row.
    assert!(inv.apps.iter().all(|a| a.app_id != reg.app_id));
    let text = serde_json::to_string(reg).unwrap();
    assert!(!text.contains("Qq7"), "credential hint leaked");
}

// --- adversarial review follow-ups on #59 ----------------------------------------------

#[tokio::test]
async fn user_only_app_roles_are_never_listed_as_app_permissions() {
    // The fixture answers the user-only SSO resource with a 500: listing it
    // would fail the whole inventory.
    let inv = inventory("tenant").await.unwrap();
    let sso = inv.app("00000000-0000-4000-a000-000000000013").unwrap();
    assert!(sso.application_permissions.is_empty());
    let imap = inv.app("00000000-0000-4000-a000-000000000015").unwrap();
    assert_eq!(
        imap.application_permissions[0].permission,
        "IMAP.AccessAsApp"
    );
}

#[tokio::test]
async fn id_only_owner_stubs_leave_guest_status_unknown() {
    let inv = inventory("owner_stubs").await.unwrap();
    assert!(inv.gap("guests"));
    let legacy = inv.app("00000000-0000-4000-a000-000000000104").unwrap();
    assert_eq!(legacy.owners.len(), 1);
    assert_eq!(
        legacy.owners[0].guest, None,
        "a stub is not evidence of a member"
    );
    // Unknown guest status is never a guest flag, and never a false clean either:
    // the guests gap names the permission to grant.
    assert!(!flags::counts(&inv).contains_key("guest_owned"));
    let gap = inv.gaps.iter().find(|g| g.area == "guests").unwrap();
    assert_eq!(gap.reason.missing_permissions, ["User.Read.All"]);
}

#[tokio::test]
async fn owners_are_cross_checked_against_the_guest_list() {
    // The owner object says nothing about userType, but the id is a listed guest.
    let inv = inventory("tenant").await.unwrap();
    let legacy = inv.app("00000000-0000-4000-a000-000000000104").unwrap();
    assert_eq!(legacy.owners[0].guest, Some(true));
}

#[test]
fn every_microsoft_cloud_first_party_owner_is_recognised() {
    use junction_check::packs::apps::is_microsoft_owned;
    for tenant in [
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
        "33e01921-4d64-4f8c-a055-5bdaffd5e33d",
        "cab8a31a-1906-4287-a0d8-4eef66b95f6e",
        "a55a4d5b-9241-49b1-b4ff-befa8db00269",
    ] {
        assert!(
            is_microsoft_owned(&serde_json::json!({"appOwnerOrganizationId": tenant})),
            "{tenant}"
        );
    }
    assert!(!is_microsoft_owned(
        &serde_json::json!({"appOwnerOrganizationId": "00000000-0000-4000-8000-0000000000e1"})
    ));
}

#[test]
fn consent_and_mailbox_protocol_permissions_are_classified() {
    use junction_check::governance::flags::{Tier, Tiers};
    let tiers = Tiers::embedded();
    for p in [
        "DelegatedPermissionGrant.ReadWrite.All",
        "Policy.ReadWrite.PermissionGrant",
        "IMAP.AccessAsApp",
        "POP.AccessAsApp",
        "SMTP.SendAsApp",
    ] {
        assert_eq!(tiers.lookup(p).map(|(t, _)| t), Some(Tier::Critical), "{p}");
    }
    // Application-only advice is never offered for delegated grants.
    let mail = tiers.lookup("Mail.Read").unwrap().1;
    assert!(mail.narrower.is_some() && mail.narrower_delegated.is_none());
}

#[tokio::test]
async fn governed_gateway_waits_for_the_local_request_limit() {
    use junction_check::gateway::{
        BoxFut, CallError, FailureKind, Gateway, GatewayError, Governed, Listing,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Throttled(AtomicUsize);
    impl Gateway for Throttled {
        fn tenant_id(&self) -> &str {
            TENANT
        }
        fn get<'a>(
            &'a self,
            _: &'a str,
            _: serde_json::Value,
        ) -> BoxFut<'a, Result<serde_json::Value, GatewayError>> {
            Box::pin(async { Ok(serde_json::Value::Null) })
        }
        fn list<'a>(
            &'a self,
            _: &'a str,
            _: serde_json::Value,
        ) -> BoxFut<'a, Result<Listing, GatewayError>> {
            Box::pin(async move {
                // Refused locally far more times than the upstream retry budget.
                if self.0.fetch_add(1, Ordering::SeqCst) < 12 {
                    Err(GatewayError::Call(CallError::other(
                        FailureKind::LocalThrottle,
                        "request admission rejected",
                    )))
                } else {
                    Ok(Listing::default())
                }
            })
        }
    }
    tokio::time::pause();
    let inner = Arc::new(Throttled(AtomicUsize::new(0)));
    let governed = Governed::new(
        inner.clone(),
        1,
        junction_watch::backoff::Backoff::default(),
    );
    let result = governed
        .list("graph.service_principals.list", serde_json::json!({}))
        .await;
    assert!(result.is_ok(), "local throttling is paced, not a failure");
    assert_eq!(inner.0.load(Ordering::SeqCst), 13);
}

// --- baseline, drift and evidence export (#47) ------------------------------

use junction_check::governance::{baseline, export};

#[tokio::test]
async fn drift_reports_access_changes_and_ignores_activity() {
    let base = baseline::Baseline::from_inventory(&inventory("tenant").await.unwrap()).unwrap();
    let later = inventory("later").await.unwrap();
    let drift = baseline::diff(&base, &later).unwrap();

    let names = |apps: &[baseline::AppRef]| -> Vec<String> {
        apps.iter().map(|a| a.display_name.clone()).collect()
    };
    // Re-created under the same name with a new object id: removed plus added.
    assert_eq!(
        names(&drift.added),
        ["Northwind Inbox Analytics", "Old HR Sync"]
    );
    assert_eq!(
        names(&drift.removed),
        ["Old HR Sync", "Retired Reporting App"]
    );

    let fabrikam = drift
        .changed
        .iter()
        .find(|c| c.display_name == "Fabrikam Mail Archive v2")
        .expect("permission widened on an existing app");
    assert_eq!(
        fabrikam.application_permissions.added,
        ["Microsoft Graph/Sites.ReadWrite.All"]
    );
    assert!(fabrikam.properties[0].starts_with("display_name: "));
    let legacy = drift
        .changed
        .iter()
        .find(|c| c.display_name == "Legacy Provisioning Script")
        .unwrap();
    assert_eq!(legacy.owners.added.len(), 1);
    // A newer sign-in on Fabrikam is activity, not drift: only two apps changed.
    assert_eq!(drift.changed.len(), 2);
    assert!(drift.widened());

    let same = baseline::diff(&base, &inventory("tenant").await.unwrap()).unwrap();
    assert!(same.is_empty() && !same.widened());

    let md = baseline::markdown(&drift);
    assert!(md.contains("added application permission: Microsoft Graph/Sites.ReadWrite.All"));
    // `>` is escaped so tenant text cannot open a block quote or raw HTML.
    assert!(
        md.contains("Fabrikam Mail Archive -\\> Fabrikam Mail Archive v2"),
        "{md}"
    );
}

#[tokio::test]
async fn baselines_are_bound_to_their_tenant_and_content() {
    let inv = inventory("tenant").await.unwrap();
    let base = baseline::Baseline::from_inventory(&inv).unwrap();
    let text = serde_json::to_string(&base).unwrap();
    assert_eq!(baseline::Baseline::parse(&text).unwrap(), base);

    // Edited content no longer matches the digest.
    let edited = text.replace("Mail.Read", "Mail.Send");
    assert!(
        baseline::Baseline::parse(&edited)
            .unwrap_err()
            .to_string()
            .contains("digest")
    );

    // Another tenant's baseline is refused.
    let mut other = base.clone();
    other.tenant_id = "00000000-0000-4000-8000-000000000002".into();
    assert!(
        baseline::diff(&other, &inv)
            .unwrap_err()
            .to_string()
            .contains("tenant")
    );
    // Editing the tenant or the capture time in the file breaks the digest, so
    // a baseline cannot be relabelled for another tenant or backdated.
    let relabelled = text.replace(TENANT, "00000000-0000-4000-8000-000000000002");
    assert!(baseline::Baseline::parse(&relabelled).is_err());
    let backdated = text.replace("2026-10-25T00:00:00.000Z", "2025-01-01T00:00:00.000Z");
    assert!(baseline::Baseline::parse(&backdated).is_err());
    // Unknown fields are refused rather than ignored.
    let extra = text.replacen('{', "{\"note\":\"x\",", 1);
    assert!(baseline::Baseline::parse(&extra).is_err());

    // Without owners, an inventory cannot become a baseline.
    let no_owners = inventory("owners_forbidden").await.unwrap();
    assert!(baseline::Baseline::from_inventory(&no_owners).is_err());
}

#[tokio::test]
async fn evidence_pack_manifest_matches_every_file() {
    use sha2::{Digest, Sha256};
    let base = baseline::Baseline::from_inventory(&inventory("tenant").await.unwrap()).unwrap();
    let later = inventory("later").await.unwrap();
    let drift = baseline::diff(&base, &later).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let manifest = export::write(dir.path(), &later, Some(&drift)).unwrap();

    let files = manifest["files"].as_array().unwrap();
    let mut names: Vec<&str> = files.iter().map(|f| f["file"].as_str().unwrap()).collect();
    names.sort();
    let mut expected: Vec<&str> = export::FILES.to_vec();
    expected.extend(["drift.json", "drift.md"]);
    expected.sort();
    assert_eq!(names, expected);
    for f in files {
        let bytes = std::fs::read(dir.path().join(f["file"].as_str().unwrap())).unwrap();
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(f["sha256"], digest.as_str(), "{}", f["file"]);
        assert_eq!(f["bytes"], bytes.len());
    }
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("manifest.json")).unwrap()).unwrap();
    assert_eq!(on_disk, manifest);

    let readme = std::fs::read_to_string(dir.path().join("README.md")).unwrap();
    assert!(readme.contains("Nothing in the tenant was changed"));
    assert!(readme.contains("`Application.Read.All`"));
    assert!(readme.contains("Drift since the approved baseline"));
    assert!(
        !readme.contains('\u{2014}'),
        "no em dashes in human-facing copy"
    );

    let grants = std::fs::read_to_string(dir.path().join("grants.csv")).unwrap();
    assert!(grants.contains("\"AllPrincipals\""));
    let permissions = std::fs::read_to_string(dir.path().join("permissions.csv")).unwrap();
    assert!(permissions.contains("\"Sites.ReadWrite.All\",\"critical\""));
}

#[tokio::test]
async fn export_csv_neutralises_hostile_display_names() {
    let mut inv = inventory("tenant").await.unwrap();
    inv.apps[0].display_name = "=HYPERLINK(\"https://attacker.example\")".into();
    let csv = export::apps_csv(&inv);
    assert!(csv.contains("\"'=HYPERLINK("), "{csv}");
    assert!(!csv.contains(",\"=HYPERLINK"));
}

#[tokio::test]
async fn renaming_a_resource_is_not_drift_but_moving_tenants_is() {
    let inv = inventory("tenant").await.unwrap();
    let base = baseline::Baseline::from_inventory(&inv).unwrap();
    let mut renamed = inv.clone();
    for app in &mut renamed.apps {
        for p in &mut app.application_permissions {
            p.resource_name = "Graph (renamed)".into();
        }
        for g in &mut app.delegated_grants {
            g.resource_name = "Graph (renamed)".into();
        }
    }
    assert!(baseline::diff(&base, &renamed).unwrap().is_empty());

    let mut moved = inv.clone();
    let app = moved
        .apps
        .iter_mut()
        .find(|a| a.display_name == "Fabrikam Mail Archive")
        .unwrap();
    app.owner_tenant = junction_check::governance::inventory::OwnerTenant::Home;
    let drift = baseline::diff(&base, &moved).unwrap();
    assert!(drift.changed[0].properties[0].starts_with("owner_tenant: "));
    assert!(drift.widened(), "a change of owning tenant needs review");
}

// --- reports (#48) -------------------------------------------------------------

#[tokio::test]
async fn reports_escape_hostile_tenant_text() {
    use junction_check::governance::report::{self, View};
    let mut inv = inventory("tenant").await.unwrap();
    let hostile = "<img src=x onerror=alert(1)>|**bold**";
    let app = inv
        .apps
        .iter_mut()
        .find(|a| a.display_name == "Free PDF Helper")
        .unwrap();
    app.display_name = hostile.into();
    let view = View::default();

    let html = report::html(&inv, &view);
    assert!(
        !html.contains("<img"),
        "raw HTML from the tenant reached the page"
    );
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    assert!(!html.contains("<script"));

    let md = report::markdown(&inv, &view);
    // Every `<` and `|` from the tenant is backslash-escaped: no raw HTML, and
    // a pipe in a name cannot split the Markdown table row.
    let unescaped = |line: &str, c: char| {
        let chars: Vec<char> = line.chars().collect();
        (0..chars.len())
            .filter(|&i| chars[i] == c && (i == 0 || chars[i - 1] != '\\'))
            .count()
    };
    assert!(md.lines().all(|l| unescaped(l, '<') == 0), "{md}");
    let row = md.lines().find(|l| l.contains("onerror")).expect("app row");
    assert_eq!(unescaped(row, '|'), 8, "{row}");
    assert!(!md.contains("**bold**"));

    let table = report::table(&inv, &view);
    assert!(!table.contains('\u{1b}'));
}
