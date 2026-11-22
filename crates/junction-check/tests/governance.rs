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
    assert_eq!(inv.summary.apps, 9);
    assert_eq!(
        (
            inv.summary.home_tenant,
            inv.summary.external,
            inv.summary.microsoft
        ),
        (3, 3, 2)
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
    assert_eq!(total, 3);

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
    assert!(legacy.owners[0].guest);
    assert_eq!(legacy.owners[0].of, "application");
    assert_eq!(legacy.last_sign_in.as_deref(), Some("2026-03-01T08:00:00Z"));
    assert_eq!(legacy.credentials.len(), 2);
}

#[tokio::test]
async fn every_flag_fires_on_the_app_built_for_it() {
    let inv = inventory("tenant").await.unwrap();
    assert_eq!(
        flag_ids(&inv, "Free PDF Helper"),
        set(&[
            "critical_permission",
            "tenant_wide_delegated",
            "overbroad_scope",
            "privileged_no_recent_sign_in",
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
    // Disabled, Microsoft first-party and recently used apps stay clean.
    for clean in [
        "Retired Reporting App",
        "Office 365 Exchange Online",
        "Microsoft Graph",
        "mi-backup-runner",
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
