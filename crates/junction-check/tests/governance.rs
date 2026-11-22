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
    // External, delegated grants only: its age is unknown, so no sign-in
    // recency flag even though no sign-in is recorded.
    assert_eq!(
        flag_ids(&inv, "Free PDF Helper"),
        set(&[
            "critical_permission",
            "tenant_wide_delegated",
            "overbroad_scope",
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
            .any(|o| o.guest && o.of == "service_principal")
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
