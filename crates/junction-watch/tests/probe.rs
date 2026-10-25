mod common;
use common::*;
use junction_watch::{
    capability::{CapabilityState, Reason},
    probe::{probe_all, start_subscriptions},
    store::Store,
    upstream::Api,
};
use serde_json::json;

fn business_basic_tenant() -> Mock {
    let m = Mock::new();
    m.route(Api::Graph, "GET", "/v1.0/organization", None, vec![ok(json!({"value": [{
        "id": TENANT, "displayName": "Example Football Club",
        "verifiedDomains": [{"name": "Club.Example"}, {"name": "club.onmicrosoft.com"}, {"name": "bad domain<script>"}]
    }]}))]);
    m.route(Api::Graph, "GET", "/v1.0/subscribedSkus", None, vec![ok(json!({"value": [{
        "skuPartNumber": "O365_BUSINESS_ESSENTIALS", "capabilityStatus": "Enabled",
        "servicePlans": [{"servicePlanName": "EXCHANGE_S_STANDARD", "provisioningStatus": "Success"},
                         {"servicePlanName": "FLOW_O365_P1", "provisioningStatus": "Disabled"}]
    }]}))]);
    m.route(
        Api::Graph,
        "GET",
        "/v1.0/auditLogs/directoryAudits",
        None,
        vec![ok(json!({"value": []}))],
    );
    m.route(
        Api::Graph,
        "GET",
        "/v1.0/auditLogs/signIns",
        None,
        vec![err_msg(
            403,
            Some("Authentication_RequestFromNonPremiumTenantOrB2CTenant"),
            "Neither tenant is B2C or tenant doesn't have premium license",
        )],
    );
    m.route(
        Api::Graph,
        "GET",
        "/v1.0/admin/sharepoint/settings",
        None,
        vec![ok(json!({"sharingCapability": "externalUserSharingOnly"}))],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/list",
        None,
        vec![ok(json!([
            {"contentType": "Audit.Exchange", "status": "enabled", "webhook": null},
            {"contentType": "Audit.SharePoint", "status": "enabled", "webhook": null},
            {"contentType": "Audit.AzureActiveDirectory", "status": "disabled", "webhook": null}
        ]))],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/content",
        None,
        vec![ok(json!([]))],
    );
    m
}

#[tokio::test]
async fn free_tenant_probe_distinguishes_every_state() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = business_basic_tenant();
    let report = probe_all(&m, &store).await.unwrap();
    let state = |id: &str| {
        report
            .capabilities
            .iter()
            .find(|c| c.source == id)
            .unwrap()
            .clone()
    };

    assert_eq!(
        state("graph:signIns").state,
        CapabilityState::RequiresLicence
    );
    assert_eq!(
        state("graph:directoryAudits").state,
        CapabilityState::AvailableWithLimitations
    );
    assert_eq!(
        state("o365:Audit.Exchange").state,
        CapabilityState::Available
    );
    assert_eq!(
        state("o365:Audit.AzureActiveDirectory").reason,
        Reason::SubscriptionDisabled
    );
    assert_eq!(
        state("o365:Audit.General").reason,
        Reason::SubscriptionNotStarted
    );
    assert_eq!(
        state("o365:Audit.General").state,
        CapabilityState::NotEnabled
    );

    assert_eq!(
        report.verified_domains,
        ["club.example", "club.onmicrosoft.com"]
    );
    assert_eq!(
        report.subscriptions[0].service_plans,
        ["EXCHANGE_S_STANDARD"],
        "only provisioned plans"
    );
    assert!(
        report
            .blocked_detections
            .contains(&"M365-ID-007".to_string()),
        "sign-in detection off without P1"
    );
    assert!(
        report
            .runnable_detections
            .contains(&"M365-EXO-001".to_string())
    );
    assert!(
        report
            .blocked_detections
            .contains(&"M365-ID-001".to_string()),
        "the Graph directory audit probe succeeds, but it is not collected in this release, so it must not claim identity coverage while the unified Entra feed is disabled"
    );
    assert_eq!(
        store.capabilities().unwrap().len(),
        report.capabilities.len()
    );
    assert!(store.meta("last_probe_at").unwrap().is_some());
    // Probing is read-only: no POSTs.
    assert!(
        m.calls
            .lock()
            .unwrap()
            .iter()
            .all(|(_, method, _)| method == "GET")
    );
}

#[tokio::test]
async fn missing_permissions_are_not_reported_as_licence_gaps() {
    let store = Store::in_memory(TENANT).unwrap();
    let mut m = Mock::new();
    m.graph_roles = vec![];
    m.mgmt_roles = vec![];
    m.route(
        Api::Graph,
        "GET",
        "/v1.0/",
        None,
        vec![err(403, "Authorization_RequestDenied")],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/list",
        None,
        vec![err(401, "AF10001")],
    );
    let report = probe_all(&m, &store).await.unwrap();
    for c in &report.capabilities {
        assert_eq!(c.state, CapabilityState::RequiresPermission, "{}", c.source);
    }
    assert!(report.runnable_detections.is_empty());
}

#[tokio::test]
async fn granted_permission_still_denied_is_flagged_separately() {
    let store = Store::in_memory(TENANT).unwrap();
    // Mock::new() grants SharePointTenantSettings.Read.All in the token roles.
    let m2 = Mock::new();
    m2.route(
        Api::Graph,
        "GET",
        "/v1.0/admin/sharepoint/settings",
        None,
        vec![err(403, "accessDenied")],
    );
    m2.route(
        Api::Graph,
        "GET",
        "/v1.0/",
        None,
        vec![ok(json!({"value": []}))],
    );
    m2.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/list",
        None,
        vec![ok(json!([]))],
    );
    let report = probe_all(&m2, &store).await.unwrap();
    let sp = report
        .capabilities
        .iter()
        .find(|c| c.source == "graph:sharepointSettings")
        .unwrap();
    assert_eq!(sp.reason, Reason::AccessDeniedDespitePermission);
}

#[tokio::test]
async fn audit_disabled_tenant_is_not_enabled_not_unknown() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::Graph,
        "GET",
        "/v1.0/",
        None,
        vec![ok(json!({"value": []}))],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/list",
        None,
        vec![err_msg(
            400,
            None,
            "Microsoft.Office.Compliance.Audit.DataServiceException: Tenant 1111 does not exist.",
        )],
    );
    let report = probe_all(&m, &store).await.unwrap();
    let ex = report
        .capabilities
        .iter()
        .find(|c| c.source == "o365:Audit.Exchange")
        .unwrap();
    assert_eq!(ex.reason, Reason::AuditingDisabled);
    assert_eq!(ex.state, CapabilityState::NotEnabled);
}

#[tokio::test]
async fn subscription_start_is_audited_rate_limited_and_validated() {
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::ManagementActivity,
        "POST",
        "/subscriptions/start",
        None,
        vec![ok(
            json!({"contentType": "Audit.Exchange", "status": "enabled"}),
        )],
    );
    let out = start_subscriptions(&m, &store, "admin", &["Audit.Exchange", "DLP.All"])
        .await
        .unwrap();
    assert!(out[0].1.is_ok());
    assert!(out[1].1.is_err(), "DLP content is out of scope");
    let again = start_subscriptions(&m, &store, "admin", &["Audit.Exchange"])
        .await
        .unwrap();
    assert!(again[0].1.as_ref().unwrap_err().contains("15 minutes"));
    assert_eq!(m.calls_to("/subscriptions/start"), 1);
    let trail = store.audit_entries(10).unwrap();
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].action, "start_subscription");
    assert_eq!(store.verify_audit_trail().unwrap(), None);
    let cap = store.capability("o365:Audit.Exchange").unwrap().unwrap();
    assert_eq!(
        cap.state,
        CapabilityState::Available,
        "a started feed is collected straight away"
    );
}

#[tokio::test]
async fn enrichment_alone_never_claims_detection_coverage() {
    // Organisation and SharePoint settings probes succeed, every audit feed is off.
    let store = Store::in_memory(TENANT).unwrap();
    let m = Mock::new();
    m.route(
        Api::Graph,
        "GET",
        "/v1.0/",
        None,
        vec![ok(json!({"value": []}))],
    );
    m.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/list",
        None,
        vec![ok(json!([]))],
    );
    let report = probe_all(&m, &store).await.unwrap();
    assert!(
        report.runnable_detections.is_empty(),
        "{:?}",
        report.runnable_detections
    );
}
