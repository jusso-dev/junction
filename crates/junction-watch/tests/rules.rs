mod common;
use common::TENANT;
use junction_watch::{
    clock::Instant,
    event::from_management_record,
    incidents,
    rules::{RuleSettings, evaluate, registry},
    store::Store,
};
use serde_json::{Value, json};
fn event(source: &str, op: &str, parameters: Value) -> junction_watch::event::SecurityEvent {
    let mut raw = json!({"Id":op,"CreationTime":"2026-10-25T00:00:00Z","Operation":op,"ResultStatus":"Success","UserId":"user@club.example","ObjectId":"resource","SiteUrl":"https://club.sharepoint.com/sites/board","Parameters":parameters});
    if source == "Audit.SharePoint" {
        raw["TargetUserOrGroupName"] = json!("guest@external.example");
    }
    from_management_record(TENANT, source, &raw, Instant::now()).unwrap()
}
fn p(name: &str, value: Value) -> Value {
    json!([{"Name":name,"Value":value}])
}
#[test]
fn every_rule_has_positive_and_negative_evidence() {
    let settings = RuleSettings {
        internal_domains: vec!["club.example".into()],
        bulk_threshold: 2,
        ..Default::default()
    };
    let cases = vec![
        (
            "M365-EXO-001",
            "Audit.Exchange",
            "Set-Mailbox",
            p("ForwardingSmtpAddress", json!("smtp:thief@evil.example")),
        ),
        (
            "M365-EXO-002",
            "Audit.Exchange",
            "New-InboxRule",
            p("RedirectTo", json!("thief@evil.example")),
        ),
        (
            "M365-EXO-003",
            "Audit.Exchange",
            "Add-MailboxPermission",
            p("AccessRights", json!("FullAccess")),
        ),
        (
            "M365-EXO-004",
            "Audit.Exchange",
            "Set-TransportRule",
            p("DeleteMessage", json!(true)),
        ),
        (
            "M365-EXO-005",
            "Audit.Exchange",
            "Set-Mailbox",
            p("AuditEnabled", json!(false)),
        ),
        ("M365-EXO-006", "Audit.Exchange", "Set-InboxRule", json!([])),
        (
            "M365-SPO-001",
            "Audit.SharePoint",
            "AnonymousLinkCreated",
            json!([]),
        ),
        (
            "M365-SPO-002",
            "Audit.SharePoint",
            "SharingInvitationCreated",
            json!([]),
        ),
        (
            "M365-SPO-003",
            "Audit.SharePoint",
            "FileDownloaded",
            json!([]),
        ),
        (
            "M365-SPO-004",
            "Audit.SharePoint",
            "SiteCollectionAdminAdded",
            json!([]),
        ),
        ("M365-SPO-005", "Audit.SharePoint", "FileDeleted", json!([])),
        (
            "M365-SPO-006",
            "Audit.SharePoint",
            "SharingPolicyChanged",
            p("SharingCapability", json!("ExternalUserAndGuestSharing")),
        ),
        (
            "M365-SPO-007",
            "Audit.SharePoint",
            "AnonymousLinkCreated",
            json!([]),
        ),
        (
            "M365-ID-001",
            "Audit.AzureActiveDirectory",
            "Add member to role",
            p("Role.DisplayName", json!("Global Administrator")),
        ),
        (
            "M365-ID-002",
            "Audit.AzureActiveDirectory",
            "Add member to role",
            p("Role.DisplayName", json!("Exchange Administrator")),
        ),
        (
            "M365-ID-003",
            "Audit.AzureActiveDirectory",
            "Consent to application",
            json!([]),
        ),
        (
            "M365-ID-004",
            "Audit.AzureActiveDirectory",
            "Add application password",
            json!([]),
        ),
        (
            "M365-ID-005",
            "Audit.AzureActiveDirectory",
            "User registered security info",
            json!([]),
        ),
        (
            "M365-ID-006",
            "Audit.AzureActiveDirectory",
            "Update security defaults",
            p("IsEnabled", json!(false)),
        ),
        (
            "M365-ID-007",
            "Audit.AzureActiveDirectory",
            "SignIn",
            json!([]),
        ),
    ];
    assert_eq!(cases.len(), registry().len());
    for (id, source, op, parameters) in cases {
        let mut e = event(source, op, parameters);
        let mut history = vec![];
        match id {
            "M365-EXO-006" => {
                let mut h = e.clone();
                h.id = "snapshot".into();
                h.source = "snapshot:exchange".into();
                h.operation = "Set-InboxRule".into();
                h.metadata.insert(
                    "Parameters".into(),
                    p("ForwardTo", json!("evil@outside.example")),
                );
                history.push(h);
            }
            "M365-SPO-003" | "M365-SPO-005" => {
                let mut h = e.clone();
                h.id = "other".into();
                history.push(h);
            }
            "M365-SPO-007" => {
                for op in ["SharingInvitationCreated", "SiteCollectionAdminAdded"] {
                    history.push(event(source, op, json!([])));
                }
            }
            "M365-ID-007" => {
                e.source = "graph:signIns".into();
                e.metadata
                    .insert("riskLevelDuringSignIn".into(), json!("high"));
            }
            _ => {}
        }
        assert!(
            evaluate(&e, &history, &settings)
                .iter()
                .any(|f| f.rule_id == id),
            "positive {id}"
        );
        let mut negative = e.clone();
        negative.result = Some("failure".into());
        assert!(
            !evaluate(&negative, &history, &settings)
                .iter()
                .any(|f| f.rule_id == id),
            "failed operation {id}"
        );
        negative = e.clone();
        negative.operation = "Unrelated operation".into();
        negative.metadata.clear();
        assert!(
            !evaluate(&negative, &[], &settings)
                .iter()
                .any(|f| f.rule_id == id),
            "unrelated {id}"
        );
    }
}
#[test]
fn internal_forwarding_and_hidden_risk_do_not_alert() {
    let settings = RuleSettings {
        internal_domains: vec!["club.example".into()],
        ..Default::default()
    };
    let e = event(
        "Audit.Exchange",
        "Set-Mailbox",
        p("ForwardingSmtpAddress", json!("staff@club.example")),
    );
    assert!(evaluate(&e, &[], &settings).is_empty());
    let mut e = event("Audit.Exchange", "SignIn", json!([]));
    e.source = "graph:signIns".into();
    e.metadata
        .insert("riskLevelAggregated".into(), json!("hidden"));
    assert!(evaluate(&e, &[], &settings).is_empty());
}

#[test]
fn inbox_correlation_requires_two_successful_independent_sources() {
    let audit = event(
        "Audit.Exchange",
        "Set-InboxRule",
        p("ForwardTo", json!("evil@outside.example")),
    );
    let mut snapshot = audit.clone();
    snapshot.source = "snapshot:exchange".into();
    snapshot.id = "independent-snapshot".into();
    let settings = RuleSettings::default();
    assert!(
        !evaluate(&snapshot, std::slice::from_ref(&snapshot), &settings)
            .iter()
            .any(|f| f.rule_id == "M365-EXO-006")
    );
    let store = Store::in_memory(TENANT).unwrap();
    store
        .insert_events(&[audit.clone(), snapshot.clone()])
        .unwrap();
    incidents::detect(&store, &settings).unwrap();
    assert_eq!(
        store
            .alerts(None, None, None, 20)
            .unwrap()
            .iter()
            .filter(|a| a.rule_id == "M365-EXO-006")
            .count(),
        1
    );
    for (current, other) in [(&audit, &snapshot), (&snapshot, &audit)] {
        let findings = evaluate(current, std::slice::from_ref(other), &settings);
        let correlation = findings
            .iter()
            .find(|f| f.rule_id == "M365-EXO-006")
            .unwrap();
        assert!(correlation.evidence.contains(&audit.id));
        assert!(correlation.evidence.contains(&snapshot.id));
        let mut failed = other.clone();
        failed.result = Some("failure".into());
        assert!(
            !evaluate(current, &[failed], &settings)
                .iter()
                .any(|f| f.rule_id == "M365-EXO-006")
        );
    }
}
#[test]
fn durable_dedup_suppression_lifecycle_and_tenant_boundary() {
    let store = Store::in_memory(TENANT).unwrap();
    let e = event(
        "Audit.Exchange",
        "Set-Mailbox",
        p("ForwardingSmtpAddress", json!("thief@evil.example")),
    );
    store.insert_events(std::slice::from_ref(&e)).unwrap();
    assert_eq!(incidents::detect(&store, &Default::default()).unwrap(), 1);
    assert_eq!(incidents::detect(&store, &Default::default()).unwrap(), 0);
    let a = store.alerts(None, None, None, 50).unwrap().remove(0);
    assert!(
        store
            .transition_alert(
                &a.id,
                "RESOLVED",
                Some("remediated"),
                None,
                "fixed",
                "analyst"
            )
            .is_err()
    );
    for state in ["ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"] {
        store
            .transition_alert(
                &a.id,
                state,
                Some("remediated"),
                Some("analyst"),
                "Reviewed with owner",
                "analyst",
            )
            .unwrap();
    }
    assert_eq!(store.alert_history(&a.id).unwrap().len(), 4);
    assert!(store.verify_audit_trail().unwrap().is_none());
    let mut alien = e.clone();
    alien.tenant_id = "22222222-2222-4222-8222-222222222222".into();
    assert!(store.save_findings(&alien, &[]).is_err());
    let s = Store::in_memory(TENANT).unwrap();
    let t = Instant::parse(&e.timestamp).unwrap();
    s.suppress(
        "M365-EXO-001",
        "resource",
        t,
        t.plus(std::time::Duration::from_secs(600)),
        "Approved change",
        "admin",
    )
    .unwrap();
    s.insert_events(&[e]).unwrap();
    incidents::detect(&s, &Default::default()).unwrap();
    assert!(s.alerts(None, None, None, 5).unwrap()[0].suppressed);
}
