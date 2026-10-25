mod common;
use common::TENANT;
use junction_watch::{
    drift::{Snapshot, diff},
    store::Store,
};
use serde_json::json;
use std::collections::BTreeMap;
fn snap(at: &str, resources: serde_json::Value) -> Snapshot {
    Snapshot {
        tenant_id: TENANT.into(),
        resource_type: "mailboxes".into(),
        collected_at: at.into(),
        source_api: "exchange_online_powershell".into(),
        status: "complete".into(),
        resources: serde_json::from_value(resources).unwrap(),
    }
}
#[test]
fn reorder_missing_fields_and_partial_collections_do_not_create_false_changes() {
    let a: BTreeMap<_, _> =
        serde_json::from_value(json!({"x":{"roles":["b","a"],"AuditEnabled":true}})).unwrap();
    let b = serde_json::from_value(json!({"x":{"roles":["a","b"]}})).unwrap();
    assert!(diff(&a, &b, false).is_empty());
    let s = Store::in_memory(TENANT).unwrap();
    let (id, c) = s
        .import_snapshot(&snap(
            "2026-10-20T01:00:00Z",
            json!({"x":{"AuditEnabled":true}}),
        ))
        .unwrap();
    assert!(c.is_empty());
    s.approve_baseline(&id, "admin").unwrap();
    let mut partial = snap("2026-10-20T02:00:00Z", json!({}));
    partial.status = "partial".into();
    assert!(s.import_snapshot(&partial).unwrap().1.is_empty());
    assert!(
        s.approve_baseline(s.snapshots().unwrap()[0]["id"].as_str().unwrap(), "admin")
            .is_err()
    );
    let first = snap("2026-10-20T03:00:00Z", json!({}));
    assert!(s.import_snapshot(&first).unwrap().1.is_empty());
    let confirmed = snap("2026-10-20T04:00:00Z", json!({}));
    let changes = s.import_snapshot(&confirmed).unwrap().1;
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, "deleted");
}
#[test]
fn approved_baseline_and_foreign_tenant() {
    let s = Store::in_memory(TENANT).unwrap();
    let old = snap(
        "2026-10-20T01:00:00Z",
        json!({"x":{"ForwardingSmtpAddress":"staff@club.example"}}),
    );
    let (id, _) = s.import_snapshot(&old).unwrap();
    s.approve_baseline(&id, "admin").unwrap();
    let new = snap(
        "2026-10-20T02:00:00Z",
        json!({"x":{"ForwardingSmtpAddress":"evil@external.example"}}),
    );
    let (_, c) = s.import_snapshot(&new).unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(s.event_count().unwrap(), 1);
    let mut alien = new;
    alien.tenant_id = "22222222-2222-4222-8222-222222222222".into();
    assert!(s.import_snapshot(&alien).is_err());
    assert!(s.verify_audit_trail().unwrap().is_none());
}

#[test]
fn unknown_observations_preserve_last_known_baseline() {
    for unknown in [json!({"x":{"AuditEnabled":null}}), json!({"x":{}})] {
        let s = Store::in_memory(TENANT).unwrap();
        let (id, _) = s
            .import_snapshot(&snap(
                "2026-10-20T01:00:00Z",
                json!({"x":{"AuditEnabled":true}}),
            ))
            .unwrap();
        s.approve_baseline(&id, "admin").unwrap();
        assert!(
            s.import_snapshot(&snap("2026-10-20T02:00:00Z", unknown))
                .unwrap()
                .1
                .is_empty()
        );
        let (_, changes) = s
            .import_snapshot(&snap(
                "2026-10-20T03:00:00Z",
                json!({"x":{"AuditEnabled":false}}),
            ))
            .unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].properties["AuditEnabled"]["old"], true);
        assert_eq!(
            junction_watch::incidents::detect(&s, &Default::default()).unwrap(),
            1
        );
        assert_eq!(
            s.alerts(None, None, None, 10).unwrap()[0].rule_id,
            "M365-EXO-005"
        );
        assert!(
            s.import_snapshot(&snap(
                "2026-10-20T04:00:00Z",
                json!({"x":{"AuditEnabled":false}})
            ))
            .unwrap()
            .1
            .is_empty()
        );
    }
}

#[test]
fn enabling_existing_forwarding_rule_uses_effective_configuration() {
    let s = Store::in_memory(TENANT).unwrap();
    let mut old = snap(
        "2026-10-20T01:00:00Z",
        json!({"x":{"Enabled":false,"ForwardTo":["evil@outside.example"]}}),
    );
    old.resource_type = "inbox_rules".into();
    let (id, _) = s.import_snapshot(&old).unwrap();
    s.approve_baseline(&id, "admin").unwrap();
    old.collected_at = "2026-10-20T02:00:00Z".into();
    assert!(s.import_snapshot(&old).unwrap().1.is_empty());
    assert_eq!(
        junction_watch::incidents::detect(&s, &Default::default()).unwrap(),
        0
    );
    old.collected_at = "2026-10-20T03:00:00Z".into();
    old.resources.get_mut("x").unwrap()["Enabled"] = json!(true);
    let (_, changes) = s.import_snapshot(&old).unwrap();
    assert_eq!(
        changes[0].properties.len(),
        1,
        "changed-field provenance stays exact"
    );
    junction_watch::incidents::detect(&s, &Default::default()).unwrap();
    let alerts = s.alerts(None, None, None, 10).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "M365-EXO-002");
}

#[test]
fn pending_deletion_does_not_repeat_modifications_and_times_are_canonical() {
    let s = Store::in_memory(TENANT).unwrap();
    let (id, _) = s
        .import_snapshot(&snap(
            "2026-10-20T01:00:00Z",
            json!({"x":{"AuditEnabled":true},"y":{"AuditEnabled":true}}),
        ))
        .unwrap();
    s.approve_baseline(&id, "admin").unwrap();
    let (_, first) = s
        .import_snapshot(&snap(
            "2026-10-20T13:00:00+10:00",
            json!({"x":{"AuditEnabled":false}}),
        ))
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].kind, "modified");
    assert_eq!(
        s.changes(None).unwrap()[0]["at"],
        "2026-10-20T03:00:00.000Z"
    );
    let (_, second) = s
        .import_snapshot(&snap(
            "2026-10-20T04:00:00Z",
            json!({"x":{"AuditEnabled":false}}),
        ))
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].kind, "deleted");
    junction_watch::incidents::detect(&s, &Default::default()).unwrap();
    assert_eq!(s.alerts(None, None, None, 10).unwrap().len(), 1);
}
