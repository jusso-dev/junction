mod common;
use common::TENANT;
use junction_watch::{
    clock::Instant, event::from_management_record, evidence::EvidenceKey, incidents,
    operations::Settings, store::Store,
};
use serde_json::json;
fn event(id: &str) -> junction_watch::event::SecurityEvent {
    from_management_record(TENANT,"Audit.Exchange",&json!({"Id":id,"CreationTime":"2026-01-01T00:00:00Z","Operation":"Set-Mailbox","ObjectId":"private-user@club.example","ResultStatus":"Success","Parameters":[{"Name":"ForwardingSmtpAddress","Value":"evil@outside.example"}]}),Instant::parse("2026-01-01T01:00:00Z").unwrap()).unwrap()
}
#[test]
fn retention_preserves_open_incident_evidence_then_expires_resolved_data() {
    let store = Store::in_memory(TENANT).unwrap();
    let e = event("old");
    store.insert_events(&[e]).unwrap();
    incidents::detect(&store, &Default::default()).unwrap();
    let now = Instant::parse("2026-10-25T00:00:00Z").unwrap();
    store.retain(now, "test").unwrap();
    assert_eq!(store.event_count().unwrap(), 1);
    let a = store.alerts(None, None, None, 1).unwrap().remove(0);
    for status in ["ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"] {
        store
            .transition_alert(
                &a.id,
                status,
                Some("remediated"),
                None,
                "Owner confirmed",
                "analyst",
            )
            .unwrap();
    }
    store.retain(now, "test").unwrap();
    assert_eq!(store.event_count().unwrap(), 0);
    assert!(store.verify_audit_trail().unwrap().is_none());
}
#[test]
fn reports_minimise_data_and_schedule_idempotently() {
    let store = Store::in_memory(TENANT).unwrap();
    store.insert_events(&[event("private")]).unwrap();
    incidents::detect(&store, &Default::default()).unwrap();
    let now = Instant::now();
    store.scheduled_reports(now).unwrap();
    store.scheduled_reports(now).unwrap();
    let reports = store.reports().unwrap();
    assert_eq!(reports.len(), 2);
    let body = serde_json::to_string(&reports).unwrap();
    assert!(!body.contains("private-user"));
    assert!(!body.contains("evil@"));
    assert!(body.contains("No alerts does not prove safety"));
}
#[test]
fn quota_refuses_batch_and_settings_validation_is_strict() {
    let store = Store::in_memory(TENANT).unwrap();
    let s = Settings {
        max_events: 1000,
        ..Default::default()
    };
    store
        .save_operational_settings(&s, "club.example", "admin")
        .unwrap();
    let events: Vec<_> = (0..1001).map(|i| event(&i.to_string())).collect();
    assert!(store.insert_events(&events).is_err());
    assert_eq!(store.event_count().unwrap(), 0);
    let bad = Settings {
        retention_days: 0,
        ..s
    };
    assert!(
        store
            .save_operational_settings(&bad, "club.example", "admin")
            .is_err()
    );
}
#[test]
fn evidence_reads_are_audited_and_digest_checked() {
    let store = Store::in_memory(TENANT).unwrap();
    let e = event("evidence");
    store.insert_events(std::slice::from_ref(&e)).unwrap();
    let key = EvidenceKey::from_bytes(&[4; 32]).unwrap();
    assert!(store.retain_raw(&e.id, b"wrong record", &key).is_err());
    assert!(
        store
            .read_evidence(&e.id, &key, "analyst")
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .audit_entries(10)
            .unwrap()
            .iter()
            .any(|a| a.action == "evidence_read")
    );
}

#[tokio::test]
async fn notification_outbox_retries_and_deduplicates_without_contacting_mail() {
    use junction_watch::notify::{NotificationConfig, deliver_with};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    let s = Store::in_memory(TENANT).unwrap();
    s.insert_events(&[event("alert")]).unwrap();
    incidents::detect(&s, &Default::default()).unwrap();
    let config = NotificationConfig {
        external_email: Some("security@independent.example".into()),
        from_email: Some("monitor@host.example".into()),
        independent_destination_confirmed: true,
    };
    let now = Instant::now().plus(Duration::from_secs(1));
    let calls = AtomicUsize::new(0);
    let result = deliver_with(&s, &config, &["club.example".into()], now, |body| {
        calls.fetch_add(1, Ordering::SeqCst);
        assert!(!body.contains("private-user"));
        async { Err(()) }
    })
    .await
    .unwrap();
    assert_eq!(result["failed"], 1);
    deliver_with(&s, &config, &["club.example".into()], now, |_| {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(()) }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let later = now.plus(Duration::from_secs(3600));
    let result = deliver_with(&s, &config, &["club.example".into()], later, |_| async {
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(result["accepted"], 1);
    let result = deliver_with(&s, &config, &["club.example".into()], later, |_| async {
        panic!("duplicate notification")
    })
    .await
    .unwrap();
    assert_eq!(result["accepted"], 0);
}
#[test]
fn normalisation_removes_credential_fields() {
    let raw = json!({"Parameters":[{"Name":"AccessToken","Value":"never-store-this"}],"client_secret":"also-secret"});
    let safe = junction_watch::event::sanitise(&raw).to_string();
    assert!(!safe.contains("never-store-this"));
    assert!(!safe.contains("also-secret"));
    assert!(safe.contains("redacted"));
}
