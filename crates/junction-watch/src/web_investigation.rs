//! Investigation routes share the existing session, CSRF and escaping boundary.
use super::*;
use crate::store::EventQuery;
use axum::extract::{Path, Query};

fn analyst<U>(state: &AppState<U>, headers: &HeaderMap) -> Result<Session, Page> {
    let s = current(state, headers).ok_or(Page::Redirect("/login"))?;
    if s.user.role == Role::Viewer {
        return Err(Page::Status(StatusCode::FORBIDDEN, "analyst role required"));
    }
    Ok(s)
}
fn failure() -> Page {
    Page::Status(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Security store unavailable; no result is implied",
    )
}
#[derive(Default, Deserialize)]
pub(super) struct Filters {
    status: Option<String>,
    q: Option<String>,
    severity: Option<String>,
    before: Option<String>,
    actor: Option<String>,
    operation: Option<String>,
    source: Option<String>,
    site: Option<String>,
    since: Option<String>,
    until: Option<String>,
}
fn link(path: &str, pairs: &[(&str, &str)]) -> String {
    format!(
        "{path}?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs.iter().copied())
            .finish()
    )
}
pub(super) async fn alerts<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Query(f): Query<Filters>,
) -> Page {
    let session = match analyst(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    let rows = match state.store.search_alerts(
        f.status.as_deref().filter(|s| !s.is_empty()),
        f.severity.as_deref().filter(|s| !s.is_empty()),
        f.before.as_deref(),
        f.q.as_deref().filter(|s| !s.is_empty()),
        100,
    ) {
        Ok(r) => r,
        Err(_) => return failure(),
    };
    let body = html! {h1{"Alerts"}p.lede{"Review evidence and confirm changes with the owner through a trusted channel."}
    form method="get"{label for="q"{"Rule or resource "}input id="q" name="q" value=(f.q.as_deref().unwrap_or("")) maxlength="256";label for="status"{"Status "}select id="status" name="status"{@for v in ["","NEW","ACKNOWLEDGED","INVESTIGATING","RESOLVED"]{option value=(v) selected[f.status.as_deref()==Some(v)]{(if v.is_empty(){"All"}else{v})}}}" " label for="severity"{"Severity "}select id="severity" name="severity"{@for v in ["","CRITICAL","HIGH","MEDIUM","LOW"]{option value=(v) selected[f.severity.as_deref()==Some(v)]{(if v.is_empty(){"All"}else{v})}}}button type="submit"{"Filter"}}
    @if rows.is_empty(){p{"No matching alerts. Check Coverage and collector health before drawing conclusions."}}
    @else{table{caption.sr{"Security incidents"}thead{tr{th{"Severity"}th{"Rule"}th{"Resource"}th{"Status"}th{"Detected"}}}tbody{@for a in &rows{tr{td{(a.severity)}td{a href=(format!("/alerts/{}",a.id)){(a.rule_id)}}td{(a.resource)}td{(a.status) @if a.suppressed{" (suppressed)"}}td{(when(Some(&a.detected_at)))}}}}}}
    @if let Some(a)=rows.last(){a href=(link("/alerts",&[("before",&format!("{}|{}",a.detected_at,a.id)),("status",f.status.as_deref().unwrap_or("")),("severity",f.severity.as_deref().unwrap_or("")),("q",f.q.as_deref().unwrap_or(""))])){"Older alerts"}}
    };
    Page::Html(layout("Alerts", Some(&session), "/alerts", body))
}
pub(super) async fn alert<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Page {
    let session = match analyst(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    let a = match state.store.alert(&id) {
        Ok(Some(a)) => a,
        Ok(None) => return Page::Status(StatusCode::NOT_FOUND, "alert not found"),
        Err(_) => return failure(),
    };
    let history = match state.store.alert_history(&id) {
        Ok(h) => h,
        Err(_) => return failure(),
    };
    let rule = crate::rules::registry()
        .into_iter()
        .find(|r| r.id == a.rule_id);
    let body = html! {a href="/alerts"{"All alerts"}h1{(a.rule_id)" · "(a.severity)}p{(a.finding.explanation)}dl{dt{"Affected resource"}dd{(a.resource)}dt{"Confidence"}dd{(a.finding.confidence)"%. A detection is an indicator, not proof of compromise."}dt{"Status"}dd{(a.status)}}
    @if let Some(rule)=rule{h2{"Investigate and remediate"}p{(rule.remediation)}p.small{"ATT&CK "(rule.mitre)" · Rule version "(rule.version)}}
    h2{"Coverage at detection"}ul{@for limitation in &a.finding.coverage_limitations {li{(limitation)}}}h2{"Evidence timeline"}ul{@for id in &a.finding.evidence{@if let Ok(Some(e))=state.store.event(id){li{(e.timestamp)" · "(e.operation)" · "(e.source)" " a href=(format!("/evidence/{}",e.id)){"Inspect evidence"}}}}}
    div.callout.warn{"Coverage limits: only collected, supported events are included. Missing logs, delayed ingestion and unavailable configuration fields can hide activity. " a href="/coverage"{"View current coverage"}}
    h2{"Update incident"}form method="post" action=(format!("/alerts/{}",a.id)){input type="hidden" name="csrf" value=(session.csrf);label for="state"{"Status"}select id="state" name="status"{@for value in ["NEW","ACKNOWLEDGED","INVESTIGATING","RESOLVED"]{option value=(value) selected[value==a.status]{(value)}}}label for="disposition"{"Resolution"}select id="disposition" name="disposition"{option value=""{"Unresolved"}option value="remediated"{"Remediated"}option value="false_positive"{"False positive"}option value="accepted_risk"{"Accepted risk"}}label for="assignee"{"Assigned to"}input id="assignee" name="assignee" maxlength="128" value=(a.assigned_to.as_deref().unwrap_or(""));label for="note"{"Analyst note"}textarea id="note" name="note" maxlength="4096" required{}button type="submit"{"Save update"}}
    h2{"Resolution history"}ul{@for h in history{li{(h["at"].as_str().unwrap_or(""))" · "(h["actor"].as_str().unwrap_or(""))" · "(h["action"].as_str().unwrap_or(""))p{(h["note"].as_str().unwrap_or(""))}}}}
    };
    Page::Html(layout("Incident", Some(&session), "/alerts", body))
}
#[derive(Deserialize)]
pub(super) struct Update {
    csrf: String,
    status: String,
    disposition: String,
    assignee: String,
    note: String,
}
pub(super) async fn update<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<Update>,
) -> Page {
    let session = match analyst(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    if !csrf_ok(&session, &f.csrf) {
        return Page::Status(StatusCode::FORBIDDEN, "invalid form token");
    }
    match state.store.transition_alert(
        &id,
        &f.status,
        (!f.disposition.is_empty()).then_some(f.disposition.as_str()),
        (!f.assignee.is_empty()).then_some(f.assignee.as_str()),
        &f.note,
        &session.user.username,
    ) {
        Ok(()) => Page::Redirect("/alerts"),
        Err(_) => Page::Status(
            StatusCode::BAD_REQUEST,
            "Update rejected. Follow New, Acknowledged, Investigating, Resolved; include a resolution note and disposition.",
        ),
    }
}
pub(super) async fn activity<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Query(f): Query<Filters>,
) -> Page {
    let session = match analyst(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    let date = |v: &Option<String>| -> Result<Option<String>, ()> {
        v.as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| Instant::parse(s).map(|t| t.to_rfc3339()).map_err(|_| ()))
            .transpose()
    };
    let (since, until) = match (date(&f.since), date(&f.until)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return Page::Status(StatusCode::BAD_REQUEST, "Use ISO 8601 UTC timestamps"),
    };
    let query = EventQuery {
        actor: f.actor.clone().filter(|s| !s.is_empty()),
        operation: f.operation.clone().filter(|s| !s.is_empty()),
        source: f.source.clone().filter(|s| !s.is_empty()),
        site: f.site.clone().filter(|s| !s.is_empty()),
        target: None,
        since,
        until,
        limit: 100,
        before: f
            .before
            .as_deref()
            .and_then(|s| s.split_once('|'))
            .map(|(a, b)| (a.into(), b.into())),
    };
    let events = match state.store.events(&query) {
        Ok(e) => e,
        Err(_) => return failure(),
    };
    if state
        .store
        .audit(&session.user.username, "activity_search", "events", "{}")
        .is_err()
    {
        return failure();
    }
    let body = html! {h1{"Activity explorer"}form method="get"{@for(name,label,value)in [("actor","User",&f.actor),("operation","Operation",&f.operation),("source","Source",&f.source),("site","Site URL",&f.site),("since","From (UTC)",&f.since),("until","Until (UTC)",&f.until)]{label for=(name){(label)}input id=(name) name=(name) value=(value.as_deref().unwrap_or(""));}button type="submit"{"Search"}}
    table{caption.sr{"Collected audit activity"}thead{tr{th{"Time"}th{"User"}th{"Operation"}th{"Resource"}th{"Source"}}}tbody{@for e in &events{tr{td{a href=(format!("/evidence/{}",e.id)){(e.timestamp)}}td{(e.actor_upn.as_deref().unwrap_or("Unknown"))}td{(e.operation)}td{(e.target_id.as_deref().unwrap_or("Unknown"))}td{(e.source)}}}}}
    @if events.is_empty(){p{"No matching collected events. This does not establish that no activity occurred."}}
    @if let Some(e)=events.last(){a href=(link("/activity",&[("before",&format!("{}|{}",e.timestamp,e.id)),("actor",f.actor.as_deref().unwrap_or("")),("operation",f.operation.as_deref().unwrap_or("")),("source",f.source.as_deref().unwrap_or("")),("site",f.site.as_deref().unwrap_or("")),("since",f.since.as_deref().unwrap_or("")),("until",f.until.as_deref().unwrap_or(""))])){"Older events"}}
    };
    Page::Html(layout("Activity", Some(&session), "/activity", body))
}
pub(super) async fn evidence<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Page {
    let session = match analyst(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    if state
        .store
        .audit(&session.user.username, "evidence_view", &id, "{}")
        .is_err()
    {
        return failure();
    }
    let e = match state.store.event(&id) {
        Ok(Some(e)) => e,
        Ok(None) => return Page::Status(StatusCode::NOT_FOUND, "event not found"),
        Err(_) => return failure(),
    };
    let raw=match crate::evidence::EvidenceKey::environment(){Ok(Some(key))=>match state.store.read_evidence(&id,&key,&session.user.username){Ok(Some(bytes))=>String::from_utf8_lossy(&bytes).into_owned(),Ok(None)=>"Raw evidence was not retained for this event.".into(),Err(_)=>"Raw evidence unavailable or integrity check failed. Verify the required key version.".into()},_=>"Raw evidence is disabled or the encryption key is unavailable in this process.".into()};
    Page::Html(layout(
        "Evidence",
        Some(&session),
        "/activity",
        html! {h1{"Evidence"}p{"Raw record SHA-256: "code{(e.raw_sha256)}}h2{"Normalised event"}pre{(serde_json::to_string_pretty(&e).unwrap_or_default())}h2{"Raw audit record"}pre{(raw)}},
    ))
}
pub(super) async fn changes<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Query(f): Query<Filters>,
) -> Page {
    let session = match analyst(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    let (rows, snapshots) = match (
        state.store.changes(f.before.as_deref()),
        state.store.snapshots(),
    ) {
        (Ok(r), Ok(s)) => (r, s),
        _ => return failure(),
    };
    Page::Html(layout(
        "Configuration changes",
        Some(&session),
        "/changes",
        html! {h1{"Configuration changes"}p{"First complete snapshots require administrator approval. Partial snapshots never produce deletion alerts. Removed objects require two complete collections."}
        table{thead{tr{th{"Time"}th{"Type"}th{"Resource"}th{"Change"}}}tbody{@for r in &rows{tr{td{(r["at"].as_str().unwrap_or(""))}td{(r["resource_type"].as_str().unwrap_or(""))}td{(r["resource_id"].as_str().unwrap_or(""))}td{details{summary{(r["kind"].as_str().unwrap_or(""))}pre{(r["detail"].as_str().unwrap_or(""))}}}}}}}
        @if let Some(r)=rows.last(){a href=(link("/changes",&[("before",&format!("{}|{}",r["at"].as_str().unwrap_or(""),r["id"].as_str().unwrap_or("")))])){"Older changes"}}
        h2{"Snapshot collections"}ul{@for s in snapshots{li{(s["resource_type"].as_str().unwrap_or(""))" · "(s["collected_at"].as_str().unwrap_or(""))" · "(s["status"].as_str().unwrap_or(""))
        @if s["approved"]==false&&s["status"]=="complete"&&session.user.role==Role::Admin{a href=(format!("/snapshots/{}",s["id"].as_str().unwrap_or(""))){"Review baseline"}}
        }}}
        },
    ))
}
#[derive(Deserialize)]
pub(super) struct Baseline {
    csrf: String,
    id: String,
}
pub(super) async fn baseline<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Form(f): Form<Baseline>,
) -> Page {
    let session = match analyst(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    if session.user.role != Role::Admin || !csrf_ok(&session, &f.csrf) {
        return Page::Status(
            StatusCode::FORBIDDEN,
            "administrator and form token required",
        );
    }
    match state.store.approve_baseline(&f.id, &session.user.username) {
        Ok(()) => Page::Redirect("/changes"),
        Err(_) => Page::Status(StatusCode::BAD_REQUEST, "Complete snapshot required"),
    }
}

pub(super) async fn reports<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
) -> Page {
    let session = match analyst(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    let reports = match state.store.reports() {
        Ok(r) => r,
        Err(_) => return failure(),
    };
    Page::Html(layout(
        "Security reports",
        Some(&session),
        "/reports",
        html! {
        h1{"Security reports"}p{"Daily and weekly summaries are generated by the collection scheduler. Reports omit personal details. Use your browser's print command to save a copy."}
        @if reports.is_empty(){p{"No scheduled report yet. Run a collection pass to generate the first report."}}
        @for report in reports {section {h2{(report["period"].as_str().unwrap_or(""))" · "(report["until"].as_str().unwrap_or(""))}
        h3{"What changed"}p{(report["what_changed"].as_str().unwrap_or(""))}
        h3{"What was potentially dangerous"}table{thead{tr{th{"Rule"}th{"Severity"}th{"Status"}th{"Count"}}}tbody{@if let Some(items)=report["potentially_dangerous"].as_array(){@for r in items{tr{td{(r["name"].as_str().or_else(||r["rule"].as_str()).unwrap_or(""))}td{(r["severity"].as_str().unwrap_or(""))}td{(r["status"].as_str().unwrap_or(""))}td{(r["count"])}}}}}}
        h3{"What action was taken"}p{(report["action_taken"].as_str().unwrap_or(""))}
        h3{"What still needs attention"}p{(report["still_needs_attention"].as_str().unwrap_or(""))}
        h3{"Monitoring coverage"}ul{@if let Some(items)=report["not_monitored"].as_array(){@for c in items{li{(c["source"].as_str().unwrap_or(""))" · "(c["state"].as_str().unwrap_or(""))}}}}
        p.small{(report["important"].as_str().unwrap_or(""))}
        }}
        },
    ))
}
fn administrator<U>(state: &AppState<U>, headers: &HeaderMap) -> Result<Session, Page> {
    let s = analyst(state, headers)?;
    if s.user.role != Role::Admin {
        return Err(Page::Status(
            StatusCode::FORBIDDEN,
            "administrator required",
        ));
    }
    Ok(s)
}
pub(super) async fn settings<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
) -> Page {
    let session = match administrator(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    let s = match state.store.operational_settings() {
        Ok(s) => s,
        Err(_) => return failure(),
    };
    let usage = state.store.storage_usage().unwrap_or_default();
    Page::Html(layout(
        "Tenant settings",
        Some(&session),
        "/settings",
        html! {
        h1{"Tenant settings"}p{"One tenant per database and process. These controls apply to " strong{(state.tenant_domain)}". Certificate rotation stays in the host's secret environment and Entra portal."}
        p{"Stored events: "(usage["events"])". Encrypted evidence bytes: "(usage["encrypted_evidence_bytes"])". Notifications awaiting handoff: "(usage["pending_notifications"])}
        form method="post" action="/settings"{
        input type="hidden" name="csrf" value=(session.csrf);
        @for(name,label,value,min,max)in [("poll_minutes","Poll interval (minutes)",s.poll_minutes,5,1440),("retention_days","Event retention (days)",s.retention_days,8,3650),("evidence_retention_days","Raw evidence retention (days)",s.evidence_retention_days,1,3650),("max_events","Event quota",s.max_events,1000,100000000),("max_evidence_bytes","Encrypted evidence quota (bytes)",s.max_evidence_bytes,0,107374182400_u64),("bulk_threshold","Bulk operation minimum",s.bulk_threshold as u64,2,10000)]{div{label for=(name){(label)}input type="number" id=(name) name=(name) value=(value) min=(min) max=(max) required;}}
        label for="approved_domains"{"Approved external domains, one per line"}textarea id="approved_domains" name="approved_domains" maxlength="32000"{(s.approved_external_domains.join("\n"))}
        label for="sensitive_sites"{"Sensitive site URLs, one per line"}textarea id="sensitive_sites" name="sensitive_sites" maxlength="32000"{(s.sensitive_sites.join("\n"))}
        h2{"Independent alert email"}p{"Configure the host mail service separately. Recipient and delivery service must be controlled outside the monitored tenant. Mail handoff does not prove inbox delivery."}
        label for="external_email"{"External recipient"}input type="email" id="external_email" name="external_email" value=(s.notifications.external_email.as_deref().unwrap_or(""));
        label for="from_email"{"Sender"}input type="email" id="from_email" name="from_email" value=(s.notifications.from_email.as_deref().unwrap_or(""));
        label{input type="checkbox" name="independent" value="yes" checked[s.notifications.independent_destination_confirmed];" Recipient and mail service are independently secured."}
        button type="submit"{"Save settings"}}
        h2{"Approved exceptions and maintenance"}p{"Suppression is time-bounded and preserves the detection record. Use * for all rules or all resources."}
        form method="post" action="/actions/suppress"{input type="hidden" name="csrf" value=(session.csrf);@for(name,label)in [("rule","Rule ID"),("resource","Exact resource ID"),("start","Start (ISO UTC)"),("end","End (ISO UTC)"),("reason","Reason")]{label for=(name){(label)}input id=(name) name=(name) required;}button type="submit"{"Approve exception"}}
        },
    ))
}
#[derive(Deserialize)]
pub(super) struct SettingsForm {
    csrf: String,
    poll_minutes: u64,
    retention_days: u64,
    evidence_retention_days: u64,
    max_events: u64,
    max_evidence_bytes: u64,
    bulk_threshold: usize,
    approved_domains: String,
    sensitive_sites: String,
    external_email: String,
    from_email: String,
    independent: Option<String>,
}
pub(super) async fn save_settings<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Form(f): Form<SettingsForm>,
) -> Page {
    let session = match administrator(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    if !csrf_ok(&session, &f.csrf) {
        return Page::Status(StatusCode::FORBIDDEN, "invalid form token");
    }
    let s = crate::operations::Settings {
        poll_minutes: f.poll_minutes,
        retention_days: f.retention_days,
        evidence_retention_days: f.evidence_retention_days,
        max_events: f.max_events,
        max_evidence_bytes: f.max_evidence_bytes,
        bulk_threshold: f.bulk_threshold,
        approved_external_domains: f
            .approved_domains
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        sensitive_sites: f
            .sensitive_sites
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        notifications: crate::notify::NotificationConfig {
            external_email: (!f.external_email.is_empty()).then_some(f.external_email),
            from_email: (!f.from_email.is_empty()).then_some(f.from_email),
            independent_destination_confirmed: f.independent.as_deref() == Some("yes"),
        },
    };
    match state
        .store
        .save_operational_settings(&s, &state.tenant_domain, &session.user.username)
    {
        Ok(()) => Page::Redirect("/settings"),
        Err(_) => Page::Status(
            StatusCode::BAD_REQUEST,
            "Settings rejected. Check numeric limits, domains, HTTPS site URLs and independent email confirmation.",
        ),
    }
}
#[derive(Deserialize)]
pub(super) struct SuppressionForm {
    csrf: String,
    rule: String,
    resource: String,
    start: String,
    end: String,
    reason: String,
}
pub(super) async fn suppress<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Form(f): Form<SuppressionForm>,
) -> Page {
    let session = match administrator(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    if !csrf_ok(&session, &f.csrf) {
        return Page::Status(StatusCode::FORBIDDEN, "invalid form token");
    }
    let (start, end) = match (Instant::parse(&f.start), Instant::parse(&f.end)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return Page::Status(StatusCode::BAD_REQUEST, "ISO UTC timestamps required"),
    };
    match state.store.suppress(
        &f.rule,
        &f.resource,
        start,
        end,
        &f.reason,
        &session.user.username,
    ) {
        Ok(()) => Page::Redirect("/settings"),
        Err(_) => Page::Status(
            StatusCode::BAD_REQUEST,
            "Invalid rule, resource, reason or maintenance window (maximum 30 days)",
        ),
    }
}

#[derive(Default, Deserialize)]
pub(super) struct SnapshotPage {
    after: Option<String>,
}
pub(super) async fn snapshot<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(page): Query<SnapshotPage>,
) -> Page {
    let session = match analyst(&state, &headers) {
        Ok(s) => s,
        Err(p) => return p,
    };
    let snapshot = match state.store.snapshot(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return Page::Status(StatusCode::NOT_FOUND, "snapshot not found"),
        Err(_) => return failure(),
    };
    if state
        .store
        .audit(&session.user.username, "snapshot_view", &id, "{}")
        .is_err()
    {
        return failure();
    }
    let resources: Vec<_> = snapshot
        .resources
        .iter()
        .filter(|(key, _)| page.after.as_ref().is_none_or(|a| *key > a))
        .take(100)
        .collect();
    Page::Html(layout(
        "Review snapshot",
        Some(&session),
        "/changes",
        html! {
        h1{"Review configuration baseline"}p{(snapshot.resource_type)" · "(snapshot.collected_at)" · "(snapshot.status)}p{"Confirm these resources and security settings with the organisation before approving. Existing configuration becomes the starting point; later changes are compared with it."}
        table{thead{tr{th{"Resource"}th{"Configuration"}}}tbody{@for(resource,value)in &resources{tr{th scope="row"{(resource)}td{pre{(serde_json::to_string_pretty(value).unwrap_or_default())}}}}}}
        @if resources.len()==100{@if let Some((resource,_))=resources.last(){a href=(link(&format!("/snapshots/{id}"),&[("after",resource)])){"Next resources"}}}
        @if snapshot.status=="complete"&&session.user.role==Role::Admin{form method="post" action="/actions/baseline"{input type="hidden" name="csrf" value=(session.csrf);input type="hidden" name="id" value=(id);button type="submit"{"Approve reviewed baseline"}}}
        },
    ))
}
