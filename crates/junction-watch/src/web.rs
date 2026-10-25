//! Server-rendered dashboard.
//!
//! Security model: loopback bind only; Host header pinned (DNS-rebinding defence);
//! session cookie is HttpOnly + SameSite=Strict; every POST needs a CSRF token and,
//! when the browser sends one, a same-origin `Origin`; strict CSP with no script;
//! all audit content is rendered through maud's auto-escaping. No numeric
//! "security score" is shown: absence of alerts never implies safety.
use crate::{
    auth::{self, LoginThrottle, Role, Session},
    capability::CapabilityState,
    catalog,
    clock::Instant,
    probe,
    store::{CapabilityRecord, Store},
    upstream::Upstream,
};
use axum::{
    Form, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

pub struct AppState<U> {
    pub store: Store,
    pub upstream: Option<Arc<U>>,
    pub tenant_domain: String,
    pub content_types: Vec<String>,
    pub session_lifetime: Duration,
    /// Accepted `Host` header values, e.g. `127.0.0.1:8787` and `localhost:8787`.
    pub allowed_hosts: Vec<String>,
    pub throttle: LoginThrottle,
}

#[path = "web_investigation.rs"]
mod investigation;

const SESSION_COOKIE: &str = "jw_session";
const LOGIN_CSRF_COOKIE: &str = "jw_login_csrf";

pub fn router<U: Upstream + 'static>(state: Arc<AppState<U>>) -> Router {
    Router::new()
        .route("/", get(overview::<U>))
        .route("/reports", get(investigation::reports::<U>))
        .route(
            "/settings",
            get(investigation::settings::<U>).post(investigation::save_settings::<U>),
        )
        .route("/actions/suppress", post(investigation::suppress::<U>))
        .route("/alerts", get(investigation::alerts::<U>))
        .route(
            "/alerts/:id",
            get(investigation::alert::<U>).post(investigation::update::<U>),
        )
        .route("/activity", get(investigation::activity::<U>))
        .route("/evidence/:id", get(investigation::evidence::<U>))
        .route("/changes", get(investigation::changes::<U>))
        .route("/snapshots/:id", get(investigation::snapshot::<U>))
        .route("/actions/baseline", post(investigation::baseline::<U>))
        .route("/coverage", get(coverage::<U>))
        .route("/collectors", get(collectors::<U>))
        .route("/login", get(login_page::<U>).post(login::<U>))
        .route("/logout", post(logout::<U>))
        .route("/actions/probe", post(action_probe::<U>))
        .route("/actions/subscribe", post(action_subscribe::<U>))
        .route("/assets/app.css", get(css))
        .layer(axum::extract::DefaultBodyLimit::max(65536))
        .layer(middleware::from_fn_with_state(state.clone(), guard::<U>))
        .with_state(state)
}

/// Host pinning, POST origin check and security headers for every response.
async fn guard<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    request: Request,
    next: Next,
) -> Response {
    static REQUESTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
    let Ok(_permit) = REQUESTS.try_acquire() else {
        return (StatusCode::TOO_MANY_REQUESTS, "Request limit reached").into_response();
    };
    let headers = request.headers();
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if !state
        .allowed_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
    {
        return (StatusCode::MISDIRECTED_REQUEST, "unexpected host").into_response();
    }
    if request.method() == axum::http::Method::POST
        && let Some(origin) = headers.get(header::ORIGIN)
    {
        let expected = format!("http://{host}");
        if origin.to_str().ok() != Some(expected.as_str()) {
            return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
        }
    }
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    response
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

fn current<U>(state: &AppState<U>, headers: &HeaderMap) -> Option<Session> {
    let token = cookie(headers, SESSION_COOKIE)?;
    auth::session(&state.store, &token).ok().flatten()
}

fn csrf_ok(session: &Session, supplied: &str) -> bool {
    use subtle::ConstantTimeEq;
    !supplied.is_empty() && bool::from(session.csrf.as_bytes().ct_eq(supplied.as_bytes()))
}

enum Page {
    Html(Markup),
    Redirect(&'static str),
    Status(StatusCode, &'static str),
}
impl IntoResponse for Page {
    fn into_response(self) -> Response {
        match self {
            Page::Html(m) => (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                m.into_string(),
            )
                .into_response(),
            Page::Redirect(to) => Redirect::to(to).into_response(),
            Page::Status(code, msg) => (code, msg).into_response(),
        }
    }
}

// ---------- layout ----------

fn layout(title: &str, session: Option<&Session>, active: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en-AU" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · M365 Security" }
                link rel="stylesheet" href="/assets/app.css";
            }
            body {
                a.skip href="#main" { "Skip to content" }
                header.top {
                    span.brand { "Junction · M365 Security" }
                    @if let Some(s) = session {
                        nav aria-label="Main" {
                            @for (href, label) in [("/", "Overview"), ("/alerts", "Alerts"), ("/activity", "Activity"), ("/changes", "Changes"), ("/coverage", "Coverage"), ("/collectors", "Collectors"), ("/reports", "Reports"), ("/settings", "Settings")] {
                                a href=(href) aria-current=[(active == href).then_some("page")] { (label) }
                            }
                        }
                        form.logout method="post" action="/logout" {
                            input type="hidden" name="csrf" value=(s.csrf);
                            span.who { (s.user.username) " (" (s.user.role.as_str()) ")" }
                            button type="submit" { "Sign out" }
                        }
                    }
                }
                main id="main" { (body) }
                footer { "Independent project, not affiliated with Microsoft. No alerts does not mean no compromise: check Coverage for what is not monitored." }
            }
        }
    }
}

fn badge(state: CapabilityState) -> Markup {
    let (class, label) = match state {
        CapabilityState::Available => ("ok", "Available"),
        CapabilityState::AvailableWithLimitations => ("warn", "Available, with limits"),
        CapabilityState::RequiresPermission => ("bad", "Needs permission"),
        CapabilityState::RequiresLicence => ("muted", "Needs licence"),
        CapabilityState::NotEnabled => ("bad", "Not enabled"),
        CapabilityState::Unsupported => ("muted", "Unsupported"),
        CapabilityState::TemporarilyUnavailable => ("warn", "Temporarily unavailable"),
        CapabilityState::Unknown => ("warn", "Unknown"),
    };
    html! { span class={"badge " (class)} { (label) } }
}

fn when(ts: Option<&str>) -> Markup {
    match ts.and_then(|t| Instant::parse(t).ok()) {
        Some(t) => {
            let ago = Instant::now().since(t).as_secs();
            let rel = match ago {
                0..=89 => "just now".to_owned(),
                90..=5399 => format!("{} min ago", ago / 60),
                5400..=172_799 => format!("{} h ago", ago / 3600),
                _ => format!("{} days ago", ago / 86_400),
            };
            html! { time datetime=(t.to_rfc3339()) title=(t.to_rfc3339()) { (rel) } }
        }
        None => html! { span.muted { "never" } },
    }
}

// ---------- pages ----------

async fn overview<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
) -> Page {
    let Some(session) = current(&state, &headers) else {
        return Page::Redirect("/login");
    };
    let store = &state.store;
    let caps = store.capabilities().unwrap_or_default();
    let (runnable, blocked) = probe::detection_coverage(&caps);
    let month = Instant::now().minus(Duration::from_secs(30 * 86_400));
    let users = store.distinct_actors_since(month).unwrap_or(0);
    let sites = store.distinct_sites_since(month).unwrap_or(0);
    let gaps = store.gaps().unwrap_or_default();
    let collectors: Vec<(String, Option<crate::store::RunRecord>)> = state
        .content_types
        .iter()
        .map(|ct| {
            let id = format!("o365:{ct}");
            let last = store.last_success(&id).ok().flatten();
            (id, last)
        })
        .chain(
            crate::graph::SOURCES
                .into_iter()
                .map(|id| (id.to_owned(), store.last_success(id).ok().flatten())),
        )
        .collect();
    let last_ok = collectors
        .iter()
        .filter_map(|(_, r)| r.as_ref())
        .filter_map(|r| r.finished_at.clone())
        .max();
    // Freshness per feed: one healthy feed must not hide another that has
    // stopped. Feeds known to be unavailable are reported on Coverage instead.
    let stale: Vec<(String, Option<String>)> = collectors
        .iter()
        .filter(|(id, _)| {
            !caps
                .iter()
                .any(|c| &c.source == id && c.state.is_settled_negative())
        })
        .filter_map(|(id, run)| {
            let finished = run.as_ref().and_then(|r| r.finished_at.clone());
            let fresh = finished
                .as_deref()
                .and_then(|t| Instant::parse(t).ok())
                .is_some_and(|t| Instant::now().since(t) <= Duration::from_secs(6 * 3600));
            (!fresh).then(|| {
                let title = catalog::source(id)
                    .map(|s| s.title)
                    .unwrap_or(id)
                    .to_owned();
                (title, finished)
            })
        })
        .collect();
    let unusable = caps.iter().filter(|c| !c.state.usable()).count();
    let body = html! {
        h1 { "Overview" }
        p.lede { "Tenant " strong { (state.tenant_domain) } ". One connected Microsoft 365 tenant." }
        @if !stale.is_empty() {
            div.callout.bad role="alert" {
                strong { "Collection is behind. " }
                "No successful collection in the last 6 hours for: "
                @for (i, (title, last)) in stale.iter().enumerate() {
                    @if i > 0 { ", " }
                    strong { (title) } " (last success " (when(last.as_deref())) ")"
                }
                ". Microsoft keeps audit content for 7 days; collect before then or events are lost from this tool (they stay searchable in Purview)."
            }
        }
        @if unusable > 0 {
            div.callout.warn {
                strong { (unusable) " data source(s) not available. " }
                "Detections that depend on them are switched off. " a href="/coverage" { "See coverage" } "."
            }
        }
        section.grid aria-label="Monitoring health" {
            div.card { h2 { "Last successful collection" } p.big { (when(last_ok.as_deref())) } }
            div.card { h2 { "Detections with data available" } p.big { (runnable.len()) " of " (runnable.len() + blocked.len()) } }
            div.card { h2 { "Active users seen (30 days)" } p.big { (users) } }
            div.card { h2 { "SharePoint sites seen (30 days)" } p.big { (sites) } }
            div.card { h2 { "Recorded collection gaps" } p.big { (gaps.len()) } }
            div.card { h2 { "Active alerts" } p { a href="/alerts" { "Review security alerts" } } p.small { "Deterministic rules evaluate collected evidence. Missing sources remain monitoring gaps." } }
        }
        h2 { "Collectors" }
        table {
            caption.sr { "Audit feed collectors" }
            thead { tr { th scope="col" { "Feed" } th scope="col" { "Last success" } th scope="col" { "Worst ingestion delay" } th scope="col" { "New events" } } }
            tbody {
                @for (id, run) in &collectors {
                    tr {
                        td { (catalog::source(id).map(|s| s.title).unwrap_or(id)) }
                        td { (when(run.as_ref().and_then(|r| r.finished_at.as_deref()))) }
                        td { @match run.as_ref().and_then(|r| r.max_delay_seconds) { Some(s) => { (format!("{:.1} h", s as f64 / 3600.0)) } None => { span.muted { "–" } } } }
                        td { (run.as_ref().map(|r| r.events_new).unwrap_or(0)) }
                    }
                }
            }
        }
        @if !blocked.is_empty() {
            h2 { "Detections that cannot run" }
            p { "These need a data source that is unavailable. They will start automatically when coverage changes." }
            ul.inline { @for d in &blocked { li { code { (d) } } } }
        }
    };
    Page::Html(layout("Overview", Some(&session), "/", body))
}

async fn coverage<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
) -> Page {
    let Some(session) = current(&state, &headers) else {
        return Page::Redirect("/login");
    };
    let caps = state.store.capabilities().unwrap_or_default();
    let month = Instant::now().minus(Duration::from_secs(30 * 86_400));
    let last_probe = state.store.meta("last_probe_at").ok().flatten();
    let gaps = state.store.gaps().unwrap_or_default();
    let can_act = session.user.role == Role::Admin && state.upstream.is_some();
    let not_started: Vec<&CapabilityRecord> = caps
        .iter()
        .filter(|c| {
            c.source.starts_with("o365:")
                && matches!(
                    c.reason,
                    crate::capability::Reason::SubscriptionNotStarted
                        | crate::capability::Reason::SubscriptionDisabled
                )
        })
        .collect();
    let body = html! {
        h1 { "Coverage" }
        p.lede { "What this tool can and cannot see in your tenant, based on live checks against Microsoft, not on licence names. Last checked " (when(last_probe.as_deref())) "." }
        @if can_act {
            form method="post" action="/actions/probe" {
                input type="hidden" name="csrf" value=(session.csrf);
                button type="submit" { "Re-test now" }
            }
            @if !not_started.is_empty() {
                form method="post" action="/actions/subscribe" {
                    input type="hidden" name="csrf" value=(session.csrf);
                    p { "Some audit feeds are not started. Starting a feed only turns on delivery of audit data Microsoft already records; it changes nothing else in the tenant." }
                    button type="submit" { "Start audit feeds" }
                }
            }
        }
        @if caps.is_empty() {
            p.callout.warn { "No checks have run yet. Run " code { "junction watch probe" } " or press Re-test." }
        }
        table {
            caption.sr { "Data sources" }
            thead { tr {
                th scope="col" { "Source" } th scope="col" { "Status" } th scope="col" { "What to do" }
                th scope="col" { "Permission" } th scope="col" { "Licence" } th scope="col" { "Last successful collection" } th scope="col" { "Observed (30 days)" } th scope="col" { "Detections" }
            } }
            tbody {
                @for c in &caps {
                    @let spec = catalog::source(&c.source);
                    tr {
                        th scope="row" {
                            (spec.map(|s| s.title).unwrap_or(&c.source))
                            @if c.docs_url.starts_with("https://learn.microsoft.com/") {
                                br; a.small href=(c.docs_url) rel="noreferrer" { "Microsoft docs" }
                            }
                        }
                        td { (badge(c.state)) br; span.small.muted { (c.reason.as_str()) @if let Some(code) = &c.error_code { " · " code { (code) } } } }
                        td.small { (c.reason.remedy()) @if let Some(d) = &c.detail { br; span.muted { (d) } } }
                        td { code { (c.required_permission) } }
                        td.small { (c.licence_note) }
                        td { @if spec.is_some_and(|s|s.collected) { (when(state.store.last_success(&c.source).ok().flatten().and_then(|r| r.finished_at).as_deref())) } @else if c.source.starts_with("snapshot:") { (when(Some(&c.checked_at))) } @else { span.muted { "probe only" } } }
                        td.small {
                            @if spec.is_some_and(|s| s.collected) {
                                @let (ops, events) = state.store.observed_coverage(&c.source, month).unwrap_or((0, 0));
                                (events) " events, " (ops) " distinct operations"
                            } @else { span.muted { "not collected in this release" } }
                        }
                        td.small { @for d in spec.map(|s| s.detections).unwrap_or(&[]) { code { (d) } " " } }
                    }
                }
            }
        }
        h2 { "Monitoring gaps" }
        @if gaps.is_empty() {
            p { "No gaps recorded." }
        } @else {
            table {
                thead { tr { th scope="col" { "Feed" } th scope="col" { "From" } th scope="col" { "To" } th scope="col" { "Why" } } }
                tbody { @for g in &gaps { tr { td { (g.collector) } td { (g.gap_start) } td { (g.gap_end) } td.small { (g.reason) } } } }
            }
        }
        h2 { "Not monitored by design" }
        ul {
            li { "Email and file contents. The watchdog never reads messages or documents." }
            li { "Sign-in risk, unless the tenant has Entra ID P1 or P2. Sign-ins visible in the admin portal on free plans are not available to apps." }
            li { "Exchange configuration snapshots (forwarding, delegation, transport rules) need the optional Exchange runner. Changes are still caught from the audit feed." }
        }
    };
    Page::Html(layout("Coverage", Some(&session), "/coverage", body))
}

async fn collectors<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
) -> Page {
    let Some(session) = current(&state, &headers) else {
        return Page::Redirect("/login");
    };
    let runs = state.store.recent_runs(100).unwrap_or_default();
    let body = html! {
        h1 { "Collectors" }
        p.lede { "Recent collection runs. Audit content can arrive hours after the event; the delay column shows the worst case seen in each run." }
        table {
            thead { tr {
                th scope="col" { "Feed" } th scope="col" { "Started" } th scope="col" { "Status" } th scope="col" { "Blobs" }
                th scope="col" { "New" } th scope="col" { "Duplicate" } th scope="col" { "Worst delay" } th scope="col" { "Error" }
            } }
            tbody {
                @for r in &runs {
                    tr {
                        td { (r.collector) }
                        td { (when(Some(&r.started_at))) }
                        td { span class={"badge " (match r.status.as_str() { "ok" => "ok", "partial" | "running" => "warn", "skipped" => "muted", _ => "bad" })} { (r.status) } }
                        td { (r.content_blobs) }
                        td { (r.events_new) }
                        td { (r.events_duplicate) }
                        td { @match r.max_delay_seconds { Some(s) => { (format!("{:.1} h", s as f64 / 3600.0)) } None => { "–" } } }
                        td.small { (r.error.as_deref().unwrap_or("")) }
                    }
                }
            }
        }
    };
    Page::Html(layout("Collectors", Some(&session), "/collectors", body))
}

// ---------- login ----------

async fn login_page<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
) -> Response {
    if current(&state, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    login_form(None)
}

fn login_form(error: Option<&str>) -> Response {
    let Ok(csrf) = auth::random_token() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "randomness unavailable").into_response();
    };
    let body = html! {
        h1 { "Sign in" }
        @if let Some(e) = error { p.callout.bad role="alert" { (e) } }
        form.login method="post" action="/login" {
            input type="hidden" name="csrf" value=(csrf);
            label for="username" { "Username" }
            input id="username" name="username" autocomplete="username" required maxlength="64";
            label for="password" { "Password" }
            input id="password" name="password" type="password" autocomplete="current-password" required maxlength="1024";
            button type="submit" { "Sign in" }
        }
    };
    let mut response = Page::Html(layout("Sign in", None, "", body)).into_response();
    if let Ok(v) = HeaderValue::from_str(&format!(
        "{LOGIN_CSRF_COOKIE}={csrf}; HttpOnly; SameSite=Strict; Path=/login; Max-Age=900"
    )) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
    response
}

#[derive(Deserialize)]
struct LoginForm {
    csrf: String,
    username: String,
    password: String,
}

async fn login<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    use subtle::ConstantTimeEq;
    let expected = cookie(&headers, LOGIN_CSRF_COOKIE).unwrap_or_default();
    if expected.is_empty() || !bool::from(expected.as_bytes().ct_eq(form.csrf.as_bytes())) {
        return login_form(Some("Your sign-in form expired. Try again."));
    }
    let generic = "Incorrect username or password, or the account is locked.";
    if auth::validate_username(&form.username).is_err() || state.throttle.locked(&form.username) {
        return login_form(Some(generic));
    }
    let store = state.store.clone();
    let (username, password) = (form.username.clone(), form.password);
    // Argon2 is deliberately slow; keep it off the async workers.
    let verified =
        tokio::task::spawn_blocking(move || auth::verify_login(&store, &username, &password))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
    let Some(user) = verified else {
        state.throttle.failed(&form.username);
        let _ = state
            .store
            .audit(&form.username, "login_failed", "dashboard", "{}");
        return login_form(Some(generic));
    };
    state.throttle.succeeded(&user.username);
    let Ok((token, _)) = auth::create_session(&state.store, &user, state.session_lifetime) else {
        return (StatusCode::SERVICE_UNAVAILABLE, "session unavailable").into_response();
    };
    let _ = state
        .store
        .audit(&user.username, "login", "dashboard", "{}");
    let mut response = Redirect::to("/").into_response();
    let max_age = state.session_lifetime.as_secs();
    if let Ok(v) = HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}"
    )) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "jw_login_csrf=; HttpOnly; SameSite=Strict; Path=/login; Max-Age=0",
        ),
    );
    response
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

async fn logout<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Some(session) = current(&state, &headers)
        && csrf_ok(&session, &form.csrf)
        && let Some(token) = cookie(&headers, SESSION_COOKIE)
    {
        let _ = auth::end_session(&state.store, &token);
        let _ = state
            .store
            .audit(&session.user.username, "logout", "dashboard", "{}");
    }
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static("jw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    response
}

// ---------- admin actions ----------

fn admin<U>(
    state: &AppState<U>,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<(Session, Arc<U>), Page> {
    let session = current(state, headers).ok_or(Page::Redirect("/login"))?;
    if !csrf_ok(&session, csrf) {
        return Err(Page::Status(StatusCode::FORBIDDEN, "invalid form token"));
    }
    if session.user.role != Role::Admin {
        return Err(Page::Status(
            StatusCode::FORBIDDEN,
            "administrator role required",
        ));
    }
    let upstream = state.upstream.clone().ok_or(Page::Status(
        StatusCode::SERVICE_UNAVAILABLE,
        "Microsoft connection not configured in this process",
    ))?;
    Ok((session, upstream))
}

async fn action_probe<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Page {
    let (session, upstream) = match admin(&state, &headers, &form.csrf) {
        Ok(v) => v,
        Err(page) => return page,
    };
    let _ = state
        .store
        .audit(&session.user.username, "probe", "tenant", "{}");
    match probe::probe_all(upstream.as_ref(), &state.store).await {
        Ok(_) => Page::Redirect("/coverage"),
        Err(_) => Page::Status(
            StatusCode::BAD_GATEWAY,
            "re-test failed; see collector logs",
        ),
    }
}

async fn action_subscribe<U: Upstream + 'static>(
    State(state): State<Arc<AppState<U>>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Page {
    let (session, upstream) = match admin(&state, &headers, &form.csrf) {
        Ok(v) => v,
        Err(page) => return page,
    };
    // Only feeds that are not started or disabled; never re-start a healthy feed.
    let caps = state.store.capabilities().unwrap_or_default();
    let types: Vec<&str> = state
        .content_types
        .iter()
        .map(String::as_str)
        .filter(|ct| {
            caps.iter().any(|c| {
                c.source == format!("o365:{ct}")
                    && matches!(
                        c.reason,
                        crate::capability::Reason::SubscriptionNotStarted
                            | crate::capability::Reason::SubscriptionDisabled
                    )
            })
        })
        .collect();
    if types.is_empty() {
        return Page::Redirect("/coverage");
    }
    let started = probe::start_subscriptions(
        upstream.as_ref(),
        &state.store,
        &session.user.username,
        &types,
    )
    .await;
    // Re-probe first so Coverage shows the current reason either way.
    let _ = probe::probe_all(upstream.as_ref(), &state.store).await;
    match started {
        Ok(results) if results.iter().all(|(_, r)| r.is_ok()) => Page::Redirect("/coverage"),
        _ => Page::Status(
            StatusCode::BAD_GATEWAY,
            "could not start every audit feed; see Coverage for the reason",
        ),
    }
}

async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        PreEscaped(CSS).into_string(),
    )
}

const CSS: &str = r#"
:root{--ink:#1c1917;--muted:#57534e;--line:#e7e5e4;--bg:#fafaf9;--card:#fff;--ok:#166534;--okbg:#dcfce7;--warn:#854d0e;--warnbg:#fef9c3;--bad:#991b1b;--badbg:#fee2e2;--accent:#1d4ed8}
@media (prefers-color-scheme:dark){:root{--ink:#f5f5f4;--muted:#a8a29e;--line:#44403c;--bg:#1c1917;--card:#292524;--ok:#86efac;--okbg:#14532d;--warn:#fde047;--warnbg:#422006;--bad:#fca5a5;--badbg:#450a0a;--accent:#93c5fd}}
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);background:var(--bg)}
a{color:var(--accent)}a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:1rem;background:var(--card);padding:.5rem;z-index:9}
.top{display:flex;flex-wrap:wrap;gap:1rem;align-items:center;padding:.75rem 1.25rem;border-bottom:1px solid var(--line);background:var(--card)}
.brand{font-weight:700}.top nav{display:flex;flex-wrap:wrap;gap:1rem;flex:1}.top nav a{text-decoration:none;padding:.25rem 0}.top nav a[aria-current=page]{font-weight:700;border-bottom:2px solid var(--accent)}
.logout{display:flex;gap:.5rem;align-items:center}.who{color:var(--muted);font-size:.875rem}
main{max-width:1200px;margin:0 auto;padding:1.5rem 1.25rem}h1{margin:.25rem 0 .5rem}h2{font-size:1.1rem;margin:1.75rem 0 .5rem}
.lede{color:var(--muted);margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:1rem}.card h2{margin:0;font-size:.875rem;color:var(--muted);font-weight:600}.big{font-size:1.6rem;font-weight:700;margin:.25rem 0 0}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;vertical-align:top;padding:.5rem .75rem;border-bottom:1px solid var(--line)}thead th{font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}
.small{font-size:.85rem}td code{overflow-wrap:anywhere}.muted{color:var(--muted)}.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
.badge{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.8rem;font-weight:600;white-space:nowrap}
.badge.ok{color:var(--ok);background:var(--okbg)}.badge.warn{color:var(--warn);background:var(--warnbg)}.badge.bad{color:var(--bad);background:var(--badbg)}.badge.muted{color:var(--muted);background:var(--line)}
.callout{padding:.75rem 1rem;border-radius:8px;margin:1rem 0}.callout.bad{background:var(--badbg);color:var(--bad)}.callout.warn{background:var(--warnbg);color:var(--warn)}
button{font:inherit;padding:.45rem .9rem;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:100%} select,textarea,input{font:inherit;max-width:100%;padding:.4rem;border:1px solid var(--line);background:var(--card);color:var(--ink)} textarea{display:block;width:100%;min-height:6rem} label{display:inline-block;margin:.5rem .5rem .5rem 0} select:focus-visible,textarea:focus-visible{outline:3px solid var(--accent)} form{margin:.5rem 0}.login{display:grid;gap:.5rem;max-width:22rem}.login input{font:inherit;padding:.5rem;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink)}
.inline{display:flex;flex-wrap:wrap;gap:.5rem;list-style:none;padding:0}footer{max-width:1200px;margin:2rem auto;padding:0 1.25rem;color:var(--muted);font-size:.85rem}
@media print{.top,.logout,form,footer{display:none}section{break-inside:avoid}}
@media (max-width:720px){table{display:block;overflow-x:auto}}
"#;
