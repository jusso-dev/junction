mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::*;
use junction_watch::{
    auth::{self, Role},
    capability::{CapabilityState, Reason},
    store::{CapabilityRecord, Store},
    upstream::Api,
    web::{AppState, router},
};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:8787";

fn app(store: Store, upstream: Option<Arc<Mock>>) -> axum::Router {
    app_with(store, upstream, &["Audit.Exchange"])
}

fn app_with(store: Store, upstream: Option<Arc<Mock>>, feeds: &[&str]) -> axum::Router {
    router(Arc::new(AppState {
        store,
        upstream,
        tenant_domain: "club.example".into(),
        content_types: feeds.iter().map(|f| f.to_string()).collect(),
        session_lifetime: Duration::from_secs(3600),
        allowed_hosts: vec![HOST.into(), "localhost:8787".into()],
        throttle: Default::default(),
    }))
}

async fn send(
    app: &axum::Router,
    req: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path).header(header::HOST, HOST);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::empty()).unwrap()
}

fn post(path: &str, cookie: Option<&str>, form: &str) -> Request<Body> {
    let mut b = Request::post(path)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::from(form.to_owned())).unwrap()
}

fn csrf_from(html: &str) -> String {
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker).expect("csrf field") + marker.len();
    html[start..].split('"').next().unwrap().to_owned()
}

fn set_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .map(|v| v.split(';').next().unwrap().to_owned())
}

async fn login(app: &axum::Router, user: &str) -> (String, String) {
    let (_, headers, html) = send(app, get("/login", None)).await;
    let csrf = csrf_from(&html);
    let login_cookie = set_cookie(&headers, "jw_login_csrf").unwrap();
    let (status, headers, _) = send(
        app,
        post(
            "/login",
            Some(&login_cookie),
            &format!("csrf={csrf}&username={user}&password=correct+horse+battery"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let session = set_cookie(&headers, "jw_session").expect("session cookie");
    let (_, _, html) = send(app, get("/", Some(&session))).await;
    (session, csrf_from(&html))
}

fn store_with_users() -> Store {
    let store = Store::in_memory(TENANT).unwrap();
    auth::create_user(&store, "admin", "correct horse battery", Role::Admin).unwrap();
    auth::create_user(&store, "viewer", "correct horse battery", Role::Viewer).unwrap();
    store
}

#[tokio::test]
async fn pages_require_login_and_send_security_headers() {
    let app = app(store_with_users(), None);
    for path in ["/", "/coverage", "/collectors"] {
        let (status, headers, _) = send(&app, get(path, None)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(headers[header::LOCATION], "/login");
        assert!(
            headers[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("default-src 'none'")
        );
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }
    let (status, _, _) = send(
        &app,
        get(
            "/",
            Some("jw_session=forged-token-value-forged-token-value-forged1"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "forged session rejected");
}

#[tokio::test]
async fn unexpected_host_is_refused() {
    let app = app(store_with_users(), None);
    let req = Request::get("/login")
        .header(header::HOST, "attacker.example:8787")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn login_requires_matching_csrf_and_correct_password() {
    let store = store_with_users();
    let app = app(store.clone(), None);
    let (_, headers, html) = send(&app, get("/login", None)).await;
    let csrf = csrf_from(&html);
    let cookie = set_cookie(&headers, "jw_login_csrf").unwrap();
    assert!(
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|v| v.to_str().unwrap().contains("HttpOnly; SameSite=Strict"))
    );

    let (_, h, body) = send(
        &app,
        post(
            "/login",
            Some(&cookie),
            "csrf=wrong&username=admin&password=correct+horse+battery",
        ),
    )
    .await;
    assert!(set_cookie(&h, "jw_session").is_none());
    assert!(body.contains("expired"));

    let (_, h, body) = send(
        &app,
        post(
            "/login",
            Some(&cookie),
            &format!("csrf={csrf}&username=admin&password=nope-nope-nope"),
        ),
    )
    .await;
    assert!(set_cookie(&h, "jw_session").is_none());
    assert!(body.contains("Incorrect username or password"));

    let (session, _) = login(&app, "admin").await;
    let (status, _, html) = send(&app, get("/", Some(&session))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Overview") && html.contains("club.example"));
    assert!(!html.contains("score"), "no misleading security score");
    let trail = store.audit_entries(10).unwrap();
    assert!(
        trail.iter().any(|e| e.action == "login_failed")
            && trail.iter().any(|e| e.action == "login")
    );
}

#[tokio::test]
async fn repeated_failures_lock_the_account() {
    let app = app(store_with_users(), None);
    for _ in 0..5 {
        let (_, headers, html) = send(&app, get("/login", None)).await;
        let cookie = set_cookie(&headers, "jw_login_csrf").unwrap();
        send(
            &app,
            post(
                "/login",
                Some(&cookie),
                &format!(
                    "csrf={}&username=admin&password=wrong-wrong-wrong",
                    csrf_from(&html)
                ),
            ),
        )
        .await;
    }
    let (_, headers, html) = send(&app, get("/login", None)).await;
    let cookie = set_cookie(&headers, "jw_login_csrf").unwrap();
    let (_, h, _) = send(
        &app,
        post(
            "/login",
            Some(&cookie),
            &format!(
                "csrf={}&username=admin&password=correct+horse+battery",
                csrf_from(&html)
            ),
        ),
    )
    .await;
    assert!(
        set_cookie(&h, "jw_session").is_none(),
        "correct password refused while locked"
    );
}

#[tokio::test]
async fn cross_origin_posts_are_refused() {
    let app = app(store_with_users(), None);
    let req = Request::post("/login")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, "https://evil.example")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("csrf=x&username=admin&password=y"))
        .unwrap();
    let (status, _, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn same_origin_browser_posts_are_accepted() {
    let app = app(store_with_users(), None);
    let (_, headers, html) = send(&app, get("/login", None)).await;
    assert_eq!(
        headers[header::REFERRER_POLICY],
        "same-origin",
        "no-referrer makes browsers send Origin: null"
    );
    let req = Request::post("/login")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(
            header::COOKIE,
            set_cookie(&headers, "jw_login_csrf").unwrap(),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "csrf={}&username=admin&password=correct+horse+battery",
            csrf_from(&html)
        )))
        .unwrap();
    let (status, h, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(set_cookie(&h, "jw_session").is_some());
    let null = Request::post("/login")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, "null")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(&app, null).await.0,
        StatusCode::FORBIDDEN,
        "opaque origins are refused"
    );
}

#[tokio::test]
async fn admin_actions_need_admin_role_and_csrf() {
    let mock = Arc::new(Mock::new());
    mock.route(
        Api::Graph,
        "GET",
        "/v1.0/",
        None,
        vec![ok(json!({"value": []}))],
    );
    mock.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/list",
        None,
        vec![ok(json!([]))],
    );
    let app = app(store_with_users(), Some(mock.clone()));

    let (viewer, viewer_csrf) = login(&app, "viewer").await;
    let (status, _, _) = send(
        &app,
        post(
            "/actions/probe",
            Some(&viewer),
            &format!("csrf={viewer_csrf}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, _, html) = send(&app, get("/coverage", Some(&viewer))).await;
    assert!(
        !html.contains("Re-test now"),
        "viewers do not see admin actions"
    );

    let (admin, admin_csrf) = login(&app, "admin").await;
    let (status, _, _) = send(&app, post("/actions/probe", Some(&admin), "csrf=forged")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = send(
        &app,
        post(
            "/actions/probe",
            Some(&admin),
            &format!("csrf={viewer_csrf}"),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "another session's token does not work"
    );
    assert_eq!(mock.total_calls(), 0);

    let (status, headers, _) = send(
        &app,
        post(
            "/actions/probe",
            Some(&admin),
            &format!("csrf={admin_csrf}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/coverage");
    assert!(mock.total_calls() > 0);
}

#[tokio::test]
async fn audit_content_is_escaped() {
    let store = store_with_users();
    store
        .put_capability(&CapabilityRecord {
            source: "o365:Audit.Exchange".into(),
            state: CapabilityState::Unknown,
            reason: Reason::Unclassified,
            http_status: Some(400),
            error_code: Some("X".into()),
            detail: Some("<script>alert(1)</script><img src=x onerror=alert(2)>".into()),
            required_permission: "ActivityFeed.Read".into(),
            licence_note: "n".into(),
            docs_url: "javascript:alert(3)".into(),
            checked_at: "2026-10-25T00:00:00.000Z".into(),
        })
        .unwrap();
    let app = app(store, None);
    let (session, _) = login(&app, "viewer").await;
    let (_, _, html) = send(&app, get("/coverage", Some(&session))).await;
    assert!(!html.contains("<script>alert(1)"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.contains("<img src=x"));
    assert!(
        !html.contains("javascript:"),
        "only Microsoft Learn links are rendered"
    );
}

#[tokio::test]
async fn logout_ends_the_session() {
    let app = app(store_with_users(), None);
    let (session, csrf) = login(&app, "admin").await;
    let (status, _, _) = send(
        &app,
        post("/logout", Some(&session), &format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _, _) = send(&app, get("/", Some(&session))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
}

fn cap(source: &str, state: CapabilityState, reason: Reason) -> CapabilityRecord {
    CapabilityRecord {
        source: source.into(),
        state,
        reason,
        http_status: None,
        error_code: None,
        detail: None,
        required_permission: "ActivityFeed.Read".into(),
        licence_note: "n".into(),
        docs_url: "https://learn.microsoft.com/".into(),
        checked_at: "2026-10-25T00:00:00.000Z".into(),
    }
}

#[tokio::test]
async fn a_healthy_feed_does_not_hide_a_stale_one() {
    use junction_watch::store::{InsertCounts, RunSummary};
    let store = store_with_users();
    store
        .put_capability(&cap(
            "o365:Audit.Exchange",
            CapabilityState::Available,
            Reason::Ok,
        ))
        .unwrap();
    store
        .put_capability(&cap(
            "o365:Audit.SharePoint",
            CapabilityState::Available,
            Reason::Ok,
        ))
        .unwrap();
    let run = store.start_run("o365:Audit.SharePoint").unwrap();
    store
        .finish_run(
            run,
            &RunSummary {
                status: "ok",
                window: None,
                content_blobs: 1,
                counts: InsertCounts::default(),
                max_delay_seconds: None,
                rejected_entries: 0,
                unparseable_records: 0,
                quarantined_blobs: 0,
                error: None,
            },
        )
        .unwrap();
    let app = app_with(store, None, &["Audit.Exchange", "Audit.SharePoint"]);
    let (session, _) = login(&app, "viewer").await;
    let (_, _, html) = send(&app, get("/", Some(&session))).await;
    let alert = html
        .split("Collection is behind")
        .nth(1)
        .expect("stale warning shown")
        .split("</div>")
        .next()
        .unwrap()
        .to_owned();
    assert!(alert.contains("Exchange audit feed"), "{alert}");
    assert!(
        !alert.contains("SharePoint and OneDrive"),
        "fresh feed not listed: {alert}"
    );
}

#[tokio::test]
async fn dashboard_starts_only_feeds_that_need_it() {
    let store = store_with_users();
    store
        .put_capability(&cap(
            "o365:Audit.Exchange",
            CapabilityState::Available,
            Reason::Ok,
        ))
        .unwrap();
    store
        .put_capability(&cap(
            "o365:Audit.SharePoint",
            CapabilityState::NotEnabled,
            Reason::SubscriptionNotStarted,
        ))
        .unwrap();
    let mock = Arc::new(Mock::new());
    mock.route(
        Api::ManagementActivity,
        "POST",
        "/subscriptions/start",
        None,
        vec![ok(json!({"status": "enabled"}))],
    );
    mock.route(
        Api::Graph,
        "GET",
        "/v1.0/",
        None,
        vec![ok(json!({"value": []}))],
    );
    mock.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/list",
        None,
        vec![ok(json!([]))],
    );
    let app = app_with(
        store,
        Some(mock.clone()),
        &["Audit.Exchange", "Audit.SharePoint"],
    );
    let (admin, csrf) = login(&app, "admin").await;
    let (status, _, _) = send(
        &app,
        post("/actions/subscribe", Some(&admin), &format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let starts: Vec<String> = mock
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, method, u)| method == "POST" && u.path().ends_with("/subscriptions/start"))
        .map(|(_, _, u)| u.query().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(starts.len(), 1, "{starts:?}");
    assert!(starts[0].contains("contentType=Audit.SharePoint"));
}

#[tokio::test]
async fn dashboard_reports_a_feed_that_failed_to_start() {
    let store = store_with_users();
    store
        .put_capability(&cap(
            "o365:Audit.Exchange",
            CapabilityState::NotEnabled,
            Reason::SubscriptionNotStarted,
        ))
        .unwrap();
    let mock = Arc::new(Mock::new());
    mock.route(
        Api::ManagementActivity,
        "POST",
        "/subscriptions/start",
        None,
        vec![err(400, "AF20020")],
    );
    mock.route(
        Api::Graph,
        "GET",
        "/v1.0/",
        None,
        vec![ok(json!({"value": []}))],
    );
    mock.route(
        Api::ManagementActivity,
        "GET",
        "/subscriptions/list",
        None,
        vec![ok(json!([]))],
    );
    let app = app(store, Some(mock.clone()));
    let (admin, csrf) = login(&app, "admin").await;
    let (status, _, body) = send(
        &app,
        post("/actions/subscribe", Some(&admin), &format!("csrf={csrf}")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(
        mock.calls_to("/subscriptions/list") > 0,
        "coverage re-probed before reporting"
    );
}
