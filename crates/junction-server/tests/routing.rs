use junction_server::{Route, route};
use serde_json::json;

#[test]
fn documented_routes_produce_validated_shared_host_calls() {
    assert!(matches!(
        route("GET", "/health", b"").ok(),
        Some(Route::Health)
    ));
    assert!(matches!(
        route("GET", "/openapi.json", b"").ok(),
        Some(Route::Openapi)
    ));
    let Some(Route::Tool { name, arguments }) = route(
        "GET",
        "/v1/search?query=list+users&limit=5&allow_preview=false",
        b"",
    )
    .ok() else {
        panic!("search route")
    };
    assert_eq!(name, "junction_search");
    assert_eq!(
        arguments,
        json!({"query":"list users","limit":5,"allow_preview":false})
    );
    for (path, name) in [
        ("operations", "junction_describe"),
        ("permissions", "junction_permissions"),
    ] {
        let Some(Route::Tool {
            name: actual,
            arguments,
        }) = route(
            "GET",
            &format!("/v1/{path}/graph.users.list?api_version=beta&allow_preview=true"),
            b"",
        )
        .ok()
        else {
            panic!("selection route")
        };
        assert_eq!(actual, name);
        assert_eq!(
            arguments,
            json!({"operation":"graph.users.list","api_version":"beta","allow_preview":true})
        );
    }
    let Some(Route::Tool { name, arguments }) = route(
        "POST",
        "/v1/execute/graph%2Eusers%2Elist",
        br#"{"input":{},"all":true,"max_items":10}"#,
    )
    .ok() else {
        panic!("execute route")
    };
    assert_eq!(name, "junction_execute");
    assert_eq!(
        arguments,
        json!({"operation":"graph.users.list","input":{},"all":true,"max_items":10})
    );
    let Some(Route::Tool { name, arguments }) = route(
        "POST",
        "/v1/batch",
        br#"{"operations":[{"id":"users","operation":"graph.users.list"}]}"#,
    )
    .ok() else {
        panic!("batch route")
    };
    assert_eq!(name, "junction_batch");
    assert_eq!(arguments["operations"][0]["id"], "users");
    let Some(Route::Tool { name, arguments }) = route("GET", "/v1/contexts", b"").ok() else {
        panic!("context route")
    };
    assert_eq!(name, "junction_context");
    assert_eq!(arguments, json!({"action":"list"}));
    let Some(Route::Operations {
        offset,
        limit,
        product,
        service,
        allow_preview,
    }) = route(
        "GET",
        "/v1/operations?offset=20&limit=10&product=graph&service=users&allow_preview=true",
        b"",
    )
    .ok()
    else {
        panic!("list route")
    };
    assert_eq!((offset, limit), (20, 10));
    assert_eq!(product.as_deref(), Some("graph"));
    assert_eq!(service.as_deref(), Some("users"));
    assert!(allow_preview);
}

#[test]
fn invalid_targets_options_and_credentials_fail_without_echoing_input() {
    for (method, target, body, status) in [
        ("GET", "https://private.invalid/health", &b""[..], 400),
        ("GET", "//private.invalid/health", &b""[..], 400),
        ("GET", "/health#private-token", &b""[..], 400),
        ("GET", "/v1/operations/graph%2Fprivate", &b""[..], 400),
        ("GET", "/v1/search?query=%FF", &b""[..], 400),
        ("GET", "/v1/search?query=%invalid", &b""[..], 400),
        ("GET", "/v1/search?query=one&query=private", &b""[..], 400),
        (
            "GET",
            "/v1/search?query=one&allow_preview=True",
            &b""[..],
            400,
        ),
        ("GET", "/v1/search?query=one&limit=0", &b""[..], 400),
        ("GET", "/v1/search?query=one&token=private", &b""[..], 400),
        ("GET", "/v1/operations?limit=101", &b""[..], 400),
        ("GET", "/health", &b"private-input"[..], 400),
        ("POST", "/health", &b""[..], 405),
        ("GET", "/private-not-found", &b""[..], 404),
        (
            "POST",
            "/v1/execute/graph.users.list?token=private",
            &b"{}"[..],
            400,
        ),
        (
            "POST",
            "/v1/execute/graph.users.list",
            &br#"{"input":{},"policy":"full","token":"private"}"#[..],
            400,
        ),
        (
            "POST",
            "/v1/execute/graph.users.list",
            &br#"{"operation":"private.override","input":{}}"#[..],
            400,
        ),
        ("POST", "/v1/batch", &br#"{"operations":[]}"#[..], 400),
    ] {
        let error = route(method, target, body)
            .err()
            .expect("invalid request accepted");
        assert_eq!(error.status, status);
        assert!(!error.body.to_string().contains("private"));
    }
    let error = route("POST", "/v1/batch", &vec![b'x'; 16 * 1024 * 1024 + 1])
        .err()
        .unwrap();
    assert_eq!(error.status, 413);
}

#[test]
fn check_routes_map_to_check_tools_and_validate_input() {
    let Some(Route::Tool { name, arguments }) =
        route("GET", "/v1/checks?pack=identity,email&tag=e8:ml1", b"").ok()
    else {
        panic!("check list route")
    };
    assert_eq!(name, "junction_check_list");
    assert_eq!(
        arguments,
        json!({"packs":["identity","email"],"tags":["e8:ml1"]})
    );
    assert!(route("GET", "/v1/checks?pack=nope", b"").is_err());

    let body = br#"{"contexts":["contoso"],"packs":["identity"],"background":true}"#;
    let Some(Route::Tool { name, arguments }) = route("POST", "/v1/checks/run", body).ok() else {
        panic!("check run route")
    };
    assert_eq!(name, "junction_check_run");
    assert_eq!(arguments["background"], true);
    assert!(route("POST", "/v1/checks/run", br#"{"contexts":["../x"]}"#).is_err());
    assert!(route("GET", "/v1/checks/run", b"").is_err());

    let Some(Route::Tool { name, arguments }) = route(
        "GET",
        "/v1/checks/runs/20261025t000000-abcd?context=contoso",
        b"",
    )
    .ok() else {
        panic!("run status route")
    };
    assert_eq!(name, "junction_check_run_status");
    assert_eq!(
        arguments,
        json!({"run_id":"20261025t000000-abcd","context":"contoso"})
    );

    let Some(Route::Tool { arguments, .. }) =
        route("GET", "/v1/checks/attestations?context=contoso", b"").ok()
    else {
        panic!("pending route")
    };
    assert_eq!(arguments, json!({"action":"pending","context":"contoso"}));
    let submit = br#"{"context":"contoso","check":"backup.restore_tested","answer":"yes"}"#;
    let Some(Route::Tool { arguments, .. }) = route("POST", "/v1/checks/attestations", submit).ok()
    else {
        panic!("submit route")
    };
    assert_eq!(arguments["action"], "submit");
    assert!(
        route(
            "POST",
            "/v1/checks/attestations",
            br#"{"check":"backup.restore_tested","answer":"maybe"}"#
        )
        .is_err()
    );
}
