use junction_core::{ApiMaturity, JunctionOperation, RegistryManifest};
use junction_registry::Registry;
use serde_json::json;
fn operation(version: &str, maturity: ApiMaturity) -> JunctionOperation {
    serde_json::from_value(json!({"id":"graph.users.list","product":"graph","service":"users","resource":"users","operation":"list","description":"list users","method":"GET","base_url":"https://graph.microsoft.com","path":"/users","api_version":version,"parameters":[],"request_body":null,"responses":{},"security":[],"risk":"read_only","preview":false,"maturity":maturity,"source":{"id":"official","upstream":"official","operation_id":"Users_List"}})).unwrap()
}
fn registry(operations: Vec<JunctionOperation>) -> Registry {
    Registry::load(RegistryManifest {
        format_version: 1,
        operations,
        schemas: json!({}),
    })
    .unwrap()
}

#[test]
fn loaded_query_continuation_metadata_rejects_ambiguous_parameters_and_invalid_pointers() {
    let mut op = operation("v1.0", ApiMaturity::Stable);
    op.parameters = serde_json::from_value(json!([{"name":"cursor", "location":"query", "required":false, "schema":{"type":"string"}}])).unwrap();
    op.query_continuation = Some(junction_core::QueryContinuation {
        query_parameter: "cursor".into(),
        response_pointer: "/metadata/resume~1key~0value".into(),
    });
    let load = |operation| {
        Registry::load(RegistryManifest {
            format_version: 1,
            operations: vec![operation],
            schemas: json!({}),
        })
    };
    assert!(load(op.clone()).is_ok());
    for pointer in ["metadata/token", "/token~", "/token~2", "/token\n"] {
        let mut invalid = op.clone();
        invalid
            .query_continuation
            .as_mut()
            .unwrap()
            .response_pointer = pointer.into();
        assert!(load(invalid).is_err());
    }
    let mut ambiguous = op.clone();
    ambiguous.parameters.push(op.parameters[0].clone());
    assert!(load(ambiguous).is_err());
    let mut absent = op.clone();
    absent.parameters.clear();
    assert!(load(absent).is_err());
    let mut wrong_location = op;
    wrong_location.parameters[0].location = "header".into();
    assert!(load(wrong_location).is_err());
}

#[test]
fn related_operations_preserve_versionless_identity_and_reject_ambiguity() {
    let mut initial = operation("v1.0", ApiMaturity::Stable);
    initial.api_version = None;
    let mut next = initial.clone();
    next.id = "graph.users.next".into();
    next.source.operation_id = "Users_Next".into();
    let mut newer = next.clone();
    newer.api_version = Some("v2.0".into());
    let r = registry(vec![initial.clone(), next.clone(), newer]);
    assert!(
        r.resolve_related(&initial, "Users_Next", false)
            .unwrap()
            .api_version
            .is_none()
    );
    let mut ambiguous = next.clone();
    ambiguous.id = "graph.users.next_alternative".into();
    let r = registry(vec![initial.clone(), next.clone(), ambiguous]);
    assert!(r.resolve_related(&initial, "Users_Next", false).is_err());
    for maturity in [
        ApiMaturity::Preview,
        ApiMaturity::Beta,
        ApiMaturity::Retired,
    ] {
        next.maturity = maturity;
        let r = registry(vec![initial.clone(), next.clone()]);
        assert!(r.resolve_related(&initial, "Users_Next", false).is_err());
        assert_eq!(
            r.resolve_related(&initial, "Users_Next", true).is_ok(),
            maturity != ApiMaturity::Retired
        );
    }
}
#[test]
fn listing_filters_versions_before_counting_offsets() {
    let stable = operation("v1.0", ApiMaturity::Stable);
    let mut beta = operation("beta", ApiMaturity::Beta);
    beta.id = "graph.groups.list".into();
    beta.service = "groups".into();
    let mut retired = stable.clone();
    retired.id = "graph.retired.list".into();
    retired.maturity = ApiMaturity::Retired;
    let r = registry(vec![
        stable.clone(),
        operation("beta", ApiMaturity::Beta),
        beta,
        retired,
    ]);
    let defaults = junction_registry::SearchOptions::default();
    let (page, next) = r.list_filtered(0, 1, &defaults).unwrap();
    assert_eq!(page[0].api_version, stable.api_version);
    assert_eq!(next, None);
    let preview = junction_registry::SearchOptions {
        allow_preview: true,
        ..Default::default()
    };
    let (page, next) = r.list_filtered(0, 1, &preview).unwrap();
    assert_eq!(page[0].id, "graph.groups.list");
    assert_eq!(next, Some(1));
    let (page, next) = r.list_filtered(1, 1, &preview).unwrap();
    assert_eq!(page[0].id, "graph.users.list");
    assert_eq!(next, None);
    assert!(r.list_filtered(0, 0, &defaults).is_err());
    assert!(r.list_filtered(0, 101, &defaults).is_err());
    assert!(
        r.list_filtered(usize::MAX, 100, &defaults)
            .unwrap()
            .0
            .is_empty()
    );
    let filtered = junction_registry::SearchOptions {
        service: Some("users"),
        ..preview
    };
    assert_eq!(
        r.list_filtered(0, 1, &filtered).unwrap().0[0].id,
        "graph.users.list"
    );
}
#[test]
fn discovery_exposes_scope_alternatives_without_inventing_missing_permissions() {
    let mut op = operation("v1.0", ApiMaturity::Stable);
    for (security, expected) in [
        (
            json!([{"oauth":["write","read","read"]},{"oauth":["admin"]}]),
            json!([["read", "write"], ["admin"]]),
        ),
        (json!([{}, {"oauth":["read"]}]), json!([[], ["read"]])),
        (json!([]), json!(null)),
        (json!([{"bearer":[]}]), json!(null)),
        (json!([{"oauth":["read",42]}]), json!(null)),
    ] {
        op.security = security;
        let r = registry(vec![op.clone()]);
        let matches = serde_json::to_value(r.discover("users", 1)).unwrap();
        assert_eq!(matches[0]["required_permissions"], expected);
        let filtered =
            serde_json::to_value(r.discover_filtered("users", 1, &Default::default())).unwrap();
        assert_eq!(filtered, matches);
        assert!(matches[0].get("responses").is_none());
    }
}
#[test]
fn stable_remains_default_even_when_preview_enabled() {
    let r = registry(vec![
        operation("2025-01-01", ApiMaturity::Stable),
        operation("2026-01-01-preview", ApiMaturity::Preview),
    ]);
    for enabled in [false, true] {
        assert_eq!(
            r.resolve("graph.users.list", Some("latest"), enabled)
                .unwrap()
                .api_version
                .as_deref(),
            Some("2025-01-01")
        );
    }
    assert!(
        r.resolve("graph.users.list", Some("2026-01-01-preview"), false)
            .is_err()
    );
    assert!(
        r.resolve("graph.users.list", Some("2026-01-01-preview"), true)
            .is_ok()
    );
}
#[test]
fn retired_never_resolves_and_deprecated_requires_exact_version() {
    let r = registry(vec![
        operation("2027-01-01", ApiMaturity::Retired),
        operation("2026-01-01", ApiMaturity::Deprecated),
        operation("2025-01-01", ApiMaturity::Stable),
    ]);
    assert_eq!(
        r.resolve("graph.users.list", None, true)
            .unwrap()
            .api_version
            .as_deref(),
        Some("2025-01-01")
    );
    assert!(
        r.resolve("graph.users.list", Some("2027-01-01"), true)
            .is_err()
    );
    assert!(
        r.resolve("graph.users.list", Some("2026-01-01"), false)
            .is_ok()
    );
    assert_eq!(
        r.search("users", 20)[0].api_version.as_deref(),
        Some("2025-01-01")
    );
}
#[test]
fn beta_only_catalog_needs_opt_in() {
    let r = registry(vec![operation("beta", ApiMaturity::Beta)]);
    assert!(r.resolve("graph.users.list", None, false).is_err());
    assert!(r.resolve("graph.users.list", None, true).is_ok());
    assert!(r.search("users", 20).is_empty());
}

#[test]
fn numeric_versions_use_natural_order() {
    let r = registry(vec![
        operation("v2.0", ApiMaturity::Stable),
        operation("v10.0", ApiMaturity::Stable),
        operation("v9.0", ApiMaturity::Stable),
    ]);
    assert_eq!(
        r.resolve("graph.users.list", None, false)
            .unwrap()
            .api_version
            .as_deref(),
        Some("v10.0")
    );
}

#[test]
fn discovery_is_compact_bounded_and_hierarchical() {
    let r = registry(vec![
        operation("v1.0", ApiMaturity::Stable),
        operation("beta", ApiMaturity::Beta),
    ]);
    assert_eq!(r.products(), vec!["graph"]);
    assert_eq!(r.services(Some("graph")), vec![("graph", "users")]);
    assert!(r.services(Some("azure")).is_empty());
    assert_eq!(r.stats().operations, 1);
    assert_eq!(r.stats().versions, 2);
    assert_eq!(r.stats().beta, 1);
    assert_eq!(r.versions("graph.users.list").unwrap().len(), 2);
    assert!(r.versions("missing").is_err());
    let results = serde_json::to_value(r.discover("list users", 20)).unwrap();
    assert_eq!(results[0]["operation"], "graph.users.list");
    assert!(results[0].get("responses").is_none());
    assert!(r.discover("users", 0).is_empty());
}

#[test]
fn changes_are_order_independent_and_report_metadata_without_values() {
    use junction_registry::changes;
    let before = RegistryManifest {
        format_version: 1,
        operations: vec![
            operation("v1", ApiMaturity::Stable),
            operation("v2", ApiMaturity::Stable),
        ],
        schemas: json!({"User":{"type":"object"}}),
    };
    let mut after = before.clone();
    after.operations.reverse();
    let report = changes(&before, &after).unwrap();
    assert!(report.added.is_empty() && report.removed.is_empty() && report.modified.is_empty());
    after
        .operations
        .retain(|op| op.api_version.as_deref() != Some("v1"));
    after.operations[0].description = "sensitive-example-value".into();
    after.operations.push(operation("v3", ApiMaturity::Preview));
    after.schemas = json!({});
    let report = changes(&before, &after).unwrap();
    assert_eq!(report.added[0].api_version.as_deref(), Some("v3"));
    assert_eq!(report.removed[0].api_version.as_deref(), Some("v1"));
    assert_eq!(report.modified[0].fields, vec!["description"]);
    assert!(report.schemas_changed);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("sensitive-example-value")
    );
    after.operations.push(operation("v3", ApiMaturity::Preview));
    assert!(changes(&before, &after).is_err());
}

#[test]
fn ranked_discovery_prefers_canonical_root_operations_and_respects_filters() {
    use junction_registry::SearchOptions;
    let root = operation("v1.0", ApiMaturity::Stable);
    let mut nested = root.clone();
    nested.id = "graph.users.authentication.methods.list".into();
    nested.resource = "users.authentication.methods".into();
    let mut description_only = root.clone();
    description_only.id = "graph.applications.get".into();
    description_only.operation = "get".into();
    description_only.service = "applications".into();
    description_only.resource = "applications".into();
    let mut other_product = root.clone();
    other_product.id = "defender.users.list".into();
    other_product.product = "defender".into();
    let mut beta = root.clone();
    beta.id = "graph.preview_users.list".into();
    beta.api_version = Some("beta".into());
    beta.maturity = ApiMaturity::Beta;
    let ops = vec![nested, description_only, root, other_product, beta];
    let r = registry(ops.clone());
    let options = SearchOptions {
        product: Some("graph"),
        ..SearchOptions::default()
    };
    let results = r.search_filtered("please find list users", 20, &options);
    assert_eq!(results[0].id, "graph.users.list");
    assert_eq!(results[1].id, "graph.users.authentication.methods.list");
    assert_eq!(results[2].id, "graph.applications.get");
    assert_eq!(results.len(), 3);
    let options = SearchOptions {
        service: Some("applications"),
        ..SearchOptions::default()
    };
    assert_eq!(
        r.search_filtered("users", 20, &options)[0].id,
        "graph.applications.get"
    );
    let options = SearchOptions {
        allow_preview: true,
        ..SearchOptions::default()
    };
    assert!(
        r.search_filtered("users", 20, &options)
            .iter()
            .any(|op| op.id == "graph.preview_users.list")
    );
    assert_eq!(r.search("graph.users.list", 1)[0].id, "graph.users.list");
    assert!(r.search("please find", 20).is_empty());
    assert!(r.search(&"x".repeat(1025), 20).is_empty());
    let mut reversed = ops;
    reversed.reverse();
    assert_eq!(
        r.search("users", 20)
            .iter()
            .map(|op| &op.id)
            .collect::<Vec<_>>(),
        registry(reversed)
            .search("users", 20)
            .iter()
            .map(|op| &op.id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn describe_input_schema_validates_envelope_and_keeps_only_reachable_definitions() {
    let mut op = operation("v1.0", ApiMaturity::Stable);
    op.parameters = serde_json::from_value(json!([
        {"name":"id","location":"path","required":true,"schema":{"type":"string","minLength":1}},
        {"name":"api-version","location":"query","required":true,"schema":{"type":"string"}}
    ]))
    .unwrap();
    op.request_body = Some(
        json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Node"}}}}),
    );
    let r = Registry::load(RegistryManifest { format_version:1, operations:vec![op], schemas:json!({"components":{"schemas":{
        "Node":{"type":"object","required":["name"],"properties":{"name":{"type":"string","nullable":true},"child":{"$ref":"#/components/schemas/Node"}}},
        "Unused":{"type":"string"}
    }}}) }).unwrap();
    let schema = r.input_schema("graph.users.list", None, false).unwrap();
    assert!(schema.pointer("/components/schemas/Unused").is_none());
    for valid in [
        json!({"parameters":{"id":"a"},"body":{"name":null}}),
        json!({"parameters":{"id":"a","api-version":"v1.0"},"body":{"name":"a","child":{"name":"b"}}}),
    ] {
        junction_schema::validate_json_schema(&schema, &valid).unwrap();
    }
    for invalid in [
        json!({}),
        json!({"parameters":{"id":""},"body":{"name":"a"}}),
        json!({"parameters":{"id":"a","api-version":"beta"},"body":{"name":"a"}}),
        json!({"parameters":{"id":"a"},"body":{"child":{}}}),
        json!({"parameters":{"id":"a"},"body":{"name":"a"},"approved":true}),
    ] {
        assert!(junction_schema::validate_json_schema(&schema, &invalid).is_err());
    }
}

#[test]
fn input_schema_traversal_distinguishes_properties_from_annotations() {
    let mut op = operation("v1.0", ApiMaturity::Stable);
    op.request_body = Some(json!({"content":{"application/json":{"schema":{
        "type":"object","properties":{"default":{"$ref":"#/definitions/A~1B~0C"}},
        "example":{"$ref":"https://example.invalid/annotation"}
    }}}}));
    let schemas = json!({"definitions":{"A/B~C":{"type":"string"},"Unused":{"type":"integer"}}});
    let r = Registry::load(RegistryManifest {
        format_version: 1,
        operations: vec![op.clone()],
        schemas: schemas.clone(),
    })
    .unwrap();
    let schema = r.input_schema(&op.id, None, false).unwrap();
    assert_eq!(schema["definitions"]["A/B~C"]["type"], "string");
    junction_schema::validate_json_schema(&schema, &json!({"body":{"default":"okay"}})).unwrap();
    assert!(
        junction_schema::validate_json_schema(&schema, &json!({"body":{"default":1}})).is_err()
    );
    op.request_body = Some(
        json!({"content":{"application/json":{"schema":{"$ref":"#/definitions/A~1B~0C/properties/missing"}}}}),
    );
    let r = Registry::load(RegistryManifest {
        format_version: 1,
        operations: vec![op.clone()],
        schemas,
    })
    .unwrap();
    assert!(r.input_schema(&op.id, None, false).is_err());
}

#[test]
fn risk_overrides_apply_to_all_versions_and_fail_on_invalid_targets() {
    use junction_core::OperationRisk;
    use junction_registry::overrides::RiskOverrides;
    let r = registry(vec![
        operation("v1", ApiMaturity::Stable),
        operation("v2", ApiMaturity::Stable),
    ]);
    let overrides = RiskOverrides::parse("[[operations]]\noperation='graph.users.list'\nrisk='privileged'\nreason='Operator-reviewed security-sensitive query'\n").unwrap();
    let r = r.with_risk_overrides(overrides).unwrap();
    assert!(
        r.versions("graph.users.list")
            .unwrap()
            .iter()
            .all(|op| op.risk == OperationRisk::Privileged)
    );
    assert_eq!(r.discover("users", 1)[0].risk, &OperationRisk::Privileged);
    let unknown = RiskOverrides::parse(
        "[[operations]]\noperation='missing'\nrisk='write'\nreason='Review'\n",
    )
    .unwrap();
    assert!(r.with_risk_overrides(unknown).is_err());
    for invalid in [
        "[[operations]]\noperation='x'\nrisk='read_only'\nreason=''",
        "[[operations]]\noperation='x'\nrisk='read_only'\nreason='Review'\napproved=true",
        "[[operations]]\noperation='x'\nrisk='write'\nreason='Review'\n[[operations]]\noperation='x'\nrisk='read_only'\nreason='Review'",
    ] {
        assert!(RiskOverrides::parse(invalid).is_err());
    }
}
