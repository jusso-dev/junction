use serde_json::json;

fn manifest() -> junction_core::RegistryManifest {
    junction_discovery::ingest(&json!({"swagger":"2.0","host":"management.azure.com","info":{"version":"2025-01-01"},
        "paths":{"/items":{"get":{"operationId":"Items_List","x-ms-pageable":{"nextLinkName":"nextLink","operationName":"Items_Next"}}},
            "/items/next":{"get":{"operationId":"Items_Next"}}}}),"azure","resources","official").unwrap()
}

#[test]
fn declared_post_pages_validate_the_next_body_and_preserve_policy() {
    let manifest = junction_discovery::ingest(&json!({
        "swagger":"2.0","host":"management.azure.com","info":{"version":"2025-01-01"},
        "paths":{
            "/items/query":{"post":{"operationId":"Items_List",
                "parameters":[{"name":"body","in":"body","required":true,"schema":{"$ref":"#/definitions/Query"}}],
                "x-ms-pageable":{"itemName":"items","nextLinkName":"more","operationName":"Items_Next"}}},
            "/items/query/next":{"post":{"operationId":"Items_Next",
                "parameters":[{"name":"body","in":"body","required":true,"schema":{"$ref":"#/definitions/Query"}}]}}
        },
        "definitions":{"Query":{"type":"object","required":["filter"],
            "properties":{"filter":{"type":"string","minLength":1}},"additionalProperties":false}}
    }), "azure", "resources", "official").unwrap();
    let input = json!({"body":{"filter":"active"}});
    let check = |manifest: junction_core::RegistryManifest, policy: junction_policy::Policy| {
        junction_runtime::Executor::new(
            junction_registry::Registry::load(manifest).unwrap(),
            policy,
        )
        .unwrap()
        .preflight_pages(
            "azure.resources.items.list",
            &input,
            "customer-a",
            "https://management.azure.com",
            &Default::default(),
        )
    };
    let policy = junction_policy::Policy::parse("[agent]\nmode='safe-write'").unwrap();
    assert_eq!(
        check(manifest.clone(), Default::default())
            .err()
            .unwrap()
            .to_string(),
        "policy_rejected"
    );
    check(manifest.clone(), policy.clone()).unwrap();
    let mut body_changed = manifest.clone();
    let next = body_changed
        .operations
        .iter_mut()
        .find(|op| op.operation == "next")
        .unwrap();
    next.request_body = Some(
        json!({"required":true,"content":{"application/json":{"schema":{
        "type":"object","required":["other"],"properties":{"other":{"type":"string"}},
        "additionalProperties":false}}}}),
    );
    assert!(check(body_changed, policy.clone()).is_err());
    let mut denied = policy.clone();
    denied
        .deny
        .operations
        .push("azure.resources.items.next".into());
    assert_eq!(
        check(manifest.clone(), denied).err().unwrap().to_string(),
        "policy_rejected"
    );
    let mut undeclared = manifest.clone();
    undeclared
        .operations
        .iter_mut()
        .find(|op| op.operation == "list")
        .unwrap()
        .pageable = None;
    assert!(check(undeclared, policy).is_err());
    for method in ["PUT", "PATCH", "DELETE"] {
        let mut unsupported = manifest.clone();
        unsupported
            .operations
            .iter_mut()
            .find(|op| op.operation == "next")
            .unwrap()
            .method = method.into();
        let full = junction_policy::Policy::parse("[agent]\nmode='full'").unwrap();
        assert_eq!(
            check(unsupported, full).err().unwrap().to_string(),
            if method == "DELETE" {
                "approval_required"
            } else {
                "named pagination requires GET or POST without service headers"
            }
        );
    }
}

fn preflight(
    manifest: junction_core::RegistryManifest,
    policy: junction_policy::Policy,
) -> anyhow::Result<()> {
    let executor =
        junction_runtime::Executor::new(junction_registry::Registry::load(manifest)?, policy)?;
    executor.preflight_pages(
        "azure.resources.items.list",
        &json!({}),
        "customer-a",
        "https://management.azure.com",
        &Default::default(),
    )
}

#[test]
fn named_get_pagination_checks_next_operation_policy_and_source_identity() {
    assert!(preflight(manifest(), Default::default()).is_ok());
    let mut policy = junction_policy::Policy::default();
    policy
        .deny
        .operations
        .push("azure.resources.items.next".into());
    assert!(preflight(manifest(), policy).is_err());
    for change in ["source", "version", "preview", "method", "body", "headers"] {
        let mut manifest = manifest();
        let next = manifest
            .operations
            .iter_mut()
            .find(|operation| operation.source.operation_id == "Items_Next")
            .unwrap();
        match change {
            "source" => next.source.upstream = "other-official-document".into(),
            "version" => next.api_version = Some("2026-01-01".into()),
            "preview" => next.preview = true,
            "method" => next.method = "POST".into(),
            "body" => {
                next.request_body =
                    Some(json!({"content":{"application/json":{"schema":{"type":"object"}}}}))
            }
            "headers" => next.parameters.push(junction_core::Parameter {
                name: "x-service".into(),
                location: "header".into(),
                required: false,
                schema: json!({"type":"string"}),
                serialization: Default::default(),
            }),
            _ => unreachable!(),
        }
        assert!(preflight(manifest, Default::default()).is_err(), "{change}");
    }
    let mut missing = manifest();
    missing
        .operations
        .retain(|operation| operation.source.operation_id != "Items_Next");
    assert!(preflight(missing, Default::default()).is_err());
}
