use junction_discovery::{ingest, merge::merge};
use junction_registry::Registry;
use serde_json::{Value, json};

fn document(version: &str, kind: &str) -> junction_core::RegistryManifest {
    ingest(&json!({"openapi":"3.1.0","info":{"version":version},"servers":[{"url":"https://example.invalid"}],
        "components":{"schemas":{"Item":{"type":"object","properties":{"value":{"type":kind},"example":{"$ref":"#/components/schemas/Value"}},"required":["value"],"default":{"$ref":"literal-data"}},"Value":{"type":kind}}},
        "paths":{"/items":{"post":{"operationId":"Items_Create","requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}},"responses":{"default":{"description":"result","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}}}}}}}), "azure", "compute", "official-source").unwrap()
}
#[test]
fn merge_is_order_independent_and_keeps_version_schema_namespaces_isolated() {
    let older = document("2025-01-01", "integer");
    let newer = document("2026-01-01", "string");
    let merged = merge(vec![older.clone(), newer.clone()]).unwrap();
    assert_eq!(
        serde_json::to_value(&merged).unwrap(),
        serde_json::to_value(merge(vec![newer.clone(), older.clone()]).unwrap()).unwrap()
    );
    assert_eq!(merged.operations.len(), 2);
    assert_eq!(
        merged.schemas["components"]["schemas"]
            .as_object()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(merged.schemas["canonical"].as_object().unwrap().len(), 4);
    let registry = Registry::load(merged.clone()).unwrap();
    for (version, good, bad) in [
        ("2025-01-01", json!(3), json!("three")),
        ("2026-01-01", json!("three"), json!(3)),
    ] {
        let input = registry
            .input_schema("azure.compute.items.create", Some(version), false)
            .unwrap();
        junction_schema::validate_json_schema(
            &input,
            &json!({"body":{"value":good,"example":good}}),
        )
        .unwrap();
        assert!(
            junction_schema::validate_json_schema(&input, &json!({"body":{"value":bad}})).is_err()
        );
        let operation = registry
            .resolve("azure.compute.items.create", Some(version), false)
            .unwrap();
        junction_schema::validate_with_definitions(
            &operation.responses["default"]["content"]["application/json"]["schema"],
            registry.schemas(),
            &json!({"value":good}),
        )
        .unwrap();
    }
    assert_eq!(
        registry
            .resolve("azure.compute.items.create", None, false)
            .unwrap()
            .api_version
            .as_deref(),
        Some("2026-01-01")
    );
    for schema in merged.schemas["components"]["schemas"]
        .as_object()
        .unwrap()
        .values()
    {
        if let Some(default) = schema.get("default") {
            assert_eq!(default["$ref"], "literal-data");
        }
    }
    assert_eq!(
        merge(vec![older.clone(), older]).unwrap().operations.len(),
        1
    );
    assert!(merge(vec![newer.clone(), document("2026-01-01", "integer")]).is_err());
}
#[test]
fn swagger_definitions_and_escaped_names_remain_resolvable() {
    let spec = json!({"swagger":"2.0","info":{"version":"2026-01-01"},"host":"example.invalid","definitions":{"Item/Name":{"type":"string"}},"paths":{"/items":{"post":{"operationId":"Items_Create","parameters":[{"name":"body","in":"body","required":true,"schema":{"$ref":"#/definitions/Item~1Name"}}],"responses":{"200":{"description":"ok"}}}}}});
    let manifest = ingest(&spec, "purview", "audit", "official").unwrap();
    let registry = Registry::load(merge(vec![manifest]).unwrap()).unwrap();
    let input = registry
        .input_schema("purview.audit.items.create", None, false)
        .unwrap();
    junction_schema::validate_json_schema(&input, &json!({"body":"item"})).unwrap();
    assert!(junction_schema::validate_json_schema(&input, &json!({"body":3})).is_err());
    let mut invalid = document("2026-01-01", "string");
    invalid.format_version = 2;
    assert!(merge(vec![invalid]).is_err());
    assert!(merge(Vec::new()).is_err());
    let _: Value = input;
}

#[test]
fn refresh_provenance_survives_order_independent_and_nested_merges() {
    let mut older = document("2025-01-01", "integer");
    let mut newer = document("2026-01-01", "string");
    let receipt = json!({"inventory":{"revision":"a".repeat(40)},"documents":[{"receipt":{"sha256":"b".repeat(64)},"status":"imported"}],"literal":{"$ref":"#/components/schemas/Item"}});
    older.schemas["x-junction-refresh"] = receipt.clone();
    older.schemas["components"]["x-upstream"] = json!({"revision":"original"});
    newer.schemas["x-junction-refresh"] = json!({"inventory":{"revision":"c".repeat(40)}});
    let merged = merge(vec![older.clone(), newer.clone(), older.clone()]).unwrap();
    assert_eq!(
        serde_json::to_value(&merged).unwrap(),
        serde_json::to_value(merge(vec![newer, older]).unwrap()).unwrap()
    );
    let metadata = merged.schemas["x-junction-import-metadata"]
        .as_object()
        .unwrap();
    assert_eq!(metadata.len(), 2);
    let original = metadata
        .values()
        .find(|value| value["x-junction-refresh"] == receipt)
        .unwrap();
    assert_eq!(original["components"]["x-upstream"]["revision"], "original");
    let nested = merge(vec![merged.clone()]).unwrap();
    let parent = nested.schemas["x-junction-import-metadata"]
        .as_object()
        .unwrap();
    assert_eq!(parent.len(), 1);
    assert_eq!(
        parent.values().next().unwrap()["x-junction-import-metadata"],
        merged.schemas["x-junction-import-metadata"]
    );
    Registry::load(nested).unwrap();
}
