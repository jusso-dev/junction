use junction_discovery::{bundle::bundle, ingest};
use junction_registry::Registry;
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn relative_schema_and_parameter_references_bundle_with_recursive_types() {
    let entry = json!({"swagger":"2.0","info":{"version":"2026-01-01"},"host":"example.invalid","schemes":["https"],
        "paths":{"/items":{"post":{"operationId":"Items_Create","parameters":[{"$ref":"../shared/common.json#/parameters/Body"}],
        "responses":{"200":{"description":"ok","schema":{"$ref":"../shared/common.json#/definitions/Item~1Name"}}}}}}});
    let shared = json!({"parameters":{"Body":{"name":"body","in":"body","required":true,"schema":{"$ref":"#/definitions/Item~1Name"}}},
        "definitions":{"Item/Name":{"type":"object","properties":{"value":{"$ref":"./types.json#/definitions/default"},"child":{"$ref":"#/definitions/Item~1Name"},"example":{"$ref":"./types.json#/definitions/default"}},"required":["value"],"default":{"$ref":"literal"}}}});
    let types = json!({"definitions":{"default":{"type":"integer"}}});
    let documents = BTreeMap::from([
        ("specification/compute/api.json".into(), entry),
        ("specification/shared/common.json".into(), shared),
        ("specification/shared/types.json".into(), types),
    ]);
    let bundled = bundle("specification/compute/api.json", &documents).unwrap();
    assert_eq!(bundled["definitions"].as_object().unwrap().len(), 2);
    assert_eq!(
        bundled["components"]["parameters"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    let manifest = ingest(&bundled, "azure", "compute", "pinned-official-source").unwrap();
    let registry = Registry::load(manifest).unwrap();
    let schema = registry
        .input_schema("azure.compute.items.create", None, false)
        .unwrap();
    junction_schema::validate_json_schema(
        &schema,
        &json!({"body":{"value":3,"child":{"value":4},"example":5}}),
    )
    .unwrap();
    assert!(
        junction_schema::validate_json_schema(&schema, &json!({"body":{"value":"wrong"}})).is_err()
    );
    assert_eq!(
        bundled,
        bundle("specification/compute/api.json", &documents).unwrap()
    );
}
#[test]
fn missing_unsafe_and_unsupported_reference_semantics_fail() {
    for reference in [
        "../../outside.json#/definitions/A",
        "https://evil.invalid/private#/definitions/A",
        "other.json#/definitions/A",
        "#/definitions/missing",
        "#/definitions/A~2",
        "other.json#anchor",
    ] {
        let entry = json!({"definitions":{"A":{"$ref":reference}}});
        let documents = BTreeMap::from([("api.json".into(), entry)]);
        let error = bundle("api.json", &documents).unwrap_err().to_string();
        assert!(!error.contains("evil.invalid"));
        assert!(!error.contains("outside.json"));
    }
    let documents = BTreeMap::from([(
        "api.json".into(),
        json!({"definitions":{"A":{"$id":"other.json","type":"string"}}}),
    )]);
    assert!(bundle("api.json", &documents).is_err());
}

#[test]
fn missing_document_discovery_follows_transitive_refs_and_ignores_literals() {
    use junction_discovery::bundle::missing_documents;
    let mut documents = BTreeMap::from([(
        "specification/api.json".into(),
        json!({"definitions":{"A":{"$ref":"shared.json#/definitions/A"}},"example":{"$ref":"https://private.invalid"}}),
    )]);
    assert_eq!(
        missing_documents("specification/api.json", &documents)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        ["specification/shared.json"]
    );
    documents.insert("specification/shared.json".into(), json!({"definitions":{"A":{"type":"object","properties":{"default":{"$ref":"./types.json#/definitions/T"}},"default":{"$ref":"literal-invalid"}}}}));
    assert_eq!(
        missing_documents("specification/api.json", &documents)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        ["specification/types.json"]
    );
    documents.insert(
        "specification/types.json".into(),
        json!({"definitions":{"T":{"type":"string"}}}),
    );
    assert!(
        missing_documents("specification/api.json", &documents)
            .unwrap()
            .is_empty()
    );
    documents.insert("specification/types.json".into(), json!({"definitions":{}}));
    assert!(missing_documents("specification/api.json", &documents).is_err());
}

#[test]
fn azure_x_ms_paths_references_are_bundled_but_examples_stay_opaque() {
    let entry = json!({"swagger":"2.0","info":{"version":"2026-04-01"},"host":"management.azure.com","schemes":["https"],
        "paths":{},
        "x-ms-paths":{"/items?view=full":{"get":{"operationId":"Items_ListFull",
            "parameters":[{"$ref":"../shared/types.json#/parameters/ApiVersion"}],
            "responses":{"200":{"description":"ok","schema":{"$ref":"../shared/types.json#/definitions/Item"}}},
            "x-ms-examples":{"full":{"$ref":"./examples/missing.json"}}}}}});
    let shared = json!({"parameters":{"ApiVersion":{"name":"api-version","in":"query","required":true,"type":"string"}},
        "definitions":{"Item":{"type":"object"}}});
    let documents = BTreeMap::from([
        ("specification/compute/api.json".into(), entry),
        ("specification/shared/types.json".into(), shared),
    ]);
    let missing =
        junction_discovery::bundle::missing_documents("specification/compute/api.json", &documents)
            .unwrap();
    assert!(missing.is_empty(), "{missing:?}");
    let bundled = bundle("specification/compute/api.json", &documents).unwrap();
    let text = serde_json::to_string(&bundled["x-ms-paths"]).unwrap();
    assert!(!text.contains("../shared/types.json"));
    assert!(text.contains("./examples/missing.json"));
    let manifest = ingest(&bundled, "azure", "compute", "pinned-official-source").unwrap();
    assert_eq!(manifest.operations.len(), 1);
}
