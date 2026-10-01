use serde_json::{Value, json};
use std::collections::BTreeSet;
fn refs(value: &Value, root: &Value) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                assert!(reference.starts_with("#/"));
                assert!(
                    root.pointer(&reference[1..]).is_some(),
                    "unresolved contract reference"
                );
            }
            for value in object.values() {
                refs(value, root);
            }
        }
        Value::Array(values) => {
            for value in values {
                refs(value, root);
            }
        }
        _ => {}
    }
}
#[test]
fn local_contract_imports_and_closes_execution_requests_to_host_configuration() {
    let contract = junction_server::openapi();
    assert_eq!(contract["openapi"], "3.1.1");
    assert_eq!(contract["servers"][0]["url"], "http://127.0.0.1:8080");
    assert_eq!(contract["security"], json!([{"JunctionBearer":[]}]));
    assert_eq!(
        contract["components"]["securitySchemes"]["JunctionBearer"]["scheme"],
        "bearer"
    );
    refs(&contract, &contract);
    let mut ids = BTreeSet::new();
    for (path, item) in contract["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            assert!(["get", "post"].contains(&method.as_str()));
            assert!(ids.insert(operation["operationId"].as_str().unwrap()));
            assert!(operation["responses"]["200"]["content"]["application/json"].is_object());
            if path.contains("{id}") {
                assert!(operation["parameters"].as_array().unwrap().iter().any(
                    |parameter| parameter["name"] == "id"
                        && parameter["in"] == "path"
                        && parameter["required"] == true
                ));
            }
        }
    }
    assert_eq!(ids.len(), 9);
    let error_schema = &contract["paths"]["/v1/execute/{id}"]["post"]["responses"]["429"]["content"]
        ["application/json"]["schema"];
    assert_eq!(error_schema["properties"]["retryable"]["type"], "boolean");
    junction_schema::validate_json_schema(
        error_schema,
        &json!({
            "status":"credential_busy", "error":"credential_busy",
            "message":"Retry after the active credential transaction completes", "retryable":true
        }),
    )
    .unwrap();
    assert!(
        junction_schema::validate_json_schema(
            error_schema,
            &json!({
                "status":"credential_busy", "retryable":"yes"
            })
        )
        .is_err()
    );
    let manifest =
        junction_discovery::ingest(&contract, "junction", "local", "junction-local").unwrap();
    assert_eq!(manifest.operations.len(), 9);
    junction_registry::Registry::load(manifest).unwrap();
    let schema = &contract["components"]["schemas"]["ExecuteRequest"];
    junction_schema::validate_json_schema(
        schema,
        &json!({"input":{},"all":true,"max_items":50,"max_pages":5}),
    )
    .unwrap();
    for input in [
        json!({"input":{},"policy":"full"}),
        json!({"input":{},"token":"private-token"}),
        json!({"input":{},"endpoint":"https://private.invalid"}),
        json!({"input":{},"max_pages":0}),
    ] {
        assert!(junction_schema::validate_json_schema(schema, &input).is_err());
    }
}
