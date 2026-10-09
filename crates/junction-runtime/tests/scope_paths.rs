use serde_json::json;

fn prepare(
    operation: &junction_core::JunctionOperation,
    scope: &str,
) -> anyhow::Result<junction_runtime::PreparedRequest> {
    junction_runtime::prepare(
        operation,
        &json!({"parameters":{"scope":scope,"name":"a/b"}}),
        "customer-a",
        "https://management.azure.com",
        &Default::default(),
    )
}

#[test]
fn skip_url_encoding_keeps_scope_separators_and_rejects_traversal() {
    let spec = json!({"swagger":"2.0","host":"management.azure.com","paths":{
        "/{scope}/providers/Microsoft.Security/pricings/{name}":{"get":{
            "operationId":"Pricings_Get","parameters":[
                {"name":"scope","in":"path","required":true,"type":"string",
                 "x-ms-skip-url-encoding":true},
                {"name":"name","in":"path","required":true,"type":"string"}]}}}});
    let operation = junction_discovery::ingest(&spec, "azure", "security", "official")
        .unwrap()
        .operations
        .remove(0);
    assert!(operation.parameters[0].serialization.skip_url_encoding);
    assert!(!operation.parameters[1].serialization.skip_url_encoding);

    for scope in [
        "subscriptions/00000000-0000-0000-0000-000000000000",
        "/subscriptions/00000000-0000-0000-0000-000000000000",
    ] {
        assert_eq!(
            prepare(&operation, scope).unwrap().url.path(),
            "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/pricings/a%2Fb"
        );
    }
    assert_eq!(
        prepare(&operation, "subscriptions/s/resourceGroups/r g?x#y")
            .err()
            .map(|e| e.to_string()),
        Some("invalid path parameter".into())
    );
    assert_eq!(
        prepare(&operation, "subscriptions/s/resourceGroups/r%3Fx:y")
            .unwrap()
            .url
            .path(),
        "/subscriptions/s/resourceGroups/r%253Fx:y/providers/Microsoft.Security/pricings/a%2Fb"
    );
    for scope in [
        "subscriptions/../tenants",
        "subscriptions/./s",
        "subscriptions//s",
        "subscriptions/s/",
        "//s",
        "subscriptions/s\n",
        "subscriptions/s\u{0}",
    ] {
        assert!(prepare(&operation, scope).is_err(), "{scope:?}");
    }
}
