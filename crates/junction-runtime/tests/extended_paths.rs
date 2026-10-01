use serde_json::json;

#[test]
fn extended_path_queries_use_declared_parameters_and_preserve_encoding() {
    let spec = json!({"swagger":"2.0","host":"management.azure.com","paths":{},
        "x-ms-paths":{"/items?color={color}&ignored=source-text":{"get":{
            "operationId":"Items_ListByColor","parameters":[
                {"name":"color","in":"query","required":true,"type":"string"}]}}}});
    let operation = junction_discovery::ingest(&spec, "azure", "resources", "official")
        .unwrap()
        .operations
        .remove(0);
    let request = junction_runtime::prepare(
        &operation,
        &json!({"parameters":{"color":"red & blue"}}),
        "customer-a",
        "https://management.azure.com",
        &Default::default(),
    )
    .unwrap();
    assert_eq!(request.url.path(), "/items");
    assert_eq!(
        request.url.query_pairs().collect::<Vec<_>>(),
        vec![("color".into(), "red & blue".into())]
    );
    assert!(
        junction_runtime::prepare(
            &operation,
            &json!({}),
            "customer-a",
            "https://management.azure.com",
            &Default::default()
        )
        .is_err()
    );
}
