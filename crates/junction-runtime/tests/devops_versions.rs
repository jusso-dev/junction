use junction_discovery::ingest;
use junction_policy::Policy;
use junction_registry::Registry;
use junction_runtime::prepare;
use serde_json::json;

#[test]
fn merged_products_keep_swagger_body_constraints_and_separate_schema_names() {
    let devops = json!({"swagger":"2.0","info":{"version":"7.1"},
        "host":"dev.azure.com","definitions":{"Project":{"type":"object",
            "required":["name"],"properties":{"name":{"type":"string","minLength":1}},
            "additionalProperties":false}},
        "paths":{"/{organization}/_apis/projects":{"post":{
            "operationId":"Projects_Create","parameters":[
                {"name":"organization","in":"path","required":true,"type":"string"},
                {"name":"api-version","in":"query","required":true,"type":"string"},
                {"name":"body","in":"body","required":true,"schema":{"$ref":"#/definitions/Project"}}],
            "responses":{}}}}});
    let graph = json!({"swagger":"2.0","info":{"version":"v1.0"},
        "host":"graph.microsoft.com","basePath":"/v1.0",
        "definitions":{"Project":{"type":"integer"}},"paths":{}});
    let devops_manifest = ingest(&devops, "azure-devops", "core", "official-devops").unwrap();
    let id = devops_manifest.operations[0].id.clone();
    let graph_manifest = ingest(&graph, "graph", "graph", "official-graph").unwrap();
    let registry = Registry::load(
        junction_discovery::merge::merge(vec![graph_manifest, devops_manifest]).unwrap(),
    )
    .unwrap();
    let schema = registry.input_schema(&id, None, false).unwrap();
    for valid in [
        json!({"parameters":{"organization":"customer-a"},"body":{"name":"Project A"}}),
        json!({"parameters":{"organization":"customer-a","api-version":"7.1"},"body":{"name":"Project B"}}),
    ] {
        junction_schema::validate_json_schema(&schema, &valid).unwrap();
    }
    for invalid in [
        json!({"body":{"name":"Project A"}}),
        json!({"parameters":{"organization":"customer-a"}}),
        json!({"parameters":{"organization":"customer-a"},"body":42}),
        json!({"parameters":{"organization":"customer-a"},"body":{"name":""}}),
        json!({"parameters":{"organization":"customer-a"},"body":{"name":"A","unexpected":true}}),
        json!({"parameters":{"organization":"customer-a","api-version":"7.1-preview.1"},"body":{"name":"A"}}),
    ] {
        assert!(junction_schema::validate_json_schema(&schema, &invalid).is_err());
    }
}

#[test]
fn imported_devops_preview_is_gated_and_sent_as_selected_wire_version() {
    let spec = json!({"swagger":"2.0","info":{"version":"7.1"},
        "host":"dev.azure.com","basePath":"/",
        "parameters":{"version":{"name":"api-version","in":"query",
            "required":true,"type":"string"}},
        "paths":{"/{organization}/_apis/projects":{"get":{
            "operationId":"Projects_List","x-ms-docs-override-version":"7.1-preview.3",
            "x-ms-preview":true,"parameters":[
                {"name":"organization","in":"path","required":true,"type":"string"},
                {"$ref":"#/parameters/version"}],"responses":{}}}}});
    let manifest = ingest(&spec, "azure-devops", "core", "official").unwrap();
    let id = manifest.operations[0].id.clone();
    let registry = Registry::load(manifest).unwrap();
    assert!(registry.resolve(&id, None, false).is_err());
    assert!(registry.resolve(&id, Some("7.1-preview.3"), false).is_err());
    let operation = registry.resolve(&id, Some("7.1-preview.3"), true).unwrap();
    let input = json!({"parameters":{"organization":"customer-a"}});
    let request = prepare(
        operation,
        &input,
        "tenant-a",
        "https://dev.azure.com",
        &Policy::default(),
    )
    .unwrap();
    assert_eq!(
        request.url.as_str(),
        "https://dev.azure.com/customer%2Da/_apis/projects?api%2Dversion=7%2E1%2Dpreview%2E3"
    );
    // Agent input cannot substitute a different version after registry selection.
    for version in ["7.1", "7.1-preview.1"] {
        let input = json!({"parameters":{"organization":"customer-a","api-version":version}});
        assert!(
            prepare(
                operation,
                &input,
                "tenant-a",
                "https://dev.azure.com",
                &Policy::default()
            )
            .is_err()
        );
    }
    let mut incompatible = operation.clone();
    let parameter = incompatible
        .parameters
        .iter_mut()
        .find(|parameter| parameter.name == "api-version")
        .unwrap();
    parameter.schema = json!({"type":"string","enum":["7.1"]});
    assert!(
        prepare(
            &incompatible,
            &input,
            "tenant-a",
            "https://dev.azure.com",
            &Policy::default()
        )
        .is_err()
    );
}
