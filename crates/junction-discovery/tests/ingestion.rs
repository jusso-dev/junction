use junction_core::OperationRisk;
use junction_discovery::ingest;
use serde_json::json;

#[test]
fn fabric_lro_markers_select_the_fabric_protocol_and_reject_conflicts() {
    let mut spec = json!({"swagger":"2.0","host":"api.fabric.microsoft.com","basePath":"/v1",
        "paths":{"/items":{"post":{"operationId":"Items_Create","x-ms-fabric-sdk-long-running-operation":true}}}});
    let manifest = ingest(&spec, "fabric", "platform", "official").unwrap();
    assert_eq!(
        manifest.operations[0]
            .long_running
            .as_ref()
            .unwrap()
            .protocol,
        Some(junction_core::LroProtocol::Fabric)
    );
    spec["paths"]["/items"]["post"]["x-ms-long-running-operation"] = true.into();
    assert!(ingest(&spec, "fabric", "platform", "official").is_err());
    spec["paths"]["/items"]["post"]
        .as_object_mut()
        .unwrap()
        .remove("x-ms-long-running-operation");
    spec["paths"]["/items"]["post"]["x-ms-fabric-sdk-long-running-operation"] = false.into();
    assert!(
        ingest(&spec, "fabric", "platform", "official")
            .unwrap()
            .operations[0]
            .long_running
            .is_none()
    );
    spec["paths"]["/items"]["post"]["x-ms-fabric-sdk-long-running-operation"] = "invalid".into();
    assert!(ingest(&spec, "fabric", "platform", "official").is_err());
}

#[test]
fn pageable_metadata_requires_valid_declared_field_names() {
    let mut spec = json!({"swagger":"2.0","host":"management.azure.com","paths":{
        "/items":{"get":{"operationId":"Items_List","x-ms-pageable":{"nextLinkName":null}}}}});
    let metadata = ingest(&spec, "azure", "resources", "official")
        .unwrap()
        .operations
        .remove(0)
        .pageable
        .unwrap();
    assert_eq!(metadata.item_name, "value");
    assert!(metadata.next_link_name.is_none());
    for invalid in [
        json!({}),
        json!({"nextLinkName":42}),
        json!({"nextLinkName":"next","itemName":""}),
        json!({"nextLinkName":"next","operationName":false}),
    ] {
        spec["paths"]["/items"]["get"]["x-ms-pageable"] = invalid;
        assert!(ingest(&spec, "azure", "resources", "official").is_err());
    }
}

#[test]
fn extended_paths_import_overloads_without_query_suffixes() {
    let mut spec = json!({"swagger":"2.0","host":"management.azure.com","paths":{
        "/items":{"get":{"operationId":"Items_List"}}},
        "x-ms-paths":{"/items?color={color}":{"get":{"operationId":"Items_ListByColor",
            "parameters":[{"name":"color","in":"query","required":true,"type":"string"}]}},
            "/items?ignored=documentation":{"get":{"operationId":"Items_ListAlternative"}}}});
    let imported = ingest(&spec, "azure", "resources", "official").unwrap();
    assert_eq!(imported.operations.len(), 3);
    assert!(
        imported
            .operations
            .iter()
            .all(|operation| operation.path == "/items")
    );
    let overload = imported
        .operations
        .iter()
        .find(|operation| operation.source.operation_id == "Items_ListByColor")
        .unwrap();
    assert_eq!(overload.parameters[0].name, "color");
    assert_eq!(overload.parameters[0].location, "query");
    assert!(overload.parameters[0].required);
    spec["x-ms-paths"] = json!([]);
    assert!(ingest(&spec, "azure", "resources", "official").is_err());
}

#[test]
fn unresolved_host_variables_survive_registry_serialization() {
    let mut spec = json!({"swagger":"2.0","host":"management.azure.com",
        "x-ms-parameterized-host":{"hostTemplate":"{account}.vault.azure.net","parameters":[
            {"name":"account","in":"path","type":"string"}]},
        "paths":{"/items":{"get":{"operationId":"Items_List"}}}});
    let manifest = ingest(&spec, "azure", "vault", "official").unwrap();
    let manifest: junction_core::RegistryManifest =
        serde_json::from_value(serde_json::to_value(manifest).unwrap()).unwrap();
    let operation = &manifest.operations[0];
    assert_eq!(operation.base_url, "https://{account}.vault.azure.net");
    let template = operation.endpoint_template.as_ref().unwrap();
    assert!(template.resolve(&Default::default()).is_err());
    assert_eq!(
        template
            .resolve(&std::collections::BTreeMap::from([(
                "account".into(),
                "customer-a".into()
            )]))
            .unwrap(),
        "https://customer-a.vault.azure.net"
    );
    spec["paths"]["/items"]["get"]["servers"] = json!([{"url":"https://other.example"}]);
    let operation = ingest(&spec, "azure", "vault", "official")
        .unwrap()
        .operations
        .remove(0);
    assert!(operation.endpoint_template.is_none());
    assert_eq!(operation.base_url, "https://other.example");
}

#[test]
fn swagger_parameterized_hosts_override_standard_hosts() {
    let mut spec = json!({"swagger":"2.0","host":"management.azure.com","schemes":["https"],
        "basePath":"/v1","info":{"version":"2025-01-01"},
        "x-ms-parameterized-host":{"hostTemplate":"{account}.{suffix}","parameters":[
            {"name":"account","in":"path","type":"string","default":"example"},
            {"$ref":"#/parameters/suffix"}]},
        "parameters":{"suffix":{"name":"suffix","in":"path","type":"string","default":"vault.azure.net","enum":["vault.azure.net"]}},
        "paths":{"/items":{"get":{"operationId":"Items_List"}}}});
    let imported = ingest(&spec, "azure", "vault", "official").unwrap();
    assert_eq!(
        imported.operations[0].base_url,
        "https://example.vault.azure.net/v1"
    );
    spec["x-ms-parameterized-host"] = json!({"hostTemplate":"{endpoint}","useSchemePrefix":false,
        "parameters":[{"name":"endpoint","in":"path","type":"string","default":"https://example.vault.azure.net"}]});
    assert_eq!(
        ingest(&spec, "azure", "vault", "official")
            .unwrap()
            .operations[0]
            .base_url,
        "https://example.vault.azure.net/v1"
    );
    for invalid in [
        json!({"hostTemplate":"{endpoint}","useSchemePrefix":"false","parameters":[]}),
        json!({"hostTemplate":"{endpoint}","parameters":[{"name":"endpoint","in":"query","type":"string","default":"example"}]}),
        json!({"hostTemplate":"{endpoint}","parameters":[{"name":"endpoint","in":"path","type":"string","default":"private-secret@example.com"}]}),
        json!({"hostTemplate":"{endpoint}","parameters":[{"name":"endpoint","in":"path","type":"string","default":"example.com","enum":["other.com"]}]}),
    ] {
        spec["x-ms-parameterized-host"] = invalid;
        let error = ingest(&spec, "azure", "vault", "official")
            .unwrap_err()
            .to_string();
        assert!(!error.contains("private-secret"));
    }
}

#[test]
fn swagger_endpoints_preserve_schemes_and_reject_malformed_hosts() {
    let mut spec = json!({"swagger":"2.0","host":"service.example:8443","basePath":"/v1",
    "schemes":["http","https"],"paths":{
        "/items":{"get":{"operationId":"Items_List","responses":{}}}
    }});
    assert_eq!(
        ingest(&spec, "azure", "service", "official")
            .unwrap()
            .operations[0]
            .base_url,
        "https://service.example:8443/v1"
    );
    spec["schemes"] = json!(["http"]);
    assert_eq!(
        ingest(&spec, "azure", "service", "official")
            .unwrap()
            .operations[0]
            .base_url,
        "http://service.example:8443/v1"
    );
    for schemes in [json!([]), json!(["ftp"]), json!("https")] {
        spec["schemes"] = schemes;
        assert!(ingest(&spec, "azure", "service", "official").is_err());
    }
    spec["schemes"] = json!(["https"]);
    for host in [
        "private@service.example",
        "service.example/path",
        "service.example?private=value",
        "service.example\\path",
        " service.example",
        "service.example\n",
    ] {
        spec["host"] = json!(host);
        let error = ingest(&spec, "azure", "service", "official").err().unwrap();
        assert!(!error.to_string().contains(host));
    }
    spec["host"] = json!("service.example");
    for path in ["v1", "/v1?private=value", "/v1#fragment", "/v1\n"] {
        spec["basePath"] = json!(path);
        assert!(ingest(&spec, "azure", "service", "official").is_err());
    }
}

#[test]
fn non_arm_sources_do_not_inherit_an_arm_host() {
    let mut spec = json!({"openapi":"3.0.3","paths":{
        "/items":{"get":{"operationId":"Items_List","responses":{}}}
    }});
    for product in ["azure", "graph", "azure-devops", "defender", "fabric"] {
        assert!(ingest(&spec, product, "items", "official").is_err());
    }
    spec["servers"] = json!([{"url":"https://service.example"}]);
    assert_eq!(
        ingest(&spec, "fabric", "items", "official")
            .unwrap()
            .operations[0]
            .base_url,
        "https://service.example"
    );
}

#[test]
fn operation_servers_work_without_a_document_endpoint() {
    let spec = json!({"openapi":"3.0.3","paths":{
        "/items":{"servers":[{"url":"https://path.example"}],
            "get":{"operationId":"Items_List","responses":{}},
            "post":{"operationId":"Items_Create","servers":[{"url":"https://operation.example"}],"responses":{}}}
    }});
    let manifest = ingest(&spec, "azure", "service", "official").unwrap();
    assert_eq!(
        manifest
            .operations
            .iter()
            .find(|operation| operation.operation == "list")
            .unwrap()
            .base_url,
        "https://path.example"
    );
    assert_eq!(
        manifest
            .operations
            .iter()
            .find(|operation| operation.operation == "create")
            .unwrap()
            .base_url,
        "https://operation.example"
    );
}

#[test]
fn openapi_server_defaults_and_local_overrides_are_resolved() {
    let mut spec = json!({"openapi":"3.0.3","servers":[{
    "url":"https://{region}.service.example/{version}","variables":{
        "region":{"default":"west","enum":["west","east"]},"version":{"default":"v1"}}}],
    "paths":{
        "/items":{"get":{"operationId":"Items_List","responses":{}}},
        "/other":{"servers":[{"url":"https://path.example/v2"}],
            "get":{"operationId":"Other_List","responses":{}},
            "post":{"operationId":"Other_Create","servers":[{"url":"https://operation.example/v3"}],"responses":{}}}
    }});
    let imported = ingest(&spec, "azure", "service", "official").unwrap();
    let endpoint = |id: &str| {
        imported
            .operations
            .iter()
            .find(|operation| operation.source.operation_id == id)
            .unwrap()
            .base_url
            .as_str()
    };
    assert_eq!(endpoint("Items_List"), "https://west.service.example/v1");
    assert_eq!(endpoint("Other_List"), "https://path.example/v2");
    assert_eq!(endpoint("Other_Create"), "https://operation.example/v3");
    let operation = imported
        .operations
        .iter()
        .find(|operation| operation.source.operation_id == "Items_List")
        .unwrap();
    let template = operation.endpoint_template.as_ref().unwrap();
    assert_eq!(
        template
            .resolve(&std::collections::BTreeMap::from([(
                "region".into(),
                "east".into()
            )]))
            .unwrap(),
        "https://east.service.example/v1"
    );
    assert!(
        imported
            .operations
            .iter()
            .filter(|operation| operation.source.operation_id != "Items_List")
            .all(|operation| operation.endpoint_template.is_none())
    );
    for default in [
        json!(null),
        json!("north"),
        json!("{region}"),
        json!("user@host"),
        json!("west?secret=value"),
    ] {
        spec["servers"][0]["variables"]["region"]["default"] = default;
        assert!(ingest(&spec, "azure", "service", "official").is_err());
    }
}

#[test]
fn local_server_templates_retain_only_the_selected_variables() {
    let spec = json!({"openapi":"3.0.3","servers":[{"url":"https://{root}.example","variables":{"root":{"default":"root"}}}],
        "paths":{"/items":{"servers":[{"url":"https://{path}.example/{prefix}","variables":{"path":{"default":"path"},"prefix":{"default":""}}}],
            "get":{"operationId":"Items_List"},
            "post":{"operationId":"Items_Create","servers":[{"url":"https://{operation}.example","variables":{"operation":{"default":"operation"}}}]}}}});
    let imported = ingest(&spec, "azure", "service", "official").unwrap();
    for operation in &imported.operations {
        let template = operation.endpoint_template.as_ref().unwrap();
        if operation.method == "GET" {
            assert_eq!(operation.base_url, "https://path.example/");
            assert_eq!(
                template
                    .variables
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec!["path", "prefix"]
            );
            assert_eq!(
                template
                    .resolve(&std::collections::BTreeMap::from([
                        ("path".into(), "east".into()),
                        ("prefix".into(), "v2".into())
                    ]))
                    .unwrap(),
                "https://east.example/v2"
            );
        } else {
            assert_eq!(operation.base_url, "https://operation.example");
            assert_eq!(
                template
                    .variables
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                vec!["operation"]
            );
        }
    }
}

#[test]
fn swagger_oauth_metadata_survives_import_and_merge() {
    let schemes = json!({"oauth2":{"type":"oauth2","flow":"accessCode",
        "authorizationUrl":"https://app.vssps.visualstudio.com/oauth2/authorize",
        "tokenUrl":"https://app.vssps.visualstudio.com/oauth2/token",
        "scopes":{"vso.project":"Read project metadata","vso.profile":"Read profiles"}}});
    let spec = json!({"swagger":"2.0","info":{"version":"7.1"},
    "host":"dev.azure.com","securityDefinitions":schemes,
    "security":[{"oauth2":["vso.project","vso.profile"]}],
    "paths":{
        "/projects":{"get":{"operationId":"Projects_List","responses":{}}},
        "/public":{"get":{"operationId":"Public_Get","security":[],"responses":{}}}
    }});
    let imported = ingest(&spec, "azure-devops", "core", "official").unwrap();
    assert_eq!(imported.schemas["x-junction-security-schemes"], schemes);
    let merged = junction_discovery::merge::merge(vec![imported]).unwrap();
    let metadata = merged.schemas["x-junction-import-metadata"]
        .as_object()
        .unwrap();
    assert!(
        metadata
            .values()
            .any(|document| document["x-junction-security-schemes"] == schemes)
    );
    let registry = junction_registry::Registry::load(merged).unwrap();
    let list = registry
        .permissions("azure_devops.core.projects.list", None, false)
        .unwrap();
    assert_eq!(
        list.required_permissions,
        Some(vec![vec!["vso.profile".into(), "vso.project".into()]])
    );
    let public = registry
        .permissions("azure_devops.core.public.get", None, false)
        .unwrap();
    assert_eq!(public.required_permissions, None);
}

#[test]
fn mixed_devops_versions_preserve_preview_operations() {
    let mut spec = json!({"swagger":"2.0","info":{"version":"7.1"},
        "host":"dev.azure.com","paths":{
        "/projects":{"get":{"operationId":"Projects_List","responses":{}}},
        "/avatar":{"delete":{"operationId":"Avatar_Remove",
            "x-ms-docs-override-version":"7.1-preview.1","x-ms-preview":true,"responses":{}}},
        "/experimental":{"get":{"operationId":"Experimental_Get",
            "x-ms-preview":true,"responses":{}}}
    }});
    let manifest = ingest(&spec, "azure-devops", "core", "official").unwrap();
    let stable = manifest
        .operations
        .iter()
        .find(|op| op.operation == "list")
        .unwrap();
    assert_eq!(stable.api_version.as_deref(), Some("7.1"));
    assert!(!stable.preview);
    assert_eq!(stable.maturity, junction_core::ApiMaturity::Stable);
    let avatar = manifest
        .operations
        .iter()
        .find(|op| op.resource == "avatar")
        .unwrap();
    assert_eq!(avatar.api_version.as_deref(), Some("7.1-preview.1"));
    assert!(avatar.preview);
    assert_eq!(avatar.maturity, junction_core::ApiMaturity::Preview);
    assert!(
        manifest
            .operations
            .iter()
            .find(|op| op.resource == "experimental")
            .unwrap()
            .preview
    );
    for invalid in [json!(null), json!(42), json!(""), json!("7.1&secret=value")] {
        spec["paths"]["/avatar"]["delete"]["x-ms-docs-override-version"] = invalid;
        assert!(ingest(&spec, "azure-devops", "core", "official").is_err());
    }
}

#[test]
fn long_running_extensions_preserve_declared_final_state_and_validate_markers() {
    let mut spec = json!({"swagger":"2.0","host":"management.azure.com","paths":{
        "/vms/start":{"post":{"operationId":"VirtualMachines_Start","responses":{}}}
    }});
    assert!(
        ingest(&spec, "azure", "compute", "official")
            .unwrap()
            .operations[0]
            .long_running
            .is_none()
    );
    spec["paths"]["/vms/start"]["post"]["x-ms-long-running-operation"] = json!(true);
    let manifest = ingest(&spec, "azure", "compute", "official").unwrap();
    assert_eq!(
        manifest.operations[0].long_running,
        Some(Default::default())
    );
    for strategy in [
        "azure-async-operation",
        "location",
        "original-uri",
        "operation-location",
    ] {
        spec["paths"]["/vms/start"]["post"]["x-ms-long-running-operation-options"] =
            json!({"final-state-via":strategy,"final-state-schema":"#/definitions/VM"});
        let manifest = ingest(&spec, "azure", "compute", "official").unwrap();
        let metadata = serde_json::to_value(&manifest.operations[0].long_running).unwrap();
        assert_eq!(metadata["final_state_via"], strategy);
        assert_eq!(metadata["final_state_schema"], "#/definitions/VM");
    }
    for options in [
        json!({"final-state-via":"private-secret-value"}),
        json!({"final-state-schema":"https://private.example.com/schema"}),
        json!(null),
    ] {
        spec["paths"]["/vms/start"]["post"]["x-ms-long-running-operation-options"] = options;
        let error = ingest(&spec, "azure", "compute", "official")
            .unwrap_err()
            .to_string();
        assert!(!error.contains("private"));
    }
    spec["paths"]["/vms/start"]["post"]["x-ms-long-running-operation-options"] =
        json!({"final-state-via":"location"});
    for marker in [json!(false), json!("true")] {
        spec["paths"]["/vms/start"]["post"]["x-ms-long-running-operation"] = marker;
        assert!(ingest(&spec, "azure", "compute", "official").is_err());
    }
}

#[test]
fn documentation_links_use_operation_precedence_and_exclude_credentials() {
    let root = "https://learn.microsoft.com/graph/overview";
    let specific = "https://learn.microsoft.com/graph/api/user-list";
    let mut spec = json!({"openapi":"3.0.0", "servers":[{"url":"https://graph.microsoft.com/v1.0"}], "externalDocs":{"url":root}, "paths":{
        "/users":{"get":{"operationId":"Users_List","responses":{}}}
    }});
    assert_eq!(
        ingest(&spec, "graph", "directory", "official")
            .unwrap()
            .operations[0]
            .documentation_url
            .as_deref(),
        Some(root)
    );
    spec["paths"]["/users"]["get"]["externalDocs"] = json!({"url":specific});
    assert_eq!(
        ingest(&spec, "graph", "directory", "official")
            .unwrap()
            .operations[0]
            .documentation_url
            .as_deref(),
        Some(specific)
    );
    for link in [
        "https://secret-user:secret-password@learn.microsoft.com/docs",
        "https://learn.microsoft.com/docs?secret-token=value",
        "javascript:private",
        "https://learn.microsoft.com/docs#secret-token",
        "relative/docs",
    ] {
        spec["paths"]["/users"]["get"]["externalDocs"] = json!({"url":link});
        let manifest = ingest(&spec, "graph", "directory", "official").unwrap();
        assert!(manifest.operations[0].documentation_url.is_none());
        assert!(
            !serde_json::to_string(&manifest)
                .unwrap()
                .contains("secret-")
        );
    }
}

#[test]
fn swagger_preserves_schema_and_classifies_delete() {
    let spec = json!({"swagger":"2.0", "info":{"version":"2025-01-01-preview"},
        "host":"management.azure.com", "definitions":{"VM":{"type":"object"}},
        "paths":{"/vms/{id}":{"parameters":[{"name":"id","in":"path","required":true,"type":"string"}],
            "delete":{"operationId":"VirtualMachines_Delete","responses":{"204":{}}}}}});
    let manifest = ingest(&spec, "azure", "compute", "official").unwrap();
    let op = &manifest.operations[0];
    assert_eq!(op.id, "azure.compute.virtual_machines.delete");
    assert_eq!(op.risk, OperationRisk::Destructive);
    assert!(op.preview);
    assert!(op.parameters[0].required);
    assert_eq!(manifest.schemas["definitions"]["VM"]["type"], "object");
}

#[test]
fn rejects_unresolved_parameter_references() {
    let spec = json!({"openapi":"3.0.0","paths":{"/users":{"get":{
        "operationId":"Users_List","parameters":[{"$ref":"#/components/parameters/id"}]}}}});
    assert!(ingest(&spec, "graph", "directory", "official").is_err());
}

#[test]
fn resolves_local_parameters_and_operation_overrides() {
    let spec = json!({"openapi":"3.0.0","servers":[{"url":"https://graph.microsoft.com/v1.0"}],"components":{"parameters":{"Top":{"name":"$top","in":"query","schema":{"type":"integer"}}},"schemas":{"User":{"type":"object","properties":{"id":{"type":"string","format":"uuid"}}}}},"paths":{"/users":{"parameters":[{"$ref":"#/components/parameters/Top"}],"get":{"operationId":"Users_List","parameters":[{"name":"$top","in":"query","required":true,"schema":{"type":"integer","maximum":100}}],"responses":{}}}}});
    let manifest = ingest(&spec, "graph", "directory", "official").unwrap();
    assert_eq!(manifest.operations[0].parameters.len(), 1);
    assert!(manifest.operations[0].parameters[0].required);
    assert_eq!(manifest.operations[0].parameters[0].schema["maximum"], 100);
    assert_eq!(
        manifest.schemas["canonical"]["#/components/schemas/User"]["schema_type"]["kind"],
        "object"
    );
    assert_eq!(manifest.schemas["components"], spec["components"]);
}

#[test]
fn reference_cycles_and_missing_targets_fail() {
    for reference in [
        "#/parameters/Loop",
        "#/parameters/Missing",
        "https://example.com/spec.json#/id",
    ] {
        let spec = json!({"swagger":"2.0","parameters":{"Loop":{"$ref":"#/parameters/Loop"}},"paths":{"/users":{"get":{"operationId":"Users_List","parameters":[{"$ref":reference}]}}}});
        assert!(ingest(&spec, "graph", "directory", "official").is_err());
    }
}

#[test]
fn yaml_and_json_produce_equivalent_manifests() {
    use junction_discovery::parse_document;
    let yaml = b"openapi: 3.0.0\ninfo:\n  version: v1.0\nservers:\n  - url: https://graph.microsoft.com/v1.0\npaths:\n  /users:\n    get:\n      operationId: Users_List\n      responses:\n        '200':\n          description: Success\n";
    let document = parse_document(yaml).unwrap();
    let json_bytes = serde_json::to_vec(&document).unwrap();
    let from_json = parse_document(&json_bytes).unwrap();
    assert_eq!(document, from_json);
    let a = ingest(&document, "graph", "directory", "official").unwrap();
    let b = ingest(&from_json, "graph", "directory", "official").unwrap();
    assert_eq!(
        serde_json::to_value(a).unwrap(),
        serde_json::to_value(b).unwrap()
    );
}

#[test]
fn malformed_documents_have_safe_errors() {
    use junction_discovery::parse_document;
    for bytes in [
        b"{\"client_secret\":\"sensitive\",}".as_slice(),
        b"a: [sensitive",
        &[0xff],
    ] {
        let error = parse_document(bytes).unwrap_err().to_string();
        assert!(!error.contains("sensitive"));
    }
    assert!(parse_document(b"---\na: 1\n---\nb: 2").is_err());
}

#[test]
fn swagger_body_and_parameter_serialization_are_normalized() {
    let spec = json!({"swagger":"2.0","host":"management.azure.com","info":{"version":"2025-01-01"},"consumes":["application/json"],"paths":{"/items":{"post":{
        "operationId":"Items_Create","parameters":[
            {"name":"item","in":"body","required":true,"schema":{"$ref":"#/definitions/Item"}},
            {"name":"ids","in":"query","type":"array","items":{"type":"string"},"collectionFormat":"multi"}
        ]}}},"definitions":{"Item":{"type":"object"}}});
    let manifest = ingest(&spec, "azure", "items", "official").unwrap();
    let op = &manifest.operations[0];
    assert_eq!(op.parameters.len(), 1);
    assert_eq!(
        op.parameters[0].serialization.collection_format.as_deref(),
        Some("multi")
    );
    assert_eq!(op.request_body.as_ref().unwrap()["required"], true);
    assert_eq!(
        op.request_body
            .as_ref()
            .unwrap()
            .pointer("/content/application~1json/schema/$ref")
            .unwrap(),
        "#/definitions/Item"
    );
    // Azure DevOps updates declare only JSON Patch; the media type is retained.
    let mut patch = spec.clone();
    patch["consumes"] = json!(["application/json-patch+json"]);
    let manifest = ingest(&patch, "azure", "items", "official").unwrap();
    assert!(
        manifest.operations[0]
            .request_body
            .as_ref()
            .unwrap()
            .pointer("/content/application~1json-patch+json/schema")
            .is_some()
    );
    let mut unspecified = spec.clone();
    unspecified["consumes"] = json!([]);
    assert!(ingest(&unspecified, "azure", "items", "official").is_ok());
    let mut invalid = spec;
    for media in [
        json!(["application/xml"]),
        json!(["text/json+json"]),
        json!("application/json"),
    ] {
        invalid["consumes"] = media;
        assert!(ingest(&invalid, "azure", "items", "official").is_err());
    }
}
#[test]
fn request_body_object_references_resolve_without_flattening_schema_references() {
    let spec = json!({"openapi":"3.0.0","servers":[{"url":"https://graph.microsoft.com/v1.0"}],"paths":{"/items":{"post":{"operationId":"Items_Create","requestBody":{"$ref":"#/components/requestBodies/Item"},"parameters":[{"name":"ids","in":"query","schema":{"type":"array","items":{"type":"string"}},"style":"form","explode":false}]}}},"components":{"requestBodies":{"Item":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}}},"schemas":{"Item":{"type":"object"}}}});
    let manifest = ingest(&spec, "graph", "items", "official").unwrap();
    let op = &manifest.operations[0];
    assert_eq!(op.parameters[0].serialization.explode, Some(false));
    assert_eq!(
        op.request_body
            .as_ref()
            .unwrap()
            .pointer("/content/application~1json/schema/$ref")
            .unwrap(),
        "#/components/schemas/Item"
    );
    let mut invalid = spec;
    invalid["components"]["requestBodies"]["Item"] =
        json!({"$ref":"#/components/requestBodies/Item"});
    assert!(ingest(&invalid, "graph", "items", "official").is_err());
}

#[test]
fn yaml_parameter_names_follow_strict_boolean_rules() {
    let document = junction_discovery::parse_document(b"openapi: 3.0.0\nservers:\n  - url: https://graph.microsoft.com/v1.0\npaths:\n  /items/{on}:\n    get:\n      operationId: Items_Get\n      parameters:\n        - name: on\n          in: path\n          required: true\n          schema:\n            type: string\n").unwrap();
    assert_eq!(
        document
            .pointer("/paths/~1items~1{on}/get/parameters/0/name")
            .unwrap(),
        "on"
    );
    assert!(ingest(&document, "graph", "items", "official").is_ok());
}
#[test]
fn catalog_yaml_supports_more_than_configuration_sized_node_limits() {
    let mut yaml = String::from("values:\n");
    for _ in 0..250_001 {
        yaml.push_str("  - true\n");
    }
    let document = junction_discovery::parse_document(yaml.as_bytes()).unwrap();
    assert_eq!(document["values"].as_array().unwrap().len(), 250_001);
}

#[test]
fn azure_compute_vm_names_paging_and_async_actions_match_runtime_contract() {
    // Representative official Compute Swagger metadata, with local parameters
    // instead of external common-types references for this offline regression.
    let collection = "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines";
    let parameters = json!([
        {"name":"subscriptionId","in":"path","required":true,"type":"string"},
        {"name":"resourceGroupName","in":"path","required":true,"type":"string"},
        {"name":"api-version","in":"query","required":true,"type":"string"}
    ]);
    let mut paths = serde_json::Map::new();
    paths.insert(
        collection.into(),
        json!({"get":{
            "operationId":"VirtualMachines_List","parameters":parameters,
            "x-ms-pageable":{"nextLinkName":"nextLink"},
            "responses":{"200":{"schema":{"type":"object","properties":{
                "value":{"type":"array","items":{"type":"object"}},"nextLink":{"type":"string"}
            }}}}
        }}),
    );
    for action in ["Start", "Restart"] {
        let mut parameters = parameters.as_array().unwrap().clone();
        parameters.push(json!({"name":"vmName","in":"path","required":true,"type":"string"}));
        paths.insert(
            format!("{collection}/{{vmName}}/{}", action.to_ascii_lowercase()),
            json!({"post":{
                "operationId":format!("VirtualMachines_{action}"),"parameters":parameters,
                "x-ms-long-running-operation":true,"responses":{"202":{"description":"Accepted"}}
            }}),
        );
    }
    let spec = json!({"swagger":"2.0","info":{"version":"2024-07-01"},
        "host":"management.azure.com","schemes":["https"],"paths":paths});
    let manifest = ingest(&spec, "azure", "compute", "azure-compute").unwrap();
    assert_eq!(manifest.operations.len(), 3);
    for operation in &manifest.operations {
        assert_eq!(operation.api_version.as_deref(), Some("2024-07-01"));
        assert_eq!(operation.resource, "virtual_machines");
        assert_eq!(operation.service, "compute");
        assert!(
            operation
                .parameters
                .iter()
                .any(|parameter| parameter.name == "subscriptionId" && parameter.required)
        );
        if operation.operation == "list" {
            assert_eq!(operation.id, "azure.compute.virtual_machines.list");
            assert_eq!(operation.risk, OperationRisk::ReadOnly);
            assert_eq!(
                operation
                    .pageable
                    .as_ref()
                    .unwrap()
                    .next_link_name
                    .as_deref(),
                Some("nextLink")
            );
        } else {
            assert_eq!(
                operation.id,
                format!("azure.compute.virtual_machines.{}", operation.operation)
            );
            assert_eq!(operation.risk, OperationRisk::Write);
            assert!(operation.long_running.is_some());
        }
    }
    assert_eq!(
        serde_json::to_value(&manifest).unwrap(),
        serde_json::to_value(ingest(&spec, "azure", "compute", "azure-compute").unwrap()).unwrap()
    );
}

fn marked_token_spec() -> serde_json::Value {
    json!({"openapi":"3.0.3","servers":[{"url":"https://service.example"}],
    "paths":{"/items":{"get":{"operationId":"Items_List","parameters":[{
        "name":"cursor","in":"query","schema":{"type":"string"},"x-ms-list-continuation-token":true
    }],"responses":{"200":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Page"}}}}}}}},
    "components":{"schemas":{"Page":{"allOf":[{"type":"object","properties":{
        "value":{"type":"array","items":{"type":"integer"}},
        "metadata":{"type":"object","properties":{"resume/key~value":{
            "type":"string","nullable":true,"x-ms-list-continuation-token":true
        }}}
    }}]}}}})
}
#[test]
fn authoritative_token_markers_pair_custom_query_and_nested_response_fields() {
    let spec = marked_token_spec();
    let manifest = ingest(&spec, "azure", "service", "official").unwrap();
    let continuation = manifest.operations[0].query_continuation.as_ref().unwrap();
    assert_eq!(continuation.query_parameter, "cursor");
    assert_eq!(
        continuation.response_pointer,
        "/metadata/resume~1key~0value"
    );
    assert_eq!(
        serde_json::to_value(&manifest).unwrap(),
        serde_json::to_value(ingest(&spec, "azure", "service", "official").unwrap()).unwrap()
    );
    junction_registry::Registry::load(manifest).unwrap();
}
#[test]
fn token_markers_reject_unpaired_ambiguous_wrong_type_and_non_query_metadata() {
    for change in [
        "request_missing",
        "response_missing",
        "request_duplicate",
        "response_duplicate",
        "request_type",
        "response_type",
        "header",
        "invalid_marker",
    ] {
        let mut spec = marked_token_spec();
        let request = "/paths/~1items/get/parameters/0";
        let property =
            "/components/schemas/Page/allOf/0/properties/metadata/properties/resume~1key~0value";
        match change {
            "request_missing" => {
                spec.pointer_mut(request)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove("x-ms-list-continuation-token");
            }
            "response_missing" => {
                spec.pointer_mut(property)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove("x-ms-list-continuation-token");
            }
            "request_duplicate" => {
                let mut next = spec.pointer(request).unwrap().clone();
                next["name"] = "another".into();
                spec.pointer_mut("/paths/~1items/get/parameters")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .push(next);
            }
            "response_duplicate" => {
                spec.pointer_mut("/components/schemas/Page/allOf/0/properties")
                    .unwrap()["another"] =
                    json!({"type":"string","x-ms-list-continuation-token":true});
            }
            "request_type" => spec.pointer_mut(request).unwrap()["schema"]["type"] = "array".into(),
            "response_type" => spec.pointer_mut(property).unwrap()["type"] = "integer".into(),
            "header" => spec.pointer_mut(request).unwrap()["in"] = "header".into(),
            _ => {
                spec.pointer_mut(request).unwrap()["x-ms-list-continuation-token"] =
                    "private-secret".into()
            }
        }
        let error = ingest(&spec, "azure", "service", "official")
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("private-secret"), "{change}");
    }
}
#[test]
fn unmarked_external_and_boolean_response_schemas_stay_importable() {
    for schema in [json!({"$ref":"outside.json#/Page"}), json!(true)] {
        let spec = json!({"openapi":"3.1.0","servers":[{"url":"https://service.example"}],
            "paths":{"/items":{"get":{"operationId":"Items_List","responses":{"200":{
                "content":{"application/json":{"schema":schema}}}}}}}});
        assert!(
            ingest(&spec, "azure", "service", "official")
                .unwrap()
                .operations[0]
                .query_continuation
                .is_none()
        );
    }
}

#[test]
fn operation_parameter_overrides_and_false_markers_disable_token_strategy() {
    let mut spec = marked_token_spec();
    let parameter = spec
        .pointer("/paths/~1items/get/parameters/0")
        .unwrap()
        .clone();
    spec.pointer_mut("/paths/~1items").unwrap()["parameters"] = json!([parameter]);
    spec.pointer_mut("/paths/~1items/get/parameters/0").unwrap()["x-ms-list-continuation-token"] =
        false.into();
    spec.pointer_mut(
        "/components/schemas/Page/allOf/0/properties/metadata/properties/resume~1key~0value",
    )
    .unwrap()["x-ms-list-continuation-token"] = false.into();
    assert!(
        ingest(&spec, "azure", "service", "official")
            .unwrap()
            .operations[0]
            .query_continuation
            .is_none()
    );
}

#[test]
fn large_unmarked_response_does_not_require_continuation_schema_traversal() {
    let properties: serde_json::Map<String, serde_json::Value> = (0..5000)
        .map(|index| (format!("field{index}"), json!({"type":"string"})))
        .collect();
    let spec = json!({"openapi":"3.0.0","servers":[{"url":"https://service.example"}],
        "paths":{"/items":{"get":{"operationId":"Items_List","responses":{"200":{
            "content":{"application/json":{"schema":{"type":"object","properties":properties}}}}}}}}});
    assert!(
        ingest(&spec, "azure", "service", "official")
            .unwrap()
            .operations[0]
            .query_continuation
            .is_none()
    );
}

#[test]
fn mixed_marked_catalog_preserves_large_unrelated_operations() {
    let mut spec = marked_token_spec();
    let properties: serde_json::Map<String, serde_json::Value> = (0..5000)
        .map(|index| (format!("field{index}"), json!({"type":"string"})))
        .collect();
    spec["components"]["schemas"]["Large"] = json!({"type":"object","properties":properties});
    spec["paths"]["/ordinary"] = json!({"get":{"operationId":"Ordinary_List","responses":{"200":{
        "content":{"application/json":{"schema":{"$ref":"#/components/schemas/Large"}}}}}}});
    let manifest = ingest(&spec, "azure", "service", "official").unwrap();
    assert_eq!(manifest.operations.len(), 2);
    assert_eq!(
        manifest
            .operations
            .iter()
            .filter(|operation| operation.query_continuation.is_some())
            .count(),
        1
    );
}

#[test]
fn fabric_leading_preview_notes_preserve_operation_maturity() {
    let mut spec = json!({"swagger":"2.0","info":{"version":"v1"},
        "host":"api.fabric.microsoft.com","basePath":"/v1/admin",
        "paths":{"/tenantsettings/update":{"post":{"operationId":"Tenants_Update",
        "description":"> [!NOTE]\n> This API is part of a Preview release and is provided for evaluation.",
        "responses":{}}}}});
    let manifest = ingest(&spec, "fabric", "admin", "official").unwrap();
    assert!(manifest.operations[0].preview);
    assert_eq!(
        manifest.operations[0].maturity,
        junction_core::ApiMaturity::Preview
    );
    // Descriptive mentions and unrelated notices do not declare maturity.
    for description in [
        "Returns preview configuration settings.",
        "> [!NOTE]\n> This API returns preview configuration settings.",
        "Stable API.\n> [!NOTE]\n> This API is part of a Preview release.",
    ] {
        spec["paths"]["/tenantsettings/update"]["post"]["description"] = description.into();
        assert!(
            !ingest(&spec, "fabric", "admin", "official")
                .unwrap()
                .operations[0]
                .preview
        );
    }
    spec["paths"]["/tenantsettings/update"]["post"]["description"] =
        "> [!NOTE]\n> This API is part of a Preview release.".into();
    assert!(
        !ingest(&spec, "graph", "graph", "official")
            .unwrap()
            .operations[0]
            .preview
    );
}

#[test]
fn malformed_maturity_markers_fail_without_echoing_source_values() {
    let mut spec = json!({"openapi":"3.0.3","info":{"version":"v1"},
        "servers":[{"url":"https://example.invalid"}],
        "paths":{"/items":{"get":{"operationId":"Items_List","responses":{}}}}});
    for marker in ["x-ms-preview", "deprecated"] {
        for invalid in [
            json!(null),
            json!("private-source-value"),
            json!(1),
            json!([]),
            json!({}),
        ] {
            spec["paths"]["/items"]["get"][marker] = invalid;
            let error = ingest(&spec, "fixture", "items", "official").unwrap_err();
            assert_eq!(error.to_string(), "invalid operation maturity marker");
        }
        spec["paths"]["/items"]["get"][marker] = false.into();
        let stable = ingest(&spec, "fixture", "items", "official").unwrap();
        assert!(!stable.operations[0].preview);
        assert_eq!(
            stable.operations[0].maturity,
            junction_core::ApiMaturity::Stable
        );
        spec["paths"]["/items"]["get"][marker] = true.into();
        let marked = ingest(&spec, "fixture", "items", "official").unwrap();
        assert_eq!(
            marked.operations[0].maturity,
            if marker == "deprecated" {
                junction_core::ApiMaturity::Deprecated
            } else {
                junction_core::ApiMaturity::Preview
            }
        );
        spec["paths"]["/items"]["get"]
            .as_object_mut()
            .unwrap()
            .remove(marker);
    }
}

#[test]
fn mutation_action_names_classify_post_deletion_and_keep_reads_read_only() {
    for action in [
        "DeleteItems",
        "RemoveAllSharingLinks",
        "BulkRemoveSharingLinks",
        "PurgeItems",
        "EraseItems",
        "DropItems",
        "TruncateItems",
    ] {
        let spec = json!({"swagger":"2.0","host":"api.fabric.microsoft.com","basePath":"/v1/admin",
            "paths":{"/items/action":{"post":{"operationId":format!("Items_{action}"),"responses":{}}}}});
        assert_eq!(
            ingest(&spec, "fabric", "admin", "official")
                .unwrap()
                .operations[0]
                .risk,
            OperationRisk::Destructive
        );
    }
    for (method, action, risk) in [
        ("get", "GetRemovedItems", OperationRisk::ReadOnly),
        ("post", "ListRemovedItems", OperationRisk::Write),
        ("post", "CreateItems", OperationRisk::Write),
        ("post", "RemovalStatus", OperationRisk::Write),
    ] {
        let mut spec = json!({"swagger":"2.0","host":"api.fabric.microsoft.com","paths":{}});
        spec["paths"]["/items/action"] =
            json!({method:{"operationId":format!("Items_{action}"),"responses":{}}});
        assert_eq!(
            ingest(&spec, "fabric", "admin", "official")
                .unwrap()
                .operations[0]
                .risk,
            risk
        );
    }
    let privileged = json!({"swagger":"2.0","host":"graph.microsoft.com",
        "paths":{"/conditionalAccess/policies/action":{"post":{"operationId":"Policies_DeleteAll","responses":{}}}}});
    assert_eq!(
        ingest(&privileged, "graph", "graph", "official")
            .unwrap()
            .operations[0]
            .risk,
        OperationRisk::Privileged
    );
}

#[test]
fn graph_dotted_actions_preserve_destructive_risk_after_naming() {
    for action in [
        "delete",
        "removeAllSharingLinks",
        "bulkRemoveSharingLinks",
        "purge",
    ] {
        let path = format!("/items/microsoft.graph.{action}");
        let mut spec = json!({"openapi":"3.0.3","servers":[{"url":"https://graph.microsoft.com/v1.0"}],"paths":{}});
        spec["paths"][&path] = json!({"post":{"operationId":format!("items.microsoft.graph.{action}"),"responses":{}}});
        let manifest = ingest(&spec, "graph", "graph", "official").unwrap();
        assert_eq!(manifest.operations[0].risk, OperationRisk::Destructive);
    }
    let spec = json!({"openapi":"3.0.3","servers":[{"url":"https://graph.microsoft.com/v1.0"}],
        "paths":{"/items/microsoft.graph.getRemovedItems":{"get":{"operationId":"items.microsoft.graph.getRemovedItems","responses":{}}}}});
    assert_eq!(
        ingest(&spec, "graph", "graph", "official")
            .unwrap()
            .operations[0]
            .risk,
        OperationRisk::ReadOnly
    );
}

#[test]
fn posture_changing_and_privilege_actions_require_approval_risk() {
    let spec = json!({"openapi":"3.0.0","servers":[{"url":"https://api.security.microsoft.com"}],"paths":{
        "/api/machines/{id}/isolate":{"post":{"operationId":"Machines_Isolate","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]}},
        "/api/machines/{id}/offboard":{"post":{"operationId":"Machines_Offboard","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]}},
        "/api/machines/{id}/runAntiVirusScan":{"post":{"operationId":"Machines_RunAntiVirusScan","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]}},
        "/providers/Microsoft.Authorization/roleAssignments/{id}":{
            "put":{"operationId":"RoleAssignments_Create","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]},
            "get":{"operationId":"RoleAssignments_Get","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}]}}
    }});
    let manifest = ingest(&spec, "defender", "endpoint", "official").unwrap();
    let risk = |id: &str| {
        serde_json::to_value(
            &manifest
                .operations
                .iter()
                .find(|op| op.id == id)
                .unwrap()
                .risk,
        )
        .unwrap()
    };
    assert_eq!(risk("defender.endpoint.machines.isolate"), "privileged");
    assert_eq!(risk("defender.endpoint.machines.offboard"), "destructive");
    assert_eq!(
        risk("defender.endpoint.machines.run_anti_virus_scan"),
        "write"
    );
    assert_eq!(
        risk("defender.endpoint.role_assignments.create"),
        "privileged"
    );
    assert_eq!(risk("defender.endpoint.role_assignments.get"), "read_only");
}
