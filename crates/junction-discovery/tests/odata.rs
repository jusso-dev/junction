use junction_discovery::odata;
use serde_json::json;

const XML: &[u8] = include_bytes!("fixtures/odata.xml");
#[test]
fn function_overloads_have_stable_names_and_ambiguous_signatures_are_rejected() {
    let xml = std::str::from_utf8(XML).unwrap().replace("<EntityContainer Name=\"Service\">",r#"
        <Function Name="Lookup"><Parameter Name="term" Type="Edm.String"/><ReturnType Type="Edm.Int32"/></Function>
        <Function Name="Lookup"><Parameter Name="year" Type="Edm.Int32"/><ReturnType Type="Edm.Int32"/></Function>
        <EntityContainer Name="Service"><FunctionImport Name="lookup" Function="self.Lookup"/>
    "#);
    for (product, prefix) in [
        ("graph", "graph.lookup"),
        ("purview", "purview.directory.lookup"),
    ] {
        let manifest = odata::ingest(
            xml.as_bytes(),
            product,
            "directory",
            "official-csdl",
            "https://example.invalid",
            "v1.0",
        )
        .unwrap();
        let registry = junction_registry::Registry::load(manifest).unwrap();
        for parameter in ["term", "year"] {
            let operation = registry
                .resolve(&format!("{prefix}.invoke_by_{parameter}"), None, false)
                .unwrap();
            assert_eq!(operation.method, "GET");
            assert_eq!(operation.path, format!("/lookup({parameter}=@{parameter})"));
            assert_eq!(
                operation.parameters[0].serialization.style.as_deref(),
                Some("odata")
            );
        }
    }
    let duplicate = xml.replace("Name=\"year\"", "Name=\"term\"");
    assert!(ingest(duplicate.as_bytes()).is_err());
}
fn ingest(bytes: &[u8]) -> anyhow::Result<junction_core::RegistryManifest> {
    odata::ingest(
        bytes,
        "graph",
        "directory",
        "official-csdl",
        "https://graph.microsoft.com/v1.0",
        "v1.0",
    )
}
#[test]
fn csdl_generates_deterministic_routes_and_preserves_schema_semantics() {
    let manifest = ingest(XML).unwrap();
    assert_eq!(
        serde_json::to_value(&manifest).unwrap(),
        serde_json::to_value(ingest(XML).unwrap()).unwrap()
    );
    assert_eq!(
        manifest
            .operations
            .iter()
            .map(|o| o.id.as_str())
            .collect::<Vec<_>>(),
        [
            "graph.me.get",
            "graph.me.manager.get",
            "graph.me.reports.list",
            "graph.reset.invoke",
            "graph.users.get",
            "graph.users.list",
            "graph.users.manager.get",
            "graph.users.reports.list"
        ]
    );
    let registry = junction_registry::Registry::load(manifest.clone()).unwrap();
    let list = registry.resolve("graph.users.list", None, false).unwrap();
    assert_eq!(list.method, "GET");
    assert_eq!(list.api_version.as_deref(), Some("v1.0"));
    assert_eq!(list.base_url, "https://graph.microsoft.com/v1.0");
    assert!(list.parameters.iter().any(|p| p.name == "$filter"));
    assert_eq!(list.required_permissions(), None);
    let schemas = &manifest.schemas["components"]["schemas"];
    let user = &schemas["Demo.User"];
    assert_eq!(user["description"], "User & account");
    assert_eq!(user["allOf"][0]["$ref"], "#/components/schemas/Demo.Base");
    let properties = &user["allOf"][1]["properties"];
    assert_eq!(properties["addresses"]["type"], "array");
    assert_eq!(
        properties["addresses"]["items"]["$ref"],
        "#/components/schemas/Demo.Address"
    );
    assert_eq!(properties["tags"]["items"]["anyOf"][0]["maxLength"], 5);
    assert_eq!(properties["tags"]["items"]["anyOf"][1]["type"], "null");
    assert_eq!(
        schemas["Demo.State"]["enum"],
        json!(["healthy", "degraded"])
    );
    let input = registry
        .input_schema("graph.reset.invoke", None, false)
        .unwrap();
    for invalid in [
        json!({"body":{"name":"ok"}}),
        json!({"body":{"name":"too-long-name","targets":[]}}),
        json!({"body":{"name":null,"targets":[]}}),
        json!({"body":{"name":"ok","targets":[],"private":true}}),
    ] {
        assert!(junction_schema::validate_json_schema(&input, &invalid).is_err());
    }
    junction_schema::validate_json_schema(&input, &json!({"body":{"name":"ok","targets":[]}}))
        .unwrap();
    let mut populated = json!({"body":{"name":"ok","targets":[{"id":"123e4567-e89b-12d3-a456-426614174000","state":"healthy","addresses":[{"city":"Canberra"}],"tags":["short",null]}]}});
    junction_schema::validate_json_schema(&input, &populated).unwrap();
    populated["body"]["targets"][0]["state"] = json!("unknown-state");
    assert!(junction_schema::validate_json_schema(&input, &populated).is_err());
    populated["body"]["targets"][0]["state"] = json!("healthy");
    populated["body"]["targets"][0]["tags"] = json!(["too-long"]);
    assert!(junction_schema::validate_json_schema(&input, &populated).is_err());
    let action = registry.resolve("graph.reset.invoke", None, false).unwrap();
    assert_eq!(action.method, "POST");
    assert_eq!(action.risk, junction_core::OperationRisk::Write);
    assert_eq!(
        action.responses["200"]["content"]["application/json"]["schema"]["properties"]["value"]["type"],
        "boolean"
    );
}
#[test]
fn csdl_api_version_gates_preview_independently_of_xml_format_version() {
    let manifest = odata::ingest(
        XML,
        "graph",
        "directory",
        "official-csdl",
        "https://graph.microsoft.com/beta",
        "beta",
    )
    .unwrap();
    let registry = junction_registry::Registry::load(manifest).unwrap();
    assert!(registry.resolve("graph.users.list", None, false).is_err());
    assert_eq!(
        registry
            .resolve("graph.users.list", None, true)
            .unwrap()
            .api_version
            .as_deref(),
        Some("beta")
    );
}
#[test]
fn csdl_rejects_unsafe_xml_and_ambiguous_metadata_without_echoing_values() {
    let xml = std::str::from_utf8(XML).unwrap();
    let invalid = [
        xml.replace("Version=\"4.0\"", "Version=\"3.0\""),
        xml.replace("Nullable=\"false\"", "Nullable=\"private-secret\""),
        xml.replace(
            "http://docs.oasis-open.org/odata/ns/edm\"",
            "https://private-secret.invalid/edm\"",
        ),
        xml.replace(
            "<EntityContainer Name=\"Service\">",
            "<EntityContainer Name=\"Service\" Extends=\"self.Other\">",
        ),
        xml.replace(
            "<Property Name=\"id\"",
            "<Property Name=\"id\" Name=\"private-secret\"",
        ),
        xml.replace(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<!DOCTYPE root [<!ENTITY private SYSTEM 'file:///private-secret'>]>",
        ),
        xml.replace("User &amp; account", "&private-secret;"),
        xml.replace("User &amp; account", "User &#0; account"),
        xml.replace("encoding=\"utf-8\"", "encoding=\"iso-8859-1\""),
        format!("{xml}{xml}"),
        xml.replace("</Schema>", "</PrivateSecret>"),
    ];
    for document in invalid {
        let error = ingest(document.as_bytes()).unwrap_err().to_string();
        assert!(!error.contains("private-secret"));
    }
    let deep = format!(
        "<edmx:Edmx Version='4.0' xmlns:edmx='http://docs.oasis-open.org/odata/ns/edmx'>{}{}</edmx:Edmx>",
        "<edmx:Reference>".repeat(130),
        "</edmx:Reference>".repeat(130)
    );
    assert!(ingest(deep.as_bytes()).is_err());
    for endpoint in [
        "http://example.invalid",
        "https://private-secret@example.invalid",
        "https://example.invalid?private-secret=x",
        "https://example.invalid#private-secret",
    ] {
        assert!(
            odata::ingest(XML, "graph", "directory", "official-csdl", endpoint, "v1.0").is_err()
        );
    }
}

#[test]
fn entity_keys_are_inherited_typed_and_composite_routes_are_deterministic() {
    let xml = std::str::from_utf8(XML).unwrap();
    let composite = xml.replace("<Key><PropertyRef Name=\"id\"/></Key>", "<Key><PropertyRef Name=\"region\"/><PropertyRef Name=\"id\"/></Key><Property Name=\"region\" Type=\"Edm.String\" Nullable=\"false\"/>");
    for (document, path, count) in [
        (xml, "/users(@id)", 1),
        (composite.as_str(), "/users(region=@region,id=@id)", 2),
    ] {
        for product in ["graph", "purview"] {
            let manifest = odata::ingest(
                document.as_bytes(),
                product,
                "directory",
                "official",
                "https://example.invalid",
                "v1.0",
            )
            .unwrap();
            let registry = junction_registry::Registry::load(manifest).unwrap();
            let id = if product == "graph" {
                "graph.users.get"
            } else {
                "purview.directory.users.get"
            };
            let operation = registry.resolve(id, None, false).unwrap();
            assert_eq!(operation.path, path);
            assert_eq!(operation.risk, junction_core::OperationRisk::ReadOnly);
            assert_eq!(
                operation.parameters.iter().filter(|p| p.required).count(),
                count
            );
            let key = operation
                .parameters
                .iter()
                .find(|p| p.name == "@id")
                .unwrap();
            assert_eq!(key.schema["format"], "uuid");
            assert_eq!(key.schema["x-junction-odata-literal"], "Edm.Guid");
            assert_eq!(
                operation.responses["200"]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/Demo.User"
            );
        }
    }
    for invalid in [
        xml.replace("<PropertyRef Name=\"id\"/>", "<PropertyRef Name=\"missing\"/>"),
        xml.replace("<PropertyRef Name=\"id\"/>", "<PropertyRef Name=\"id\"/><PropertyRef Name=\"id\"/>"),
        xml.replace("Type=\"Edm.Guid\" Nullable=\"false\"", "Type=\"Edm.Guid\" Nullable=\"true\""),
        xml.replace("<EntityType Name=\"Base\">", "<EntityType Name=\"Base\" BaseType=\"self.User\">"),
        xml.replace("<EntityType Name=\"User\" BaseType=\"self.Base\">", "<EntityType Name=\"User\" BaseType=\"self.Base\"><Key><PropertyRef Name=\"id\"/></Key>"),
    ] {
        assert!(ingest(invalid.as_bytes()).is_err());
    }
}

#[test]
fn key_read_restrictions_override_collection_reads_inline_and_external() {
    let xml = std::str::from_utf8(XML).unwrap();
    for external in [false, true] {
        for (collection, keyed) in [(false, true), (true, false), (false, false), (true, true)] {
            let annotation = format!(
                r#"<Annotation Term="Caps.ReadRestrictions"><Record><PropertyValue Property="Readable" Bool="{collection}"/><PropertyValue Property="ReadByKeyRestrictions"><Record><PropertyValue Property="Readable"><Bool>{keyed}</Bool></PropertyValue></Record></PropertyValue></Record></Annotation>"#
            );
            let document = if external {
                xml.replace("</Schema>", &format!(r#"<Annotations Target="self.Service/users">{annotation}</Annotations></Schema>"#))
            } else {
                xml.replace(
                    r#"<EntitySet Name="users" EntityType="self.User"/>"#,
                    &format!(
                        r#"<EntitySet Name="users" EntityType="self.User">{annotation}</EntitySet>"#
                    ),
                )
            };
            let registry =
                junction_registry::Registry::load(ingest(document.as_bytes()).unwrap()).unwrap();
            assert_eq!(
                registry.resolve("graph.users.list", None, false).is_ok(),
                collection
            );
            assert_eq!(
                registry.resolve("graph.users.get", None, false).is_ok(),
                keyed
            );
        }
    }
}

#[test]
fn non_indexable_entity_sets_keep_collection_reads_without_key_routes() {
    let xml = std::str::from_utf8(XML).unwrap().replace(r#"<EntitySet Name="users" EntityType="self.User"/>"#, r#"<EntitySet Name="users" EntityType="self.User"><Annotation Term="Caps.IndexableByKey" Bool="false"/></EntitySet>"#);
    let registry = junction_registry::Registry::load(ingest(xml.as_bytes()).unwrap()).unwrap();
    assert!(registry.resolve("graph.users.list", None, false).is_ok());
    assert!(registry.resolve("graph.users.get", None, false).is_err());
}

#[test]
fn navigation_reads_preserve_cardinality_inherited_keys_and_nullable_results() {
    for product in ["graph", "purview"] {
        let manifest = odata::ingest(
            XML,
            product,
            "directory",
            "official",
            "https://example.invalid",
            "v1.0",
        )
        .unwrap();
        let registry = junction_registry::Registry::load(manifest).unwrap();
        let prefix = if product == "graph" {
            "graph"
        } else {
            "purview.directory"
        };
        for root in ["users", "me"] {
            for (navigation, action, collection) in
                [("manager", "get", false), ("reports", "list", true)]
            {
                let operation = registry
                    .resolve(
                        &format!("{prefix}.{root}.{navigation}.{action}"),
                        None,
                        false,
                    )
                    .unwrap();
                let base = if root == "users" {
                    "/users(@id)"
                } else {
                    "/me"
                };
                assert_eq!(operation.path, format!("{base}/{navigation}"));
                assert_eq!(operation.method, "GET");
                assert_eq!(operation.risk, junction_core::OperationRisk::ReadOnly);
                assert_eq!(
                    operation.parameters.iter().filter(|p| p.required).count(),
                    usize::from(root == "users")
                );
                assert_eq!(operation.responses.get("204").is_some(), !collection);
                let schema = &operation.responses["200"]["content"]["application/json"]["schema"];
                if collection {
                    assert_eq!(
                        schema["properties"]["value"]["items"]["$ref"],
                        "#/components/schemas/Demo.User"
                    );
                    assert!(operation.parameters.iter().any(|p| p.name == "$top"));
                } else {
                    assert_eq!(schema["$ref"], "#/components/schemas/Demo.User");
                    assert!(!operation.parameters.iter().any(|p| p.name == "$top"));
                }
            }
        }
    }
    let xml = std::str::from_utf8(XML).unwrap();
    let inherited = xml.replace(r#"<NavigationProperty Name="manager" Type="self.User"/>"#, "").replace(r#"<EntityType Name="Base">"#, r#"<EntityType Name="Base"><NavigationProperty Name="manager" Type="self.User" Nullable="false"/>"#);
    let registry =
        junction_registry::Registry::load(ingest(inherited.as_bytes()).unwrap()).unwrap();
    assert!(
        registry
            .resolve("graph.users.manager.get", None, false)
            .unwrap()
            .responses
            .get("204")
            .is_none()
    );
    let hidden = xml.replace(r#"<NavigationProperty Name="manager" Type="self.User"/>"#, r#"<NavigationProperty Name="manager" Type="self.User"><Annotation Term="Caps.ReadRestrictions"><Record><PropertyValue Property="Readable" Bool="false"/></Record></Annotation></NavigationProperty>"#);
    let registry = junction_registry::Registry::load(ingest(hidden.as_bytes()).unwrap()).unwrap();
    assert!(
        registry
            .resolve("graph.users.manager.get", None, false)
            .is_err()
    );
    assert!(
        registry
            .resolve("graph.me.manager.get", None, false)
            .is_err()
    );
    assert!(
        registry
            .resolve("graph.users.reports.list", None, false)
            .is_ok()
    );
    for invalid in [
        xml.replace(r#"<NavigationProperty Name="manager" Type="self.User"/>"#, r#"<NavigationProperty Name="manager" Type="self.Address"/>"#),
        xml.replace(r#"<NavigationProperty Name="manager" Type="self.User"/>"#, r#"<NavigationProperty Name="manager" Type="self.Missing"/>"#),
        inherited.replace(r#"<EntityType Name="User" BaseType="self.Base">"#, r#"<EntityType Name="User" BaseType="self.Base"><NavigationProperty Name="manager" Type="self.User"/>"#),
    ] {
        assert!(ingest(invalid.as_bytes()).is_err());
    }
}

#[test]
fn external_navigation_annotations_follow_declaring_types_and_qualifiers() {
    let xml = std::str::from_utf8(XML).unwrap();
    for target in ["self.User/manager", "Demo.User/manager"] {
        let document = xml.replace("</Schema>", &format!(r#"<Annotations Target="{target}"><Annotation Term="Caps.ReadRestrictions"><Record><PropertyValue Property="Readable" Bool="false"/></Record></Annotation></Annotations></Schema>"#));
        let registry =
            junction_registry::Registry::load(ingest(document.as_bytes()).unwrap()).unwrap();
        assert!(
            registry
                .resolve("graph.users.manager.get", None, false)
                .is_err()
        );
        assert!(
            registry
                .resolve("graph.me.manager.get", None, false)
                .is_err()
        );
        assert!(
            registry
                .resolve("graph.users.reports.list", None, false)
                .is_ok()
        );
        assert!(registry.resolve("graph.users.get", None, false).is_ok());
        for qualified in [
            document.replace(
                &format!(r#"Target="{target}""#),
                &format!(r#"Target="{target}" Qualifier="Tablet""#),
            ),
            document.replace(
                r#"Term="Caps.ReadRestrictions""#,
                r#"Term="Caps.ReadRestrictions" Qualifier="Tablet""#,
            ),
        ] {
            let registry =
                junction_registry::Registry::load(ingest(qualified.as_bytes()).unwrap()).unwrap();
            assert!(
                registry
                    .resolve("graph.users.manager.get", None, false)
                    .is_ok()
            );
        }
    }
    let inherited = xml
        .replace(
            r#"<NavigationProperty Name="manager" Type="self.User"/>"#,
            "",
        )
        .replace(
            r#"<EntityType Name="Base">"#,
            r#"<EntityType Name="Base"><NavigationProperty Name="manager" Type="self.User"/>"#,
        );
    let inherited = inherited.replace("</Schema>", r#"<Annotations Target="self.Base/manager"><Annotation Term="Caps.ReadRestrictions"><Record><PropertyValue Property="Readable" Bool="false"/></Record></Annotation></Annotations></Schema>"#);
    let registry =
        junction_registry::Registry::load(ingest(inherited.as_bytes()).unwrap()).unwrap();
    assert!(
        registry
            .resolve("graph.users.manager.get", None, false)
            .is_err()
    );
    assert!(
        registry
            .resolve("graph.me.manager.get", None, false)
            .is_err()
    );
    let unsafe_expression = inherited.replace(
        r#"Bool="false"/></Record></Annotation></Annotations>"#,
        r#"Bool="private-secret"/></Record></Annotation></Annotations>"#,
    );
    assert!(
        !ingest(unsafe_expression.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("private-secret")
    );
}

#[test]
fn query_capabilities_shape_closed_inputs_and_required_filters() {
    let xml = std::str::from_utf8(XML).unwrap();
    let restrictions = r#"<Annotation Term="Caps.TopSupported" Bool="false"/><Annotation Term="Caps.SkipSupported"><Bool>false</Bool></Annotation><Annotation Term="Caps.SelectSupport"><Record><PropertyValue Property="Supported" Bool="false"/></Record></Annotation><Annotation Term="Caps.ExpandRestrictions"><Record><PropertyValue Property="Expandable" Bool="false"/></Record></Annotation><Annotation Term="Caps.FilterRestrictions"><Record><PropertyValue Property="Filterable" Bool="false"/></Record></Annotation><Annotation Term="Caps.SortRestrictions"><Record><PropertyValue Property="Sortable" Bool="false"/></Record></Annotation><Annotation Term="Caps.CountRestrictions"><Record><PropertyValue Property="Countable" Bool="false"/></Record></Annotation><Annotation Term="Caps.SearchRestrictions"><Record><PropertyValue Property="Searchable" Bool="false"/></Record></Annotation>"#;
    for external in [false, true] {
        let document = if external {
            xml.replace("</Schema>", &format!(r#"<Annotations Target="self.Service/users">{restrictions}</Annotations></Schema>"#))
        } else {
            xml.replace(
                r#"<EntitySet Name="users" EntityType="self.User"/>"#,
                &format!(
                    r#"<EntitySet Name="users" EntityType="self.User">{restrictions}</EntitySet>"#
                ),
            )
        };
        let registry =
            junction_registry::Registry::load(ingest(document.as_bytes()).unwrap()).unwrap();
        assert!(
            registry
                .resolve("graph.users.list", None, false)
                .unwrap()
                .parameters
                .is_empty()
        );
        assert_eq!(
            registry
                .resolve("graph.users.get", None, false)
                .unwrap()
                .parameters
                .len(),
            1
        );
        // Resource restrictions do not become unrelated navigation-property restrictions.
        assert!(
            registry
                .resolve("graph.users.reports.list", None, false)
                .unwrap()
                .parameters
                .iter()
                .any(|p| p.name == "$top")
        );
        let schema = registry
            .input_schema("graph.users.list", None, false)
            .unwrap();
        for option in ["$select", "$expand", "$filter", "$orderby", "$top", "$skip"] {
            assert!(
                junction_schema::validate_json_schema(&schema, &json!({"parameters":{option:"x"}}))
                    .is_err()
            );
        }
    }
    let required = xml.replace("</Schema>", r#"<Annotations Target="self.Service/users"><Annotation Term="Caps.FilterRestrictions"><Record><PropertyValue Property="RequiresFilter" Bool="true"/></Record></Annotation></Annotations></Schema>"#);
    let registry = junction_registry::Registry::load(ingest(required.as_bytes()).unwrap()).unwrap();
    let schema = registry
        .input_schema("graph.users.list", None, false)
        .unwrap();
    assert!(junction_schema::validate_json_schema(&schema, &json!({})).is_err());
    assert!(
        junction_schema::validate_json_schema(&schema, &json!({"parameters":{"$filter":""}}))
            .is_err()
    );
    junction_schema::validate_json_schema(
        &schema,
        &json!({"parameters":{"$filter":"name eq 'example'"}}),
    )
    .unwrap();
    assert!(
        registry
            .resolve("graph.users.get", None, false)
            .unwrap()
            .parameters
            .iter()
            .all(|p| p.name != "$filter")
    );
    assert!(
        registry
            .resolve("graph.me.get", None, false)
            .unwrap()
            .parameters
            .iter()
            .all(|p| !matches!(p.name.as_str(), "$filter" | "$orderby" | "$top" | "$skip"))
    );
    for invalid in [
        required.replace(r#"Property="RequiresFilter" Bool="true""#, r#"Property="RequiresFilter" Bool="private-secret""#),
        required.replace(r#"Property="RequiresFilter" Bool="true"/>"#, r#"Property="RequiresFilter" Bool="true"/><PropertyValue Property="Filterable" Bool="false"/>"#),
        required.replace(r#"Property="RequiresFilter" Bool="true"/>"#, r#"Property="RequiresFilter"><Path>private-secret</Path></PropertyValue>"#),
        required.replace(r#"Property="RequiresFilter" Bool="true"/>"#, r#"Property="RequiresFilter" Bool="true"/><PropertyValue Property="RequiresFilter" Bool="false"/>"#),
    ] {
        let error = ingest(invalid.as_bytes()).unwrap_err().to_string();
        assert!(!error.contains("private-secret"));
    }
    let nav = xml.replace("</Schema>", r#"<Annotations Target="self.User/reports"><Annotation Term="Caps.TopSupported" Bool="false"/></Annotations></Schema>"#);
    let registry = junction_registry::Registry::load(ingest(nav.as_bytes()).unwrap()).unwrap();
    for id in ["graph.users.reports.list", "graph.me.reports.list"] {
        assert!(
            registry
                .resolve(id, None, false)
                .unwrap()
                .parameters
                .iter()
                .all(|p| p.name != "$top")
        );
    }
}

#[test]
fn count_and_search_queries_are_typed_collection_options_with_capability_gates() {
    let registry = junction_registry::Registry::load(ingest(XML).unwrap()).unwrap();
    for id in [
        "graph.users.list",
        "graph.users.reports.list",
        "graph.me.reports.list",
    ] {
        let schema = registry.input_schema(id, None, false).unwrap();
        let operation = registry.resolve(id, None, false).unwrap();
        let response_schema = &operation.responses["200"]["content"]["application/json"]["schema"];
        for count in [json!(2), json!("9223372036854775807")] {
            junction_schema::validate_with_definitions(
                response_schema,
                registry.schemas(),
                &json!({"value":[],"@odata.count":count}),
            )
            .unwrap();
        }
        for count in [json!(-1), json!(true), json!("-2"), json!("many")] {
            assert!(
                junction_schema::validate_with_definitions(
                    response_schema,
                    registry.schemas(),
                    &json!({"value":[],"@odata.count":count})
                )
                .is_err()
            );
        }
        let key = if id.starts_with("graph.users.reports") {
            json!({"@id":"123e4567-e89b-12d3-a456-426614174000"})
        } else {
            json!({})
        };
        for count in [json!(true), json!(false)] {
            let mut parameters = key.clone();
            parameters["$count"] = count;
            parameters["$search"] = json!("quoted & term");
            junction_schema::validate_json_schema(&schema, &json!({"parameters":parameters}))
                .unwrap();
        }
        for (name, value) in [
            ("$count", json!("true")),
            ("$count", json!(1)),
            ("$count", json!(null)),
            ("$search", json!(true)),
            ("$search", json!(["term"])),
        ] {
            let mut parameters = key.clone();
            parameters[name] = value;
            assert!(
                junction_schema::validate_json_schema(&schema, &json!({"parameters":parameters}))
                    .is_err()
            );
        }
    }
    for id in ["graph.users.get", "graph.me.get", "graph.users.manager.get"] {
        assert!(
            registry
                .resolve(id, None, false)
                .unwrap()
                .parameters
                .iter()
                .all(|p| !matches!(p.name.as_str(), "$count" | "$search"))
        );
    }
    let xml = std::str::from_utf8(XML).unwrap().replace("</Schema>", r#"<Annotations Target="self.User/reports"><Annotation Term="Caps.CountRestrictions"><Record><PropertyValue Property="Countable" Bool="false"/></Record></Annotation><Annotation Term="Caps.SearchRestrictions"><Record><PropertyValue Property="Searchable"><Bool>false</Bool></PropertyValue></Record></Annotation></Annotations></Schema>"#);
    let registry = junction_registry::Registry::load(ingest(xml.as_bytes()).unwrap()).unwrap();
    for id in ["graph.users.reports.list", "graph.me.reports.list"] {
        assert!(
            registry
                .resolve(id, None, false)
                .unwrap()
                .parameters
                .iter()
                .all(|p| !matches!(p.name.as_str(), "$count" | "$search"))
        );
    }
    assert!(
        registry
            .resolve("graph.users.list", None, false)
            .unwrap()
            .parameters
            .iter()
            .any(|p| p.name == "$count")
    );
}

#[test]
fn csdl_removal_actions_remain_destructive_even_with_neutral_import_aliases() {
    let xml = std::str::from_utf8(XML).unwrap().replace("<EntityContainer Name=\"Service\">", r#"
        <Action Name="BulkRemoveSharingLinks"/>
        <EntityContainer Name="Service"><ActionImport Name="executeCleanup" Action="self.BulkRemoveSharingLinks"/>
    "#);
    for product in ["graph", "purview"] {
        let manifest = odata::ingest(
            xml.as_bytes(),
            product,
            "directory",
            "official-csdl",
            "https://example.invalid",
            "v1.0",
        )
        .unwrap();
        let operation = manifest
            .operations
            .iter()
            .find(|op| op.path == "/executeCleanup")
            .unwrap();
        assert_eq!(operation.method, "POST");
        assert_eq!(operation.risk, junction_core::OperationRisk::Destructive);
        let unchanged = manifest
            .operations
            .iter()
            .find(|op| op.path == "/reset")
            .unwrap();
        assert_eq!(unchanged.risk, junction_core::OperationRisk::Write);
    }
}
