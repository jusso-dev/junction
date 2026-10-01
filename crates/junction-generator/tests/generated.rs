use junction_generator::generate;
use junction_schema::CanonicalSchema;
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn emitted_module_compiles_and_preserves_presence_nullability_and_recursion() {
    let schemas = BTreeMap::from([
        ("#/components/schemas/User".into(), CanonicalSchema::normalize(&json!({"type":"object","additionalProperties":false,
            "properties":{"type":{"type":"string"},"state":{"type":"string","enum":["active","quote\"value", "\u{1}"]},
            "nickname":{"type":["string","null"]},"optional":{"type":["string","null"]},"child":{"$ref":"#/components/schemas/User"}},
            "required":["type","state","nickname"]})).unwrap()),
    ]);
    let module = generate(&schemas).unwrap();
    assert!(module.dynamic.is_empty());
    assert_eq!(module.source, generate(&schemas).unwrap().source);
    let user = &module.types["#/components/schemas/User"];
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("src")).unwrap();
    std::fs::write(directory.path().join("Cargo.toml"), "[package]\nname = \"junction-generated-check\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\n[dependencies]\nserde = { version = \"1\", features = [\"derive\"] }\nserde_json = \"1\"\n").unwrap();
    let main = format!(
        r##"
fn main() {{
    type User = {user};
    let good = serde_json::json!({{"type":"user","state":"active","nickname":null,"optional":null,"child":{{"type":"child","state":"active","nickname":"name"}}}});
    let value: User = serde_json::from_value(good.clone()).unwrap();
    assert_eq!(serde_json::to_value(value).unwrap(), good);
    for bad in [
        serde_json::json!({{"type":"user","state":"active"}}),
        serde_json::json!({{"type":null,"state":"active","nickname":null}}),
        serde_json::json!({{"type":"user","state":"invalid","nickname":null}}),
        serde_json::json!({{"type":"user","state":"active","nickname":null,"unexpected":1}}),
    ] {{ assert!(serde_json::from_value::<User>(bad).is_err()); }}
    let omitted = serde_json::json!({{"type":"user","state":"active","nickname":null}});
    let value: User = serde_json::from_value(omitted.clone()).unwrap();
    assert_eq!(serde_json::to_value(value).unwrap(), omitted);
    let metadata: serde_json::Value = serde_json::from_str(SCHEMAS_JSON).unwrap();
    assert!(metadata.get("#/components/schemas/User").is_some());
}}
"##
    );
    std::fs::write(
        directory.path().join("src/main.rs"),
        format!("#![allow(dead_code)]\n{}\n{main}", module.source),
    )
    .unwrap();
    let result = std::process::Command::new("cargo")
        .args(["run", "--offline", "--quiet", "--manifest-path"])
        .arg(directory.path().join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", directory.path().join("target"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
fn reference_closure_and_dynamic_composition_are_explicit() {
    let schemas = BTreeMap::from([(
        "#/A".into(),
        CanonicalSchema::normalize(&json!({"$ref":"#/missing"})).unwrap(),
    )]);
    assert!(generate(&schemas).is_err());
    assert!(generate(&BTreeMap::new()).is_err());
    let schemas = BTreeMap::from([(
        "#/A".into(),
        CanonicalSchema::normalize(&json!({"oneOf":[{"type":"string"},{"type":"integer"}]}))
            .unwrap(),
    )]);
    let module = generate(&schemas).unwrap();
    assert_eq!(module.dynamic.len(), 1);
    assert!(module.source.contains("serde_json::Value"));
}

#[test]
fn selected_generation_includes_recursive_reference_closure() {
    let schemas = BTreeMap::from([
        (
            "#/A".into(),
            CanonicalSchema::normalize(&json!({"type":"array","items":{"$ref":"#/B"}})).unwrap(),
        ),
        (
            "#/B".into(),
            CanonicalSchema::normalize(
                &json!({"type":"object","properties":{"parent":{"$ref":"#/A"}}}),
            )
            .unwrap(),
        ),
        (
            "#/unused".into(),
            CanonicalSchema::normalize(&json!({"type":"boolean"})).unwrap(),
        ),
    ]);
    let module = junction_generator::generate_selected(&schemas, &["#/A".into()]).unwrap();
    assert_eq!(module.types.len(), 2);
    assert!(!module.types.contains_key("#/unused"));
}
