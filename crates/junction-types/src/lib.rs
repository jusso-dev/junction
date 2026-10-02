//! Generated Rust/Serde types for common Microsoft Graph resources.
//!
//! Regenerated daily from Microsoft's published Graph OpenAPI definitions by
//! `scripts/update-catalogs.sh` (`generators/graph/common-schema-names.txt`
//! selects the roots; referenced types are included automatically). Types that
//! cannot be represented faithfully fall back to `serde_json::Value`, and
//! `graph::SCHEMAS_JSON` retains the full constraints for validation.
//!
//! Junction is independent of Microsoft; see DISCLAIMER.md.
#![allow(clippy::all, non_camel_case_types, dead_code)]

pub mod graph {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../generated/types/graph-common.rs"
    ));
}

#[cfg(test)]
mod tests {
    #[test]
    fn common_graph_resources_deserialize() {
        let user: super::graph::User = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "displayName": "Example",
            "businessPhones": []
        }))
        .unwrap();
        let value = serde_json::to_value(&user).unwrap();
        assert_eq!(value["displayName"], "Example");
        assert!(super::graph::SCHEMAS_JSON.len() > 1000);
    }
}
