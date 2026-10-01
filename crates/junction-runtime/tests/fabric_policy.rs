use junction_core::{OperationRisk, RegistryManifest};
use junction_policy::{AgentMode, Decision, Policy};
use junction_registry::Registry;
use serde_json::json;

#[test]
fn imported_post_deletion_requires_approval_after_manifest_round_trip() {
    let spec = json!({"swagger":"2.0","info":{"version":"v1"},
        "host":"api.fabric.microsoft.com","basePath":"/v1/admin",
        "paths":{"/items/bulkRemoveSharingLinks":{"post":{
            "operationId":"SharingLinks_BulkRemoveSharingLinks",
            "responses":{"202":{"description":"Accepted"}},
            "x-ms-fabric-sdk-long-running-operation":true}}}});
    let manifest = junction_discovery::ingest(&spec, "fabric", "admin", "official").unwrap();
    let id = manifest.operations[0].id.clone();
    let encoded = serde_json::to_vec(&manifest).unwrap();
    let restored: RegistryManifest = serde_json::from_slice(&encoded).unwrap();
    let registry = Registry::load(restored).unwrap();
    let operation = registry.resolve(&id, None, false).unwrap();
    assert_eq!(operation.method, "POST");
    assert_eq!(operation.risk, OperationRisk::Destructive);
    for mode in [AgentMode::SafeWrite, AgentMode::Full] {
        let mut policy = Policy::default();
        policy.agent.mode = mode;
        let decision = policy.authorize_operation(operation, "customer-a");
        assert!(matches!(decision, Decision::ApprovalRequired { .. }));
        let failure = junction_runtime::prepare(
            operation,
            &json!({}),
            "customer-a",
            "https://api.fabric.microsoft.com",
            &policy,
        )
        .err()
        .unwrap();
        let structured: serde_json::Value = serde_json::to_value(
            &failure
                .downcast_ref::<junction_runtime::ExecutionDenied>()
                .unwrap()
                .0,
        )
        .unwrap();
        assert_eq!(structured["status"], "approval_required");
        assert_eq!(structured["operation"], id);
        policy.deny.operations.push(id.clone());
        assert!(matches!(
            policy.authorize_operation(operation, "customer-a"),
            Decision::PolicyRejected { .. }
        ));
    }
    assert!(matches!(
        Policy::default().authorize_operation(operation, "customer-a"),
        Decision::PolicyRejected { .. }
    ));
}

#[test]
fn neutral_csdl_alias_cannot_bypass_destructive_action_policy() {
    let xml = br#"<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
      <edmx:DataServices><Schema Namespace="Demo" xmlns="http://docs.oasis-open.org/odata/ns/edm">
        <Action Name="PurgeItems"/>
        <EntityContainer Name="Service"><ActionImport Name="run" Action="Demo.PurgeItems"/></EntityContainer>
      </Schema></edmx:DataServices></edmx:Edmx>"#;
    for product in ["graph", "purview"] {
        let manifest = junction_discovery::odata::ingest(
            xml,
            product,
            "directory",
            "official",
            "https://example.invalid",
            "v1.0",
        )
        .unwrap();
        let restored = serde_json::from_slice(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        let registry = Registry::load(restored).unwrap();
        let id = &manifest.operations[0].id;
        let operation = registry.resolve(id, None, false).unwrap();
        assert_eq!(operation.path, "/run");
        assert_eq!(operation.risk, OperationRisk::Destructive);
        let mut policy = Policy::default();
        policy.agent.mode = AgentMode::Full;
        let failure = junction_runtime::prepare(
            operation,
            &json!({"body":{}}),
            "customer-a",
            "https://example.invalid",
            &policy,
        )
        .err()
        .unwrap();
        assert!(matches!(
            failure
                .downcast_ref::<junction_runtime::ExecutionDenied>()
                .unwrap()
                .0,
            Decision::ApprovalRequired { .. }
        ));
    }
}
