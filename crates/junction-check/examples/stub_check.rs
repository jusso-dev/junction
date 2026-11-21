//! Registering a check: metadata, an async evaluation and tags (data, not code).
use junction_check::{check::*, model::*, *};
use std::sync::Arc;

#[rustfmt::skip]
const META: CheckMeta = CheckMeta {
    id: "identity.example_users_exist", title: "The tenant has users", pack: Pack::Identity,
    kind: CheckKind::Automated, severity: Severity::Low, effort: Level::Low, impact: Level::Low,
    description: "Lists users.", remediation: "Create a user.", links: &[], references: &[], manual: None,
    requires: Requirements { apis: &[ApiRequirement { operation: "graph.users.list", permissions: &["User.Read.All"] }], licences: &[] },
};

async fn evaluate(ctx: &CheckContext) -> Evaluation {
    let users = ctx
        .list_with("graph.users.list", serde_json::json!({"$top": 1}))
        .await?;
    Ok(Finding::pass_if(
        !users.is_empty(),
        "Users found.",
        "No users.",
    ))
}
junction_check::check!(UsersExist, &META, evaluate);

fn main() -> anyhow::Result<()> {
    let tags = "identity.example_users_exist: {mitre: [T1078]}";
    let registry = CheckRegistry::new(vec![Arc::new(UsersExist)], &[("example", tags)])?;
    println!("registered {}", registry.all()[0].id());
    Ok(())
}
