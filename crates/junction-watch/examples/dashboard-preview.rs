//! Synthetic, in-memory UI fixture. Never connects to Microsoft or sends email.
use junction_watch::{
    auth::{self, Role},
    clock::Instant,
    event, incidents,
    store::Store,
    upstream::{Api, CallError, FailureKind, Reply, Upstream},
    web,
};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use url::Url;
struct Offline;
impl Upstream for Offline {
    fn base(&self, _: Api) -> Url {
        Url::parse("https://example.invalid").unwrap()
    }
    fn tenant_id(&self) -> &str {
        "11111111-1111-4111-8111-111111111111"
    }
    async fn get(&self, _: Api, _: Url) -> Result<Reply, CallError> {
        Err(CallError::other(
            FailureKind::Transport,
            "synthetic fixture",
        ))
    }
    async fn post(&self, _: Api, _: Url, _: Option<serde_json::Value>) -> Result<Reply, CallError> {
        Err(CallError::other(
            FailureKind::Transport,
            "synthetic fixture",
        ))
    }
    async fn granted_roles(&self, _: Api) -> Result<Vec<String>, CallError> {
        Ok(vec![])
    }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let store = Store::in_memory("11111111-1111-4111-8111-111111111111")?;
    // Public fixture credential, valid only in this ephemeral loopback demo.
    auth::create_user(&store, "preview", "synthetic-preview-only", Role::Admin)?;
    let raw = json!({"Id":"fixture-forwarding","CreationTime":Instant::now().to_rfc3339(),"Operation":"Set-Mailbox","ResultStatus":"Success","ObjectId":"treasurer@club.example","UserId":"admin@club.example","Parameters":[{"Name":"ForwardingSmtpAddress","Value":"unknown@external.example"}]});
    let e =
        event::from_management_record(store.tenant_id(), "Audit.Exchange", &raw, Instant::now())
            .unwrap();
    store.insert_events(&[e])?;
    incidents::detect(&store, &Default::default())?;
    store.scheduled_reports(Instant::now())?;
    let state = Arc::new(web::AppState::<Offline> {
        store,
        upstream: None,
        tenant_domain: "club.example (synthetic preview)".into(),
        content_types: vec!["Audit.Exchange".into(), "Audit.SharePoint".into()],
        session_lifetime: Duration::from_secs(3600),
        allowed_hosts: vec!["127.0.0.1:18787".into(), "localhost:18787".into()],
        throttle: Default::default(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:18787").await?;
    axum::serve(listener, web::router(state))
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;
    Ok(())
}
