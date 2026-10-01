use junction_mcp::{Incoming, ToolResult, serve_messages};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
struct Guard(Arc<AtomicBool>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
fn message(id: u64, method: &str, params: Value) -> anyhow::Result<Incoming> {
    Ok(Incoming::Message(
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
    ))
}
#[tokio::test]
async fn cancellation_drops_active_work_keeps_ping_responsive_and_releases_capacity() {
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    let (responses, mut output) = tokio::sync::mpsc::unbounded_channel();
    let started = Arc::new(tokio::sync::Notify::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let started_host = started.clone();
    let dropped_host = dropped.clone();
    let driver = tokio::spawn(serve_messages(
        receiver,
        move |_, args| {
            let started = started_host.clone();
            let dropped = dropped_host.clone();
            async move {
                if args["query"] == "slow" {
                    let _guard = Guard(dropped);
                    started.notify_one();
                    std::future::pending::<()>().await;
                }
                ToolResult::success(json!({"matches":[]}))
            }
        },
        move |value| {
            responses.send(value).unwrap();
            Ok(())
        },
    ));
    sender
        .send(message(
            1,
            "initialize",
            json!({"protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"test","version":"1"}}),
        ))
        .await
        .unwrap();
    sender
        .send(Ok(Incoming::Message(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )))
        .await
        .unwrap();
    sender
        .send(message(
            2,
            "tools/call",
            json!({"name":"junction_search","arguments":{"query":"slow"}}),
        ))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    assert_eq!(output.recv().await.unwrap()["id"], 1);
    sender
        .send(Ok(Incoming::Message(
            json!({"jsonrpc":"2.0","method":"notifications/cancelled",
        "params":{"requestId":"2","reason":"private-cancellation-reason"}}),
        )))
        .await
        .unwrap();
    sender.send(message(3, "ping", json!({}))).await.unwrap();
    let ping = output.recv().await.unwrap();
    assert_eq!(ping["id"], 3);
    assert_eq!(ping["result"], json!({}));
    assert!(
        !dropped.load(Ordering::SeqCst),
        "mismatched cancellation ID must be ignored"
    );
    sender
        .send(message(
            4,
            "tools/call",
            json!({"name":"junction_search","arguments":{"query":"quick"}}),
        ))
        .await
        .unwrap();
    let busy = output.recv().await.unwrap();
    assert_eq!(busy["id"], 4);
    assert_eq!(busy["error"]["code"], -32000);
    sender
        .send(Ok(Incoming::Message(
            json!({"jsonrpc":"2.0","method":"notifications/cancelled",
        "params":{"requestId":2,"reason":"private-cancellation-reason"}}),
        )))
        .await
        .unwrap();
    sender
        .send(message(
            6,
            "tools/call",
            json!({"name":"junction_search","arguments":{"query":"quick"}}),
        ))
        .await
        .unwrap();
    drop(sender);
    let result = output.recv().await.unwrap();
    assert_eq!(result["id"], 6);
    assert_eq!(result["result"]["isError"], false);
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!result.to_string().contains("private"));
    tokio::time::timeout(std::time::Duration::from_secs(2), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        output.recv().await.is_none(),
        "cancelled requests must not emit a response"
    );
}
