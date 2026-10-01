use crate::{Session, ToolResult, error};
use serde_json::{Value, json};
use std::{future::Future, pin::Pin};
pub enum Incoming {
    Message(Value),
    ParseError,
}

/// One active host call; control messages stay responsive. Dropping a future
/// never promises that a request already sent to Microsoft is rolled back.
pub async fn serve_messages<F, Fut, W>(
    mut incoming: tokio::sync::mpsc::Receiver<anyhow::Result<Incoming>>,
    mut call: F,
    mut send: W,
) -> anyhow::Result<()>
where
    F: FnMut(String, Value) -> Fut,
    Fut: Future<Output = ToolResult>,
    W: FnMut(Value) -> anyhow::Result<()>,
{
    let mut session = Session::default();
    let mut active: Option<(Value, Pin<Box<Fut>>)> = None;
    let mut open = true;
    loop {
        if !open && active.is_none() {
            break;
        }
        tokio::select! {
            biased;
            result = async {active.as_mut().expect("active call").1.as_mut().await}, if active.is_some() => {
                let (id,_) = active.take().expect("completed call");
                send(json!({"jsonrpc":"2.0","id":id,"result":result.into_value()}))?;
            }
            frame = incoming.recv(), if open => {
                let Some(frame) = frame else {open=false;continue};
                let message = match frame? {
                    Incoming::Message(message) => message,
                    Incoming::ParseError => {send(Session::parse_error())?;continue;}
                };
                if message.get("jsonrpc") == Some(&json!("2.0")) && message.get("id").is_none()
                    && message.get("method") == Some(&json!("notifications/cancelled")) {
                    if active.as_ref().is_some_and(|(id,_)|message.pointer("/params/requestId")==Some(id)) {active.take();}
                    continue;
                }
                match session.prepare(message) {
                    Err(Some(response)) => send(response)?,
                    Err(None) => {},
                    Ok(tool) => {
                        if active.is_some() {send(error(tool.id,-32000,"Server busy; retry after the active call finishes"))?;}
                        else {active=Some((tool.id,Box::pin(call(tool.name,tool.arguments))));}
                    }
                }
            }
        }
    }
    Ok(())
}
