use anyhow::Result;
use junction_mcp::ToolResult;
use junction_runtime::{ExecutionContext, Executor};
use serde_json::{Value, json};
use std::path::PathBuf;

pub struct Host {
    executor: Executor,
    policy: junction_policy::Policy,
    context: Option<Vec<u8>>,
    contexts: PathBuf,
    operations: PathBuf,
    pages: crate::mcp_pages::Store,
    http_call: tokio::sync::Mutex<()>,
}
impl Host {
    pub fn new(
        registry: junction_registry::Registry,
        policy: junction_policy::Policy,
        context: Option<Vec<u8>>,
        contexts: PathBuf,
        operations: PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            executor: Executor::new(registry, policy.clone())?,
            policy,
            context,
            contexts,
            operations,
            pages: crate::mcp_pages::Store::new()?,
            http_call: tokio::sync::Mutex::new(()),
        })
    }
    pub async fn serve(&self) -> Result<()> {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            loop {
                let frame = match junction_mcp::read_frame(&mut reader) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(error) => {
                        let _ = sender.blocking_send(Err(error));
                        break;
                    }
                };
                let incoming = match serde_json::from_slice(&frame) {
                    Ok(message) => junction_mcp::Incoming::Message(message),
                    Err(_) => junction_mcp::Incoming::ParseError,
                };
                if sender.blocking_send(Ok(incoming)).is_err() {
                    break;
                }
            }
        });
        let stdout = std::io::stdout();
        let mut writer = stdout.lock();
        junction_mcp::serve_messages(
            receiver,
            |name, args| self.call(name, args),
            |response| junction_mcp::write_response(&mut writer, &response),
        )
        .await
    }
    async fn call(&self, name: String, args: Value) -> ToolResult {
        match self.dispatch(&name, args).await {
            Ok(value) => ToolResult::success(value),
            Err(error) => safe_tool_error(&error),
        }
    }
    async fn dispatch(&self, name: &str, args: Value) -> Result<Value> {
        let registry = self.executor.registry();
        let operation = args["operation"].as_str().unwrap_or_default();
        let version = args["api_version"].as_str();
        let preview = args["allow_preview"].as_bool().unwrap_or(false);
        match name {
            "junction_search" => Ok(json!({"matches":registry.discover_filtered(
                args["query"].as_str().unwrap_or_default(),args["limit"].as_u64().unwrap_or(20) as usize,
                &junction_registry::SearchOptions { product:args["product"].as_str(),service:args["service"].as_str(),allow_preview:preview })})),
            "junction_describe" => {
                let mut description =
                    serde_json::to_value(registry.resolve(operation, version, preview)?)?;
                description["input_schema"] = registry.input_schema(operation, version, preview)?;
                description["required_permissions"] = serde_json::to_value(
                    registry
                        .permissions(operation, version, preview)?
                        .required_permissions,
                )?;
                Ok(description)
            }
            "junction_permissions" => Ok(serde_json::to_value(
                registry.permissions(operation, version, preview)?,
            )?),
            "junction_context" => match args["action"].as_str() {
                Some("list") => Ok(json!({"contexts":crate::context_store::list(&self.contexts)?})),
                Some("show") => {
                    let name = args["name"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("context name required"))?;
                    crate::validated_context(&crate::context_store::read(&self.contexts, name)?)
                }
                _ => anyhow::bail!("unknown context action"),
            },
            "junction_execute" => {
                let selected = registry.resolve(operation, version, preview)?;
                let context = self.config(selected)?;
                let mut input = args["input"].clone();
                crate::scope::apply(
                    selected,
                    &mut input,
                    None,
                    None,
                    (
                        context.subscription.as_deref(),
                        context.default_resource_group.as_deref(),
                    ),
                )?;
                self.executor.preflight(
                    operation,
                    &input,
                    &context.token_request.tenant,
                    &context.endpoint,
                    version,
                    preview,
                )?;
                let wait = args["wait"].as_bool().unwrap_or(false);
                let lro = selected.long_running.is_some();
                let all = args["all"].as_bool().unwrap_or(false);
                if (all && (wait || lro))
                    || (!all
                        && ["max_items", "max_pages", "continuation"]
                            .iter()
                            .any(|field| args.get(field).is_some()))
                {
                    anyhow::bail!("invalid pagination options");
                }
                let page_options = junction_runtime::PageOptions {
                    max_items: args["max_items"].as_u64().unwrap_or(100) as usize,
                    max_pages: args["max_pages"].as_u64().unwrap_or(5) as usize,
                    api_version: version.map(str::to_owned),
                    allow_preview: preview,
                };
                let mut page_state = if all {
                    self.executor.preflight_pages(
                        operation,
                        &input,
                        &context.token_request.tenant,
                        &context.endpoint,
                        &page_options,
                    )?;
                    Some(self.pages.prepare(args["continuation"].as_str())?)
                } else {
                    None
                };
                if wait && !lro {
                    anyhow::bail!("wait requires a declared LRO");
                }
                if lro {
                    crate::operation_store::prepare(&self.operations)?;
                }
                let token = crate::auth_cli::acquire(&context.token_request).await?;
                let execution = ExecutionContext {
                    tenant: &context.token_request.tenant,
                    audience: &context.token_request.audience,
                    endpoint: &context.endpoint,
                    token: &token,
                };
                if all {
                    let mut prepared = page_state.take().expect("pagination prepared");
                    let result = self
                        .executor
                        .execute_pages_resuming(
                            operation,
                            input,
                            execution,
                            page_options,
                            prepared.continuation.take(),
                        )
                        .await?;
                    self.pages.finish_page(prepared, result)
                } else if lro {
                    let handle = self
                        .executor
                        .start_lro(
                            operation,
                            input,
                            execution,
                            junction_runtime::lro::LroStartOptions {
                                api_version: version.map(str::to_owned),
                                allow_preview: preview,
                                max_polls: 100,
                            },
                        )
                        .await?;
                    crate::operation_store::save_initial(&self.operations, &handle)?;
                    if wait {
                        let id = handle.snapshot().operation_id.to_owned();
                        let mut stored =
                            crate::operation_store::LockedHandle::acquire(&self.operations, &id)?;
                        let path = stored.checkpoint_path();
                        let result = self
                            .executor
                            .wait_lro_checkpointed(
                                &mut stored.handle,
                                execution,
                                args["timeout_seconds"].as_u64().unwrap_or(300),
                                |handle| crate::operation_store::persist_at(&path, handle),
                            )
                            .await
                            .and_then(|snapshot| Ok(serde_json::to_value(snapshot)?));
                        stored.persist()?;
                        result
                    } else {
                        Ok(serde_json::to_value(handle.snapshot())?)
                    }
                } else {
                    let response = self
                        .executor
                        .execute(operation, input, execution, version, preview)
                        .await?;
                    Ok(
                        json!({"status":response.status,"body":response.body,"correlation":response.correlation}),
                    )
                }
            }
            "junction_batch" => {
                let request =
                    serde_json::from_value(args).map_err(|_| anyhow::anyhow!("invalid batch"))?;
                let mut plan =
                    junction_runtime::batch::BatchPlan::build(request, &self.policy.limits)?;
                let first = &plan.request.operations[0];
                let context = self.config(registry.resolve(
                    &first.operation,
                    first.api_version.as_deref(),
                    first.allow_preview,
                )?)?;
                for item in &mut plan.request.operations {
                    let selected = registry.resolve(
                        &item.operation,
                        item.api_version.as_deref(),
                        item.allow_preview,
                    )?;
                    let other = self.config(selected)?;
                    if serde_json::to_value(&other)? != serde_json::to_value(&context)? {
                        anyhow::bail!("batch context mismatch");
                    }
                    crate::scope::apply(
                        selected,
                        &mut item.input,
                        None,
                        None,
                        (
                            other.subscription.as_deref(),
                            other.default_resource_group.as_deref(),
                        ),
                    )?;
                }
                let plan =
                    junction_runtime::batch::BatchPlan::build(plan.request, &self.policy.limits)?;
                self.executor.preflight_batch(
                    &plan,
                    &context.token_request.tenant,
                    &context.endpoint,
                )?;
                let token = crate::auth_cli::acquire(&context.token_request).await?;
                Ok(serde_json::to_value(
                    self.executor
                        .execute_batch(
                            plan.request,
                            ExecutionContext {
                                tenant: &context.token_request.tenant,
                                audience: &context.token_request.audience,
                                endpoint: &context.endpoint,
                                token: &token,
                            },
                        )
                        .await?,
                )?)
            }
            _ => anyhow::bail!("unknown tool"),
        }
    }
    fn config(
        &self,
        operation: &junction_core::JunctionOperation,
    ) -> Result<crate::ExecutionConfig> {
        crate::load_execution_config(
            self.context
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("execution context required"))?,
            operation,
        )
    }
}
impl junction_server::HttpHost for Host {
    fn handle<'a>(
        &'a self,
        method: &'a str,
        target: &'a str,
        body: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = junction_server::HttpResponse> + Send + 'a>,
    > {
        Box::pin(junction_server::dispatch(
            self.executor.registry(),
            method,
            target,
            body,
            move |name, args| async move {
                // A continuation is consumed by one top-level call at a time. Batch
                // still uses the executor's independently bounded request concurrency.
                let _guard = match self.http_call.try_lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        return ToolResult::error(
                            json!({"status":"server_busy","reason":"A host tool call is already active"}),
                        );
                    }
                };
                self.call(name, args).await
            },
        ))
    }
}

fn safe_tool_error(error: &anyhow::Error) -> ToolResult {
    let safe = if let Some(busy) = error.downcast_ref::<crate::credential_lock::CredentialBusy>() {
        let mut value = busy.response();
        value["status"] = json!("credential_busy");
        value
    } else if error
        .downcast_ref::<junction_mcp::ResponseTooLarge>()
        .is_some()
    {
        json!({"status":"response_too_large","reason":"Reduce max_items or narrow API projections; an existing continuation remains usable."})
    } else if let Some(required) = error.downcast_ref::<crate::api_key::CredentialRequired>() {
        // Agents cannot supply keys; tell them what the operator must do.
        let mut value = serde_json::to_value(required)
            .unwrap_or_else(|_| json!({"error":"credential_required"}));
        value["status"] = json!("credential_required");
        value
    } else if let Some(denied) = error.downcast_ref::<junction_runtime::ExecutionDenied>() {
        serde_json::to_value(&denied.0).unwrap_or_else(|_| json!({"status":"policy_rejected"}))
    } else if let Some(timeout) = error.downcast_ref::<junction_runtime::lro::LroWaitTimeout>() {
        serde_json::to_value(timeout)
            .unwrap_or_else(|_| json!({"status":"operation_wait_timed_out"}))
    } else if let Some(auth) =
        error.downcast_ref::<junction_runtime::authorization::AuthorizationFailure>()
    {
        serde_json::to_value(auth).unwrap_or_else(|_| json!({"status":"authorization_failed"}))
    } else {
        json!({"status":"operation_failed","reason":"Operation or host configuration is invalid or unavailable; inspect the operation schema and configured context."})
    };
    ToolResult::error(safe)
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use junction_server::HttpHost;

    #[tokio::test]
    async fn credential_contention_is_retryable_in_mcp_and_http_without_echoing_errors() {
        let error = anyhow::Error::new(crate::credential_lock::CredentialBusy)
            .context("private-credential-details");
        let mcp = safe_tool_error(&error).into_value();
        assert_eq!(mcp["isError"], true);
        assert_eq!(mcp["structuredContent"]["status"], "credential_busy");
        assert_eq!(mcp["structuredContent"]["retryable"], true);
        assert!(!mcp.to_string().contains("private-credential-details"));
        let http = junction_server::dispatch(
            &registry(),
            "POST",
            "/v1/execute/graph.users.list",
            br#"{"input":{}}"#,
            |_, _| async { safe_tool_error(&error) },
        )
        .await;
        assert_eq!(http.status, 429);
        assert_eq!(http.body["status"], "credential_busy");
        assert_eq!(http.body["retryable"], true);
        let unknown = safe_tool_error(&anyhow::anyhow!("private-token-payload")).into_value();
        assert_eq!(unknown["structuredContent"]["status"], "operation_failed");
        assert!(!unknown.to_string().contains("private-token-payload"));
    }

    fn registry() -> junction_registry::Registry {
        let operations = [("list", "GET"), ("create", "POST"), ("delete", "DELETE")].into_iter().map(|(action, method)| json!({
            "id":format!("graph.users.{action}"),"product":"graph","service":"users","resource":"users",
            "operation":action,"description":"User operation","method":method,"base_url":"https://example.invalid",
            "path":"/users","parameters":[],"responses":{},"security":[],"risk":"read_only","preview":false,
            "source":{"id":"official","upstream":"official","operation_id":format!("Users_{action}")}
        })).collect::<Vec<_>>();
        junction_registry::Registry::load(
            serde_json::from_value(
                json!({"format_version":1,"schemas":{},"operations":operations}),
            )
            .unwrap(),
        )
        .unwrap()
    }
    #[tokio::test]
    async fn http_uses_real_registry_context_and_policy_before_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let context = serde_json::to_vec(&json!({"endpoint":"https://example.invalid","token_request":{
            "tenant":"tenant-a","authority":"https://login.example.invalid","audience":"https://example.invalid",
            "scopes":[],"credential_profile":"environment","flow":"client_credentials"}})).unwrap();
        for (mode, operation, expected) in [
            ("read-only", "create", "policy_rejected"),
            ("full", "delete", "approval_required"),
        ] {
            let host = Host::new(
                registry(),
                junction_policy::Policy::parse(&format!("[agent]\nmode = '{mode}'\n")).unwrap(),
                Some(context.clone()),
                directory.path().join("contexts"),
                directory.path().join("operations"),
            )
            .unwrap();
            let denied = host
                .handle(
                    "POST",
                    &format!("/v1/execute/graph.users.{operation}"),
                    br#"{"input":{}}"#,
                )
                .await;
            assert_eq!(denied.status, 403);
            assert_eq!(denied.body["status"], expected);
            let batch = host.handle("POST","/v1/batch",format!(r#"{{"operations":[{{"id":"one","operation":"graph.users.{operation}","input":{{}}}}]}}"#).as_bytes()).await;
            assert_eq!(batch.status, 403);
            assert_eq!(batch.body["status"], expected);
            let description = host
                .handle("GET", "/v1/operations/graph.users.list", &[])
                .await;
            assert_eq!(description.status, 200);
            assert!(description.body["input_schema"].is_object());
            assert_eq!(
                host.handle("GET", "/v1/contexts", &[]).await.body,
                json!({"contexts":[]})
            );
            let guard = host.http_call.lock().await;
            assert_eq!(host.handle("GET", "/health", &[]).await.status, 200);
            assert_eq!(
                host.handle("GET", "/v1/operations?limit=1", &[]).await.body["operations"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                host.handle("GET", "/v1/permissions/graph.users.list", &[])
                    .await
                    .status,
                429
            );
            drop(guard);
            assert_eq!(
                host.handle("GET", "/v1/permissions/graph.users.list", &[])
                    .await
                    .status,
                200
            );
        }
    }
}
