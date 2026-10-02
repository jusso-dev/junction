//! Azure async status normalization. Response bodies are never stored in progress metadata.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
mod checkpoint;
use serde_json::Value;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Running,
    Succeeded,
    Failed,
    Canceled,
}
impl OperationState {
    pub fn is_terminal(self) -> bool {
        self != Self::Running
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PollProtocol {
    AzureAsyncOperation,
    OperationLocation,
    Location,
    Resource,
    FabricLocation,
}

/// Azure-AsyncOperation/Operation-Location require explicit status. Resource polling
/// uses provisioningState; Location polling can finish with an empty 200/204 response.
pub fn state_from_response(
    protocol: PollProtocol,
    status: u16,
    body: &Value,
) -> Result<OperationState> {
    if !(200..300).contains(&status) {
        bail!("long-running status request failed");
    }
    let marker = match protocol {
        PollProtocol::AzureAsyncOperation
        | PollProtocol::OperationLocation
        | PollProtocol::FabricLocation => body.get("status"),
        PollProtocol::Location | PollProtocol::Resource => body
            .pointer("/properties/provisioningState")
            .or_else(|| body.get("provisioningState")),
    };
    if let Some(marker) = marker {
        let marker = marker
            .as_str()
            .filter(|value| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            })
            .ok_or_else(|| anyhow::anyhow!("invalid long-running operation state"))?;
        return Ok(match marker.to_ascii_lowercase().as_str() {
            "succeeded" => OperationState::Succeeded,
            "failed" => OperationState::Failed,
            "canceled" | "cancelled" => OperationState::Canceled,
            _ => OperationState::Running,
        });
    }
    if matches!(
        protocol,
        PollProtocol::AzureAsyncOperation
            | PollProtocol::OperationLocation
            | PollProtocol::FabricLocation
    ) {
        bail!("long-running status response is missing state");
    }
    if status == 202 {
        Ok(OperationState::Running)
    } else {
        Ok(OperationState::Succeeded)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationProgress {
    pub state: OperationState,
    pub polls: usize,
}
/// Terminal states are absorbing; malformed responses do not advance state.
pub struct LroTracker {
    protocol: PollProtocol,
    progress: OperationProgress,
    max_polls: usize,
}
impl LroTracker {
    pub fn new(protocol: PollProtocol, max_polls: usize) -> Result<Self> {
        if !(1..=10_000).contains(&max_polls) {
            bail!("long-running poll limit must be between 1 and 10000");
        }
        Ok(Self {
            protocol,
            progress: OperationProgress {
                state: OperationState::Running,
                polls: 0,
            },
            max_polls,
        })
    }
    pub fn progress(&self) -> OperationProgress {
        self.progress
    }
    pub fn observe(&mut self, status: u16, body: &Value) -> Result<OperationProgress> {
        if self.progress.state.is_terminal() {
            return Ok(self.progress);
        }
        self.reserve_poll()?;
        self.accept(status, body)
    }
    fn reserve_poll(&mut self) -> Result<()> {
        if self.progress.polls >= self.max_polls {
            bail!("long-running poll limit exceeded");
        }
        self.progress.polls += 1;
        Ok(())
    }
    fn accept(&mut self, status: u16, body: &Value) -> Result<OperationProgress> {
        self.progress.state = state_from_response(self.protocol, status, body)?;
        Ok(self.progress)
    }
}

#[derive(Clone)]
pub struct LroStartOptions {
    pub api_version: Option<String>,
    pub allow_preview: bool,
    pub max_polls: usize,
}
impl Default for LroStartOptions {
    fn default() -> Self {
        Self {
            api_version: None,
            allow_preview: false,
            max_polls: 100,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct OperationSnapshot<'a> {
    pub operation_id: &'a str,
    pub operation: &'a str,
    pub state: OperationState,
    pub polls: usize,
}
/// Local waiting expired; the remote operation may still be running.
#[derive(Debug, Serialize)]
pub struct LroWaitTimeout {
    pub status: &'static str,
    pub operation_id: String,
    pub operation: String,
    pub state: OperationState,
    pub polls: usize,
}
impl std::fmt::Display for LroWaitTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.status)
    }
}
impl std::error::Error for LroWaitTimeout {}
/// Safe final-result diagnostics: no service body, URL or credential data.
#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum LroResultError {
    #[serde(rename = "operation_not_succeeded")]
    NotSucceeded,
    #[serde(rename = "operation_result_unavailable")]
    MissingBinding,
    #[serde(rename = "operation_result_not_succeeded")]
    FinalNotSucceeded,
}
impl std::fmt::Display for LroResultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotSucceeded => "long-running operation has not succeeded",
            Self::MissingBinding => "operation checkpoint has no final result binding",
            Self::FinalNotSucceeded => "long-running final result is not succeeded",
        })
    }
}
impl std::error::Error for LroResultError {}
/// Trusted runtime handle. Sensitive bindings serialize only to private checkpoints.
pub struct LroHandle {
    operation_id: String,
    operation: String,
    version: Option<String>,
    allow_preview: bool,
    tenant: String,
    audience: String,
    endpoint: String,
    poll_url: Url,
    final_target: Option<(Url, PollProtocol)>,
    tracker: LroTracker,
    ready_at: Instant,
}
impl LroHandle {
    pub fn api_version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    pub fn allows_preview(&self) -> bool {
        self.allow_preview
    }
    pub fn snapshot(&self) -> OperationSnapshot<'_> {
        OperationSnapshot {
            operation_id: &self.operation_id,
            operation: &self.operation,
            state: self.tracker.progress.state,
            polls: self.tracker.progress.polls,
        }
    }
    pub fn retry_after(&self) -> Duration {
        self.ready_at.saturating_duration_since(Instant::now())
    }
    fn from_initial(
        operation: &junction_core::JunctionOperation,
        response: &junction_http::HttpResponse,
        original: Url,
        context: crate::ExecutionContext<'_>,
        options: &LroStartOptions,
    ) -> Result<Self> {
        let links = &response.async_links;
        let fabric = operation
            .long_running
            .as_ref()
            .is_some_and(|metadata| metadata.protocol == Some(junction_core::LroProtocol::Fabric));
        let target = if fabric {
            links
                .location()
                .or_else(|| links.fabric_operation())
                .map(|url| (PollProtocol::FabricLocation, url))
        } else {
            links
                .azure_async_operation()
                .map(|url| (PollProtocol::AzureAsyncOperation, url))
                .or_else(|| {
                    links
                        .operation_location()
                        .map(|url| (PollProtocol::OperationLocation, url))
                })
                .or_else(|| links.location().map(|url| (PollProtocol::Location, url)))
        };
        let mut state = state_from_response(
            if response.body.get("status").is_some() {
                PollProtocol::AzureAsyncOperation
            } else {
                PollProtocol::Resource
            },
            response.status,
            &response.body,
        )?;
        if !fabric
            && response.status == 201
            && target.is_some()
            && response.body.get("status").is_none()
            && response.body.get("provisioningState").is_none()
            && response
                .body
                .pointer("/properties/provisioningState")
                .is_none()
        {
            state = OperationState::Running;
        }
        let (protocol, poll_url) = if let Some((protocol, url)) = target {
            (protocol, url.clone())
        } else if state.is_terminal() || matches!(operation.method.as_str(), "PUT" | "PATCH") {
            (PollProtocol::Resource, original.clone())
        } else {
            bail!("long-running operation has no safe polling endpoint");
        };
        if poll_url.origin() != original.origin()
            || poll_url.scheme() != "https"
            || !poll_url.username().is_empty()
            || poll_url.password().is_some()
            || poll_url.fragment().is_some()
        {
            bail!("invalid long-running polling endpoint");
        }
        // Keep a usable polling handle even when a service omits its declared
        // final-result header. Retrieval then fails without losing operation state.
        let final_target = final_target(operation, links, &original, &poll_url, protocol).ok();
        let mut tracker = LroTracker::new(protocol, options.max_polls)?;
        tracker.progress.state = state;
        let ready_at = Instant::now()
            .checked_add(response.retry_after.unwrap_or(Duration::from_secs(1)))
            .ok_or_else(|| anyhow::anyhow!("invalid long-running retry delay"))?;
        Ok(Self {
            operation_id: response
                .correlation
                .client_request_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing operation correlation identifier"))?,
            operation: operation.id.clone(),
            version: operation.api_version.clone(),
            allow_preview: options.allow_preview,
            tenant: context.tenant.to_ascii_lowercase(),
            audience: context.audience.into(),
            endpoint: context.endpoint.into(),
            poll_url,
            final_target,
            tracker,
            ready_at,
        })
    }
    fn validate_context(&self, context: crate::ExecutionContext<'_>) -> Result<()> {
        if !self.tenant.eq_ignore_ascii_case(context.tenant)
            || self.audience != context.audience
            || self.endpoint != context.endpoint
        {
            bail!("long-running operation context mismatch");
        }
        Ok(())
    }
}
/// Final-state hints affect POST result retrieval, not the status polling protocol.
fn final_target(
    operation: &junction_core::JunctionOperation,
    links: &junction_http::AsyncLinks,
    original: &Url,
    poll_url: &Url,
    protocol: PollProtocol,
) -> Result<(Url, PollProtocol)> {
    if operation
        .long_running
        .as_ref()
        .is_some_and(|metadata| metadata.protocol == Some(junction_core::LroProtocol::Fabric))
    {
        bail!("Fabric result target requires the completed operation response");
    }
    use junction_core::LroFinalStateVia;
    let hint = if operation.method == "POST" {
        operation
            .long_running
            .as_ref()
            .and_then(|metadata| metadata.final_state_via)
    } else {
        None
    };
    let (url, protocol) = match hint {
        Some(LroFinalStateVia::OriginalUri) => (original, PollProtocol::Resource),
        Some(LroFinalStateVia::Location) => (
            links
                .location()
                .ok_or_else(|| anyhow::anyhow!("missing long-running final location"))?,
            PollProtocol::Location,
        ),
        Some(LroFinalStateVia::AzureAsyncOperation) => (
            links
                .azure_async_operation()
                .ok_or_else(|| anyhow::anyhow!("missing long-running final status endpoint"))?,
            PollProtocol::AzureAsyncOperation,
        ),
        Some(LroFinalStateVia::OperationLocation) => (
            links
                .operation_location()
                .ok_or_else(|| anyhow::anyhow!("missing long-running final status endpoint"))?,
            PollProtocol::OperationLocation,
        ),
        None if matches!(operation.method.as_str(), "PUT" | "PATCH") => {
            (original, PollProtocol::Resource)
        }
        None if operation.method == "POST" && links.location().is_some() => {
            (links.location().unwrap(), PollProtocol::Location)
        }
        None => (poll_url, protocol),
    };
    if url.scheme() != "https"
        || url.origin() != original.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("invalid long-running final endpoint");
    }
    Ok((url.clone(), protocol))
}
impl crate::Executor {
    /// Fetch the result of a succeeded operation under current policy and credentials.
    /// This is an explicit GET; bodies are returned to the caller, never checkpointed.
    pub async fn final_lro_result(
        &self,
        handle: &LroHandle,
        context: crate::ExecutionContext<'_>,
    ) -> Result<junction_http::HttpResponse> {
        let operation = self.authorize_lro(handle, context)?;
        if handle.tracker.progress.state != OperationState::Succeeded {
            return Err(LroResultError::NotSucceeded.into());
        }
        let (url, protocol) = handle
            .final_target
            .as_ref()
            .ok_or(LroResultError::MissingBinding)?;
        let response = self
            .transport
            .send_with_headers_retries(
                "GET",
                url.clone(),
                None,
                Some(&context.token.credential()),
                &junction_http::RequestHeaders::new(),
            )
            .await
            .map_err(|error| crate::authorization::enrich(error, operation, context))?;
        if state_from_response(*protocol, response.status, &response.body)?
            != OperationState::Succeeded
        {
            return Err(LroResultError::FinalNotSucceeded.into());
        }
        Ok(response)
    }
    /// Recheck a saved handle's bindings and policy before acquiring credentials.
    pub fn preflight_lro(
        &self,
        handle: &LroHandle,
        tenant: &str,
        audience: &str,
        endpoint: &str,
    ) -> Result<()> {
        if !handle.tenant.eq_ignore_ascii_case(tenant)
            || handle.audience != audience
            || handle.endpoint != endpoint
        {
            bail!("long-running operation context mismatch");
        }
        let operation = self.registry.resolve(
            &handle.operation,
            handle.version.as_deref(),
            handle.allow_preview,
        )?;
        crate::enforce(self.policy.authorize_operation(operation, tenant))?;
        if operation.long_running.is_none() {
            bail!("operation no longer declares long-running support");
        }
        Ok(())
    }
    fn authorize_lro<'a>(
        &'a self,
        handle: &LroHandle,
        context: crate::ExecutionContext<'_>,
    ) -> Result<&'a junction_core::JunctionOperation> {
        handle.validate_context(context)?;
        self.preflight_lro(handle, context.tenant, context.audience, context.endpoint)?;
        let operation = self.registry.resolve(
            &handle.operation,
            handle.version.as_deref(),
            handle.allow_preview,
        )?;
        // Status polls are reads of an operation that was already started. A
        // trusted approval covered the start; deny rules and read-only mode
        // still stop polling.
        match self.policy.authorize_operation(operation, context.tenant) {
            junction_policy::Decision::ApprovalRequired { .. } => {}
            decision => crate::enforce(decision)?,
        }
        crate::validate_credential(context)?;
        if operation.long_running.is_none() {
            bail!("operation no longer declares long-running support");
        }
        Ok(operation)
    }
    /// Deadline covers polling delays and every status request/retry. Timing out
    /// does not cancel the remote operation or reset the trusted handle.
    pub async fn wait_lro<'a>(
        &self,
        handle: &'a mut LroHandle,
        context: crate::ExecutionContext<'_>,
        timeout_seconds: u64,
    ) -> Result<OperationSnapshot<'a>> {
        self.wait_lro_checkpointed(handle, context, timeout_seconds, |_| Ok(()))
            .await
    }
    /// Persist each poll reservation before transport and each observed result.
    /// A failed checkpoint stops polling; callbacks must never expose private URLs.
    pub async fn wait_lro_checkpointed<'a>(
        &self,
        handle: &'a mut LroHandle,
        context: crate::ExecutionContext<'_>,
        timeout_seconds: u64,
        mut checkpoint: impl FnMut(&LroHandle) -> Result<()>,
    ) -> Result<OperationSnapshot<'a>> {
        if !(1..=3600).contains(&timeout_seconds) {
            bail!("long-running wait timeout must be between 1 and 3600 seconds");
        }
        self.authorize_lro(handle, context)?;
        let waiting = async {
            while !handle.tracker.progress.state.is_terminal() {
                tokio::time::sleep(handle.retry_after()).await;
                self.poll_lro_checkpointed(handle, context, &mut checkpoint)
                    .await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        match tokio::time::timeout(Duration::from_secs(timeout_seconds), waiting).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(LroWaitTimeout {
                    status: "operation_wait_timed_out",
                    operation_id: handle.operation_id.clone(),
                    operation: handle.operation.clone(),
                    state: handle.tracker.progress.state,
                    polls: handle.tracker.progress.polls,
                }
                .into());
            }
        }
        Ok(handle.snapshot())
    }
    pub async fn start_lro(
        &self,
        operation: &str,
        input: Value,
        context: crate::ExecutionContext<'_>,
        options: LroStartOptions,
    ) -> Result<LroHandle> {
        LroTracker::new(PollProtocol::Resource, options.max_polls)?;
        let selected = self.registry.resolve(
            operation,
            options.api_version.as_deref(),
            options.allow_preview,
        )?;
        if selected.long_running.is_none() {
            bail!("operation does not declare long-running support");
        }
        let request = crate::prepare_with_schemas(
            selected,
            &input,
            context.tenant,
            context.endpoint,
            &self.policy,
            self.registry.schemas(),
        )?;
        crate::validate_credential(context)?;
        let response = self
            .transport
            .send_with_headers_retries(
                &request.method,
                request.url.clone(),
                request.body.as_ref(),
                Some(&context.token.credential()),
                &request.headers,
            )
            .await
            .map_err(|error| crate::authorization::enrich(error, selected, context))?;
        LroHandle::from_initial(selected, &response, request.url, context, &options)
    }
    /// Start a declared long-running operation under a single-use trusted grant.
    pub async fn start_lro_with_approval(
        &self,
        operation: &str,
        input: Value,
        context: crate::ExecutionContext<'_>,
        options: LroStartOptions,
        approval: crate::ApprovedExecution<'_>,
    ) -> Result<LroHandle> {
        LroTracker::new(PollProtocol::Resource, options.max_polls)?;
        let endpoint = Url::parse(context.endpoint)
            .map_err(|_| anyhow::anyhow!("approval_context_mismatch"))?;
        if endpoint.as_str() != approval.context.endpoint()
            || context.audience != approval.context.audience()
        {
            bail!("approval_context_mismatch");
        }
        let selected = self.registry.resolve(
            operation,
            options.api_version.as_deref(),
            options.allow_preview,
        )?;
        if selected.long_running.is_none() {
            bail!("operation does not declare long-running support");
        }
        crate::enforce(self.policy.authorize_with_approval(
            selected,
            context.tenant,
            &input,
            approval.context,
            approval.grant,
        )?)?;
        let request = crate::prepare_authorized(
            selected,
            &input,
            approval.context.endpoint(),
            self.registry.schemas(),
        )?;
        crate::validate_credential(context)?;
        let response = self
            .transport
            .send_with_headers_retries(
                &request.method,
                request.url.clone(),
                request.body.as_ref(),
                Some(&context.token.credential()),
                &request.headers,
            )
            .await
            .map_err(|error| crate::authorization::enrich(error, selected, context))?;
        LroHandle::from_initial(selected, &response, request.url, context, &options)
    }
    /// One status request. Caller can wait retry_after() before invoking again.
    pub async fn poll_lro<'a>(
        &self,
        handle: &'a mut LroHandle,
        context: crate::ExecutionContext<'_>,
    ) -> Result<OperationSnapshot<'a>> {
        self.poll_lro_checkpointed(handle, context, |_| Ok(()))
            .await
    }
    pub async fn poll_lro_checkpointed<'a>(
        &self,
        handle: &'a mut LroHandle,
        context: crate::ExecutionContext<'_>,
        mut checkpoint: impl FnMut(&LroHandle) -> Result<()>,
    ) -> Result<OperationSnapshot<'a>> {
        let operation = self.authorize_lro(handle, context)?;
        if handle.tracker.progress.state.is_terminal() {
            return Ok(handle.snapshot());
        }
        if !handle.retry_after().is_zero() {
            bail!("long-running operation is not ready to poll");
        }
        handle.tracker.reserve_poll()?;
        // Persist a fallback delay with the reservation, so interruption or
        // transport failure cannot leave the checkpoint immediately pollable.
        handle.ready_at = Instant::now() + Duration::from_secs(1);
        checkpoint(handle)?;
        let response = self
            .transport
            .send_with_headers_retries(
                "GET",
                handle.poll_url.clone(),
                None,
                Some(&context.token.credential()),
                &junction_http::RequestHeaders::new(),
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                if let Some(delay) = error
                    .downcast_ref::<junction_http::HttpStatusError>()
                    .and_then(|status| status.retry_after)
                {
                    handle.ready_at = Instant::now()
                        .checked_add(delay)
                        .ok_or_else(|| anyhow::anyhow!("invalid long-running retry delay"))?;
                }
                checkpoint(handle)?;
                return Err(crate::authorization::enrich(error, operation, context));
            }
        };
        handle.ready_at = Instant::now()
            .checked_add(response.retry_after.unwrap_or(Duration::from_secs(1)))
            .ok_or_else(|| anyhow::anyhow!("invalid long-running retry delay"))?;
        let observed = handle.tracker.accept(response.status, &response.body);
        if observed.is_ok() && handle.tracker.protocol == PollProtocol::FabricLocation {
            handle.final_target = fabric_result_target(
                handle.tracker.progress.state,
                &handle.poll_url,
                &response.async_links,
            )?;
        }
        checkpoint(handle)?;
        observed?;
        Ok(handle.snapshot())
    }
}

fn fabric_result_target(
    state: OperationState,
    poll_url: &Url,
    links: &junction_http::AsyncLinks,
) -> Result<Option<(Url, PollProtocol)>> {
    if state != OperationState::Succeeded {
        return Ok(None);
    }
    let Some(url) = links.location() else {
        return Ok(None);
    };
    if url == poll_url {
        return Ok(None);
    }
    if url.origin() != poll_url.origin()
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("invalid Fabric operation result endpoint");
    }
    Ok(Some((url.clone(), PollProtocol::Location)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn fabric_result_location_is_selected_only_after_success() {
        let poll = Url::parse("https://api.fabric.microsoft.com/v1/operations/job").unwrap();
        let mut headers = junction_http::RequestHeaders::new();
        headers.insert("location", "/v1/operations/job/result".parse().unwrap());
        let links = junction_http::AsyncLinks::from_headers(&headers, &poll);
        for state in [
            OperationState::Running,
            OperationState::Failed,
            OperationState::Canceled,
        ] {
            assert!(
                fabric_result_target(state, &poll, &links)
                    .unwrap()
                    .is_none()
            );
        }
        let result = fabric_result_target(OperationState::Succeeded, &poll, &links)
            .unwrap()
            .unwrap();
        assert_eq!(result.0.path(), "/v1/operations/job/result");
        assert_eq!(result.1, PollProtocol::Location);
        for location in [
            "/v1/operations/job",
            "https://attacker.example/result",
            "http://api.fabric.microsoft.com/result",
            "/result#private",
        ] {
            headers.insert("location", location.parse().unwrap());
            let links = junction_http::AsyncLinks::from_headers(&headers, &poll);
            assert!(
                fabric_result_target(OperationState::Succeeded, &poll, &links)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            fabric_result_target(OperationState::Succeeded, &poll, &Default::default())
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn fabric_location_polls_require_explicit_status() {
        for (status, expected) in [
            ("Running", OperationState::Running),
            ("NotStarted", OperationState::Running),
            ("Succeeded", OperationState::Succeeded),
            ("Failed", OperationState::Failed),
        ] {
            assert_eq!(
                state_from_response(PollProtocol::FabricLocation, 200, &json!({"status":status}))
                    .unwrap(),
                expected
            );
        }
        assert!(state_from_response(PollProtocol::FabricLocation, 200, &Value::Null).is_err());
        assert!(
            state_from_response(PollProtocol::FabricLocation, 200, &json!({"status":42})).is_err()
        );
    }
    #[tokio::test]
    async fn executor_polling_rechecks_context_policy_credentials_and_bounds() {
        let mut operation = crate::tests::operation();
        operation.method = "PUT".into();
        operation.risk = junction_core::OperationRisk::Write;
        operation.long_running = Some(Default::default());
        let token = junction_auth::AccessToken::new(
            junction_auth::Secret::new("private-access-token".into()).unwrap(),
            junction_auth::TokenMetadata {
                tenant: "a".into(),
                audience: "resource".into(),
                expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        );
        let context = crate::ExecutionContext {
            tenant: "a",
            audience: "resource",
            endpoint: "https://example.invalid",
            token: &token,
        };
        let response = junction_http::HttpResponse {
            continuation_token: None,
            status: 201,
            body: json!({"properties":{"provisioningState":"Accepted"},"private":"body-secret"}),
            retry_after: Some(Duration::from_secs(30)),
            async_links: Default::default(),
            correlation: junction_http::CorrelationIds {
                client_request_id: Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into()),
                ..Default::default()
            },
        };
        let options = LroStartOptions {
            max_polls: 1,
            ..Default::default()
        };
        let mut handle = LroHandle::from_initial(
            &operation,
            &response,
            Url::parse("https://example.invalid/resources/vm?private=url-secret").unwrap(),
            context,
            &options,
        )
        .unwrap();
        let snapshot = serde_json::to_string(&handle.snapshot()).unwrap();
        assert!(!snapshot.contains("body-secret") && !snapshot.contains("url-secret"));
        let directory = tempfile::tempdir().unwrap();
        let checkpoint = directory.path().join("operation.json");
        handle.save(&checkpoint).unwrap();
        assert!(handle.save(&checkpoint).is_err());
        let mut restored = LroHandle::load(&checkpoint).unwrap();
        assert_eq!(
            serde_json::to_value(restored.snapshot()).unwrap(),
            serde_json::to_value(handle.snapshot()).unwrap()
        );
        assert!(restored.retry_after() <= Duration::from_secs(32));
        assert!(
            restored
                .validate_context(crate::ExecutionContext {
                    tenant: "b",
                    ..context
                })
                .is_err()
        );
        restored.tracker.reserve_poll().unwrap();
        let second = directory.path().join("next-operation.json");
        restored.save(&second).unwrap();
        assert_eq!(LroHandle::load(&second).unwrap().snapshot().polls, 1);
        let original_bytes = std::fs::read(&checkpoint).unwrap();
        assert_eq!(
            restored.final_target.as_ref().unwrap().0,
            handle.final_target.as_ref().unwrap().0
        );
        let mut legacy: Value = serde_json::from_slice(&original_bytes).unwrap();
        legacy.as_object_mut().unwrap().remove("final_url");
        legacy.as_object_mut().unwrap().remove("final_protocol");
        std::fs::write(&checkpoint, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(LroHandle::load(&checkpoint).unwrap().final_target.is_none());
        let mut unsafe_final: Value = serde_json::from_slice(&original_bytes).unwrap();
        unsafe_final["final_url"] = json!("https://other.invalid/private-secret");
        std::fs::write(&checkpoint, serde_json::to_vec(&unsafe_final).unwrap()).unwrap();
        assert_eq!(
            LroHandle::load(&checkpoint).err().unwrap().to_string(),
            "invalid operation checkpoint endpoint"
        );
        std::fs::write(&checkpoint, &original_bytes).unwrap();
        let mut tampered: Value = serde_json::from_slice(&original_bytes).unwrap();
        tampered["poll_url"] = json!("https://other.example.com/private-secret");
        std::fs::write(&checkpoint, serde_json::to_vec(&tampered).unwrap()).unwrap();
        let error = LroHandle::load(&checkpoint).err().unwrap().to_string();
        assert!(!error.contains("private-secret"));
        std::fs::write(&checkpoint, &original_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&checkpoint).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&checkpoint, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(LroHandle::load(&checkpoint).is_err());
            std::fs::set_permissions(&checkpoint, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let registry = || {
            junction_registry::Registry::load(junction_core::RegistryManifest {
                format_version: 1,
                operations: vec![operation.clone()],
                schemas: json!({}),
            })
            .unwrap()
        };
        let policy = junction_policy::Policy::parse("[agent]\nmode='safe-write'").unwrap();
        let executor = crate::Executor::new(registry(), policy).unwrap();
        assert_eq!(
            executor
                .final_lro_result(&handle, context)
                .await
                .err()
                .unwrap()
                .to_string(),
            "long-running operation has not succeeded"
        );
        handle.tracker.progress.state = OperationState::Succeeded;
        let mismatched = crate::ExecutionContext {
            tenant: "other",
            ..context
        };
        assert_eq!(
            executor
                .final_lro_result(&handle, mismatched)
                .await
                .err()
                .unwrap()
                .to_string(),
            "long-running operation context mismatch"
        );
        let final_target = handle.final_target.take();
        assert_eq!(
            executor
                .final_lro_result(&handle, context)
                .await
                .err()
                .unwrap()
                .to_string(),
            "operation checkpoint has no final result binding"
        );
        handle.final_target = final_target;
        handle.tracker.progress.state = OperationState::Running;
        let mismatch = crate::ExecutionContext {
            tenant: "b",
            ..context
        };
        assert!(executor.poll_lro(&mut handle, mismatch).await.is_err());
        assert!(
            executor
                .poll_lro(&mut handle, context)
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("not ready")
        );
        let denied = crate::Executor::new(registry(), Default::default()).unwrap();
        let error = denied.poll_lro(&mut handle, context).await.err().unwrap();
        assert!(error.downcast_ref::<crate::ExecutionDenied>().is_some());
        assert!(executor.wait_lro(&mut handle, context, 0).await.is_err());
        let started = Instant::now();
        let error = executor
            .wait_lro(&mut handle, context, 1)
            .await
            .err()
            .unwrap();
        let timeout = error.downcast_ref::<LroWaitTimeout>().unwrap();
        assert_eq!(timeout.status, "operation_wait_timed_out");
        assert_eq!(timeout.state, OperationState::Running);
        assert_eq!(timeout.polls, 0);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(handle.snapshot().state, OperationState::Running);
        let encoded = serde_json::to_string(timeout).unwrap();
        assert!(
            !encoded.contains("body-secret")
                && !encoded.contains("url-secret")
                && !encoded.contains("private-access-token")
        );
        handle.tracker.progress.state = OperationState::Succeeded;
        assert_eq!(
            executor
                .wait_lro(&mut handle, context, 1)
                .await
                .unwrap()
                .state,
            OperationState::Succeeded
        );
        assert_eq!(
            executor.poll_lro(&mut handle, context).await.unwrap().state,
            OperationState::Succeeded
        );
        handle.tracker.progress.state = OperationState::Running;
        handle.ready_at = Instant::now();
        let checkpoint = directory.path().join("reserved-poll.json");
        let mut reservations = 0;
        let error = executor
            .poll_lro_checkpointed(&mut handle, context, |handle| {
                reservations += 1;
                handle.save(&checkpoint)?;
                bail!("checkpoint callback stopped transport")
            })
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "checkpoint callback stopped transport");
        assert_eq!(reservations, 1);
        let reserved = LroHandle::load(&checkpoint).unwrap();
        assert_eq!(reserved.snapshot().polls, 1);
        assert_eq!(reserved.snapshot().state, OperationState::Running);
        assert!(!reserved.retry_after().is_zero());
        assert!(!handle.retry_after().is_zero());
        assert!(
            executor
                .poll_lro(&mut handle, context)
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("not ready")
        );
        handle.ready_at = Instant::now();
        assert!(
            executor
                .poll_lro(&mut handle, context)
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("poll limit")
        );
        operation.method = "POST".into();
        assert!(
            LroHandle::from_initial(
                &operation,
                &response,
                Url::parse("https://example.invalid/resources/vm").unwrap(),
                context,
                &options
            )
            .is_err()
        );
        let original = Url::parse("https://example.invalid/resources/vm").unwrap();
        let mut headers = junction_http::RequestHeaders::new();
        headers.insert("azure-asyncoperation", "/status/job".parse().unwrap());
        let mut response = response;
        response.async_links = junction_http::AsyncLinks::from_headers(&headers, &original);
        operation.long_running.as_mut().unwrap().final_state_via =
            Some(junction_core::LroFinalStateVia::Location);
        let missing_final =
            LroHandle::from_initial(&operation, &response, original, context, &options).unwrap();
        assert_eq!(missing_final.snapshot().state, OperationState::Running);
        assert!(missing_final.final_target.is_none());
        // Fabric can recover its state URL from the service operation ID.
        operation.long_running.as_mut().unwrap().protocol =
            Some(junction_core::LroProtocol::Fabric);
        let original = Url::parse("https://example.invalid/v1/workspaces/a/items").unwrap();
        let mut headers = junction_http::RequestHeaders::new();
        headers.insert(
            "x-ms-operation-id",
            "b80e135a-adca-42e7-aaf0-59849af2ed78".parse().unwrap(),
        );
        response.status = 202;
        response.body = Value::Null;
        response.async_links = junction_http::AsyncLinks::from_headers(&headers, &original);
        let fabric =
            LroHandle::from_initial(&operation, &response, original.clone(), context, &options)
                .unwrap();
        assert_eq!(fabric.tracker.protocol, PollProtocol::FabricLocation);
        assert_eq!(
            fabric.poll_url.path(),
            "/v1/operations/b80e135a-adca-42e7-aaf0-59849af2ed78"
        );
        assert_eq!(fabric.snapshot().state, OperationState::Running);
        assert!(fabric.final_target.is_none());
        let saved = directory.path().join("fabric-operation.json");
        fabric.save(&saved).unwrap();
        let restored = LroHandle::load(&saved).unwrap();
        assert_eq!(restored.poll_url, fabric.poll_url);
        assert_eq!(restored.tracker.protocol, PollProtocol::FabricLocation);
        headers.insert("location", "/v1/operations/preferred".parse().unwrap());
        response.async_links = junction_http::AsyncLinks::from_headers(&headers, &original);
        let preferred =
            LroHandle::from_initial(&operation, &response, original, context, &options).unwrap();
        assert_eq!(preferred.poll_url.path(), "/v1/operations/preferred");
    }
    #[test]
    fn final_result_selection_follows_method_and_post_metadata() {
        use junction_core::LroFinalStateVia as Via;
        let original = Url::parse("https://example.invalid/resources/vm?api-version=1").unwrap();
        let mut headers = junction_http::RequestHeaders::new();
        headers.insert("azure-asyncoperation", "/status/job".parse().unwrap());
        headers.insert("operation-location", "/operations/job".parse().unwrap());
        headers.insert("location", "/results/job".parse().unwrap());
        let links = junction_http::AsyncLinks::from_headers(&headers, &original);
        let poll = links.azure_async_operation().unwrap();
        let mut operation = crate::tests::operation();
        operation.method = "POST".into();
        operation.long_running = Some(Default::default());
        for (hint, path, protocol) in [
            (None, "/results/job", PollProtocol::Location),
            (
                Some(Via::OriginalUri),
                "/resources/vm",
                PollProtocol::Resource,
            ),
            (Some(Via::Location), "/results/job", PollProtocol::Location),
            (
                Some(Via::AzureAsyncOperation),
                "/status/job",
                PollProtocol::AzureAsyncOperation,
            ),
            (
                Some(Via::OperationLocation),
                "/operations/job",
                PollProtocol::OperationLocation,
            ),
        ] {
            operation.long_running.as_mut().unwrap().final_state_via = hint;
            let target = final_target(
                &operation,
                &links,
                &original,
                poll,
                PollProtocol::AzureAsyncOperation,
            )
            .unwrap();
            assert_eq!(target.0.path(), path);
            assert_eq!(target.1, protocol);
        }
        for method in ["PUT", "PATCH"] {
            operation.method = method.into();
            assert_eq!(
                final_target(
                    &operation,
                    &links,
                    &original,
                    poll,
                    PollProtocol::AzureAsyncOperation
                )
                .unwrap()
                .0,
                original
            );
        }
        operation.method = "DELETE".into();
        assert_eq!(
            final_target(
                &operation,
                &links,
                &original,
                poll,
                PollProtocol::AzureAsyncOperation
            )
            .unwrap()
            .0,
            *poll
        );
        operation.method = "POST".into();
        for hint in [
            Via::Location,
            Via::AzureAsyncOperation,
            Via::OperationLocation,
        ] {
            operation.long_running.as_mut().unwrap().final_state_via = Some(hint);
            assert!(
                final_target(
                    &operation,
                    &Default::default(),
                    &original,
                    poll,
                    PollProtocol::AzureAsyncOperation
                )
                .is_err()
            );
        }
        operation.long_running.as_mut().unwrap().final_state_via = Some(Via::OriginalUri);
        let unsafe_original = Url::parse("https://user:secret@example.invalid/resource").unwrap();
        assert!(
            final_target(
                &operation,
                &links,
                &unsafe_original,
                poll,
                PollProtocol::AzureAsyncOperation
            )
            .is_err()
        );
    }
    #[test]
    fn status_and_resource_protocols_follow_azure_terminal_states() {
        for protocol in [
            PollProtocol::AzureAsyncOperation,
            PollProtocol::OperationLocation,
        ] {
            for (status, expected) in [
                ("InProgress", OperationState::Running),
                ("CustomProviderState", OperationState::Running),
                ("Succeeded", OperationState::Succeeded),
                ("Failed", OperationState::Failed),
                ("Canceled", OperationState::Canceled),
            ] {
                assert_eq!(
                    state_from_response(
                        protocol,
                        200,
                        &json!({"status":status,"error":{"message":"private-response-secret"}})
                    )
                    .unwrap(),
                    expected
                );
            }
            assert!(state_from_response(protocol, 200, &json!({})).is_err());
            assert!(state_from_response(protocol, 200, &json!({"status":42})).is_err());
        }
        assert_eq!(
            state_from_response(
                PollProtocol::Resource,
                201,
                &json!({"properties":{"provisioningState":"Accepted"}})
            )
            .unwrap(),
            OperationState::Running
        );
        assert_eq!(
            state_from_response(
                PollProtocol::Resource,
                200,
                &json!({"provisioningState":"Failed"})
            )
            .unwrap(),
            OperationState::Failed
        );
        assert_eq!(
            state_from_response(PollProtocol::Location, 202, &Value::Null).unwrap(),
            OperationState::Running
        );
        assert_eq!(
            state_from_response(PollProtocol::Location, 204, &Value::Null).unwrap(),
            OperationState::Succeeded
        );
        assert!(state_from_response(PollProtocol::Location, 401, &Value::Null).is_err());
    }
    #[test]
    fn tracker_bounds_polls_and_never_reopens_terminal_operations() {
        let mut tracker = LroTracker::new(PollProtocol::AzureAsyncOperation, 2).unwrap();
        assert_eq!(
            tracker
                .observe(200, &json!({"status":"Running"}))
                .unwrap()
                .polls,
            1
        );
        let terminal = tracker
            .observe(
                200,
                &json!({"status":"Failed","error":{"message":"private-secret"}}),
            )
            .unwrap();
        assert_eq!(terminal.state, OperationState::Failed);
        assert!(
            !serde_json::to_string(&terminal)
                .unwrap()
                .contains("private-secret")
        );
        assert_eq!(
            tracker
                .observe(202, &json!({"status":"Running"}))
                .unwrap()
                .state,
            OperationState::Failed
        );
        let mut tracker = LroTracker::new(PollProtocol::AzureAsyncOperation, 1).unwrap();
        assert!(tracker.observe(200, &json!({"status":null})).is_err());
        assert_eq!(tracker.progress().state, OperationState::Running);
        assert!(
            tracker
                .observe(200, &json!({"status":"Succeeded"}))
                .is_err()
        );
        assert!(LroTracker::new(PollProtocol::Location, 0).is_err());
    }
}
