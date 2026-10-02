//! Shared request planning and governed execution.
pub mod authorization;
pub mod lro;
mod parameters;
use anyhow::{Result, bail};
use junction_core::JunctionOperation;
use junction_policy::{Decision, Policy};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;
use std::collections::BTreeSet;
use url::Url;

/// Machine-readable denial shared by CLI, MCP and HTTP execution surfaces.
#[derive(Debug)]
pub struct ExecutionDenied(pub Decision);
impl std::fmt::Display for ExecutionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            Decision::ApprovalRequired { .. } => "approval_required",
            _ => "policy_rejected",
        })
    }
}
impl std::error::Error for ExecutionDenied {}
fn enforce(decision: Decision) -> Result<()> {
    match decision {
        Decision::Allowed => Ok(()),
        denied => Err(ExecutionDenied(denied).into()),
    }
}
// No Debug/Serialize: request URLs and bodies can contain sensitive API input.
pub struct PreparedRequest {
    pub method: String,
    pub url: Url,
    pub body: Option<Value>,
    pub headers: junction_http::RequestHeaders,
}
/// The endpoint must come from trusted execution context, never agent input.
/// Input envelope: {"parameters": {"name": value}, "body": value}.
pub fn prepare(
    operation: &JunctionOperation,
    input: &Value,
    tenant: &str,
    endpoint: &str,
    policy: &Policy,
) -> Result<PreparedRequest> {
    prepare_with_schemas(operation, input, tenant, endpoint, policy, &Value::Null)
}
fn prepare_with_schemas(
    operation: &JunctionOperation,
    input: &Value,
    tenant: &str,
    endpoint: &str,
    policy: &Policy,
    definitions: &Value,
) -> Result<PreparedRequest> {
    enforce(policy.authorize_operation(operation, tenant))?;
    prepare_authorized(operation, input, endpoint, definitions)
}
/// Prepare one explicitly approved request without obtaining credentials or sending it.
/// Issuance and the context must remain under trusted operator control.
pub fn prepare_with_approval(
    operation: &JunctionOperation,
    input: &Value,
    tenant: &str,
    context: &junction_policy::approval::ApprovalContext,
    policy: &Policy,
    grant: junction_policy::approval::ApprovalGrant,
) -> Result<PreparedRequest> {
    enforce(policy.authorize_with_approval(operation, tenant, input, context, grant)?)?;
    prepare_authorized(operation, input, context.endpoint(), &Value::Null)
}
fn prepare_authorized(
    operation: &JunctionOperation,
    input: &Value,
    endpoint: &str,
    definitions: &Value,
) -> Result<PreparedRequest> {
    let object = input
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("input must be an object"))?;
    if object
        .keys()
        .any(|key| !["parameters", "body"].contains(&key.as_str()))
    {
        bail!("unknown input field");
    }
    let empty = serde_json::Map::new();
    let parameters = object
        .get("parameters")
        .map(|p| {
            p.as_object()
                .ok_or_else(|| anyhow::anyhow!("parameters must be an object"))
        })
        .transpose()?
        .unwrap_or(&empty);
    let mut url = Url::parse(endpoint).map_err(|_| anyhow::anyhow!("invalid context endpoint"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("context endpoint must be plain HTTPS");
    }
    if !operation.path.starts_with('/')
        || operation.path.starts_with("//")
        || operation.path.contains(['?', '#', '\\'])
    {
        bail!("invalid operation path");
    }
    let mut path = operation.path.clone();
    let mut known = BTreeSet::new();
    let mut query = Vec::new();
    let mut headers = Vec::new();
    for parameter in &operation.parameters {
        known.insert(parameter.name.as_str());
        let value = parameters.get(&parameter.name);
        if value.is_none() && parameter.required && parameter.name != "api-version" {
            bail!("missing required parameter");
        }
        let Some(value) = value else {
            if parameter.location == "query"
                && parameter.serialization.style.as_deref() == Some("odata")
            {
                path = parameters::omit_odata_alias(&path, parameter)?;
            }
            continue;
        };
        junction_schema::validate_with_definitions(&parameter.schema, definitions, value)?;
        match parameter.location.as_str() {
            "path" => {
                if parameter
                    .serialization
                    .style
                    .as_deref()
                    .is_some_and(|style| style != "simple")
                {
                    bail!("unsupported path serialization");
                }
                let scalar = parameters::scalar(value)?;
                if scalar.is_empty() || scalar == "." || scalar == ".." {
                    bail!("invalid path parameter");
                }
                let placeholder = format!("{{{}}}", parameter.name);
                if !path.contains(&placeholder) {
                    bail!("path parameter has no placeholder");
                }
                path = path.replace(
                    &placeholder,
                    &utf8_percent_encode(&scalar, NON_ALPHANUMERIC).to_string(),
                );
            }
            "query" => {
                if parameter.name == "api-version"
                    && operation.api_version.as_deref() != Some(parameters::scalar(value)?.as_str())
                {
                    bail!("API version must match selected operation");
                }
                let pairs = parameters::query(parameter, value)?;
                for (name, _) in &pairs {
                    if name != &parameters::encode(&parameter.name)
                        && (name == &parameters::encode("api-version")
                            || operation.parameters.iter().any(|other| {
                                other.location == "query"
                                    && name == &parameters::encode(&other.name)
                            }))
                    {
                        bail!("expanded query object conflicts with declared parameter");
                    }
                }
                query.extend(pairs);
            }
            "header" => headers.push((
                parameter.name.clone(),
                parameters::header(parameter, value)?,
            )),
            _ => bail!("parameter serialization strategy not implemented"),
        }
    }
    if parameters.keys().any(|name| !known.contains(name.as_str())) {
        bail!("unknown parameter");
    }
    if path.contains(['{', '}']) {
        bail!("unresolved path parameter");
    }
    if let Some(version_parameter) = operation
        .parameters
        .iter()
        .find(|p| p.name == "api-version" && p.location == "query")
        && !query
            .iter()
            .any(|(name, _)| name == &parameters::encode("api-version"))
    {
        let version = operation
            .api_version
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing selected API version"))?;
        junction_schema::validate_with_definitions(
            &version_parameter.schema,
            definitions,
            &Value::String(version.to_owned()),
        )?;
        query.push((
            parameters::encode("api-version"),
            parameters::encode(version),
        ));
    }
    let base = url.path().trim_end_matches('/');
    url.set_path(&format!("{base}{path}"));
    if !query.is_empty() {
        url.set_query(Some(
            &query
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("&"),
        ));
    }
    let body = object.get("body").cloned();
    validate_body(operation, body.as_ref(), definitions)?;
    if body.is_some() {
        let media = body_media_type(operation)
            .ok_or_else(|| anyhow::anyhow!("request body schema resolution required"))?;
        if media != "application/json" {
            headers.push(("content-type".into(), media.into()));
        }
    }
    Ok(PreparedRequest {
        method: operation.method.clone(),
        url,
        body,
        headers: junction_http::request_headers(headers)?,
    })
}
/// Prefer plain JSON; otherwise the first declared JSON-structured media type.
fn body_media_type(operation: &JunctionOperation) -> Option<&str> {
    let content = operation
        .request_body
        .as_ref()?
        .get("content")?
        .as_object()?;
    if content.contains_key("application/json") {
        return Some("application/json");
    }
    content
        .keys()
        .map(String::as_str)
        .find(|media| junction_core::is_json_media_type(media))
}
fn validate_body(
    operation: &JunctionOperation,
    body: Option<&Value>,
    definitions: &Value,
) -> Result<()> {
    if body.is_some() && operation.request_body.is_none() {
        bail!("operation does not declare a request body");
    }
    if body.is_none()
        && operation
            .request_body
            .as_ref()
            .is_some_and(|b| b["required"].as_bool() == Some(true))
    {
        bail!("missing required request body");
    }
    if let Some(body) = body {
        let schema = body_media_type(operation)
            .and_then(|media| operation.request_body.as_ref()?["content"][media].get("schema"))
            .ok_or_else(|| anyhow::anyhow!("request body schema resolution required"))?;
        junction_schema::validate_with_definitions(schema, definitions, body)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    pub(super) fn operation() -> JunctionOperation {
        serde_json::from_value(json!({"id":"graph.users.get","product":"graph","service":"users","resource":"users","operation":"get","description":"","method":"GET","base_url":"https://graph.microsoft.com/v1.0","path":"/users/{id}","api_version":"v1.0","parameters":[{"name":"id","location":"path","required":true,"schema":{"type":"string"}},{"name":"$select","location":"query","required":false,"schema":{"type":"string"}}],"request_body":null,"responses":{},"security":[],"risk":"read_only","preview":false,"source":{"id":"official","upstream":"official","operation_id":"Users_Get"}})).unwrap()
    }
    #[test]
    fn json_patch_bodies_declare_their_media_type() {
        let mut patch = operation();
        patch.method = "PATCH".into();
        patch.risk = junction_core::OperationRisk::Write;
        patch.request_body = Some(
            json!({"required":true,"content":{"application/json-patch+json":{
                "schema":{"type":"array","items":{"type":"object"}}
            }}}),
        );
        let policy = Policy::parse("[agent]\nmode='safe-write'").unwrap();
        let input =
            json!({"parameters":{"id":"a"},"body":[{"op":"replace","path":"/name","value":"x"}]});
        let request = prepare(
            &patch,
            &input,
            "a",
            "https://graph.microsoft.com/v1.0",
            &policy,
        )
        .unwrap();
        assert_eq!(
            request.headers["content-type"],
            "application/json-patch+json"
        );
        // Schema validation uses the declared JSON Patch media type.
        assert!(
            prepare(
                &patch,
                &json!({"parameters":{"id":"a"},"body":{}}),
                "a",
                "https://graph.microsoft.com/v1.0",
                &policy
            )
            .is_err()
        );
        let mut plain = patch;
        plain.request_body = Some(
            json!({"required":true,"content":{"application/json":{"schema":{"type":"array"}}}}),
        );
        let request = prepare(
            &plain,
            &input,
            "a",
            "https://graph.microsoft.com/v1.0",
            &policy,
        )
        .unwrap();
        assert!(request.headers.get("content-type").is_none());
    }
    #[test]
    fn path_and_odata_values_are_encoded() {
        let request = prepare(
            &operation(),
            &json!({"parameters":{"id":"a/b","$select":"displayName,id"}}),
            "a",
            "https://graph.microsoft.com/v1.0",
            &Policy::default(),
        )
        .unwrap();
        assert_eq!(request.url.path(), "/v1.0/users/a%2Fb");
        assert_eq!(
            request.url.query_pairs().next().unwrap(),
            ("$select".into(), "displayName,id".into())
        );
    }
    #[test]
    fn declared_headers_and_query_arrays_are_planned_without_injection() {
        let mut op = operation();
        op.parameters[1].schema = json!({"type":"array","items":{"type":"string"}});
        op.parameters[1].serialization.explode = Some(false);
        op.parameters.push(serde_json::from_value(json!({"name":"ConsistencyLevel","location":"header","required":true,"schema":{"type":"string","enum":["eventual"]}})).unwrap());
        let request = prepare(&op, &json!({"parameters":{"id":"a","$select":["a,b","c&x=1"],"ConsistencyLevel":"eventual"}}), "a", "https://graph.microsoft.com/v1.0", &Policy::default()).unwrap();
        assert_eq!(request.url.query(), Some("%24select=a%2Cb,c%26x%3D1"));
        assert_eq!(request.headers["consistencylevel"], "eventual");
        op.parameters[1].schema = json!({"type":"object"});
        op.parameters[1].serialization.explode = Some(true);
        assert!(prepare(&op, &json!({"parameters":{"id":"a","$select":{"api-version":"beta"},"ConsistencyLevel":"eventual"}}), "a", "https://graph.microsoft.com/v1.0", &Policy::default()).is_err());
    }
    #[test]
    fn rejects_policy_bypass_and_invalid_inputs() {
        let mut op = operation();
        op.risk = junction_core::OperationRisk::Destructive;
        assert_eq!(
            prepare(
                &op,
                &json!({}),
                "a",
                "https://example.com",
                &Policy::default()
            )
            .err()
            .unwrap()
            .to_string(),
            "policy_rejected"
        );
        op = operation();
        for input in [
            json!({}),
            json!({"parameters":{"id":".."}}),
            json!({"parameters":{"id":"a","unknown":1}}),
            json!({"parameters":{"id":"a"},"approved":true}),
        ] {
            assert!(prepare(&op, &input, "a", "https://example.com", &Policy::default()).is_err());
        }
    }
}

/// Trusted caller configuration, kept outside the operation input envelope.
#[derive(Clone, Copy)]
pub struct ExecutionContext<'a> {
    pub tenant: &'a str,
    pub audience: &'a str,
    pub endpoint: &'a str,
    pub token: &'a junction_auth::AccessToken,
}
/// Trusted operator capability and binding, never deserialized from tool input.
/// The caller must establish the cloud and credential profile independently.
pub struct ApprovedExecution<'a> {
    pub context: &'a junction_policy::approval::ApprovalContext,
    pub grant: junction_policy::approval::ApprovalGrant,
}
/// Selection and lifetime for a trusted operator approval.
pub struct ApprovalOptions<'a> {
    pub api_version: Option<&'a str>,
    pub allow_preview: bool,
    pub lifetime: std::time::Duration,
}
pub struct Executor {
    registry: junction_registry::Registry,
    policy: Policy,
    transport: junction_http::HttpTransport,
}
impl Executor {
    /// Issue a grant only after registry selection and complete request validation.
    /// Hosts must keep this method inside their trusted operator boundary.
    pub fn issue_approval(
        &self,
        operation: &str,
        input: &Value,
        tenant: &str,
        context: &junction_policy::approval::ApprovalContext,
        options: ApprovalOptions<'_>,
    ) -> Result<junction_policy::approval::ApprovalGrant> {
        let selected =
            self.registry
                .resolve(operation, options.api_version, options.allow_preview)?;
        let decision = self.policy.authorize_operation(selected, tenant);
        if !matches!(decision, Decision::ApprovalRequired { .. }) {
            enforce(decision)?;
            bail!("request does not qualify for trusted approval");
        }
        prepare_authorized(selected, input, context.endpoint(), self.registry.schemas())?;
        self.policy
            .issue_approval(selected, tenant, input, context, options.lifetime)
    }
    /// Consume a trusted grant and prepare against the loaded registry schemas.
    /// No credentials are acquired and no request is sent.
    pub fn prepare_with_approval(
        &self,
        operation: &str,
        input: &Value,
        tenant: &str,
        api_version: Option<&str>,
        allow_preview: bool,
        approval: ApprovedExecution<'_>,
    ) -> Result<PreparedRequest> {
        let selected = self
            .registry
            .resolve(operation, api_version, allow_preview)?;
        enforce(self.policy.authorize_with_approval(
            selected,
            tenant,
            input,
            approval.context,
            approval.grant,
        )?)?;
        prepare_authorized(
            selected,
            input,
            approval.context.endpoint(),
            self.registry.schemas(),
        )
    }
    pub fn registry(&self) -> &junction_registry::Registry {
        &self.registry
    }
    pub fn new(registry: junction_registry::Registry, policy: Policy) -> Result<Self> {
        let governor = junction_policy::RequestGovernor::new(&policy)?;
        let transport = junction_http::HttpTransport::new(
            governor,
            std::time::Duration::from_secs(30),
            16 * 1024 * 1024,
        )?;
        Ok(Self {
            registry,
            policy,
            transport,
        })
    }
    /// Validate registry selection, policy and input without acquiring credentials or sending requests.
    pub fn preflight(
        &self,
        operation: &str,
        input: &Value,
        tenant: &str,
        endpoint: &str,
        api_version: Option<&str>,
        allow_preview: bool,
    ) -> Result<()> {
        let operation = self
            .registry
            .resolve(operation, api_version, allow_preview)?;
        prepare_with_schemas(
            operation,
            input,
            tenant,
            endpoint,
            &self.policy,
            self.registry.schemas(),
        )?;
        Ok(())
    }
    /// Validate pagination selection and bounds before acquiring credentials.
    pub fn preflight_pages(
        &self,
        operation_id: &str,
        input: &Value,
        tenant: &str,
        endpoint: &str,
        options: &PageOptions,
    ) -> Result<()> {
        let operation = self.registry.resolve(
            operation_id,
            options.api_version.as_deref(),
            options.allow_preview,
        )?;
        let request = prepare_with_schemas(
            operation,
            input,
            tenant,
            endpoint,
            &self.policy,
            self.registry.schemas(),
        )?;
        if (operation.method == "GET" && request.body.is_some())
            || (operation.method != "GET"
                && !(operation.method == "POST"
                    && (operation.pageable.is_some() || operation.query_continuation.is_some())))
        {
            bail!("pagination requires GET without a body or a declared pageable POST");
        }
        if let Some(continuation) = &operation.query_continuation {
            continuation.validate(operation)?;
        }
        if let Some(pageable) = &operation.pageable {
            pageable.validate()?;
            if let Some(name) = &pageable.operation_name {
                let next = self
                    .registry
                    .resolve_related(operation, name, options.allow_preview)?;
                enforce(self.policy.authorize_operation(next, tenant))?;
                if !matches!(next.method.as_str(), "GET" | "POST")
                    || (next.method == "GET" && next.request_body.is_some())
                    || next.parameters.iter().any(|parameter| {
                        parameter.location == "header" || parameter.location == "cookie"
                    })
                {
                    bail!("named pagination requires GET or POST without service headers");
                }
                if next.method == "POST" {
                    validate_body(
                        next,
                        if next.request_body.is_some() {
                            request.body.as_ref()
                        } else {
                            None
                        },
                        self.registry.schemas(),
                    )?;
                }
            }
        }
        pagination::PageAccumulator::new(
            request.url,
            options.max_items,
            options.max_pages,
            &self.policy.limits,
        )?;
        Ok(())
    }
    /// Retrieve Graph/ARM next-link pages within configured limits.
    /// Input remains separate from options so limits cannot bypass operation validation.
    pub async fn execute_pages(
        &self,
        operation_id: &str,
        input: Value,
        context: ExecutionContext<'_>,
        options: PageOptions,
    ) -> Result<pagination::PageResult> {
        self.execute_pages_resuming(operation_id, input, context, options, None)
            .await
    }
    /// Resume an opaque in-memory continuation under current policy and credentials.
    pub async fn execute_pages_resuming(
        &self,
        operation_id: &str,
        input: Value,
        context: ExecutionContext<'_>,
        options: PageOptions,
        continuation: Option<pagination::Continuation>,
    ) -> Result<pagination::PageResult> {
        let operation = self.registry.resolve(
            operation_id,
            options.api_version.as_deref(),
            options.allow_preview,
        )?;
        self.preflight_pages(
            operation_id,
            &input,
            context.tenant,
            context.endpoint,
            &options,
        )?;
        // Named continuation policy and body were checked above. The next-link URL
        // remains subject to the accumulator's origin and cycle checks.
        let mut page_operation = operation.clone();
        if let Some(pageable) = &mut page_operation.pageable {
            pageable.operation_name = None;
        }
        let next_operation = operation
            .pageable
            .as_ref()
            .and_then(|pageable| pageable.operation_name.as_deref())
            .map(|name| {
                self.registry
                    .resolve_related(operation, name, options.allow_preview)
            })
            .transpose()?;
        let request = prepare_with_schemas(
            operation,
            &input,
            context.tenant,
            context.endpoint,
            &self.policy,
            self.registry.schemas(),
        )?;
        validate_credential(context)?;
        let binding = (
            operation.id.clone(),
            context.tenant.to_ascii_lowercase(),
            context.audience.to_owned(),
            serde_json::to_string(&(&input, operation, next_operation))?,
        );
        let mut url = request.url.clone();
        let mut accumulator = if let Some(continuation) = continuation {
            if continuation.binding.as_ref() != Some(&binding) {
                bail!("continuation context mismatch");
            }
            let (accumulator, next, result) = pagination::PageAccumulator::resume(
                url.clone(),
                continuation,
                options.max_items,
                options.max_pages,
                &self.policy.limits,
            )?;
            if let Some(result) = result {
                return Ok(result);
            }
            url = next.ok_or_else(|| anyhow::anyhow!("missing pagination continuation"))?;
            accumulator
        } else {
            pagination::PageAccumulator::new(
                url.clone(),
                options.max_items,
                options.max_pages,
                &self.policy.limits,
            )?
        };
        loop {
            validate_credential(context)?;
            let (selected, method, body) = page_request(
                operation,
                next_operation,
                &request,
                accumulator.is_initial_request(),
            );
            accumulator.begin_page(&url)?;
            let response = self
                .transport
                .send_with_headers_retries(
                    method,
                    url.clone(),
                    body,
                    Some(&context.token.credential()),
                    &request.headers,
                )
                .await
                .map_err(|error| authorization::enrich(error, selected, context))?;
            let (next, result) = accumulator.accept_response(&page_operation, &response)?;
            if let Some(mut result) = result {
                if let Some(continuation) = &mut result.continuation {
                    continuation.binding = Some(binding);
                }
                return Ok(result);
            }
            url = next.ok_or_else(|| anyhow::anyhow!("missing pagination continuation"))?;
        }
    }
    /// Check every operation's policy before credentials; reference-dependent schemas are checked after substitution.
    pub fn preflight_batch(
        &self,
        plan: &batch::BatchPlan,
        tenant: &str,
        endpoint: &str,
    ) -> Result<()> {
        for (index, item) in plan.request.operations.iter().enumerate() {
            let operation = self.registry.resolve(
                &item.operation,
                item.api_version.as_deref(),
                item.allow_preview,
            )?;
            enforce(self.policy.authorize_operation(operation, tenant))?;
            if !plan.has_references(index) {
                self.preflight(
                    &item.operation,
                    &item.input,
                    tenant,
                    endpoint,
                    item.api_version.as_deref(),
                    item.allow_preview,
                )?;
            }
        }
        Ok(())
    }
    /// Execute a dependency-aware batch in one trusted tenant/audience context.
    pub async fn execute_batch(
        &self,
        request: batch::BatchRequest,
        context: ExecutionContext<'_>,
    ) -> Result<batch::BatchResult> {
        let plan = batch::BatchPlan::build(request, &self.policy.limits)?;
        self.preflight_batch(&plan, context.tenant, context.endpoint)?;
        validate_credential(context)?;
        Ok(batch::run(&plan, |operation, input| async move {
            let response = self
                .execute(
                    &operation.operation,
                    input,
                    context,
                    operation.api_version.as_deref(),
                    operation.allow_preview,
                )
                .await?;
            Ok(serde_json::json!({"status":response.status,"body":response.body,"correlation":response.correlation}))
        })
        .await)
    }
    /// Execute a single approved request, rechecking policy, input and credentials.
    pub async fn execute_with_approval(
        &self,
        operation: &str,
        input: Value,
        context: ExecutionContext<'_>,
        api_version: Option<&str>,
        allow_preview: bool,
        approval: ApprovedExecution<'_>,
    ) -> Result<junction_http::HttpResponse> {
        let endpoint = Url::parse(context.endpoint)
            .map_err(|_| anyhow::anyhow!("approval_context_mismatch"))?;
        if endpoint.as_str() != approval.context.endpoint()
            || context.audience != approval.context.audience()
        {
            bail!("approval_context_mismatch");
        }
        let operation = self
            .registry
            .resolve(operation, api_version, allow_preview)?;
        enforce(self.policy.authorize_with_approval(
            operation,
            context.tenant,
            &input,
            approval.context,
            approval.grant,
        )?)?;
        let request = prepare_authorized(
            operation,
            &input,
            approval.context.endpoint(),
            self.registry.schemas(),
        )?;
        validate_credential(context)?;
        self.transport
            .send_with_headers_retries(
                &request.method,
                request.url,
                request.body.as_ref(),
                Some(&context.token.credential()),
                &request.headers,
            )
            .await
            .map_err(|error| authorization::enrich(error, operation, context))
    }
    pub async fn execute(
        &self,
        operation: &str,
        input: Value,
        context: ExecutionContext<'_>,
        api_version: Option<&str>,
        allow_preview: bool,
    ) -> Result<junction_http::HttpResponse> {
        let operation = self
            .registry
            .resolve(operation, api_version, allow_preview)?;
        let request = prepare_with_schemas(
            operation,
            &input,
            context.tenant,
            context.endpoint,
            &self.policy,
            self.registry.schemas(),
        )?;
        validate_credential(context)?;
        self.transport
            .send_with_headers_retries(
                &request.method,
                request.url,
                request.body.as_ref(),
                Some(&context.token.credential()),
                &request.headers,
            )
            .await
            .map_err(|error| authorization::enrich(error, operation, context))
    }
}

fn page_request<'a>(
    operation: &'a JunctionOperation,
    next_operation: Option<&'a JunctionOperation>,
    request: &'a PreparedRequest,
    initial: bool,
) -> (&'a JunctionOperation, &'a str, Option<&'a Value>) {
    if initial {
        return (operation, &request.method, request.body.as_ref());
    }
    match next_operation {
        Some(next) => (
            next,
            &next.method,
            if next.method == "POST" && next.request_body.is_some() {
                request.body.as_ref()
            } else {
                None
            },
        ),
        None if operation.query_continuation.is_some() => {
            (operation, &request.method, request.body.as_ref())
        }
        None => (operation, "GET", None),
    }
}
#[cfg(test)]
mod executor_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn marked_post_query_tokens_reuse_the_post_body_and_require_declared_metadata() {
        let mut operation = super::tests::operation();
        operation.method = "POST".into();
        operation.path = "/query".into();
        operation.parameters.clear();
        operation.parameters.push(junction_core::Parameter {
            name: "page.cursor".into(),
            location: "query".into(),
            required: false,
            schema: json!({"type":"string"}),
            serialization: Default::default(),
        });
        operation.request_body = Some(json!({"required":true,"content":{"application/json":{
            "schema":{"type":"object","required":["filter"],"properties":{"filter":{"type":"string"}}}
        }}}));
        operation.query_continuation = Some(junction_core::QueryContinuation {
            query_parameter: "page.cursor".into(),
            response_pointer: "/next_token".into(),
        });
        let policy = Policy::parse("[agent]\nmode='safe-write'").unwrap();
        let input = json!({"body":{"filter":"active"}});
        let executor = Executor::new(
            junction_registry::Registry::load(junction_core::RegistryManifest {
                format_version: 1,
                operations: vec![operation.clone()],
                schemas: json!({}),
            })
            .unwrap(),
            policy.clone(),
        )
        .unwrap();
        executor
            .preflight_pages(
                &operation.id,
                &input,
                "a",
                "https://example.invalid",
                &Default::default(),
            )
            .unwrap();
        let request = prepare(&operation, &input, "a", "https://example.invalid", &policy).unwrap();
        let (_, method, body) = page_request(&operation, None, &request, false);
        assert_eq!(method, "POST");
        assert_eq!(body, input.get("body"));
        operation.query_continuation = None;
        let (_, method, body) = page_request(&operation, None, &request, false);
        assert_eq!(method, "GET");
        assert!(body.is_none());
        let executor = Executor::new(
            junction_registry::Registry::load(junction_core::RegistryManifest {
                format_version: 1,
                operations: vec![operation],
                schemas: json!({}),
            })
            .unwrap(),
            policy,
        )
        .unwrap();
        assert!(
            executor
                .preflight_pages(
                    "graph.users.get",
                    &input,
                    "a",
                    "https://example.invalid",
                    &Default::default()
                )
                .is_err()
        );
    }
    #[test]
    fn post_pagination_defaults_to_get_and_resumes_without_replaying_initial_body() {
        let mut operation = super::tests::operation();
        operation.parameters.clear();
        operation.path = "/query".into();
        operation.method = "POST".into();
        operation.request_body = Some(json!({"required":true,"content":{"application/json":{
            "schema":{"type":"object","required":["filter"],"properties":{"filter":{"type":"string"}}}
        }}}));
        operation.pageable = Some(junction_core::Pageable {
            item_name: "value".into(),
            next_link_name: Some("nextLink".into()),
            operation_name: None,
        });
        let policy = Policy::parse("[agent]\nmode='safe-write'").unwrap();
        let input = json!({"body":{"filter":"active"}});
        let request = prepare(&operation, &input, "a", "https://example.invalid", &policy).unwrap();
        let mut pages =
            pagination::PageAccumulator::new(request.url.clone(), 1, 2, &policy.limits).unwrap();
        assert!(pages.is_initial_request());
        let (_, method, body) =
            page_request(&operation, None, &request, pages.is_initial_request());
        assert_eq!(method, "POST");
        assert_eq!(body, input.get("body"));
        pages.begin_page(&request.url).unwrap();
        let (_, result) = pages
            .accept(&json!({"value":[1,2],"nextLink":"?page=2"}))
            .unwrap();
        let continuation = result.unwrap().continuation.unwrap();
        let (mut resumed, next, result) = pagination::PageAccumulator::resume(
            request.url.clone(),
            continuation,
            10,
            2,
            &policy.limits,
        )
        .unwrap();
        assert!(result.is_none());
        assert!(!resumed.is_initial_request());
        let (_, method, body) =
            page_request(&operation, None, &request, resumed.is_initial_request());
        assert_eq!(method, "GET");
        assert!(body.is_none());
        let mut next_operation = operation.clone();
        next_operation.id = "graph.users.next".into();
        let (selected, method, body) =
            page_request(&operation, Some(&next_operation), &request, false);
        assert_eq!(selected.id, "graph.users.next");
        assert_eq!(method, "POST");
        assert_eq!(body, input.get("body"));
        next_operation.request_body = None;
        assert!(
            page_request(&operation, Some(&next_operation), &request, false)
                .2
                .is_none()
        );
        resumed.begin_page(&next.unwrap()).unwrap();
        let (_, result) = resumed.accept(&json!({"value":[3]})).unwrap();
        assert_eq!(result.unwrap().items, vec![json!(2), json!(3)]);
    }
    #[test]
    fn approved_preparation_keeps_input_and_policy_validation() {
        use junction_policy::approval::ApprovalContext;
        let mut operation = super::tests::operation();
        operation.method = "DELETE".into();
        operation.risk = junction_core::OperationRisk::Destructive;
        operation.path = "/users".into();
        operation.parameters.clear();
        let policy = Policy::parse("[agent]\nmode='safe-write'").unwrap();
        let context = ApprovalContext::new(
            junction_core::cloud::MicrosoftCloud::Public,
            "https://example.invalid",
            "resource",
            "profile",
        )
        .unwrap();
        let input = json!({});
        assert!(prepare(&operation, &input, "tenant-a", context.endpoint(), &policy).is_err());
        let grant = policy
            .issue_approval(
                &operation,
                "tenant-a",
                &input,
                &context,
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        let prepared =
            prepare_with_approval(&operation, &input, "tenant-a", &context, &policy, grant)
                .unwrap();
        assert_eq!(prepared.method, "DELETE");
        assert_eq!(prepared.url.as_str(), "https://example.invalid/users");
        let invalid = json!({"approved":true});
        let grant = policy
            .issue_approval(
                &operation,
                "tenant-a",
                &invalid,
                &context,
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(
            prepare_with_approval(&operation, &invalid, "tenant-a", &context, &policy, grant)
                .err()
                .unwrap()
                .to_string(),
            "unknown input field"
        );
        let grant = policy
            .issue_approval(
                &operation,
                "tenant-a",
                &input,
                &context,
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        assert!(
            prepare_with_approval(
                &operation,
                &json!({"body":{}}),
                "tenant-a",
                &context,
                &policy,
                grant
            )
            .is_err()
        );
    }
    #[test]
    fn registry_approved_preparation_validates_referenced_body_schema() {
        let mut operation = super::tests::operation();
        operation.method = "POST".into();
        operation.risk = junction_core::OperationRisk::Destructive;
        operation.path = "/users/purge".into();
        operation.parameters.clear();
        operation.request_body = Some(json!({"required":true,"content":{"application/json":{
            "schema":{"$ref":"#/components/schemas/Purge"}
        }}}));
        let policy = Policy::parse("[agent]\nmode='safe-write'").unwrap();
        let binding = junction_policy::approval::ApprovalContext::new(
            junction_core::cloud::MicrosoftCloud::Public,
            "https://example.invalid",
            "resource",
            "profile",
        )
        .unwrap();
        let executor = Executor::new(junction_registry::Registry::load(
            junction_core::RegistryManifest {
                format_version:1, operations:vec![operation.clone()],
                schemas:json!({"components":{"schemas":{"Purge":{
                    "type":"object","required":["confirm"],"properties":{"confirm":{"type":"boolean"}},
                    "additionalProperties":false
                }}}}),
            }
        ).unwrap(), policy.clone()).unwrap();
        for (body, valid) in [
            (json!({"confirm":true}), true),
            (json!({}), false),
            (json!({"confirm":"yes"}), false),
            (json!({"confirm":true,"other":1}), false),
        ] {
            let input = json!({"body":body});
            let issued = executor.issue_approval(
                &operation.id,
                &input,
                "tenant-a",
                &binding,
                ApprovalOptions {
                    api_version: None,
                    allow_preview: false,
                    lifetime: std::time::Duration::from_secs(60),
                },
            );
            assert_eq!(issued.is_ok(), valid);
            // Even a lower-level grant cannot bypass registry body validation.
            let grant = issued.unwrap_or_else(|_| {
                policy
                    .issue_approval(
                        &operation,
                        "tenant-a",
                        &input,
                        &binding,
                        std::time::Duration::from_secs(60),
                    )
                    .unwrap()
            });
            let result = executor.prepare_with_approval(
                &operation.id,
                &input,
                "tenant-a",
                None,
                false,
                ApprovedExecution {
                    context: &binding,
                    grant,
                },
            );
            assert_eq!(result.is_ok(), valid);
            if let Ok(request) = result {
                assert_eq!(request.body.as_ref(), input.get("body"));
                assert_eq!(request.url.as_str(), "https://example.invalid/users/purge");
            }
        }
    }
    #[test]
    fn registry_approved_preparation_rechecks_tenant_input_and_policy() {
        let mut operation = super::tests::operation();
        operation.method = "DELETE".into();
        operation.risk = junction_core::OperationRisk::Destructive;
        operation.path = "/users/{id}".into();
        let policy = Policy::parse("[agent]\nmode='safe-write'").unwrap();
        let binding = junction_policy::approval::ApprovalContext::new(
            junction_core::cloud::MicrosoftCloud::Public,
            "https://example.invalid",
            "resource",
            "profile",
        )
        .unwrap();
        let input = json!({"parameters":{"id":"user-a"}});
        for change in ["tenant", "input", "deny", "readonly", "limits"] {
            let grant = policy
                .issue_approval(
                    &operation,
                    "tenant-a",
                    &input,
                    &binding,
                    std::time::Duration::from_secs(60),
                )
                .unwrap();
            let mut current_policy = policy.clone();
            let mut current_input = input.clone();
            let mut tenant = "tenant-a";
            match change {
                "tenant" => tenant = "tenant-b",
                "input" => current_input["parameters"]["id"] = json!("user-b"),
                "deny" => current_policy.deny.operations.push(operation.id.clone()),
                "readonly" => current_policy.agent.mode = junction_policy::AgentMode::ReadOnly,
                "limits" => current_policy.limits.max_pages += 1,
                _ => unreachable!(),
            }
            let registry = junction_registry::Registry::load(junction_core::RegistryManifest {
                format_version: 1,
                operations: vec![operation.clone()],
                schemas: json!({}),
            })
            .unwrap();
            let executor = Executor::new(registry, current_policy).unwrap();
            let error = executor
                .prepare_with_approval(
                    &operation.id,
                    &current_input,
                    tenant,
                    None,
                    false,
                    ApprovedExecution {
                        context: &binding,
                        grant,
                    },
                )
                .err()
                .unwrap();
            assert!(
                matches!(
                    error.downcast_ref::<ExecutionDenied>().unwrap().0,
                    Decision::PolicyRejected { .. }
                ),
                "{change}"
            );
        }
    }
    #[tokio::test]
    async fn approved_execution_checks_bindings_before_transport() {
        let mut op = super::tests::operation();
        op.method = "DELETE".into();
        op.risk = junction_core::OperationRisk::Destructive;
        op.path = "/users".into();
        op.parameters.clear();
        let policy = Policy::parse("[agent]\nmode='safe-write'").unwrap();
        let binding = junction_policy::approval::ApprovalContext::new(
            junction_core::cloud::MicrosoftCloud::Public,
            "https://example.invalid",
            "resource",
            "profile",
        )
        .unwrap();
        let executor = Executor::new(
            junction_registry::Registry::load(junction_core::RegistryManifest {
                format_version: 1,
                operations: vec![op.clone()],
                schemas: json!({}),
            })
            .unwrap(),
            policy.clone(),
        )
        .unwrap();
        let token = junction_auth::AccessToken::new(
            junction_auth::Secret::new("test-token".into()).unwrap(),
            junction_auth::TokenMetadata {
                tenant: "different-tenant".into(),
                audience: "resource".into(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        );
        for (endpoint, audience, tenant, input, expected) in [
            (
                "https://other.invalid",
                "resource",
                "tenant-a",
                json!({}),
                "approval_context_mismatch",
            ),
            (
                "https://example.invalid",
                "other",
                "tenant-a",
                json!({}),
                "approval_context_mismatch",
            ),
            (
                "https://example.invalid",
                "resource",
                "tenant-b",
                json!({}),
                "policy_rejected",
            ),
            (
                "https://example.invalid",
                "resource",
                "tenant-a",
                json!({"body":{}}),
                "policy_rejected",
            ),
            (
                "https://example.invalid",
                "resource",
                "tenant-a",
                json!({}),
                "credential_context_mismatch",
            ),
        ] {
            let grant = policy
                .issue_approval(
                    &op,
                    "tenant-a",
                    &json!({}),
                    &binding,
                    std::time::Duration::from_secs(60),
                )
                .unwrap();
            let error = executor
                .execute_with_approval(
                    &op.id,
                    input,
                    ExecutionContext {
                        tenant,
                        audience,
                        endpoint,
                        token: &token,
                    },
                    None,
                    false,
                    ApprovedExecution {
                        context: &binding,
                        grant,
                    },
                )
                .await
                .err()
                .unwrap();
            assert_eq!(error.to_string(), expected);
        }
    }
    #[tokio::test]
    async fn credential_mismatch_is_rejected_before_network_access() {
        let op: JunctionOperation=serde_json::from_value(json!({"id":"graph.users.list","product":"graph","service":"users","resource":"users","operation":"list","description":"","method":"GET","base_url":"https://example.invalid","path":"/users","parameters":[],"responses":{},"security":[],"risk":"read_only","preview":false,"source":{"id":"official","upstream":"official","operation_id":"Users_List"}})).unwrap();
        let registry = junction_registry::Registry::load(junction_core::RegistryManifest {
            format_version: 1,
            operations: vec![op],
            schemas: json!({}),
        })
        .unwrap();
        let executor = Executor::new(registry, Policy::default()).unwrap();
        let token = junction_auth::AccessToken::new(
            junction_auth::Secret::new("test-token".into()).unwrap(),
            junction_auth::TokenMetadata {
                tenant: "customer-b".into(),
                audience: "resource-a".into(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        );
        let error = executor
            .execute(
                "graph.users.list",
                json!({}),
                ExecutionContext {
                    tenant: "customer-a",
                    audience: "resource-a",
                    endpoint: "https://example.invalid",
                    token: &token,
                },
                None,
                false,
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "credential_context_mismatch");
    }
    #[test]
    fn pagination_preflight_enforces_json_bounds_and_policy_before_credentials() {
        let mut op = super::tests::operation();
        op.parameters.clear();
        op.path = "/users".into();
        let registry = junction_registry::Registry::load(junction_core::RegistryManifest {
            format_version: 1,
            operations: vec![op.clone()],
            schemas: json!({}),
        })
        .unwrap();
        let executor = Executor::new(registry, Policy::default()).unwrap();
        let options: PageOptions =
            serde_json::from_value(json!({"max_items":10,"max_pages":2})).unwrap();
        assert!(!options.allow_preview);
        executor
            .preflight_pages(&op.id, &json!({}), "a", "https://example.invalid", &options)
            .unwrap();
        for options in [
            PageOptions {
                max_items: 0,
                ..PageOptions::default()
            },
            PageOptions {
                max_pages: 21,
                ..PageOptions::default()
            },
            PageOptions {
                max_items: 10001,
                ..PageOptions::default()
            },
        ] {
            assert!(
                executor
                    .preflight_pages(&op.id, &json!({}), "a", "https://example.invalid", &options)
                    .is_err()
            );
        }
        assert!(serde_json::from_value::<PageOptions>(json!({"approved":true})).is_err());
        op.method = "POST".into();
        let registry = junction_registry::Registry::load(junction_core::RegistryManifest {
            format_version: 1,
            operations: vec![op.clone()],
            schemas: json!({}),
        })
        .unwrap();
        let executor = Executor::new(registry, Policy::default()).unwrap();
        let error = executor
            .preflight_pages(
                &op.id,
                &json!({"unknown":"secret"}),
                "a",
                "https://example.invalid",
                &PageOptions::default(),
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "policy_rejected");
    }
    #[tokio::test]
    async fn buffered_resume_rejects_changed_initial_or_named_operation_metadata() {
        let mut operation = super::tests::operation();
        operation.parameters.clear();
        operation.path = "/users".into();
        operation.pageable = Some(junction_core::Pageable {
            item_name: "value".into(),
            next_link_name: Some("nextLink".into()),
            operation_name: Some("Users_Next".into()),
        });
        let mut next = operation.clone();
        next.id = "graph.users.next".into();
        next.operation = "next".into();
        next.source.operation_id = "Users_Next".into();
        next.pageable = None;
        let executor = Executor::new(
            junction_registry::Registry::load(junction_core::RegistryManifest {
                format_version: 1,
                operations: vec![operation.clone(), next.clone()],
                schemas: json!({}),
            })
            .unwrap(),
            Policy::default(),
        )
        .unwrap();
        let token = junction_auth::AccessToken::new(
            junction_auth::Secret::new("test-token".into()).unwrap(),
            junction_auth::TokenMetadata {
                tenant: "a".into(),
                audience: "resource".into(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        );
        let context = ExecutionContext {
            tenant: "a",
            audience: "resource",
            endpoint: "https://example.invalid",
            token: &token,
        };
        let input = json!({});
        for change in ["none", "initial", "next", "legacy"] {
            let origin = prepare(
                &operation,
                &input,
                "a",
                context.endpoint,
                &Policy::default(),
            )
            .unwrap()
            .url;
            let mut pages =
                pagination::PageAccumulator::new(origin.clone(), 1, 2, &Policy::default().limits)
                    .unwrap();
            pages.begin_page(&origin).unwrap();
            let (_, result) = pages.accept(&json!({"value":[1,2]})).unwrap();
            let mut continuation = result.unwrap().continuation.unwrap();
            let mut old_operation = operation.clone();
            let mut old_next = next.clone();
            if change == "initial" {
                old_operation.description = "old metadata".into();
            }
            if change == "next" {
                old_next.description = "old metadata".into();
            }
            let identity = if change == "legacy" {
                serde_json::to_string(&(&input, &operation.api_version)).unwrap()
            } else {
                serde_json::to_string(&(&input, &old_operation, Some(&old_next))).unwrap()
            };
            continuation.binding = Some((
                operation.id.clone(),
                "a".into(),
                "resource".into(),
                identity,
            ));
            let result = executor
                .execute_pages_resuming(
                    &operation.id,
                    input.clone(),
                    context,
                    PageOptions {
                        max_items: 1,
                        max_pages: 2,
                        ..Default::default()
                    },
                    Some(continuation),
                )
                .await;
            if change == "none" {
                assert_eq!(result.unwrap().items, vec![json!(2)]);
            } else {
                assert_eq!(
                    result.err().unwrap().to_string(),
                    "continuation context mismatch"
                );
            }
        }
    }
    #[tokio::test]
    async fn resume_checks_binding_before_returning_buffered_records() {
        let registry = junction_registry::Registry::load(junction_core::RegistryManifest {
            format_version: 1,
            operations: vec![super::tests::operation()],
            schemas: json!({}),
        })
        .unwrap();
        let executor = Executor::new(registry, Policy::default()).unwrap();
        let token = junction_auth::AccessToken::new(
            junction_auth::Secret::new("test-token".into()).unwrap(),
            junction_auth::TokenMetadata {
                tenant: "a".into(),
                audience: "resource".into(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                scopes: vec![],
                roles: vec![],
                account: None,
            },
        );
        let input = json!({"parameters":{"id":"one"}});
        let context = ExecutionContext {
            tenant: "a",
            audience: "resource",
            endpoint: "https://example.invalid",
            token: &token,
        };
        for wrong_input in [false, true] {
            let origin = prepare(
                &super::tests::operation(),
                &input,
                "a",
                context.endpoint,
                &Policy::default(),
            )
            .unwrap()
            .url;
            let mut accumulator =
                pagination::PageAccumulator::new(origin.clone(), 1, 2, &Policy::default().limits)
                    .unwrap();
            accumulator.begin_page(&origin).unwrap();
            let (_, result) = accumulator.accept(&json!({"value":[1,2]})).unwrap();
            let mut continuation = result.unwrap().continuation.unwrap();
            continuation.binding = Some((
                "graph.users.get".into(),
                "a".into(),
                "resource".into(),
                serde_json::to_string(&(
                    &input,
                    &super::tests::operation(),
                    Option::<&JunctionOperation>::None,
                ))
                .unwrap(),
            ));
            let result = executor
                .execute_pages_resuming(
                    "graph.users.get",
                    if wrong_input {
                        json!({"parameters":{"id":"other"}})
                    } else {
                        input.clone()
                    },
                    context,
                    PageOptions {
                        max_items: 1,
                        max_pages: 2,
                        api_version: None,
                        allow_preview: false,
                    },
                    Some(continuation),
                )
                .await;
            if wrong_input {
                assert_eq!(
                    result.err().unwrap().to_string(),
                    "continuation context mismatch"
                );
            } else {
                let result = result.unwrap();
                assert_eq!(result.items, vec![json!(2)]);
                assert_eq!(result.pages, 0);
                assert!(result.continuation.is_none());
            }
        }
    }
    #[test]
    fn imported_swagger_body_references_are_enforced_before_execution() {
        let spec = json!({"swagger":"2.0","host":"management.azure.com","info":{"version":"2025-01-01"},"paths":{"/items":{"post":{"operationId":"Items_Create","parameters":[{"name":"item","in":"body","required":true,"schema":{"$ref":"#/definitions/Item"}}]}}},"definitions":{"Item":{"type":"object","required":["name"],"properties":{"name":{"type":"string","minLength":1}},"additionalProperties":false}}});
        let manifest = junction_discovery::ingest(&spec, "azure", "items", "official").unwrap();
        let registry = junction_registry::Registry::load(manifest).unwrap();
        let mut policy = Policy::default();
        policy.agent.mode = junction_policy::AgentMode::SafeWrite;
        let executor = Executor::new(registry, policy).unwrap();
        for input in [
            json!({}),
            json!({"body":{"name":""}}),
            json!({"body":{"unknown":"secret"}}),
        ] {
            assert!(
                executor
                    .preflight(
                        "azure.items.items.create",
                        &input,
                        "a",
                        "https://example.invalid",
                        None,
                        false
                    )
                    .is_err()
            );
        }
        executor
            .preflight(
                "azure.items.items.create",
                &json!({"body":{"name":"valid"}}),
                "a",
                "https://example.invalid",
                None,
                false,
            )
            .unwrap();
    }
    #[test]
    fn method_floor_prevents_manifest_risk_downgrade() {
        let op: JunctionOperation=serde_json::from_value(json!({"id":"graph.users.delete","product":"graph","service":"users","resource":"users","operation":"delete","description":"","method":"DELETE","base_url":"https://example.invalid","path":"/users","parameters":[],"responses":{},"security":[],"risk":"read_only","preview":false,"source":{"id":"official","upstream":"official","operation_id":"Users_Delete"}})).unwrap();
        assert_eq!(
            prepare(
                &op,
                &json!({}),
                "a",
                "https://example.invalid",
                &Policy::default()
            )
            .err()
            .unwrap()
            .to_string(),
            "policy_rejected"
        );
    }
}

pub mod pagination;

/// Bounded retrieval settings, independent of API parameters.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PageOptions {
    pub max_items: usize,
    pub max_pages: usize,
    pub api_version: Option<String>,
    pub allow_preview: bool,
}
impl Default for PageOptions {
    fn default() -> Self {
        Self {
            max_items: 100,
            max_pages: 5,
            api_version: None,
            allow_preview: false,
        }
    }
}
fn validate_credential(context: ExecutionContext<'_>) -> Result<()> {
    let metadata = context.token.metadata();
    if !metadata.tenant.eq_ignore_ascii_case(context.tenant)
        || metadata.audience != context.audience
    {
        bail!("credential_context_mismatch");
    }
    if metadata.expires_at <= std::time::SystemTime::now() + std::time::Duration::from_secs(60) {
        bail!("credential_expired");
    }
    Ok(())
}

pub mod batch;
