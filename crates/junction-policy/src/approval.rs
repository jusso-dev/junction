//! Trusted operator grants. No grant can be deserialized from agent input.
use crate::{Decision, Policy};
use anyhow::{Result, bail};
use junction_core::JunctionOperation;
use serde_json::Value;
use std::time::{Duration, Instant};

/// Explicit trusted destination/credential binding; cannot be supplied as a grant.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalContext {
    cloud: junction_core::cloud::MicrosoftCloud,
    endpoint: String,
    audience: String,
    credential_profile: String,
}
impl ApprovalContext {
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn new(
        cloud: junction_core::cloud::MicrosoftCloud,
        endpoint: &str,
        audience: &str,
        credential_profile: &str,
    ) -> Result<Self> {
        let url =
            url::Url::parse(endpoint).map_err(|_| anyhow::anyhow!("invalid approval endpoint"))?;
        if endpoint.len() > 4096
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || [audience, credential_profile].iter().any(|value| {
                value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control)
            })
        {
            bail!("invalid approval context");
        }
        Ok(Self {
            cloud,
            endpoint: url.to_string(),
            audience: audience.into(),
            credential_profile: credential_profile.into(),
        })
    }
}

/// Single-use capability: private fields, no Clone, Debug, Serialize or Deserialize.
/// Issuance must remain in the trusted operator boundary, outside agent tools.
pub struct ApprovalGrant {
    tenant: String,
    context: ApprovalContext,
    input: Value,
    operation: Value,
    policy: Value,
    deadline: Instant,
}
impl Policy {
    /// Explicit trusted approval for this exact request, valid for at most five minutes.
    /// Context must identify cloud, endpoint, audience and credential profile.
    pub fn issue_approval(
        &self,
        operation: &JunctionOperation,
        tenant: &str,
        input: &Value,
        context: &ApprovalContext,
        lifetime: Duration,
    ) -> Result<ApprovalGrant> {
        if !matches!(
            self.authorize_operation(operation, tenant),
            Decision::ApprovalRequired { .. }
        ) {
            bail!("request does not qualify for trusted approval");
        }
        if tenant.is_empty()
            || !tenant
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
            || ["common", "organizations", "consumers"]
                .contains(&tenant.to_ascii_lowercase().as_str())
            || lifetime.is_zero()
            || lifetime > Duration::from_secs(300)
        {
            bail!("invalid approval binding or lifetime");
        }
        if serde_json::to_vec(input)?.len() > 128 * 1024 {
            bail!("approval input size limit exceeded");
        }
        Ok(ApprovalGrant {
            tenant: tenant.to_ascii_lowercase(),
            context: context.clone(),
            input: input.clone(),
            operation: serde_json::to_value(operation)?,
            policy: serde_json::to_value(self)?,
            deadline: Instant::now() + lifetime,
        })
    }
    /// Consume the capability by value. Policy rejections can never be overridden.
    pub fn authorize_with_approval(
        &self,
        operation: &JunctionOperation,
        tenant: &str,
        input: &Value,
        context: &ApprovalContext,
        grant: ApprovalGrant,
    ) -> Result<Decision> {
        let decision = self.authorize_operation(operation, tenant);
        if !matches!(decision, Decision::ApprovalRequired { .. }) {
            return Ok(decision);
        }
        if Instant::now() >= grant.deadline
            || grant.tenant != tenant.to_ascii_lowercase()
            || grant.context != *context
            || grant.input != *input
            || grant.operation != serde_json::to_value(operation)?
            || grant.policy != serde_json::to_value(self)?
        {
            return Ok(Decision::PolicyRejected {
                operation: operation.id.clone(),
                reason: "approval expired or request binding changed".into(),
            });
        }
        Ok(Decision::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn operation() -> JunctionOperation {
        serde_json::from_value(json!({"id":"azure.compute.virtual_machines.delete",
            "product":"azure","service":"compute","resource":"virtual_machines","operation":"delete",
            "description":"","method":"DELETE","base_url":"https://management.azure.com",
            "path":"/vms/{id}","parameters":[],"responses":{},"security":[],"risk":"destructive",
            "preview":false,"source":{"id":"official","upstream":"official","operation_id":"VirtualMachines_Delete"}
        })).unwrap()
    }
    #[test]
    fn context_requires_a_plain_https_destination_and_credential_binding() {
        use junction_core::cloud::MicrosoftCloud;
        for endpoint in [
            "http://example.com",
            "https://user:password@example.com",
            "https://example.com?key=private",
            "https://example.com#fragment",
            "invalid",
        ] {
            assert!(
                ApprovalContext::new(MicrosoftCloud::Public, endpoint, "resource", "profile")
                    .is_err()
            );
        }
        for (audience, profile) in [
            ("", "profile"),
            ("resource", ""),
            ("private\nresource", "profile"),
        ] {
            assert!(
                ApprovalContext::new(
                    MicrosoftCloud::Public,
                    "https://example.com",
                    audience,
                    profile
                )
                .is_err()
            );
        }
        let context = ApprovalContext::new(
            MicrosoftCloud::Public,
            "https://example.com",
            "resource",
            "profile",
        )
        .unwrap();
        let policy = Policy::parse("[agent]\nmode='safe-write'").unwrap();
        for tenant in ["", "common", "ORGANIZATIONS", "consumers", "tenant/private"] {
            assert!(
                policy
                    .issue_approval(
                        &operation(),
                        tenant,
                        &json!({}),
                        &context,
                        Duration::from_secs(60)
                    )
                    .is_err()
            );
        }
        assert!(
            policy
                .issue_approval(
                    &operation(),
                    "tenant-a",
                    &json!("x".repeat(128 * 1024)),
                    &context,
                    Duration::from_secs(60)
                )
                .is_err()
        );
    }
    #[test]
    fn approval_is_exact_expiring_and_cannot_override_denial() {
        let policy = Policy::parse("[agent]\nmode='safe-write'").unwrap();
        let operation = operation();
        let input = json!({"parameters":{"id":"vm-a"}});
        let context = ApprovalContext::new(
            junction_core::cloud::MicrosoftCloud::Public,
            "https://management.azure.com",
            "https://management.azure.com/",
            "profile-a",
        )
        .unwrap();
        for change in [
            "none",
            "tenant",
            "input",
            "context",
            "cloud",
            "endpoint",
            "audience",
            "operation",
            "policy",
            "expiry",
            "deny",
            "readonly",
        ] {
            let mut grant = policy
                .issue_approval(
                    &operation,
                    "tenant-a",
                    &input,
                    &context,
                    Duration::from_secs(60),
                )
                .unwrap();
            let mut selected = operation.clone();
            let mut current = policy.clone();
            let mut actual_input = input.clone();
            let mut tenant = "tenant-a";
            let mut actual_context = context.clone();
            match change {
                "tenant" => tenant = "tenant-b",
                "input" => actual_input["parameters"]["id"] = json!("vm-b"),
                "context" => actual_context.credential_profile = "profile-b".into(),
                "cloud" => actual_context.cloud = junction_core::cloud::MicrosoftCloud::China,
                "endpoint" => actual_context.endpoint = "https://other.example/".into(),
                "audience" => actual_context.audience = "other-resource".into(),
                "operation" => selected.path = "/other/{id}".into(),
                "policy" => current.limits.max_pages += 1,
                "expiry" => grant.deadline = Instant::now(),
                "deny" => current.deny.operations.push("*.delete".into()),
                "readonly" => current.agent.mode = crate::AgentMode::ReadOnly,
                _ => {}
            }
            let decision = current
                .authorize_with_approval(&selected, tenant, &actual_input, &actual_context, grant)
                .unwrap();
            assert_eq!(decision == Decision::Allowed, change == "none", "{change}");
        }
        assert!(
            Policy::default()
                .issue_approval(
                    &operation,
                    "tenant-a",
                    &input,
                    &context,
                    Duration::from_secs(60)
                )
                .is_err()
        );
        for lifetime in [Duration::ZERO, Duration::from_secs(301)] {
            assert!(
                policy
                    .issue_approval(&operation, "tenant-a", &input, &context, lifetime)
                    .is_err()
            );
        }
    }
}
