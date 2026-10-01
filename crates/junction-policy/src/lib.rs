//! Shared, fail-closed authorization and request admission for every runtime surface.
pub mod approval;
use anyhow::{Result, bail};
use junction_core::OperationRisk;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AgentMode {
    #[default]
    ReadOnly,
    SafeWrite,
    Full,
}
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Agent {
    pub mode: AgentMode,
}
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Deny {
    pub operations: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Allow {
    pub tenants: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_requests_per_minute: usize,
    pub max_pages: usize,
    pub max_parallel_requests: usize,
    pub max_batch_operations: usize,
    pub max_items: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_requests_per_minute: 100,
            max_pages: 20,
            max_parallel_requests: 10,
            max_batch_operations: 100,
            max_items: 10_000,
        }
    }
}
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub agent: Agent,
    pub deny: Deny,
    pub allow: Allow,
    pub limits: Limits,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Decision {
    Allowed,
    PolicyRejected { operation: String, reason: String },
    ApprovalRequired { operation: String, reason: String },
}
impl Policy {
    /// Authorize catalog risk and the HTTP method independently. Operator risk
    /// corrections cannot classify a mutation as a read or remove DELETE approval.
    pub fn authorize_operation(
        &self,
        operation: &junction_core::JunctionOperation,
        tenant: &str,
    ) -> Decision {
        let decision = self.authorize(&operation.id, &operation.risk, tenant);
        if decision != Decision::Allowed {
            return decision;
        }
        let floor = match operation.method.as_str() {
            "GET" | "HEAD" | "OPTIONS" => return Decision::Allowed,
            "DELETE" => OperationRisk::Destructive,
            _ => OperationRisk::Write,
        };
        self.authorize(&operation.id, &floor, tenant)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let policy: Self = toml::from_str(text)?;
        policy.validate()?;
        Ok(policy)
    }
    pub fn validate(&self) -> Result<()> {
        let l = &self.limits;
        if [
            l.max_requests_per_minute,
            l.max_pages,
            l.max_parallel_requests,
            l.max_batch_operations,
            l.max_items,
        ]
        .contains(&0)
        {
            bail!("policy limits must be positive");
        }
        for pattern in &self.deny.operations {
            if pattern.is_empty()
                || pattern
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '*')))
            {
                bail!("invalid operation deny pattern");
            }
        }
        if self
            .allow
            .tenants
            .iter()
            .any(|tenant| tenant.trim().is_empty())
        {
            bail!("tenant allow-list contains empty identifier");
        }
        Ok(())
    }
    /// Approval is a decision, never a boolean supplied by an agent. A future trusted
    /// approval store must bind approvals to tenant, operation and exact input.
    pub fn authorize(&self, operation: &str, risk: &OperationRisk, tenant: &str) -> Decision {
        let reject = |reason: &str| Decision::PolicyRejected {
            operation: operation.into(),
            reason: reason.into(),
        };
        if self.validate().is_err() {
            return reject("invalid policy configuration");
        }
        if !self.allow.tenants.is_empty()
            && !self
                .allow
                .tenants
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(tenant))
        {
            return reject("tenant is not allowed");
        }
        if self
            .deny
            .operations
            .iter()
            .any(|pattern| wildcard(pattern, operation))
        {
            return reject("operation matches deny rule");
        }
        match (self.agent.mode, risk) {
            (_, OperationRisk::ReadOnly)
            | (AgentMode::SafeWrite | AgentMode::Full, OperationRisk::Write) => Decision::Allowed,
            (AgentMode::ReadOnly, _) => reject("read-only mode forbids mutation"),
            (_, OperationRisk::Destructive | OperationRisk::Privileged) => {
                Decision::ApprovalRequired {
                    operation: operation.into(),
                    reason: "destructive or privileged operation requires trusted approval".into(),
                }
            }
        }
    }
}

// Linear greedy glob matcher; '*' spans components, so '*.delete' works as specified.
fn wildcard(pattern: &str, value: &str) -> bool {
    let (p, v) = (pattern.as_bytes(), value.as_bytes());
    let (mut pi, mut vi, mut star, mut retry) = (0, 0, None, 0);
    while vi < v.len() {
        if pi < p.len() && p[pi] == v[vi] {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            retry = vi;
        } else if let Some(s) = star {
            retry += 1;
            vi = retry;
            pi = s + 1;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[derive(Default)]
struct AdmissionState {
    requests: VecDeque<Instant>,
    active: usize,
}
/// Clone once per server/runtime, never once per request. Limits apply across clones.
#[derive(Clone)]
pub struct RequestGovernor {
    limits: Limits,
    state: Arc<Mutex<AdmissionState>>,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionError {
    RateLimited,
    ConcurrencyLimited,
    Unavailable,
}
pub struct RequestPermit {
    state: Arc<Mutex<AdmissionState>>,
}
impl RequestGovernor {
    pub fn new(policy: &Policy) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            limits: policy.limits.clone(),
            state: Arc::new(Mutex::new(AdmissionState::default())),
        })
    }
    /// Admit each physical HTTP attempt, including retries and pagination.
    pub fn admit(&self) -> std::result::Result<RequestPermit, AdmissionError> {
        self.admit_at(Instant::now())
    }
    fn admit_at(&self, now: Instant) -> std::result::Result<RequestPermit, AdmissionError> {
        let mut state = self.state.lock().map_err(|_| AdmissionError::Unavailable)?;
        while state
            .requests
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= Duration::from_secs(60))
        {
            state.requests.pop_front();
        }
        if state.requests.len() >= self.limits.max_requests_per_minute {
            return Err(AdmissionError::RateLimited);
        }
        if state.active >= self.limits.max_parallel_requests {
            return Err(AdmissionError::ConcurrencyLimited);
        }
        state.requests.push_back(now);
        state.active += 1;
        Ok(RequestPermit {
            state: self.state.clone(),
        })
    }
}
impl Drop for RequestPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.active = state.active.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modes_and_approvals_cannot_override_denies() {
        let policy = Policy::parse("[agent]\nmode='full'\n[deny]\noperations=['*.delete']\n[allow]\ntenants=['customer-a']").unwrap();
        assert!(matches!(
            policy.authorize(
                "graph.users.delete",
                &OperationRisk::Destructive,
                "customer-a"
            ),
            Decision::PolicyRejected { .. }
        ));
        assert!(matches!(
            policy.authorize("graph.users.list", &OperationRisk::ReadOnly, "customer-b"),
            Decision::PolicyRejected { .. }
        ));
        assert!(matches!(
            policy.authorize(
                "graph.identity.update",
                &OperationRisk::Privileged,
                "customer-a"
            ),
            Decision::ApprovalRequired { .. }
        ));
        assert_eq!(
            policy.authorize("graph.users.create", &OperationRisk::Write, "customer-a"),
            Decision::Allowed
        );
        assert!(matches!(
            Policy::default().authorize("graph.users.create", &OperationRisk::Write, "a"),
            Decision::PolicyRejected { .. }
        ));
    }
    #[test]
    fn malformed_policy_fails_closed() {
        assert!(Policy::parse("[limits]\nmax_pages=0").is_err());
        assert!(Policy::parse("[agent]\nmode='unsafe'").is_err());
        assert!(Policy::parse("[agent]\nmod='full'").is_err());
    }
    #[test]
    fn wildcard_matching() {
        assert!(wildcard("*.delete", "azure.compute.vm.delete"));
        assert!(wildcard("graph.identity.*", "graph.identity.update"));
        assert!(!wildcard("*.delete", "graph.users.delete_all"));
        assert!(wildcard("*a*b", "aaab"));
        assert!(!wildcard("*a*b", "aaa"));
    }
    #[test]
    fn global_limits_and_permit_release() {
        let mut policy = Policy::default();
        policy.limits.max_parallel_requests = 1;
        policy.limits.max_requests_per_minute = 2;
        let governor = RequestGovernor::new(&policy).unwrap();
        let clone = governor.clone();
        let now = Instant::now();
        let permit = governor.admit_at(now).unwrap();
        assert!(matches!(
            clone.admit_at(now),
            Err(AdmissionError::ConcurrencyLimited)
        ));
        drop(permit);
        drop(clone.admit_at(now).unwrap());
        assert!(matches!(
            governor.admit_at(now),
            Err(AdmissionError::RateLimited)
        ));
        assert!(governor.admit_at(now + Duration::from_secs(60)).is_ok());
    }
}
