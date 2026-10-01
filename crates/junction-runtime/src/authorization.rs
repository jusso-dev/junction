//! Safe authorization diagnostics. Upstream bodies, request URLs and credential values are excluded.
use junction_core::JunctionOperation;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AuthorizationFailure {
    pub status: &'static str,
    pub http_status: u16,
    pub operation: String,
    pub audience: String,
    pub authentication: &'static str,
    /// Imported OAuth scope requirements; null means unavailable, not unrestricted access.
    pub required_permissions: Option<Vec<Vec<String>>>,
    pub documentation_url: Option<String>,
    pub correlation: junction_http::CorrelationIds,
    pub detected_scopes: Vec<String>,
    pub detected_roles: Vec<String>,
    pub remediation: &'static str,
}
impl std::fmt::Display for AuthorizationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.status)
    }
}
impl std::error::Error for AuthorizationFailure {}

pub(crate) fn enrich(
    error: anyhow::Error,
    operation: &JunctionOperation,
    context: crate::ExecutionContext<'_>,
) -> anyhow::Error {
    let Some(failure) = error
        .downcast_ref::<junction_http::HttpStatusError>()
        .filter(|error| matches!(error.status, 401 | 403))
    else {
        return error;
    };
    let status = failure.status;
    let correlation = failure.correlation.clone();
    AuthorizationFailure {
        status: "authorization_failed", http_status: status, operation: operation.id.clone(),
        audience: context.audience.to_owned(), authentication: "bearer",
        required_permissions: operation.required_permissions(),
        documentation_url: operation.documentation().map(str::to_owned),
        correlation,
        detected_scopes: context.token.metadata().scopes.clone(), detected_roles: context.token.metadata().roles.clone(),
        remediation: if status == 401 { "Check token expiry, issuer, tenant and resource audience; reacquire credentials for this context." }
            else { "Check the service's documented permissions, consent, RBAC and resource-specific access policies; Junction does not grant permissions." },
    }.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn authorization_diagnostics_preserve_alternatives_and_omit_credentials() {
        let mut operation = crate::tests::operation();
        operation.security = json!([{"oauth":["read","write"]},{"oauth":["admin"]}]);
        operation.documentation_url =
            Some("https://learn.microsoft.com/graph/api/user-list".into());
        let token = junction_auth::AccessToken::new(
            junction_auth::Secret::new("secret-access-token".into()).unwrap(),
            junction_auth::TokenMetadata {
                tenant: "a".into(),
                audience: "resource".into(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                scopes: vec!["read".into()],
                roles: vec!["Reader".into()],
                account: None,
            },
        );
        let context = crate::ExecutionContext {
            tenant: "a",
            audience: "resource",
            endpoint: "https://example.invalid",
            token: &token,
        };
        for status in [401, 403] {
            let error = enrich(
                junction_http::HttpStatusError {
                    correlation: junction_http::CorrelationIds {
                        client_request_id: Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into()),
                        ..Default::default()
                    },
                    status,
                    retry_after: None,
                }
                .into(),
                &operation,
                context,
            );
            let failure = error.downcast_ref::<AuthorizationFailure>().unwrap();
            let value = serde_json::to_value(failure).unwrap();
            assert_eq!(
                value["required_permissions"],
                json!([["read", "write"], ["admin"]])
            );
            assert_eq!(value["detected_scopes"], json!(["read"]));
            assert_eq!(value["http_status"], status);
            assert_eq!(
                value["correlation"]["client_request_id"],
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            );
            assert_eq!(
                value["documentation_url"],
                operation.documentation_url.as_deref().unwrap()
            );
            assert!(!value.to_string().contains("secret-access-token"));
        }
        operation.security = json!([]);
        operation.documentation_url =
            Some("https://learn.microsoft.com/graph?token=secret-doc-token".into());
        let error = enrich(
            junction_http::HttpStatusError {
                correlation: junction_http::CorrelationIds::default(),
                status: 403,
                retry_after: None,
            }
            .into(),
            &operation,
            context,
        );
        assert!(
            error
                .downcast_ref::<AuthorizationFailure>()
                .unwrap()
                .required_permissions
                .is_none()
        );
        let failure = error.downcast_ref::<AuthorizationFailure>().unwrap();
        assert!(failure.documentation_url.is_none());
        assert!(
            !serde_json::to_string(failure)
                .unwrap()
                .contains("secret-doc-token")
        );
        let error = enrich(
            junction_http::HttpStatusError {
                correlation: junction_http::CorrelationIds::default(),
                status: 500,
                retry_after: None,
            }
            .into(),
            &operation,
            context,
        );
        assert!(
            error
                .downcast_ref::<junction_http::HttpStatusError>()
                .is_some()
        );
    }
}
