//! Licence- and permission-aware capability model.
//!
//! A source's state comes only from a real, non-destructive probe. Subscription
//! names are shown as context but never decide entitlement, and a 403 is not
//! assumed to mean "needs a licence": the error code decides.
use crate::upstream::{CallError, FailureKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityState {
    Available,
    AvailableWithLimitations,
    RequiresPermission,
    RequiresLicence,
    NotEnabled,
    Unsupported,
    TemporarilyUnavailable,
    Unknown,
}

impl CapabilityState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "AVAILABLE",
            Self::AvailableWithLimitations => "AVAILABLE_WITH_LIMITATIONS",
            Self::RequiresPermission => "REQUIRES_PERMISSION",
            Self::RequiresLicence => "REQUIRES_LICENCE",
            Self::NotEnabled => "NOT_ENABLED",
            Self::Unsupported => "UNSUPPORTED",
            Self::TemporarilyUnavailable => "TEMPORARILY_UNAVAILABLE",
            Self::Unknown => "UNKNOWN",
        }
    }
    pub fn parse(value: &str) -> Self {
        match value {
            "AVAILABLE" => Self::Available,
            "AVAILABLE_WITH_LIMITATIONS" => Self::AvailableWithLimitations,
            "REQUIRES_PERMISSION" => Self::RequiresPermission,
            "REQUIRES_LICENCE" => Self::RequiresLicence,
            "NOT_ENABLED" => Self::NotEnabled,
            "UNSUPPORTED" => Self::Unsupported,
            "TEMPORARILY_UNAVAILABLE" => Self::TemporarilyUnavailable,
            _ => Self::Unknown,
        }
    }
    /// Collectors may run against this source.
    pub fn usable(self) -> bool {
        matches!(self, Self::Available | Self::AvailableWithLimitations)
    }
    /// Polling again before an operator re-test (or the daily re-probe) only adds
    /// load: the answer will not change on its own.
    pub fn is_settled_negative(self) -> bool {
        matches!(
            self,
            Self::RequiresPermission | Self::RequiresLicence | Self::Unsupported | Self::NotEnabled
        )
    }
}

/// Why a probe landed in its state. Kept separate from the state because several
/// distinct causes share one state and operators need the cause to fix it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Ok,
    CredentialRejected,
    MissingPermission,
    /// The app role is granted but access was still denied (admin role scoping,
    /// tenant restriction or resource-specific policy).
    AccessDeniedDespitePermission,
    ConditionalAccessBlocked,
    LicenceRequired,
    SubscriptionNotStarted,
    SubscriptionDisabled,
    AuditingDisabled,
    UnsupportedOperation,
    Throttled,
    ServiceError,
    NetworkError,
    Unclassified,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::CredentialRejected => "credential_rejected",
            Self::MissingPermission => "missing_permission",
            Self::AccessDeniedDespitePermission => "access_denied_despite_permission",
            Self::ConditionalAccessBlocked => "conditional_access_blocked",
            Self::LicenceRequired => "licence_required",
            Self::SubscriptionNotStarted => "subscription_not_started",
            Self::SubscriptionDisabled => "subscription_disabled",
            Self::AuditingDisabled => "auditing_disabled",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::Throttled => "throttled",
            Self::ServiceError => "service_error",
            Self::NetworkError => "network_error",
            Self::Unclassified => "unclassified",
        }
    }
    pub fn state(self) -> CapabilityState {
        use CapabilityState as S;
        match self {
            Self::Ok => S::Available,
            Self::MissingPermission | Self::AccessDeniedDespitePermission => S::RequiresPermission,
            Self::LicenceRequired => S::RequiresLicence,
            Self::SubscriptionNotStarted | Self::SubscriptionDisabled | Self::AuditingDisabled => {
                S::NotEnabled
            }
            Self::UnsupportedOperation => S::Unsupported,
            Self::Throttled | Self::ServiceError | Self::NetworkError => S::TemporarilyUnavailable,
            // Neither a permission nor a licence problem; the reason says what to fix.
            Self::CredentialRejected | Self::ConditionalAccessBlocked | Self::Unclassified => {
                S::Unknown
            }
        }
    }
    /// Plain-English next step for the coverage page.
    pub fn remedy(self) -> &'static str {
        match self {
            Self::Ok => "No action needed.",
            Self::CredentialRejected => {
                "The app credential was rejected. Check the certificate is registered on the app and has not expired, and that admin consent was granted."
            }
            Self::MissingPermission => {
                "Grant the listed application permission in Entra ID and give admin consent, then re-test."
            }
            Self::AccessDeniedDespitePermission => {
                "The permission is granted but Microsoft still denied access. Check directory role assignments and tenant restrictions for the app."
            }
            Self::ConditionalAccessBlocked => {
                "A Conditional Access policy blocked the app. Review workload identity policies for this app."
            }
            Self::LicenceRequired => {
                "This source needs a licence the tenant does not have. Dependent detections are switched off; everything else keeps running."
            }
            Self::SubscriptionNotStarted => {
                "The audit feed subscription has not been started. Use Start audit feeds on this page or run `junction watch subscribe`. It only turns on delivery of audit data; no tenant settings change."
            }
            Self::SubscriptionDisabled => {
                "The feed subscription is disabled. Restart it with Start audit feeds or `junction watch subscribe`, and check audit logging is on."
            }
            Self::AuditingDisabled => {
                "Unified audit logging appears to be off for the tenant. Turn on auditing in the Microsoft Purview portal, then re-test (it can take hours to start)."
            }
            Self::UnsupportedOperation => {
                "Microsoft does not support this query for the tenant. Dependent detections are switched off."
            }
            Self::Throttled => "Microsoft throttled the request. It will be retried automatically.",
            Self::ServiceError => {
                "Microsoft returned a server error. It will be retried automatically."
            }
            Self::NetworkError => {
                "The request did not reach Microsoft. Check the network; it will be retried."
            }
            Self::Unclassified => "The response was not recognised. Re-test, and check the detail.",
        }
    }
}

/// Classify a failed probe. `has_role` says whether the token carries the app role
/// the source requires (None if unknown).
pub fn classify(error: &CallError, has_role: Option<bool>) -> Reason {
    match error.kind {
        FailureKind::Credential => {
            let message = error.message.as_deref().unwrap_or_default();
            if message.contains("AADSTS53003") || message.contains("AADSTS53000") {
                Reason::ConditionalAccessBlocked
            } else if error.status.is_some_and(|s| s >= 500) {
                Reason::ServiceError
            } else {
                // Includes local configuration problems (missing env var or key file).
                Reason::CredentialRejected
            }
        }
        FailureKind::LocalThrottle => Reason::Throttled,
        FailureKind::Transport => Reason::NetworkError,
        FailureKind::Malformed => Reason::Unclassified,
        FailureKind::Http => classify_http(
            error.status.unwrap_or(0),
            error.code.as_deref().unwrap_or_default(),
            error.message.as_deref().unwrap_or_default(),
            has_role,
        ),
    }
}

fn classify_http(status: u16, code: &str, message: &str, has_role: Option<bool>) -> Reason {
    // Codes first: they are documented contracts, messages are not.
    // Management Activity API codes: learn.microsoft.com/office/office-365-management-api/
    // office-365-management-activity-api-reference#errors
    if code.starts_with("Authentication_RequestFromNonPremiumTenant")
        || code == "Authentication_RequestFromUnsupportedUserRole"
        || message.contains("doesn't have premium license")
    {
        return Reason::LicenceRequired;
    }
    match code {
        "AF20022" => return Reason::SubscriptionNotStarted,
        "AF20023" => return Reason::SubscriptionDisabled,
        "AF10001" => return Reason::MissingPermission,
        // Throttling is a 403 with AF429 on this API, not a 429.
        "AF429" => return Reason::Throttled,
        "AF50000" => return Reason::ServiceError,
        "Request_UnsupportedQuery" | "BadRequest_UnsupportedQuery" => {
            return Reason::UnsupportedOperation;
        }
        _ => {}
    }
    // With unified auditing off the API reports the tenant as missing (troubleshooting
    // guide); AF20011 is the documented code for an unknown tenant.
    if code == "AF20011"
        || (message.contains("DataServiceException") && message.contains("does not exist"))
    {
        return Reason::AuditingDisabled;
    }
    if message.contains("AADSTS53003") {
        return Reason::ConditionalAccessBlocked;
    }
    match status {
        401 => Reason::CredentialRejected,
        403 => match has_role {
            Some(true) => Reason::AccessDeniedDespitePermission,
            Some(false) => Reason::MissingPermission,
            None if code == "Authorization_RequestDenied" => Reason::MissingPermission,
            None => Reason::Unclassified,
        },
        404 | 405 | 501 => Reason::UnsupportedOperation,
        408 | 429 => Reason::Throttled,
        500..=599 => Reason::ServiceError,
        _ => Reason::Unclassified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(status: u16, code: &str) -> CallError {
        CallError::http(status, (!code.is_empty()).then_some(code), None)
    }

    #[test]
    fn forbidden_is_not_automatically_a_licence_problem() {
        assert_eq!(
            classify(&http(403, ""), Some(false)),
            Reason::MissingPermission
        );
        assert_eq!(
            classify(&http(403, ""), Some(true)),
            Reason::AccessDeniedDespitePermission
        );
        assert_eq!(classify(&http(403, ""), None), Reason::Unclassified);
        assert_eq!(
            classify(&http(403, "Authorization_RequestDenied"), None),
            Reason::MissingPermission
        );
        let licence = classify(
            &http(403, "Authentication_RequestFromNonPremiumTenant"),
            Some(true),
        );
        assert_eq!(licence, Reason::LicenceRequired);
        assert_eq!(licence.state(), CapabilityState::RequiresLicence);
        let mut ca = http(403, "");
        ca.message = Some("AADSTS53003: Access has been blocked by Conditional Access".into());
        assert_eq!(classify(&ca, Some(true)), Reason::ConditionalAccessBlocked);
        assert_eq!(
            Reason::ConditionalAccessBlocked.state(),
            CapabilityState::Unknown
        );
    }

    #[test]
    fn management_codes_and_transients() {
        assert_eq!(
            classify(&http(400, "AF20022"), None).state(),
            CapabilityState::NotEnabled
        );
        assert_eq!(
            classify(&http(400, "AF20023"), None),
            Reason::SubscriptionDisabled
        );
        assert_eq!(
            classify(&http(401, "AF10001"), None),
            Reason::MissingPermission
        );
        assert_eq!(classify(&http(403, "AF429"), Some(true)), Reason::Throttled);
        assert_eq!(
            classify(&http(400, "AF20011"), None),
            Reason::AuditingDisabled
        );
        let mut off = http(400, "");
        off.message = Some(
            "Microsoft.Office.Compliance.Audit.DataServiceException: Tenant 1 does not exist."
                .into(),
        );
        assert_eq!(classify(&off, None).state(), CapabilityState::NotEnabled);
        let mut premium = http(403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant");
        assert_eq!(classify(&premium, Some(true)), Reason::LicenceRequired);
        premium.code = None;
        premium.message =
            Some("Neither tenant is B2C or tenant doesn't have premium license".into());
        assert_eq!(classify(&premium, Some(true)), Reason::LicenceRequired);
        assert_eq!(classify(&http(401, ""), None), Reason::CredentialRejected);
        assert_eq!(
            classify(&http(429, ""), None).state(),
            CapabilityState::TemporarilyUnavailable
        );
        assert_eq!(
            classify(&http(503, ""), None).state(),
            CapabilityState::TemporarilyUnavailable
        );
        assert_eq!(
            classify(&http(404, ""), None).state(),
            CapabilityState::Unsupported
        );
        assert_eq!(
            classify(&CallError::other(FailureKind::Transport, "x"), None),
            Reason::NetworkError
        );
        assert_eq!(
            classify(&CallError::other(FailureKind::Credential, "x"), None),
            Reason::CredentialRejected
        );
    }

    #[test]
    fn state_round_trip_and_settling() {
        for s in [
            CapabilityState::Available,
            CapabilityState::AvailableWithLimitations,
            CapabilityState::RequiresPermission,
            CapabilityState::RequiresLicence,
            CapabilityState::NotEnabled,
            CapabilityState::Unsupported,
            CapabilityState::TemporarilyUnavailable,
            CapabilityState::Unknown,
        ] {
            assert_eq!(CapabilityState::parse(s.as_str()), s);
        }
        assert!(CapabilityState::RequiresLicence.is_settled_negative());
        assert!(!CapabilityState::TemporarilyUnavailable.is_settled_negative());
        assert!(!CapabilityState::RequiresLicence.usable());
    }
}
