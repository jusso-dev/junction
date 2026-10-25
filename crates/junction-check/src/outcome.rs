//! Turn a failed API call into an honest result: missing licence gives
//! `not_applicable`, missing permission gives `unknown` with the permission to
//! grant, and nothing ever becomes a false pass or fail.
//!
//! Classification is shared with `junction-watch` (`capability::classify`).
use crate::check::CheckMeta;
use crate::context::CallFailure;
use crate::gateway::GatewayError;
use crate::model::{Reason, Status};
use junction_watch::capability::{Reason as Cause, classify};

/// Status and reason for a failed call made by the check `meta`.
pub fn from_failure(meta: &CheckMeta, failure: &CallFailure) -> (Status, Reason) {
    let operation = failure.operation.as_str();
    match &failure.error {
        GatewayError::Denied(detail) => (
            Status::Unknown,
            Reason::new(
                "policy_denied",
                format!("Junction's read-only policy refused {operation}: {detail}"),
            ),
        ),
        GatewayError::Unavailable(detail) => (
            Status::Unknown,
            Reason::new(
                "unavailable",
                format!("{operation} could not be called: {detail}"),
            ),
        ),
        GatewayError::Call(error) => {
            let mut cause = classify(error, None);
            // A bare 403 from Defender or ARM (no Graph error code) is still an
            // authorisation refusal: name the permission rather than "unclassified".
            if cause == Cause::Unclassified && error.status == Some(403) {
                cause = Cause::MissingPermission;
            }
            if cause == Cause::Unclassified && licence_hint(error.message.as_deref()) {
                cause = Cause::LicenceRequired;
            }
            let mut permissions = meta.requires.permissions_for(operation);
            if permissions.is_empty() {
                permissions = crate::catalog::required_permissions(operation);
            }
            let status = match cause {
                Cause::LicenceRequired => Status::NotApplicable,
                _ => Status::Unknown,
            };
            let detail = match cause {
                Cause::MissingPermission | Cause::AccessDeniedDespitePermission
                    if !permissions.is_empty() =>
                {
                    format!(
                        "{operation} was refused ({}). Grant {} (read-only) and re-run.",
                        error.summary(),
                        permissions.join(" or ")
                    )
                }
                _ => format!("{operation}: {}. {}", error.summary(), cause.remedy()),
            };
            let mut reason = Reason::new(cause.as_str(), detail);
            if matches!(
                cause,
                Cause::MissingPermission | Cause::AccessDeniedDespitePermission
            ) {
                reason.missing_permissions = permissions;
            }
            (status, reason)
        }
    }
}

/// Licence wording some APIs use without a documented error code.
fn licence_hint(message: Option<&str>) -> bool {
    let m = message.unwrap_or_default().to_ascii_lowercase();
    m.contains("not licensed")
        || m.contains("license is required")
        || m.contains("licence is required")
        || m.contains("tenant is not provisioned")
        || m.contains("not onboarded")
}

/// Codes for `unknown` results that mean "a person has not answered yet",
/// rather than "the check could not run".
pub const AWAITING_ANSWER: &[&str] = &["not_attested", "attestation_expired"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{ApiRequirement, Requirements};
    use crate::gateway::{CallError, FailureKind};
    use crate::model::{CheckKind, Level, Pack, Severity};

    const META: CheckMeta = CheckMeta {
        id: "endpoint.example",
        title: "Example",
        pack: Pack::Endpoint,
        kind: CheckKind::Automated,
        severity: Severity::High,
        effort: Level::Low,
        impact: Level::High,
        description: "",
        requires: Requirements {
            apis: &[ApiRequirement {
                operation: "defender.endpoint.machines.list",
                permissions: &["Machine.Read.All"],
            }],
            licences: &[],
        },
        remediation: "",
        links: &[],
        references: &[],
        manual: None,
    };

    fn failure(error: CallError) -> CallFailure {
        CallFailure {
            operation: "defender.endpoint.machines.list".into(),
            error: GatewayError::Call(error),
        }
    }

    #[test]
    fn forbidden_names_the_missing_permission() {
        let (status, reason) = from_failure(
            &META,
            &failure(CallError::http(403, Some("Forbidden"), None)),
        );
        assert_eq!(status, Status::Unknown);
        assert_eq!(reason.code, "missing_permission");
        assert_eq!(reason.missing_permissions, ["Machine.Read.All"]);
        assert!(reason.detail.contains("Grant Machine.Read.All"));
    }

    #[test]
    fn licence_errors_are_not_applicable() {
        let (status, reason) = from_failure(
            &META,
            &failure(CallError::http(
                403,
                Some("Authentication_RequestFromNonPremiumTenantOrB2CTenant"),
                None,
            )),
        );
        assert_eq!(
            (status, reason.code.as_str()),
            (Status::NotApplicable, "licence_required")
        );
        let (status, _) = from_failure(
            &META,
            &failure(CallError::http(
                400,
                None,
                Some("The tenant is not provisioned for this service"),
            )),
        );
        assert_eq!(status, Status::NotApplicable);
    }

    #[test]
    fn transport_and_policy_failures_are_unknown() {
        for error in [
            GatewayError::Call(CallError::other(FailureKind::Transport, "timeout")),
            GatewayError::Denied("read-only".into()),
            GatewayError::Unavailable("offline".into()),
            GatewayError::Call(CallError::http(500, None, None)),
        ] {
            let (status, _) = from_failure(
                &META,
                &CallFailure {
                    operation: "x".into(),
                    error,
                },
            );
            assert_eq!(status, Status::Unknown);
        }
    }
}
