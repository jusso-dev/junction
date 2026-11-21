//! MFA registration and phishing-resistant methods for users and admins.
use super::ca::{self, Strengths};
use super::{
    AUTH_STRENGTHS, CA_POLICIES, GROUP_MEMBERS, PRIVILEGED_ROLES, REGISTRATION, ROLE_ASSIGNMENTS,
    USERS, ca_policies, enabled_users, full_list, percent, plural, privileged_users,
    registration_details, str_of,
};
use crate::check::{ApiRequirement, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::CheckContext;
use crate::model::{CheckKind, Level, Pack, Severity};
use serde_json::{Value, json};

const AUTH_METHODS: ApiRequirement = ApiRequirement {
    operation: "graph.users.authentication.methods.list",
    permissions: &["UserAuthenticationMethod.Read.All"],
};

/// `methodsRegistered` values that are phishing-resistant (lower case).
const PHISHING_RESISTANT_REGISTERED: &[&str] = &[
    "fido2",
    "fido2securitykey",
    "passkeydevicebound",
    "passkeydeviceboundauthenticator",
    "passkeydeviceboundwindowshello",
    "windowshelloforbusiness",
    "macossecureenclavekey",
    "platformcredential",
    "x509certificate",
    "x509certificatemultifactor",
];

/// `/users/{id}/authentication/methods` types that satisfy MFA.
const MFA_METHOD_TYPES: &[&str] = &[
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
    "#microsoft.graph.phoneAuthenticationMethod",
    "#microsoft.graph.fido2AuthenticationMethod",
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
    "#microsoft.graph.softwareOathAuthenticationMethod",
    "#microsoft.graph.hardwareOathAuthenticationMethod",
    "#microsoft.graph.platformCredentialAuthenticationMethod",
    "#microsoft.graph.x509CertificateAuthenticationMethod",
    "#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod",
];

/// MFA capable per the registration report (`isMfaCapable`, else `isMfaRegistered`).
fn mfa_capable(detail: Option<&Value>) -> bool {
    detail
        .and_then(|d| d.get("isMfaCapable").or_else(|| d.get("isMfaRegistered")))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn bool_of(v: Option<&Value>, key: &str) -> bool {
    v.and_then(|v| v.get(key)).and_then(Value::as_bool) == Some(true)
}

pub const MFA_COVERAGE: CheckMeta = CheckMeta {
    id: "identity.mfa_coverage",
    title: "Enabled users are registered for MFA",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Joins enabled member users with the authentication methods registration report and measures how many are MFA capable, separately for admins (users the report flags as holding an admin role) and for everyone. An account with no MFA method can be taken over with a password alone, and an attacker who signs in first can register their own method. Users missing from the report count as not capable. Thresholds: `admin_percent` (default 100) and `user_percent` (default 95); `exclude` lists UPNs to leave out, such as the directory synchronisation account.",
    requires: Requirements {
        apis: &[USERS, REGISTRATION],
        licences: &["entra_id_p1"],
    },
    remediation: "Run an authentication methods registration campaign (Entra admin center > Protection > Authentication methods > Registration campaign) and require MFA for all users through Conditional Access or Security Defaults so remaining users register at next sign-in. Disable stale accounts that will never register.",
    links: &[
        "https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign",
        "https://learn.microsoft.com/entra/identity/authentication/howto-authentication-methods-activity",
    ],
    references: &["CIS M365 5.2.3.4"],
    manual: None,
};

crate::check!(MfaCoverage, &MFA_COVERAGE, mfa_coverage);

async fn mfa_coverage(ctx: &CheckContext) -> Evaluation {
    let id = MFA_COVERAGE.id;
    let admin_min: f64 = ctx.setting(id, "admin_percent", 100.0);
    let user_min: f64 = ctx.setting(id, "user_percent", 95.0);
    let exclude: Vec<String> = ctx.setting(id, "exclude", vec![]);
    let users = enabled_users(ctx).await?;
    let details = registration_details(ctx).await?;
    let members: Vec<&Value> = users
        .iter()
        .filter(|u| !str_of(u, "userType").is_some_and(|t| t.eq_ignore_ascii_case("guest")))
        .filter(|u| {
            let upn = str_of(u, "userPrincipalName").unwrap_or_default();
            !exclude.iter().any(|e| e.eq_ignore_ascii_case(upn))
        })
        .collect();
    if members.is_empty() {
        return Ok(Finding::unknown(
            "no_users",
            "No enabled member users were returned, so MFA coverage cannot be measured.",
        ));
    }
    let (mut capable, mut admins, mut admins_capable, mut not_in_report) = (0, 0, 0, 0);
    let mut missing = vec![];
    let mut missing_admins = vec![];
    for u in &members {
        let uid = str_of(u, "id").unwrap_or_default();
        let upn = str_of(u, "userPrincipalName").unwrap_or(uid).to_owned();
        let detail = details.get(uid);
        not_in_report += usize::from(detail.is_none());
        let ok = mfa_capable(detail);
        let admin = bool_of(detail, "isAdmin");
        capable += usize::from(ok);
        admins += usize::from(admin);
        admins_capable += usize::from(admin && ok);
        if !ok {
            if admin {
                missing_admins.push(upn.clone());
            }
            missing.push(upn);
        }
    }
    missing.sort();
    missing_admins.sort();
    let total = members.len();
    let user_pct = percent(capable, total);
    let admin_pct = percent(admins_capable, admins);
    let exact = |part: usize, whole: usize| {
        if whole == 0 {
            100.0
        } else {
            part as f64 * 100.0 / whole as f64
        }
    };
    let users_ok = exact(capable, total) >= user_min;
    let admins_ok = exact(admins_capable, admins) >= admin_min;
    let summary = format!(
        "{user_pct}% of {} MFA capable (minimum {user_min}%); {admins_capable} of {} ({admin_pct}%, minimum {admin_min}%).",
        plural(total, "enabled member user", "enabled member users"),
        plural(admins, "admin", "admins"),
    );
    let finding = if users_ok && admins_ok {
        Finding::pass(summary)
    } else {
        Finding::fail(summary)
    };
    Ok(finding
        .data(json!({
            "users": total,
            "users_mfa_capable": capable,
            "users_percent": user_pct,
            "user_percent_min": user_min,
            "admins": admins,
            "admins_mfa_capable": admins_capable,
            "admins_percent": admin_pct,
            "admin_percent_min": admin_min,
            "not_in_report": not_in_report,
            "excluded": exclude.len(),
            "not_capable_admins": missing_admins,
            "not_capable": missing,
        }))
        .affected(missing))
}

pub const MFA_ADMINS: CheckMeta = CheckMeta {
    id: "identity.mfa_admins",
    title: "Every privileged role holder is MFA capable",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::Critical,
    effort: Level::Low,
    impact: Level::High,
    description: "Lists users with an active assignment to a privileged directory role (Global, Privileged Role, Security, Exchange, SharePoint, User, Conditional Access, Application, Cloud Application, Authentication, Privileged Authentication, Intune, Billing and Helpdesk Administrator), expanding role-assignable groups, and confirms each is MFA capable. Uses the registration report, or each admin's registered methods when the tenant has no Entra ID P1. One admin without MFA is enough to lose the tenant to a phished or sprayed password.",
    requires: Requirements {
        apis: &[ROLE_ASSIGNMENTS, GROUP_MEMBERS, REGISTRATION, AUTH_METHODS],
        licences: &[],
    },
    remediation: "Have each listed admin register Microsoft Authenticator or, better, a passkey or FIDO2 security key, then require MFA for directory roles in Conditional Access (or turn on Security Defaults). Use a Temporary Access Pass to bootstrap registration rather than leaving the account password-only.",
    links: &[
        "https://learn.microsoft.com/entra/identity/conditional-access/policy-old-require-mfa-admin",
        "https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass",
    ],
    references: &["CIS M365 5.2.3.4", "CIS M365 5.2.2.1"],
    manual: None,
};

crate::check!(MfaAdmins, &MFA_ADMINS, mfa_admins);

async fn mfa_admins(ctx: &CheckContext) -> Evaluation {
    let admins = privileged_users(ctx).await?;
    if admins.is_empty() {
        return Ok(no_admins());
    }
    // Without Entra ID P1 the registration report is unavailable; read each
    // admin's methods instead (admins are few).
    let per_user = ctx.has_feature("entra_id_p1") == Some(false);
    let mut missing = vec![];
    if per_user {
        for a in &admins {
            let methods =
                full_list(ctx, AUTH_METHODS.operation, json!({ "user-id": a.id })).await?;
            let ok = methods
                .iter()
                .any(|m| str_of(m, "@odata.type").is_some_and(|t| MFA_METHOD_TYPES.contains(&t)));
            if !ok {
                missing.push(a.upn.clone());
            }
        }
    } else {
        let details = registration_details(ctx).await?;
        missing.extend(
            admins
                .iter()
                .filter(|a| !mfa_capable(details.get(&a.id)))
                .map(|a| a.upn.clone()),
        );
    }
    let total = admins.len();
    let data = json!({
        "admins": total,
        "mfa_capable": total - missing.len(),
        "source": if per_user { "authentication_methods" } else { "registration_details" },
    });
    let finding = if missing.is_empty() {
        Finding::pass(format!(
            "All {} holding privileged roles are MFA capable.",
            plural(total, "user", "users")
        ))
    } else {
        Finding::fail(format!(
            "{} of {total} privileged users {} not MFA capable.",
            missing.len(),
            if missing.len() == 1 { "is" } else { "are" }
        ))
    };
    Ok(finding.data(data).affected(missing))
}

fn no_admins() -> Finding {
    Finding::unknown(
        "no_admins",
        "No user holds an active privileged role assignment, which is unexpected; check the role assignments are readable.",
    )
}

pub const PHISHING_RESISTANT_ADMINS: CheckMeta = CheckMeta {
    id: "identity.phishing_resistant_admins",
    title: "Admins use phishing-resistant MFA, enforced by Conditional Access",
    pack: Pack::Identity,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Confirms every privileged role holder has a phishing-resistant method registered (FIDO2 security key or passkey, Windows Hello for Business, platform credential or certificate) and that an enabled Conditional Access policy requires a phishing-resistant authentication strength for every privileged role on all resources. Push and one-time codes can be relayed by adversary-in-the-middle phishing kits; a report-only policy is a `warn`.",
    requires: Requirements {
        apis: &[
            ROLE_ASSIGNMENTS,
            GROUP_MEMBERS,
            REGISTRATION,
            CA_POLICIES,
            AUTH_STRENGTHS,
        ],
        licences: &["entra_id_p1"],
    },
    remediation: "Register a FIDO2 security key, passkey or Windows Hello for Business for each admin, then create (or switch on) a Conditional Access policy: Users > Directory roles = every privileged role, Target resources = All resources, Grant = Require authentication strength 'Phishing-resistant MFA'. Exclude only the break-glass account.",
    links: &[
        "https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-phish-resistant-mfa",
        "https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths",
    ],
    references: &["CIS M365 5.2.2.5"],
    manual: None,
};

crate::check!(
    PhishingResistantAdmins,
    &PHISHING_RESISTANT_ADMINS,
    phishing_resistant_admins
);

async fn phishing_resistant_admins(ctx: &CheckContext) -> Evaluation {
    let admins = privileged_users(ctx).await?;
    if admins.is_empty() {
        return Ok(no_admins());
    }
    let details = registration_details(ctx).await?;
    let policies = ca_policies(ctx).await?;
    let strengths =
        Strengths::from_policies(&full_list(ctx, AUTH_STRENGTHS.operation, json!({})).await?);
    let without: Vec<String> = admins
        .iter()
        .filter(|a| !has_phishing_resistant(details.get(&a.id)))
        .map(|a| a.upn.clone())
        .collect();
    let requiring = |p: &&Value| ca::targets_all_apps(p) && strengths.required_by(p);
    let enforced: Vec<&Value> = policies
        .iter()
        .filter(|p| ca::is_enabled(p))
        .filter(requiring)
        .collect();
    let report_only: Vec<&Value> = policies
        .iter()
        .filter(|p| ca::is_report_only(p))
        .filter(requiring)
        .collect();
    let uncovered = |set: &[&Value]| -> Vec<&'static str> {
        PRIVILEGED_ROLES
            .iter()
            .filter(|(role, _)| !set.iter().any(|p| ca::covers_role(p, role)))
            .map(|(_, name)| *name)
            .collect()
    };
    let uncovered_enforced = uncovered(&enforced);
    let all: Vec<&Value> = enforced.iter().chain(&report_only).copied().collect();
    let uncovered_any = uncovered(&all);
    let data = json!({
        "admins": admins.len(),
        "admins_with_phishing_resistant_method": admins.len() - without.len(),
        "enforcing_policies": enforced.iter().map(|p| ca::name(p)).collect::<Vec<_>>(),
        "report_only_policies": report_only.iter().map(|p| ca::name(p)).collect::<Vec<_>>(),
        "uncovered_roles": uncovered_enforced,
    });
    let methods = format!(
        "{} of {} admins {} a phishing-resistant method",
        admins.len() - without.len(),
        admins.len(),
        if admins.len() - without.len() == 1 {
            "has"
        } else {
            "have"
        }
    );
    let finding = if !without.is_empty() || !uncovered_any.is_empty() {
        let policy = if uncovered_enforced.is_empty() {
            "Conditional Access requires a phishing-resistant strength for every privileged role"
                .to_owned()
        } else if uncovered_enforced.len() == PRIVILEGED_ROLES.len() {
            "no enabled Conditional Access policy requires a phishing-resistant strength for privileged roles".to_owned()
        } else {
            format!(
                "{} not covered by an enabled phishing-resistant policy",
                plural(
                    uncovered_enforced.len(),
                    "privileged role is",
                    "privileged roles are"
                )
            )
        };
        Finding::fail(format!("{methods}; {policy}."))
    } else if !uncovered_enforced.is_empty() {
        Finding::warn(format!(
            "{methods}, but the phishing-resistant requirement for {} is report-only.",
            plural(
                uncovered_enforced.len(),
                "privileged role",
                "privileged roles"
            )
        ))
    } else {
        Finding::pass(format!(
            "{methods} and Conditional Access requires a phishing-resistant strength for every privileged role."
        ))
    };
    Ok(finding.data(data).affected(without))
}

fn has_phishing_resistant(detail: Option<&Value>) -> bool {
    detail
        .and_then(|d| d.get("methodsRegistered"))
        .and_then(Value::as_array)
        .is_some_and(|methods| {
            methods
                .iter()
                .filter_map(Value::as_str)
                .any(|m| PHISHING_RESISTANT_REGISTERED.contains(&m.to_ascii_lowercase().as_str()))
        })
}
