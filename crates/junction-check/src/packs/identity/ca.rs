//! Pure Conditional Access evaluators over policy JSON (ported from M365-Secure).
//!
//! "Requires X" means X is the only way to satisfy the grant (operator AND, or
//! X is the sole control), so `mfa OR compliantDevice` does not require MFA.
use serde_json::Value;
use std::collections::BTreeSet;

/// Built-in "Phishing-resistant MFA" authentication strength.
pub const PHISHING_RESISTANT_STRENGTH: &str = "00000000-0000-0000-0000-000000000004";
const PHISHING_RESISTANT_COMBINATIONS: &[&str] = &[
    "windowsHelloForBusiness",
    "fido2",
    "x509CertificateMultiFactor",
];

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn has(v: &Value, needle: &str) -> bool {
    strs(v).iter().any(|s| s.eq_ignore_ascii_case(needle))
}

pub fn name(p: &Value) -> String {
    p["displayName"]
        .as_str()
        .or(p["id"].as_str())
        .unwrap_or("(unnamed policy)")
        .to_owned()
}

pub fn is_enabled(p: &Value) -> bool {
    p["state"].as_str() == Some("enabled")
}

pub fn is_report_only(p: &Value) -> bool {
    p["state"].as_str() == Some("enabledForReportingButNotEnforced")
}

/// Emergency access accounts Microsoft recommends excluding from Conditional
/// Access: up to two users or one group. Anything wider is not "all users".
const MAX_EXCLUDED_USERS: usize = 2;
const MAX_EXCLUDED_GROUPS: usize = 1;

fn non_empty(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// Conditions that narrow a policy to some sign-ins: platforms, locations,
/// device filters or client app types other than "all". Risk levels are not
/// counted: risk policies are meant to be conditional.
pub fn restricted(p: &Value) -> bool {
    let c = &p["conditions"];
    let platforms = &c["platforms"];
    let locations = &c["locations"];
    let apps = &c["clientAppTypes"];
    (non_empty(&platforms["includePlatforms"]) && !has(&platforms["includePlatforms"], "all"))
        || non_empty(&platforms["excludePlatforms"])
        || (non_empty(&locations["includeLocations"])
            && !has(&locations["includeLocations"], "All"))
        || non_empty(&locations["excludeLocations"])
        || non_empty(&c["devices"]["deviceFilter"])
        || (non_empty(apps) && !has(apps, "all"))
}

/// The policy applies to every user (allowing only emergency-access exclusions)
/// for every sign-in. Unresolvable exclusions never count as full coverage.
pub fn targets_all_users(p: &Value) -> bool {
    all_users_except_roles(p) && !non_empty(&p["conditions"]["users"]["excludeRoles"])
}

/// All users with only emergency-access user or group exclusions; role
/// exclusions are judged per role by [`covers_role`].
fn all_users_except_roles(p: &Value) -> bool {
    let users = &p["conditions"]["users"];
    has(&users["includeUsers"], "All")
        && strs(&users["excludeUsers"]).len() <= MAX_EXCLUDED_USERS
        && strs(&users["excludeGroups"]).len() <= MAX_EXCLUDED_GROUPS
        && !non_empty(&users["excludeGuestsOrExternalUsers"])
        && !restricted_ignoring_client_apps(p)
}

/// Like [`restricted`], but legacy-authentication policies target specific
/// client app types by design.
fn restricted_ignoring_client_apps(p: &Value) -> bool {
    let mut copy = p.clone();
    if let Some(c) = copy.get_mut("conditions").and_then(Value::as_object_mut) {
        c.remove("clientAppTypes");
    }
    restricted(&copy)
}

pub fn targets_all_apps(p: &Value) -> bool {
    let apps = &p["conditions"]["applications"];
    has(&apps["includeApplications"], "All") && !non_empty(&apps["excludeApplications"])
}

fn built_in_controls(p: &Value) -> Vec<&str> {
    strs(&p["grantControls"]["builtInControls"])
}

pub fn strength_id(p: &Value) -> Option<&str> {
    p["grantControls"]["authenticationStrength"]["id"].as_str()
}

/// True when every way to satisfy the grant is in `accepted` and at least one
/// of `required` is present.
fn grant_requires(p: &Value, required: &[&str], accepted: &[&str]) -> bool {
    let controls = built_in_controls(p);
    let strength = strength_id(p).is_some();
    let present = controls.iter().any(|c| required.contains(c))
        || (strength && required.contains(&"authenticationStrength"));
    if !present {
        return false;
    }
    let and = p["grantControls"]["operator"]
        .as_str()
        .is_some_and(|o| o.eq_ignore_ascii_case("AND"));
    and || (controls.iter().all(|c| accepted.contains(c))
        && (!strength || accepted.contains(&"authenticationStrength")))
}

/// The grant requires MFA for every client app (a policy limited to, say,
/// browsers leaves other clients without MFA).
pub fn requires_mfa(p: &Value) -> bool {
    const MFA: &[&str] = &["mfa", "authenticationStrength"];
    grant_requires(p, MFA, MFA) && !restricted(p)
}

pub fn blocks(p: &Value) -> bool {
    has(&p["grantControls"]["builtInControls"], "block")
}

pub fn blocks_legacy_auth(p: &Value) -> bool {
    let types = &p["conditions"]["clientAppTypes"];
    has(types, "exchangeActiveSync") && has(types, "other") && blocks(p)
}

pub fn sign_in_risk_levels(p: &Value) -> Vec<&str> {
    strs(&p["conditions"]["signInRiskLevels"])
}

/// The policy applies to a role when the role (or All users) is in scope and
/// the role is not excluded.
pub fn covers_role(p: &Value, role: &str) -> bool {
    let users = &p["conditions"]["users"];
    (all_users_except_roles(p) || has(&users["includeRoles"], role))
        && !has(&users["excludeRoles"], role)
        && !restricted_ignoring_client_apps(p)
}

/// Phishing-resistant authentication strengths: the built-in one plus any
/// strength whose allowed combinations are all phishing-resistant.
#[derive(Debug, Clone, Default)]
pub struct Strengths(BTreeSet<String>);

fn all_phishing_resistant(combinations: &Value) -> bool {
    let c = strs(combinations);
    !c.is_empty()
        && c.iter()
            .all(|c| PHISHING_RESISTANT_COMBINATIONS.contains(c))
}

impl Strengths {
    pub fn from_policies(policies: &[Value]) -> Self {
        let mut ids = BTreeSet::from([PHISHING_RESISTANT_STRENGTH.to_owned()]);
        for p in policies {
            if let Some(id) = p["id"].as_str()
                && all_phishing_resistant(&p["allowedCombinations"])
            {
                ids.insert(id.to_ascii_lowercase());
            }
        }
        Self(ids)
    }

    /// The grant requires a phishing-resistant strength (by id, or by the
    /// combinations returned inline with the policy).
    pub fn required_by(&self, p: &Value) -> bool {
        let strength = &p["grantControls"]["authenticationStrength"];
        let Some(id) = strength["id"].as_str() else {
            return false;
        };
        (self.0.contains(&id.to_ascii_lowercase())
            || all_phishing_resistant(&strength["allowedCombinations"]))
            && grant_requires(p, &["authenticationStrength"], &["authenticationStrength"])
    }
}

/// Does the policy apply to a member user with these ids, roles and groups?
pub fn applies_to(
    p: &Value,
    user: &str,
    roles: &BTreeSet<&str>,
    groups: &BTreeSet<String>,
) -> bool {
    let users = &p["conditions"]["users"];
    let listed = |key: &str, values: &[&str]| {
        strs(&users[key])
            .iter()
            .any(|l| values.iter().any(|v| l.eq_ignore_ascii_case(v)))
    };
    let roles: Vec<&str> = roles.iter().copied().collect();
    let groups: Vec<&str> = groups.iter().map(String::as_str).collect();
    let included = listed("includeUsers", &["All", user])
        || listed("includeRoles", &roles)
        || listed("includeGroups", &groups);
    let excluded = listed("excludeUsers", &[user])
        || listed("excludeRoles", &roles)
        || listed("excludeGroups", &groups);
    included && !excluded
}

/// Group ids a policy includes or excludes.
pub fn referenced_groups(p: &Value) -> impl Iterator<Item = &str> {
    let users = &p["conditions"]["users"];
    strs(&users["includeGroups"])
        .into_iter()
        .chain(strs(&users["excludeGroups"]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(users: Value, grant: Value) -> Value {
        // Legacy client app types only on block policies, as real tenants use them.
        let apps = if grant["builtInControls"].to_string().contains("block") {
            json!(["exchangeActiveSync", "other"])
        } else {
            json!(["all"])
        };
        json!({
            "displayName": "p",
            "state": "enabled",
            "conditions": {"users": users, "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": apps},
            "grantControls": grant
        })
    }

    #[test]
    fn mfa_must_be_the_only_way_through() {
        let all = json!({"includeUsers": ["All"]});
        assert!(!requires_mfa(&policy(
            all.clone(),
            json!({"operator": "OR", "builtInControls": ["mfa", "compliantDevice"]})
        )));
        assert!(requires_mfa(&policy(
            all.clone(),
            json!({"operator": "AND", "builtInControls": ["mfa", "compliantDevice"]})
        )));
        assert!(requires_mfa(&policy(
            all.clone(),
            json!({"operator": "OR", "builtInControls": [], "authenticationStrength": {"id": "x"}})
        )));
        assert!(blocks_legacy_auth(&policy(
            all,
            json!({"operator": "OR", "builtInControls": ["block"]})
        )));
    }

    #[test]
    fn strengths_and_scope() {
        let custom =
            json!({"id": "CUSTOM", "allowedCombinations": ["fido2", "windowsHelloForBusiness"]});
        let weak = json!({"id": "weak", "allowedCombinations": ["fido2", "password,sms"]});
        let s = Strengths::from_policies(&[custom, weak]);
        let grant = |id: &str| json!({"operator": "OR", "authenticationStrength": {"id": id}});
        assert!(s.required_by(&policy(json!({}), grant("custom"))));
        assert!(s.required_by(&policy(json!({}), grant(PHISHING_RESISTANT_STRENGTH))));
        assert!(!s.required_by(&policy(json!({}), grant("weak"))));

        let p = policy(
            json!({"includeUsers": ["All"], "excludeGroups": ["bg"], "excludeRoles": ["r2"]}),
            json!({}),
        );
        let none = BTreeSet::new();
        assert!(applies_to(&p, "u1", &none, &BTreeSet::new()));
        assert!(!applies_to(
            &p,
            "u1",
            &none,
            &BTreeSet::from(["bg".to_owned()])
        ));
        assert!(!applies_to(
            &p,
            "u1",
            &BTreeSet::from(["r2"]),
            &BTreeSet::new()
        ));
        assert!(covers_role(&p, "r1") && !covers_role(&p, "r2"));
    }

    #[test]
    fn exclusions_and_conditions_are_not_full_coverage() {
        let base = json!({"state": "enabled",
            "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}});
        assert!(targets_all_users(&base) && targets_all_apps(&base) && requires_mfa(&base));
        let with = |pointer: &str, value: Value| {
            let mut p = base.clone();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            p.pointer_mut(parent).unwrap()[key] = value;
            p
        };
        // Emergency-access exclusions are allowed.
        assert!(targets_all_users(&with(
            "/conditions/users/excludeUsers",
            json!(["a", "b"])
        )));
        assert!(targets_all_users(&with(
            "/conditions/users/excludeGroups",
            json!(["g"])
        )));
        // Anything wider is not "all users".
        for (pointer, value) in [
            ("/conditions/users/excludeUsers", json!(["a", "b", "c"])),
            ("/conditions/users/excludeGroups", json!(["g1", "g2"])),
            (
                "/conditions/users/excludeRoles",
                json!(["62e90394-69f5-4237-9190-012177145e10"]),
            ),
            (
                "/conditions/users/excludeGuestsOrExternalUsers",
                json!({"guestOrExternalUserTypes": "b2bCollaborationGuest"}),
            ),
        ] {
            assert!(
                !targets_all_users(&with(pointer, value.clone())),
                "{pointer} {value}"
            );
        }
        assert!(!targets_all_apps(&with(
            "/conditions/applications/excludeApplications",
            json!(["app"])
        )));
        // Conditions that narrow sign-ins defeat universal coverage.
        let mut platforms = base.clone();
        platforms["conditions"]["platforms"] = json!({"includePlatforms": ["windows"]});
        let mut locations = base.clone();
        locations["conditions"]["locations"] =
            json!({"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]});
        let mut browsers = base.clone();
        browsers["conditions"]["clientAppTypes"] = json!(["browser"]);
        for p in [&platforms, &locations] {
            assert!(!targets_all_users(p));
            assert!(!covers_role(p, "62e90394-69f5-4237-9190-012177145e10"));
        }
        assert!(
            !requires_mfa(&browsers),
            "MFA for browsers only leaves other clients open"
        );
        // Legacy-authentication blocks target client app types by design.
        let mut legacy = base.clone();
        legacy["conditions"]["clientAppTypes"] = json!(["exchangeActiveSync", "other"]);
        legacy["grantControls"] = json!({"operator": "OR", "builtInControls": ["block"]});
        assert!(blocks_legacy_auth(&legacy) && targets_all_users(&legacy));
    }
}
