//! `collaboration` pack: SharePoint and OneDrive sharing, guest access and group
//! creation. Ported from M365-Secure `src/modules/collaboration/sharepoint.rs` (Graph
//! `sharepointSettings` path) and `src/modules/identity/settings.rs` (guest settings).
use crate::check::{ApiRequirement, Check, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::CheckContext;
use crate::model::{Level, Pack, Severity};
use crate::packs::apps::{AUTHZ, meta};
use serde_json::{Value, json};
use std::sync::Arc;

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(SharepointExternalSharing),
        Arc::new(ExternalResharingBlocked),
        Arc::new(SharingDomainRestriction),
        Arc::new(SharepointLegacyAuthBlocked),
        Arc::new(UnmanagedSyncRestricted),
        Arc::new(IdleSessionSignout),
        Arc::new(GuestAccessRestricted),
        Arc::new(GuestInvitesRestricted),
        Arc::new(EmailVerifiedJoinBlocked),
        Arc::new(GroupCreationRestricted),
    ]
}

const SPO_SETTINGS: ApiRequirement = ApiRequirement {
    operation: "graph.admin.sharepoint.settings.get",
    permissions: &["SharePointTenantSettings.Read.All"],
};
const GROUP_SETTINGS: ApiRequirement = ApiRequirement {
    operation: "graph.group_settings.list",
    permissions: &["GroupSettings.Read.All", "Directory.Read.All"],
};
const SPO_LICENCE: &[&str] = &["sharepoint_online"];

/// Guest user role ids (the same in every tenant).
const GUEST_RESTRICTED: &str = "2af84b1e-32c8-42b7-82bc-daa82404023b";
const GUEST_LIMITED: &str = "a0b1b346-4d3e-4e8b-98f8-753987be4970";
const GUEST_MEMBER: &str = "10dae51f-b6af-4016-8d66-8c2a99b929b3";
/// `Group.Unified` directory setting template.
const GROUP_UNIFIED_TEMPLATE: &str = "62375ab9-6b52-47ed-826b-58e47e0e304b";

const SHARING_LINK: &str = "https://learn.microsoft.com/sharepoint/turn-external-sharing-on-or-off";
const GUEST_LINK: &str =
    "https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure";

/// A SharePoint check: needs SharePoint Online and reads `sharepointSettings`.
#[allow(clippy::too_many_arguments)]
const fn spo(
    id: &'static str,
    title: &'static str,
    severity: Severity,
    levels: (Level, Level),
    description: &'static str,
    remediation: &'static str,
    links: &'static [&'static str],
    references: &'static [&'static str],
) -> CheckMeta {
    CheckMeta {
        requires: Requirements {
            apis: &[SPO_SETTINGS],
            licences: SPO_LICENCE,
        },
        ..meta(
            Pack::Collaboration,
            id,
            title,
            severity,
            levels,
            description,
            &[SPO_SETTINGS],
            remediation,
            links,
            references,
        )
    }
}

async fn spo_settings(ctx: &CheckContext) -> Result<Value, crate::context::CallFailure> {
    ctx.get(SPO_SETTINGS.operation, json!({})).await
}

fn not_returned(property: &str) -> Finding {
    Finding::unknown(
        "not_returned",
        format!("SharePoint settings did not return {property}."),
    )
}

/// `sharingCapability`, lower-cased. `disabled` means internal only.
fn sharing_capability(settings: &Value) -> Option<String> {
    settings["sharingCapability"]
        .as_str()
        .map(str::to_ascii_lowercase)
}

fn sharing_label(capability: &str) -> &'static str {
    match capability {
        "disabled" => "Only people in your organisation",
        "externalusersharingonly" => "New and existing guests",
        "existingexternalusersharingonly" => "Existing guests",
        "externaluserandguestsharing" => "Anyone",
        _ => "Unrecognised",
    }
}

pub const SHAREPOINT_EXTERNAL_SHARING: CheckMeta = spo(
    "collaboration.sharepoint_external_sharing",
    "SharePoint external sharing is 'New and existing guests' or stricter",
    Severity::High,
    (Level::Low, Level::High),
    "Reads the organisation-level SharePoint sharingCapability. 'Anyone' allows unauthenticated links that can be forwarded to anyone and are not tied to an identity.",
    "SharePoint admin center > Policies > Sharing: set SharePoint to 'New and existing guests' or more restrictive. If Anyone links are needed, make them expire within 30 days and view-only.",
    &[SHARING_LINK],
    &["CIS M365 7.2.3"],
);

crate::check!(
    SharepointExternalSharing,
    &SHAREPOINT_EXTERNAL_SHARING,
    sharepoint_external_sharing
);

async fn sharepoint_external_sharing(ctx: &CheckContext) -> Evaluation {
    let settings = spo_settings(ctx).await?;
    let Some(capability) = sharing_capability(&settings) else {
        return Ok(not_returned("sharingCapability"));
    };
    let label = sharing_label(&capability);
    // Graph does not return Anyone-link expiry or permissions, so Anyone is a fail
    // here (M365-Secure gives the same result when only Graph answers).
    Ok(Finding::pass_if(
        capability != "externaluserandguestsharing",
        format!("SharePoint sharing: {label}."),
        "SharePoint sharing allows Anyone links.",
    )
    .data(json!({ "sharing_capability": capability })))
}

pub const EXTERNAL_RESHARING_BLOCKED: CheckMeta = spo(
    "collaboration.external_resharing_blocked",
    "Guests cannot reshare items they do not own",
    Severity::Medium,
    (Level::Low, Level::Medium),
    "Reads isResharingByExternalUsersEnabled. When guests can reshare, the organisation loses control of who ends up with access.",
    "SharePoint admin center > Policies > Sharing > More external sharing settings: clear 'Allow guests to share items they don't own'.",
    &[SHARING_LINK],
    &["CIS M365 7.2.5"],
);

crate::check!(
    ExternalResharingBlocked,
    &EXTERNAL_RESHARING_BLOCKED,
    external_resharing_blocked
);

async fn external_resharing_blocked(ctx: &CheckContext) -> Evaluation {
    let settings = spo_settings(ctx).await?;
    if sharing_capability(&settings).as_deref() == Some("disabled") {
        return Ok(Finding::pass("External sharing is off."));
    }
    let Some(reshare) = settings["isResharingByExternalUsersEnabled"].as_bool() else {
        return Ok(not_returned("isResharingByExternalUsersEnabled"));
    };
    Ok(Finding::pass_if(
        !reshare,
        "Guests cannot reshare items.",
        "Guests can reshare items they do not own.",
    )
    .data(json!({ "resharing_by_external_users": reshare })))
}

pub const SHARING_DOMAIN_RESTRICTION: CheckMeta = spo(
    "collaboration.sharing_domain_restriction",
    "SharePoint external sharing is limited to an allow list of domains",
    Severity::Medium,
    (Level::Medium, Level::Medium),
    "Reads sharingDomainRestrictionMode and the allowed domain list. An allow list confines external sharing to known partner organisations.",
    "SharePoint admin center > Policies > Sharing > More external sharing settings: 'Limit external sharing by domain' and allow only the partner domains you work with.",
    &["https://learn.microsoft.com/sharepoint/restricted-domains-sharing"],
    &["CIS M365 7.2.6"],
);

crate::check!(
    SharingDomainRestriction,
    &SHARING_DOMAIN_RESTRICTION,
    sharing_domain_restriction
);

async fn sharing_domain_restriction(ctx: &CheckContext) -> Evaluation {
    let settings = spo_settings(ctx).await?;
    if sharing_capability(&settings).as_deref() == Some("disabled") {
        return Ok(Finding::pass("External sharing is off."));
    }
    let Some(mode) = settings["sharingDomainRestrictionMode"].as_str() else {
        return Ok(not_returned("sharingDomainRestrictionMode"));
    };
    let allowed = settings["sharingAllowedDomainList"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(0);
    let finding = match mode.to_ascii_lowercase().as_str() {
        "allowlist" => Finding::pass(format!("Allow list with {allowed} domain(s).")),
        "blocklist" => Finding::warn("Block list only; an allow list is the restrictive option."),
        "none" => Finding::fail("External sharing is not limited by domain."),
        _ => return Ok(not_returned("a recognised sharingDomainRestrictionMode")),
    };
    Ok(finding.data(json!({ "mode": mode, "allowed_domains": allowed })))
}

pub const SHAREPOINT_LEGACY_AUTH_BLOCKED: CheckMeta = spo(
    "collaboration.sharepoint_legacy_auth_blocked",
    "SharePoint requires modern authentication",
    Severity::High,
    (Level::Low, Level::High),
    "Reads isLegacyAuthProtocolsEnabled. Legacy protocols skip MFA and Conditional Access.",
    "SharePoint admin center > Policies > Access control > Apps that don't use modern authentication: Block access (Set-SPOTenant -LegacyAuthProtocolsEnabled $false).",
    &["https://learn.microsoft.com/sharepoint/control-access-from-unmanaged-devices"],
    &["CIS M365 7.2.1"],
);

crate::check!(
    SharepointLegacyAuthBlocked,
    &SHAREPOINT_LEGACY_AUTH_BLOCKED,
    sharepoint_legacy_auth_blocked
);

async fn sharepoint_legacy_auth_blocked(ctx: &CheckContext) -> Evaluation {
    let settings = spo_settings(ctx).await?;
    let Some(legacy) = settings["isLegacyAuthProtocolsEnabled"].as_bool() else {
        return Ok(not_returned("isLegacyAuthProtocolsEnabled"));
    };
    Ok(Finding::pass_if(
        !legacy,
        "SharePoint requires modern authentication.",
        "SharePoint accepts legacy authentication protocols.",
    )
    .data(json!({ "legacy_auth_protocols_enabled": legacy })))
}

pub const UNMANAGED_SYNC_RESTRICTED: CheckMeta = spo(
    "collaboration.unmanaged_sync_restricted",
    "OneDrive sync is restricted to managed devices",
    Severity::Medium,
    (Level::Medium, Level::Medium),
    "Reads isUnmanagedSyncAppForTenantRestricted. Without it, any device a user signs in on can sync a full copy of their files.",
    "SharePoint admin center > Settings > OneDrive Sync: 'Allow syncing only on computers joined to specific domains', or block downloads from unmanaged devices with Conditional Access.",
    &["https://learn.microsoft.com/sharepoint/allow-syncing-only-on-specific-domains"],
    &[],
);

crate::check!(
    UnmanagedSyncRestricted,
    &UNMANAGED_SYNC_RESTRICTED,
    unmanaged_sync_restricted
);

async fn unmanaged_sync_restricted(ctx: &CheckContext) -> Evaluation {
    let settings = spo_settings(ctx).await?;
    let Some(restricted) = settings["isUnmanagedSyncAppForTenantRestricted"].as_bool() else {
        return Ok(not_returned("isUnmanagedSyncAppForTenantRestricted"));
    };
    Ok(Finding::pass_if(
        restricted,
        "OneDrive sync is restricted to managed devices.",
        "Unmanaged devices can sync OneDrive and SharePoint files.",
    )
    .data(json!({ "unmanaged_sync_restricted": restricted })))
}

pub const IDLE_SESSION_SIGNOUT: CheckMeta = spo(
    "collaboration.idle_session_signout",
    "Idle SharePoint sessions on unmanaged devices sign out within 3 hours",
    Severity::Medium,
    (Level::Low, Level::Medium),
    "Reads idleSessionSignOut. Browser sessions left open on shared or personal devices give the next person access.",
    "SharePoint admin center > Policies > Access control > Idle session sign-out: turn on and sign out after 3 hours or less.",
    &["https://learn.microsoft.com/sharepoint/sign-out-inactive-users"],
    &[],
);

crate::check!(
    IdleSessionSignout,
    &IDLE_SESSION_SIGNOUT,
    idle_session_signout
);

async fn idle_session_signout(ctx: &CheckContext) -> Evaluation {
    let settings = spo_settings(ctx).await?;
    let idle = &settings["idleSessionSignOut"];
    let Some(enabled) = idle["isEnabled"].as_bool() else {
        return Ok(not_returned("idleSessionSignOut"));
    };
    let seconds = idle["signOutAfterInSeconds"].as_i64().unwrap_or(0);
    let hours = seconds as f64 / 3600.0;
    let finding = if !enabled {
        Finding::fail("Idle session sign-out is off.")
    } else if seconds <= 3 * 3600 {
        Finding::pass(format!("Idle sessions sign out after {hours:.1} hours."))
    } else {
        Finding::warn(format!(
            "Idle sessions sign out after {hours:.1} hours (over 3)."
        ))
    };
    Ok(finding.data(json!({ "enabled": enabled, "sign_out_after_seconds": seconds })))
}

// --- guests and groups (authorization policy) ------------------------------

pub const GUEST_ACCESS_RESTRICTED: CheckMeta = meta(
    Pack::Collaboration,
    "collaboration.guest_access_restricted",
    "Guest users have the most restricted directory access",
    Severity::Medium,
    (Level::Low, Level::Medium),
    "Reads guestUserRoleId from the authorization policy. With the default (limited) role, guests can enumerate groups and users; with member access they see the directory like employees.",
    &[AUTHZ],
    "Entra admin center > External Identities > External collaboration settings > Guest user access: 'Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)'.",
    &[GUEST_LINK],
    &["CIS M365 5.1.6.2"],
);

crate::check!(
    GuestAccessRestricted,
    &GUEST_ACCESS_RESTRICTED,
    guest_access_restricted
);

async fn guest_access_restricted(ctx: &CheckContext) -> Evaluation {
    let policy = ctx.get(AUTHZ.operation, json!({})).await?;
    let Some(role) = policy["guestUserRoleId"].as_str() else {
        return Ok(Finding::unknown(
            "not_returned",
            "The authorization policy did not return guestUserRoleId.",
        ));
    };
    let finding = match role.to_ascii_lowercase().as_str() {
        GUEST_RESTRICTED => Finding::pass("Guest access is restricted (most restrictive)."),
        GUEST_LIMITED => Finding::warn(
            "Guests have limited access (the default): they can enumerate groups and other users.",
        ),
        GUEST_MEMBER => Finding::fail("Guests have the same directory access as members."),
        _ => Finding::warn(format!("Unrecognised guest role id {role}.")),
    };
    Ok(finding.data(json!({ "guest_user_role_id": role })))
}

pub const GUEST_INVITES_RESTRICTED: CheckMeta = meta(
    Pack::Collaboration,
    "collaboration.guest_invites_restricted",
    "Only admins and Guest Inviters can invite guests",
    Severity::Medium,
    (Level::Low, Level::Medium),
    "Reads allowInvitesFrom from the authorization policy. When every member (or every guest) can invite, external accounts arrive without review.",
    &[AUTHZ],
    "Entra admin center > External Identities > External collaboration settings > Guest invite settings: 'Only users assigned to specific admin roles can invite guest users'.",
    &[GUEST_LINK],
    &["CIS M365 5.1.6.3"],
);

crate::check!(
    GuestInvitesRestricted,
    &GUEST_INVITES_RESTRICTED,
    guest_invites_restricted
);

async fn guest_invites_restricted(ctx: &CheckContext) -> Evaluation {
    let policy = ctx.get(AUTHZ.operation, json!({})).await?;
    let Some(invites) = policy["allowInvitesFrom"].as_str() else {
        return Ok(Finding::unknown(
            "not_returned",
            "The authorization policy did not return allowInvitesFrom.",
        ));
    };
    let finding = match invites {
        "none" | "adminsAndGuestInviters" => {
            Finding::pass(format!("Guest invitations: {invites}."))
        }
        "adminsGuestInvitersAndAllMembers" => Finding::warn("Every member can invite guests."),
        "everyone" => Finding::fail("Anyone, including guests, can invite guests."),
        other => Finding::warn(format!("Unrecognised allowInvitesFrom value {other}.")),
    };
    Ok(finding.data(json!({ "allow_invites_from": invites })))
}

pub const EMAIL_VERIFIED_JOIN_BLOCKED: CheckMeta = meta(
    Pack::Collaboration,
    "collaboration.email_verified_join_blocked",
    "Email-verified users cannot self-join the organisation",
    Severity::Medium,
    (Level::Low, Level::Medium),
    "Reads allowEmailVerifiedUsersToJoinOrganization. When on, anyone with a mailbox on a verified domain can create an unmanaged account in the tenant.",
    &[AUTHZ],
    "Set allowEmailVerifiedUsersToJoinOrganization to false (Update-MgPolicyAuthorizationPolicy -AllowEmailVerifiedUsersToJoinOrganization:$false).",
    &["https://learn.microsoft.com/entra/identity/users/directory-self-service-signup"],
    &[],
);

crate::check!(
    EmailVerifiedJoinBlocked,
    &EMAIL_VERIFIED_JOIN_BLOCKED,
    email_verified_join_blocked
);

async fn email_verified_join_blocked(ctx: &CheckContext) -> Evaluation {
    let policy = ctx.get(AUTHZ.operation, json!({})).await?;
    let Some(join) = policy["allowEmailVerifiedUsersToJoinOrganization"].as_bool() else {
        return Ok(Finding::unknown(
            "not_returned",
            "The authorization policy did not return allowEmailVerifiedUsersToJoinOrganization.",
        ));
    };
    Ok(Finding::pass_if(
        !join,
        "Email-verified users cannot self-join.",
        "Email-verified users can self-join the organisation.",
    )
    .data(json!({ "allow_email_verified_users_to_join": join })))
}

pub const GROUP_CREATION_RESTRICTED: CheckMeta = CheckMeta {
    requires: Requirements {
        apis: &[AUTHZ, GROUP_SETTINGS],
        licences: &[],
    },
    ..meta(
        Pack::Collaboration,
        "collaboration.group_creation_restricted",
        "Users cannot create security groups, and Microsoft 365 group creation is limited",
        Severity::Low,
        (Level::Low, Level::Low),
        "Reads allowedToCreateSecurityGroups from the authorization policy and the Group.Unified directory setting (EnableGroupCreation, GroupCreationAllowedGroupId). Unrestricted group creation sprawls access and lets users build their own sharing boundaries.",
        &[AUTHZ, GROUP_SETTINGS],
        "Entra admin center > Groups > General: set 'Users can create security groups' to No. Restrict Microsoft 365 group creation to a named group with the Group.Unified setting (EnableGroupCreation false, GroupCreationAllowedGroupId set).",
        &["https://learn.microsoft.com/microsoft-365/solutions/manage-creation-of-groups"],
        &[],
    )
};

crate::check!(
    GroupCreationRestricted,
    &GROUP_CREATION_RESTRICTED,
    group_creation_restricted
);

async fn group_creation_restricted(ctx: &CheckContext) -> Evaluation {
    let policy = ctx.get(AUTHZ.operation, json!({})).await?;
    let Some(security) = policy
        .pointer("/defaultUserRolePermissions/allowedToCreateSecurityGroups")
        .and_then(Value::as_bool)
    else {
        return Ok(Finding::unknown(
            "not_returned",
            "The authorization policy did not return allowedToCreateSecurityGroups.",
        ));
    };
    let settings = ctx.list_with(GROUP_SETTINGS.operation, json!({})).await?;
    let unified = settings
        .iter()
        .find(|s| s["templateId"].as_str() == Some(GROUP_UNIFIED_TEMPLATE));
    let value = |name: &str| {
        unified
            .and_then(|s| s["values"].as_array())
            .into_iter()
            .flatten()
            .find(|v| v["name"].as_str() == Some(name))
            .and_then(|v| v["value"].as_str())
            .map(str::to_owned)
    };
    // No Group.Unified setting means the default: everyone can create groups.
    let m365_open = value("EnableGroupCreation").is_none_or(|v| !v.eq_ignore_ascii_case("false"));
    let allowed_group = value("GroupCreationAllowedGroupId").filter(|v| !v.is_empty());
    let data = json!({
        "users_can_create_security_groups": security,
        "m365_group_creation_open": m365_open,
        "m365_group_creation_allowed_group": allowed_group,
    });
    let finding = if security {
        Finding::fail("Any user can create security groups.")
    } else if m365_open {
        Finding::warn(
            "Security group creation is restricted, but any user can create Microsoft 365 groups.",
        )
    } else {
        Finding::pass("Security and Microsoft 365 group creation are restricted.")
    };
    Ok(finding.data(data))
}
