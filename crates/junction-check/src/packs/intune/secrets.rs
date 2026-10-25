//! Windows LAPS and BitLocker recovery key escrow. Both read metadata lists
//! only: never `$select=credentials`, never `key`, never a per-item GET.
use super::*;
use crate::check::{CheckMeta, Evaluation, Requirements};
use crate::model::{CheckKind, Level, Pack, Severity};
use std::collections::BTreeSet;

const DEVICE_LOCAL_CREDENTIALS: ApiRequirement = ApiRequirement {
    operation: "graph.directory.device_local_credentials.list",
    permissions: &["DeviceLocalCredential.ReadBasic.All"],
};
const RECOVERY_KEYS: ApiRequirement = ApiRequirement {
    operation: "graph.information_protection.bitlocker.recovery_keys.list",
    permissions: &["BitlockerKey.ReadBasic.All"],
};

/// Prefix of Windows LAPS settings catalog definitions.
const LAPS_PREFIX: &str = "device_vendor_msft_laps_policies_";
const LAPS_BACKUP: &str = "device_vendor_msft_laps_policies_backupdirectory";

// ---------------------------------------------------------------- LAPS

pub const LAPS: CheckMeta = CheckMeta {
    id: "intune.laps",
    title: "Windows LAPS manages local administrator passwords and backs them up to Entra ID",
    pack: Pack::Intune,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Looks for an assigned Intune policy with Windows LAPS settings (`device_vendor_msft_laps_*`) and its backup directory, then compares active Intune-managed Windows devices with the Entra ID list of devices that have a backed-up local administrator password. Reads password metadata only (device name and backup time); the password itself is never requested. Shared local administrator passwords let one compromised device unlock all of them. Needs Microsoft Intune Plan 1.",
    requires: Requirements {
        apis: &[
            MANAGED_DEVICES,
            CONFIG_POLICIES,
            POLICY_SETTINGS,
            DEVICE_LOCAL_CREDENTIALS,
        ],
        licences: &[],
    },
    remediation: "In Intune > Endpoint security > Account protection, create a Local admin password solution (Windows LAPS) policy with Backup Directory set to Azure AD (Entra ID), and assign it to all Windows devices. Turn on 'Enable Microsoft Entra Local Administrator Password Solution' in Entra ID > Devices > Device settings. Investigate listed devices that have not backed up a password.",
    links: &[
        "https://learn.microsoft.com/intune/intune-service/protect/windows-laps-overview",
        "https://learn.microsoft.com/entra/identity/devices/howto-manage-local-admin-passwords",
    ],
    references: &[],
    manual: None,
};

crate::check!(Laps, &LAPS, laps);

async fn laps(ctx: &CheckContext) -> Evaluation {
    let id = LAPS.id;
    if let Some(finding) = without_intune(ctx, id) {
        return Ok(finding);
    }
    let devices = managed_devices(ctx).await?;
    let (windows, stale) = active_windows(ctx, &devices);
    let policies = windows_policies(ctx).await?;
    let laps: Vec<&WindowsPolicy> = policies
        .iter()
        .filter(|p| {
            p.settings
                .iter()
                .any(|(_, d, _)| d.starts_with(LAPS_PREFIX))
        })
        .collect();
    let backup = |p: &WindowsPolicy| {
        p.settings
            .iter()
            .find(|(_, d, _)| d == LAPS_BACKUP)
            .map(|(_, _, v)| match v.rsplit('_').next() {
                Some("1") => "entra_id",
                Some("2") => "active_directory",
                Some("0") => "disabled",
                _ => "unknown",
            })
            .unwrap_or("not set")
    };
    let policy_evidence: Vec<Value> = laps
        .iter()
        .map(|p| json!({"name": p.name, "assigned_to": p.scope.as_str(), "backup_directory": backup(p)}))
        .collect();
    let entra: Vec<&&WindowsPolicy> = laps.iter().filter(|p| backup(p) == "entra_id").collect();
    let mut data = json!({
        "policies": policy_evidence,
        "windows_devices": windows.len(),
        "stale_left_out": stale,
    });
    if laps.is_empty() {
        return Ok(Finding::fail(format!(
            "No assigned Intune policy configures Windows LAPS ({} active Windows devices).",
            windows.len()
        ))
        .data(data));
    }
    if entra.is_empty() {
        let directories: BTreeSet<&str> = laps.iter().map(|p| backup(p)).collect();
        let directories: Vec<&str> = directories.into_iter().collect();
        let summary = format!(
            "Windows LAPS policies are assigned but none backs up to Entra ID (backup directory: {}).",
            directories.join(", ")
        );
        return Ok(if directories.contains(&"active_directory") {
            Finding::warn(format!(
                "{summary} Backups in Active Directory cannot be verified from Microsoft Graph."
            ))
        } else {
            Finding::fail(summary)
        }
        .data(data));
    }
    if windows.is_empty() {
        return Ok(Finding::pass(format!(
            "Windows LAPS policy {} backs up to Entra ID; no active Windows devices to compare.",
            entra[0].name
        ))
        .data(data));
    }
    // Metadata only: no $select, so `credentials` is never returned.
    let backups = ctx
        .list(DEVICE_LOCAL_CREDENTIALS.operation, json!({}))
        .await?
        .items;
    let ids: BTreeSet<String> = backups
        .iter()
        .map(|b| text(b, "id").to_ascii_lowercase())
        .collect();
    let names: BTreeSet<String> = backups
        .iter()
        .map(|b| text(b, "deviceName").to_ascii_lowercase())
        .collect();
    let missing: Vec<String> = windows
        .iter()
        .filter(|d| !ids.contains(&d.entra_id) && !names.contains(&d.name.to_ascii_lowercase()))
        .map(|d| d.name.clone())
        .collect();
    data["backed_up"] = json!(windows.len() - missing.len());
    data["missing_backup"] = json!(missing.len());
    let finding = if missing.is_empty() {
        Finding::pass(format!(
            "Windows LAPS backs up to Entra ID and all {} active Windows devices have a backed-up local administrator password.",
            windows.len()
        ))
    } else {
        Finding::fail(format!(
            "{} of {} active Windows devices have no local administrator password backed up to Entra ID.",
            missing.len(),
            windows.len()
        ))
    };
    Ok(finding.data(data).affected(missing))
}

// ---------------------------------------------------------------- BitLocker

pub const BITLOCKER_ESCROW: CheckMeta = CheckMeta {
    id: "intune.bitlocker_escrow",
    title: "Encrypted Windows devices have their BitLocker recovery key in Entra ID",
    pack: Pack::Intune,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Compares active Intune-managed Windows devices that report encryption (`isEncrypted`) with the BitLocker recovery key list in Entra ID. Reads key metadata only (key id, device id, volume type); the recovery key itself is never requested. A device without an escrowed key cannot be recovered after a BitLocker lockout, which pushes people to turn encryption off. Needs Microsoft Intune Plan 1.",
    requires: Requirements {
        apis: &[MANAGED_DEVICES, RECOVERY_KEYS],
        licences: &[],
    },
    remediation: "In the Intune disk encryption (BitLocker) policy, require the recovery key to be stored in Entra ID before encryption starts ('Save BitLocker recovery information to Azure AD' and 'Do not enable BitLocker until recovery information is stored'). For listed devices, run `manage-bde -protectors -adbackup` or `BackupToAAD-BitLockerKeyProtector` on the device, or rotate the key from Intune.",
    links: &[
        "https://learn.microsoft.com/intune/intune-service/protect/encrypt-devices",
        "https://learn.microsoft.com/graph/api/bitlocker-list-recoverykeys",
    ],
    references: &["M365-Secure INTUNE-ENCRYPTION-001"],
    manual: None,
};

crate::check!(BitlockerEscrow, &BITLOCKER_ESCROW, bitlocker_escrow);

async fn bitlocker_escrow(ctx: &CheckContext) -> Evaluation {
    let id = BITLOCKER_ESCROW.id;
    if let Some(finding) = without_intune(ctx, id) {
        return Ok(finding);
    }
    let devices = managed_devices(ctx).await?;
    let (windows, stale) = active_windows(ctx, &devices);
    if windows.is_empty() {
        return Ok(Finding::not_applicable(
            "no_windows_devices",
            format!("No active Windows devices are managed by Intune ({stale} stale left out)."),
        ));
    }
    let encrypted: Vec<&Device> = windows
        .iter()
        .filter(|d| d.encrypted == Some(true))
        .collect();
    let unencrypted: Vec<String> = windows
        .iter()
        .filter(|d| d.encrypted == Some(false))
        .map(|d| d.name.clone())
        .collect();
    let mut data = json!({
        "windows_devices": windows.len(),
        "encrypted": encrypted.len(),
        "not_encrypted": unencrypted.len(),
        "stale_left_out": stale,
    });
    if encrypted.is_empty() {
        return Ok(Finding::warn(format!(
            "None of the {} active Windows devices reports BitLocker encryption, so there are no keys to check; assign a disk encryption policy.",
            windows.len()
        ))
        .data(data)
        .affected(unencrypted));
    }
    // Metadata only: no $select, so `key` is never returned.
    let keys = ctx.list(RECOVERY_KEYS.operation, json!({})).await?.items;
    let escrowed: BTreeSet<String> = keys
        .iter()
        .map(|k| text(k, "deviceId").to_ascii_lowercase())
        .collect();
    let missing: Vec<String> = encrypted
        .iter()
        .filter(|d| d.entra_id.is_empty() || !escrowed.contains(&d.entra_id))
        .map(|d| d.name.clone())
        .collect();
    data["recovery_keys"] = json!(keys.len());
    data["missing_key"] = json!(missing.len());
    let finding = if missing.is_empty() {
        Finding::pass(format!(
            "All {} encrypted Windows devices have a BitLocker recovery key in Entra ID.",
            encrypted.len()
        ))
    } else {
        Finding::fail(format!(
            "{} of {} encrypted Windows devices have no BitLocker recovery key in Entra ID.",
            missing.len(),
            encrypted.len()
        ))
    };
    Ok(finding.data(data).affected(missing))
}
