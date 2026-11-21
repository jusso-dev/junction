//! Windows update rings, OS patch age and browser versions.
use super::builds::{BuildState, WindowsBuilds};
use super::*;
use crate::check::{CheckMeta, Evaluation, Requirements};
use crate::model::{CheckKind, Level, Pack, Severity};
use std::collections::{BTreeMap, BTreeSet};

const DEVICE_CONFIGURATIONS: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.device_configurations.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};
const FEATURE_PROFILES: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.windows_feature_update_profiles.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};
const QUALITY_PROFILES: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.windows_quality_update_profiles.list",
    permissions: &["DeviceManagementConfiguration.Read.All"],
};
const MACHINE_VULNERABILITIES: ApiRequirement = ApiRequirement {
    operation: "defender.endpoint.vulnerabilities.list_machines_vulnerabilities",
    permissions: &["Vulnerability.Read.All"],
};
const VULNERABILITIES: ApiRequirement = ApiRequirement {
    operation: "defender.endpoint.vulnerabilities.list",
    permissions: &["Vulnerability.Read.All"],
};
const MACHINES: ApiRequirement = ApiRequirement {
    operation: "defender.endpoint.machines.list",
    permissions: &["Machine.Read.All"],
};
const SOFTWARE_INVENTORY: ApiRequirement = ApiRequirement {
    operation: "defender.endpoint.machines.list_software_inventory_by_machine",
    permissions: &["Software.Read.All"],
};

const TVM: &str = "defender_vulnerability_management";

// ---------------------------------------------------------------- update rings

pub const UPDATE_RINGS: CheckMeta = CheckMeta {
    id: "intune.update_rings",
    title: "Windows update rings install quality updates within a week",
    pack: Pack::Intune,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Reads Intune Windows Update for Business rings (device configurations) and, when there are none, feature and quality update profiles. Passes when a ring assigned to all devices or all users defers quality updates 7 days or less (`max_quality_deferral_days`) and is not paused; Windows Autopatch rings count. Slow or paused rings, or rings assigned only to groups, are a warning. Needs Microsoft Intune Plan 1.",
    requires: Requirements {
        apis: &[DEVICE_CONFIGURATIONS, FEATURE_PROFILES, QUALITY_PROFILES],
        licences: &[],
    },
    remediation: "In Intune > Devices > Windows updates > Update rings, create a ring with a quality update deferral of 7 days or less, a deadline of a few days and no pause, and assign it to All devices (use short-deferral pilot rings for testing). Alternatively enrol devices in Windows Autopatch.",
    links: &[
        "https://learn.microsoft.com/intune/intune-service/protect/windows-update-for-business-configure",
        "https://learn.microsoft.com/windows/deployment/windows-autopatch/overview/windows-autopatch-overview",
    ],
    references: &["M365-Secure INTUNE-UPDATE-001"],
    manual: None,
};

crate::check!(UpdateRings, &UPDATE_RINGS, update_rings);

async fn update_rings(ctx: &CheckContext) -> Evaluation {
    let id = UPDATE_RINGS.id;
    if let Some(finding) = without_intune(ctx, id) {
        return Ok(finding);
    }
    let max: i64 = ctx.setting(id, "max_quality_deferral_days", 7);
    let configs = ctx
        .list_with(
            DEVICE_CONFIGURATIONS.operation,
            json!({ "$expand": ["assignments"] }),
        )
        .await?;
    let rings: Vec<&Value> = configs
        .iter()
        .filter(|c| text(c, "@odata.type").ends_with("windowsUpdateForBusinessConfiguration"))
        .collect();
    let mut evidence = vec![];
    let (mut good_all, mut good_groups, mut slow) = (vec![], vec![], vec![]);
    let mut autopatch = false;
    for ring in &rings {
        let name = name_of(ring);
        let scope = scope(ring);
        let deferral = ring
            .get("qualityUpdatesDeferralPeriodInDays")
            .and_then(Value::as_i64);
        let paused = ring
            .get("qualityUpdatesPaused")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        evidence.push(json!({
            "name": name,
            "assigned_to": scope.as_str(),
            "quality_deferral_days": deferral,
            "quality_paused": paused,
        }));
        if scope == Scope::None {
            continue;
        }
        if name.to_ascii_lowercase().contains("autopatch") {
            autopatch = true;
            good_all.push(name);
        } else if paused || deferral.is_none_or(|d| d > max) {
            slow.push(name);
        } else if scope == Scope::All {
            good_all.push(name);
        } else {
            good_groups.push(name);
        }
    }
    let mut data = json!({
        "rings": evidence,
        "max_quality_deferral_days": max,
        "autopatch": autopatch,
    });
    let finding = if !good_all.is_empty() && slow.is_empty() {
        Finding::pass(format!(
            "Update ring{} {} assigned to all devices or users with quality deferral of {max} days or less.",
            if good_all.len() == 1 { "" } else { "s" },
            good_all.join(", ")
        ))
    } else if !good_all.is_empty() || !good_groups.is_empty() {
        let mut gaps = vec![];
        if good_all.is_empty() {
            gaps.push(format!(
                "compliant rings ({}) are assigned only to groups; confirm they cover every Windows device",
                good_groups.join(", ")
            ));
        }
        if !slow.is_empty() {
            gaps.push(format!(
                "{} defer quality updates more than {max} days or are paused",
                slow.join(", ")
            ));
        }
        Finding::warn(format!(
            "Update rings are partly in place: {}.",
            gaps.join("; ")
        ))
    } else if !slow.is_empty() {
        Finding::fail(format!(
            "No assigned update ring installs quality updates within {max} days ({} defer longer or are paused).",
            slow.join(", ")
        ))
    } else {
        // No assigned ring: feature or quality (expedite) profiles are the only
        // other Intune update control. They cannot exist without Windows Enterprise.
        let mut profiles = vec![];
        if ctx.has_feature("windows_enterprise") != Some(false) {
            for op in [FEATURE_PROFILES.operation, QUALITY_PROFILES.operation] {
                let listed = ctx
                    .list_with(op, json!({ "$expand": ["assignments"] }))
                    .await?;
                profiles.extend(
                    listed
                        .iter()
                        .filter(|p| scope(p) != Scope::None)
                        .map(name_of),
                );
            }
        }
        data["update_profiles"] = json!(profiles);
        if profiles.is_empty() {
            Finding::fail(format!(
                "No Windows update ring or update profile is assigned ({} ring{} unassigned). Windows Update deferral and deadlines are not managed by Intune.",
                rings.len(),
                if rings.len() == 1 { "" } else { "s" }
            ))
        } else {
            Finding::warn(format!(
                "Only feature or quality update profiles are assigned ({}); no update ring sets the quality update deferral.",
                profiles.join(", ")
            ))
        }
    };
    Ok(finding.data(data).affected(slow))
}

// ---------------------------------------------------------------- patch age

pub const PATCH_AGE: CheckMeta = CheckMeta {
    id: "intune.patch_age",
    title: "Windows devices have security updates within Essential Eight timeframes",
    pack: Pack::Intune,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Compares each active Intune-managed Windows device's OS build with the monthly security updates in data/windows-builds.yaml (Microsoft release health) and flags devices missing an update released more than `max_age_days` ago (default 30: Essential Eight one month for workstations, ISM-1695 and ISM-1902). When Defender Vulnerability Management is licensed it also flags vulnerabilities older than `app_max_age_days` (default 14, two weeks for browsers, Office, email clients and PDF readers, ISM-1691) or `max_age_days` for everything else, using the CVE publication date as the release date. With `maturity_level = 3` critical or exploited vulnerabilities must be fixed within `critical_max_hours` (default 48, ISM-1696). Devices that have not checked in for `[packs.intune] stale_days` are left out. Override the build data with `[packs.intune.windows_builds]`. Needs Microsoft Intune Plan 1.",
    requires: Requirements {
        apis: &[
            MANAGED_DEVICES,
            MACHINE_VULNERABILITIES,
            VULNERABILITIES,
            MACHINES,
        ],
        licences: &[],
    },
    remediation: "Make sure update rings with short deferrals and deadlines are assigned to every Windows device (see intune.update_rings), then investigate the listed devices: check Windows Update for Business reports or the device's update history for failed or blocked installs, and restart devices waiting on a reboot. Replace devices on Windows releases that are out of support.",
    links: &[
        "https://learn.microsoft.com/windows/release-health/",
        "https://learn.microsoft.com/defender-vulnerability-management/tvm-weaknesses",
        "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model",
    ],
    references: &["M365-Secure INTUNE-UPDATE-001"],
    manual: None,
};

crate::check!(PatchAge, &PATCH_AGE, patch_age);

/// Applications Essential Eight wants patched within two weeks.
const FAST_APPS: &[&str] = &[
    "edge",
    "chrome",
    "firefox",
    "office",
    "word",
    "excel",
    "powerpoint",
    "outlook",
    "teams",
    "acrobat",
    "reader",
    "pdf",
    "thunderbird",
    "java",
];

async fn patch_age(ctx: &CheckContext) -> Evaluation {
    let id = PATCH_AGE.id;
    if let Some(finding) = without_intune(ctx, id) {
        return Ok(finding);
    }
    let level: u8 = ctx.setting(id, "maturity_level", 1);
    let max_days: u64 = ctx.setting(id, "max_age_days", 30);
    let app_days: u64 = ctx.setting(id, "app_max_age_days", 14);
    let critical_hours: u64 = ctx.setting(id, "critical_max_hours", 48);
    let builds: WindowsBuilds = ctx.pack_setting(PACK, "windows_builds", WindowsBuilds::embedded());
    let now = ctx.now();

    let devices = managed_devices(ctx).await?;
    let (windows, stale) = active_windows(ctx, &devices);
    if windows.is_empty() {
        return Ok(Finding::not_applicable(
            "no_windows_devices",
            format!("No active Windows devices are managed by Intune ({stale} stale left out)."),
        ));
    }
    let cutoff = now.minus(days(max_days));
    let (mut behind, mut unsupported, mut unrecognised) = (vec![], vec![], vec![]);
    let mut affected: BTreeSet<String> = BTreeSet::new();
    let mut current = 0;
    for d in &windows {
        let server = d.os.to_ascii_lowercase().contains("server");
        match builds.locate(&d.os_version, server) {
            BuildState::Unrecognised => {
                unrecognised.push(json!({"device": d.name, "os_version": d.os_version}))
            }
            BuildState::Current(release) | BuildState::Behind(release, _)
                if release.out_of_support(now) =>
            {
                unsupported.push(json!({"device": d.name, "release": release.name}));
            }
            BuildState::Current(_) => current += 1,
            BuildState::Behind(release, update) => {
                let released = parse_date(&update.released).unwrap_or(now);
                if released < cutoff {
                    affected.insert(d.name.clone());
                    behind.push(json!({
                        "device": d.name,
                        "os_version": d.os_version,
                        "release": release.name,
                        "missing_since": update.released,
                        "missing_update": update.kb,
                    }));
                } else {
                    current += 1;
                }
            }
        }
    }
    let reviewed = builds.reviewed_at();
    let data_stale = reviewed.is_none_or(|r| now.since(r) > days(45));

    // Defender Vulnerability Management: unremediated vulnerabilities by age.
    let intune_names: BTreeMap<String, String> = windows
        .iter()
        .map(|d| (d.name.to_ascii_lowercase(), d.name.clone()))
        .collect();
    let tvm = if ctx.has_feature(TVM) == Some(false) {
        json!({"status": "not licensed"})
    } else {
        match tvm_overdue(ctx, level, max_days, app_days, critical_hours).await {
            Ok((overdue, rows)) => {
                let mut by_device: BTreeMap<String, usize> = BTreeMap::new();
                for (device, _) in &overdue {
                    // Defender names devices by DNS name; use the Intune name when they match.
                    let host = device
                        .split('.')
                        .next()
                        .unwrap_or(device)
                        .to_ascii_lowercase();
                    let name = intune_names.get(&host).unwrap_or(device);
                    *by_device.entry(name.clone()).or_default() += 1;
                }
                affected.extend(by_device.keys().cloned());
                json!({
                    "status": "read",
                    "vulnerable_software_rows": rows,
                    "overdue": overdue.len(),
                    "overdue_by_device": by_device.into_iter().take(EVIDENCE_CAP).collect::<BTreeMap<_, _>>(),
                })
            }
            // Licensed: an unreadable TVM is an unknown result, not a pass.
            Err(failure) if ctx.has_feature(TVM) == Some(true) => return Err(failure),
            Err(failure) => json!({"status": format!("not read: {failure}")}),
        }
    };
    let tvm_overdue = tvm.get("overdue").and_then(Value::as_u64).unwrap_or(0);
    let data = json!({
        "windows_devices": windows.len(),
        "stale_left_out": stale,
        "current": current,
        "behind": behind.len(),
        "behind_devices": capped(&behind),
        "unsupported": capped(&unsupported),
        "unrecognised": capped(&unrecognised),
        "max_age_days": max_days,
        "maturity_level": level,
        "builds_reviewed": builds.reviewed,
        "tvm": tvm,
    });
    let finding = if !behind.is_empty() || tvm_overdue > 0 {
        let mut parts = vec![];
        if !behind.is_empty() {
            parts.push(format!(
                "{} of {} Windows devices are missing a security update released more than {max_days} days ago",
                behind.len(),
                windows.len()
            ));
        }
        if tvm_overdue > 0 {
            parts.push(format!(
                "Defender Vulnerability Management reports {} past the patch timeframe",
                plural(tvm_overdue as usize, "vulnerable software install")
            ));
        }
        Finding::fail(format!("{}.", parts.join("; ")))
    } else if !unsupported.is_empty() {
        Finding::warn(format!(
            "{} Windows devices run a release that is out of support (Extended Security Updates at best); replace or upgrade them.",
            unsupported.len()
        ))
    } else if !unrecognised.is_empty() {
        Finding::warn(format!(
            "{} Windows devices run a build not in the release data; check them or update windows-builds.yaml.",
            unrecognised.len()
        ))
    } else if data_stale {
        Finding::warn(format!(
            "All {current} Windows devices have the updates in the release data, but that data was last reviewed {}; newer updates may be missing. Update [packs.intune.windows_builds] or Junction.",
            builds.reviewed
        ))
    } else {
        Finding::pass(format!(
            "All {current} active Windows devices have every security update older than {max_days} days."
        ))
    };
    let mut affected: Vec<String> = affected.into_iter().collect();
    affected.extend(
        unsupported
            .iter()
            .filter_map(|u| u["device"].as_str().map(str::to_owned)),
    );
    Ok(finding.data(data).affected(affected))
}

/// Overdue `(device, cve)` pairs and the number of vulnerable software rows.
async fn tvm_overdue(
    ctx: &CheckContext,
    level: u8,
    max_days: u64,
    app_days: u64,
    critical_hours: u64,
) -> Result<(Vec<(String, String)>, usize), CallFailure> {
    let rows = ctx
        .list(MACHINE_VULNERABILITIES.operation, json!({}))
        .await?
        .items;
    let catalogue = ctx.list(VULNERABILITIES.operation, json!({})).await?.items;
    let machines = ctx.list(MACHINES.operation, json!({})).await?.items;
    let names: BTreeMap<String, String> = machines
        .iter()
        .map(|m| (text(m, "id"), text(m, "computerDnsName")))
        .collect();
    // cve -> (published, critical or exploited)
    let cves: BTreeMap<String, (Option<Instant>, bool)> = catalogue
        .iter()
        .map(|v| {
            let exploited = ["publicExploit", "exploitVerified", "exploitInKit"]
                .iter()
                .any(|k| v.get(*k).and_then(Value::as_bool) == Some(true));
            let critical = text(v, "severity").eq_ignore_ascii_case("critical");
            (
                text(v, "id"),
                (
                    v.get("publishedOn")
                        .and_then(Value::as_str)
                        .and_then(parse_date),
                    critical || exploited,
                ),
            )
        })
        .collect();
    let now = ctx.now();
    let mut overdue = vec![];
    for row in &rows {
        let cve = text(row, "cveId");
        let Some((Some(published), urgent)) = cves.get(&cve).copied() else {
            continue;
        };
        let product = text(row, "productName").to_ascii_lowercase();
        let fast = FAST_APPS.iter().any(|a| product.contains(a));
        let limit = if level >= 3 && urgent {
            Duration::from_secs(critical_hours * 3600)
        } else if fast {
            days(app_days)
        } else {
            days(max_days)
        };
        if now.since(published) > limit {
            let machine = text(row, "machineId");
            let name = names
                .get(&machine)
                .filter(|n| !n.is_empty())
                .cloned()
                .unwrap_or(machine);
            overdue.push((name, cve));
        }
    }
    Ok((overdue, rows.len()))
}

// ---------------------------------------------------------------- browsers

pub const BROWSER_UPDATES: CheckMeta = CheckMeta {
    id: "intune.browser_updates",
    title: "Edge and Chrome are up to date on every device",
    pack: Pack::Intune,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "Reads the Defender Vulnerability Management software inventory and compares each device's Microsoft Edge and Google Chrome version with the newest version seen in the tenant and with an optional configured minimum (`minimum_versions = { edge = \"...\", chrome = \"...\" }`). Heuristic: both browsers ship a major version about every four weeks and update themselves, so a device more than `max_major_behind` (default 1) major versions behind the newest copy in the tenant, or below the minimum, has stopped updating. Patches within a major version are not compared; installs with known vulnerabilities are a warning. If every device is stale the tenant-relative comparison cannot see it, which is what the minimum is for.",
    requires: Requirements {
        apis: &[SOFTWARE_INVENTORY],
        licences: &[TVM],
    },
    remediation: "Keep the browsers' automatic updates on (do not disable Edge Update or Google Update by policy), manage them with the Edge and Chrome update policies in Intune, and investigate the listed devices for broken updaters or old per-user installs. Remove browsers you do not support.",
    links: &[
        "https://learn.microsoft.com/deployedge/microsoft-edge-update-policies",
        "https://learn.microsoft.com/defender-vulnerability-management/tvm-software-inventory",
    ],
    references: &[],
    manual: None,
};

crate::check!(BrowserUpdates, &BROWSER_UPDATES, browser_updates);

const BROWSERS: &[(&str, &str, &str)] = &[
    ("edge", "microsoft", "edge"),
    ("chrome", "google", "chrome"),
];

async fn browser_updates(ctx: &CheckContext) -> Evaluation {
    let id = BROWSER_UPDATES.id;
    let tolerance: u64 = ctx.setting(id, "max_major_behind", 1);
    let minimums: BTreeMap<String, String> = ctx.setting(id, "minimum_versions", BTreeMap::new());
    let listing = ctx.list(SOFTWARE_INVENTORY.operation, json!({})).await?;
    // (browser, device) -> (lowest version, weaknesses)
    let mut installs: BTreeMap<(&str, String), (String, u64)> = BTreeMap::new();
    for row in &listing.items {
        let vendor = text(row, "softwareVendor").to_ascii_lowercase();
        let name = text(row, "softwareName").to_ascii_lowercase();
        let Some((browser, _, _)) = BROWSERS.iter().find(|(_, v, n)| vendor == *v && name == *n)
        else {
            continue;
        };
        let device = row
            .get("deviceName")
            .or_else(|| row.get("deviceId"))
            .and_then(Value::as_str)
            .unwrap_or("(unnamed)")
            .to_owned();
        let version = text(row, "softwareVersion");
        let weaknesses = row
            .get("numberOfWeaknesses")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let entry = installs
            .entry((browser, device))
            .or_insert((version.clone(), weaknesses));
        if version_key(&version) < version_key(&entry.0) {
            *entry = (version, weaknesses.max(entry.1));
        } else {
            entry.1 = entry.1.max(weaknesses);
        }
    }
    if installs.is_empty() {
        return Ok(Finding::unknown(
            "no_data",
            format!(
                "The Defender software inventory has no Edge or Chrome installs ({} rows read); devices may not be onboarded.",
                listing.items.len()
            ),
        ));
    }
    let mut summary = serde_json::Map::new();
    let (mut behind, mut weak) = (vec![], vec![]);
    let mut affected = BTreeSet::new();
    for (browser, _, _) in BROWSERS {
        let mine: Vec<(&String, &(String, u64))> = installs
            .iter()
            .filter(|((b, _), _)| b == browser)
            .map(|((_, d), v)| (d, v))
            .collect();
        if mine.is_empty() {
            continue;
        }
        let newest = mine
            .iter()
            .map(|(_, (v, _))| v.clone())
            .max_by_key(|v| version_key(v))
            .unwrap_or_default();
        let newest_major = version_key(&newest).first().copied().unwrap_or(0);
        let minimum = minimums.get(*browser).cloned();
        let mut late = 0;
        for (device, (version, weaknesses)) in &mine {
            let major = version_key(version).first().copied().unwrap_or(0);
            let below_minimum = minimum
                .as_deref()
                .is_some_and(|m| version_key(version) < version_key(m));
            if below_minimum || major + tolerance < newest_major {
                late += 1;
                affected.insert((*device).clone());
                behind.push(json!({"device": device, "browser": browser, "version": version}));
            } else if *weaknesses > 0 {
                weak.push(json!({"device": device, "browser": browser, "version": version, "weaknesses": weaknesses}));
            }
        }
        summary.insert(
            (*browser).to_owned(),
            json!({"installs": mine.len(), "newest": newest, "minimum": minimum, "behind": late}),
        );
    }
    let data = json!({
        "browsers": summary,
        "max_major_behind": tolerance,
        "behind": capped(&behind),
        "with_known_weaknesses": weak.len(),
        "inventory_truncated": listing.truncated,
    });
    let finding = if !behind.is_empty() {
        Finding::fail(format!(
            "{} on {} {} more than {tolerance} major version{} behind the newest in the tenant or below the configured minimum.",
            plural(behind.len(), "browser install"),
            plural(affected.len(), "device"),
            if behind.len() == 1 { "is" } else { "are" },
            if tolerance == 1 { "" } else { "s" }
        ))
    } else if !weak.is_empty() {
        Finding::warn(format!(
            "Edge and Chrome are within {tolerance} major version of the newest in the tenant, but {} installs have known vulnerabilities (a patch within the major version is missing).",
            weak.len()
        ))
    } else {
        Finding::pass(format!(
            "All {} Edge and Chrome installs are current.",
            installs.len()
        ))
    };
    Ok(finding.data(data).affected(affected))
}
