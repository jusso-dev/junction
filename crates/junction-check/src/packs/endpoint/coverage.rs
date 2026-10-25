//! Endpoint pack: Defender for Endpoint coverage and sensor health.
//!
//! Compares the Entra ID and Intune device inventory, Azure VMs and Azure Arc
//! machines with Defender for Endpoint machines, and reads sensor health and
//! operating system support from the machine list. The device matching helpers
//! are `pub(crate)` so other endpoint checks can reuse them.
use crate::check::{ApiRequirement, Check, CheckMeta, Evaluation, Finding, Requirements};
use crate::context::{CallFailure, CheckContext};
use crate::model::{CheckKind, Level, Pack, Severity};
use junction_watch::clock::Instant;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(OnboardingCoverage),
        Arc::new(StaleSensors),
        Arc::new(UnsupportedOs),
        Arc::new(LinuxMacosHealth),
        Arc::new(ServersCovered),
    ]
}

pub(crate) const MACHINES: ApiRequirement = ApiRequirement {
    operation: "defender.endpoint.machines.list",
    permissions: &["Machine.Read.All"],
};
const DEVICES: ApiRequirement = ApiRequirement {
    operation: "graph.devices.list",
    permissions: &["Device.Read.All"],
};
const MANAGED_DEVICES: ApiRequirement = ApiRequirement {
    operation: "graph.device_management.managed_devices.list",
    permissions: &["DeviceManagementManagedDevices.Read.All"],
};
const RESOURCE_GRAPH: ApiRequirement = ApiRequirement {
    operation: "azure.resource_graph.resources.post",
    permissions: &["Reader"],
};
const ARC_MACHINES: ApiRequirement = ApiRequirement {
    operation: "azure.arc.machines.list_by_subscription",
    permissions: &["Reader"],
};
const MDE: &[&str] = &["defender_endpoint"];

const SUBSCRIPTIONS_KQL: &str = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name";
const VMS_KQL: &str = "resources | where type =~ 'microsoft.compute/virtualmachines' | project id, name, subscriptionId, vmId = tostring(properties.vmId), computerName = tostring(properties.osProfile.computerName), osType = tostring(properties.storageProfile.osDisk.osType), powerState = tostring(properties.extended.instanceView.powerState.code)";
/// Resource Graph pages read before giving up (1,000 rows each).
const GRAPH_PAGES: usize = 50;

// ---------------------------------------------------------------------------
// Device matching helpers
// ---------------------------------------------------------------------------

/// Platform family used to match and group devices and machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Platform {
    Windows,
    WindowsServer,
    MacOs,
    Linux,
    Ios,
    Android,
    Other,
}

const LINUX_DISTROS: &[&str] = &[
    "ubuntu",
    "debian",
    "centos",
    "redhat",
    "rhel",
    "suse",
    "sles",
    "opensuse",
    "oracle",
    "amazon",
    "fedora",
    "alma",
    "rocky",
    "mariner",
    "azurelinux",
];

impl Platform {
    /// From an Entra or Intune `operatingSystem` or an MDE `osPlatform`.
    pub(crate) fn from_os(os: &str) -> Self {
        let os = os.trim().to_ascii_lowercase();
        if os.starts_with("windows") && os.contains("server") {
            Self::WindowsServer
        } else if os.starts_with("windows") {
            Self::Windows
        } else if os.starts_with("mac") || os == "osx" {
            Self::MacOs
        } else if os == "ios"
            || os == "ipados"
            || os.starts_with("iphone")
            || os.starts_with("ipad")
        {
            Self::Ios
        } else if os.starts_with("android") {
            Self::Android
        } else if os.contains("linux") || LINUX_DISTROS.iter().any(|d| os.starts_with(d)) {
            Self::Linux
        } else {
            Self::Other
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::WindowsServer => "Windows Server",
            Self::MacOs => "macOS",
            Self::Linux => "Linux",
            Self::Ios => "iOS",
            Self::Android => "Android",
            Self::Other => "Other",
        }
    }
    pub(crate) fn is_mobile(self) -> bool {
        matches!(self, Self::Ios | Self::Android)
    }
    /// Could a device on `self` be the same as a machine on `other`?
    fn compatible(self, other: Platform) -> bool {
        let windows = |p| matches!(p, Self::Windows | Self::WindowsServer);
        self == other
            || self == Self::Other
            || other == Self::Other
            || (windows(self) && windows(other))
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn timestamp(value: &Value, key: &str) -> Option<Instant> {
    text(value, key).and_then(|t| Instant::parse(t).ok())
}

fn days(n: u64) -> Duration {
    Duration::from_secs(n.saturating_mul(86_400))
}

/// Matching key for a device name: lower case, first DNS label.
pub(crate) fn name_key(name: &str) -> String {
    name.trim()
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// A usable Entra device id in lower case (not empty, not the all-zero GUID).
pub(crate) fn device_id_key(id: Option<&str>) -> Option<String> {
    let id = id?.trim().to_ascii_lowercase();
    id.chars().any(|c| c != '0' && c != '-').then_some(id)
}

/// MDE `onboardingStatus` is `Onboarded` (not merely discovered).
pub(crate) fn is_onboarded(machine: &Value) -> bool {
    text(machine, "onboardingStatus").is_some_and(|s| s.eq_ignore_ascii_case("Onboarded"))
}

/// Excluded from the device inventory by an administrator.
fn is_excluded(machine: &Value) -> bool {
    machine.get("isExcluded").and_then(Value::as_bool) == Some(true)
}

pub(crate) fn machine_name(machine: &Value) -> &str {
    text(machine, "computerDnsName")
        .or_else(|| text(machine, "id"))
        .unwrap_or("(unnamed)")
}

pub(crate) fn machine_platform(machine: &Value) -> Platform {
    text(machine, "osPlatform")
        .map(Platform::from_os)
        .unwrap_or(Platform::Other)
}

/// Onboarded machines that are not excluded: the machines a sensor check reads.
fn sensors(machines: &[Value]) -> Vec<&Value> {
    machines
        .iter()
        .filter(|m| is_onboarded(m) && !is_excluded(m))
        .collect()
}

/// How an inventory device was matched to a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchedBy {
    DeviceId,
    Name,
}

/// Defender for Endpoint machines indexed by Entra device id and name.
pub(crate) struct MachineIndex<'a> {
    machines: &'a [Value],
    by_device_id: HashMap<String, Vec<usize>>,
    by_name: HashMap<String, Vec<usize>>,
}

impl<'a> MachineIndex<'a> {
    pub(crate) fn new(machines: &'a [Value]) -> Self {
        let mut by_device_id: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, m) in machines.iter().enumerate() {
            if let Some(id) = device_id_key(text(m, "aadDeviceId")) {
                by_device_id.entry(id).or_default().push(i);
            }
            if let Some(name) = text(m, "computerDnsName") {
                by_name.entry(name_key(name)).or_default().push(i);
            }
        }
        Self {
            machines,
            by_device_id,
            by_name,
        }
    }

    /// The best machine record for a device: by Entra device id, then by name
    /// among records on a compatible platform that do not carry another
    /// inventory device's id (`claimed`). Among duplicates, onboarded records
    /// win, then the most recently seen.
    pub(crate) fn find(
        &self,
        device_id: Option<&str>,
        name: &str,
        platform: Platform,
        claimed: &HashSet<String>,
    ) -> Option<(&'a Value, MatchedBy)> {
        if let Some(found) = device_id
            .and_then(|id| self.by_device_id.get(id))
            .and_then(|ids| self.best(ids))
        {
            return Some((found, MatchedBy::DeviceId));
        }
        let candidates: Vec<usize> = self
            .by_name
            .get(&name_key(name))
            .into_iter()
            .flatten()
            .copied()
            .filter(|&i| {
                let m = &self.machines[i];
                let taken = device_id_key(text(m, "aadDeviceId"))
                    .is_some_and(|id| Some(id.as_str()) != device_id && claimed.contains(&id));
                !taken && platform.compatible(machine_platform(m))
            })
            .collect();
        self.best(&candidates).map(|m| (m, MatchedBy::Name))
    }

    fn best(&self, indices: &[usize]) -> Option<&'a Value> {
        indices
            .iter()
            .map(|&i| &self.machines[i])
            .max_by_key(|m| (is_onboarded(m), timestamp(m, "lastSeen")))
    }
}

/// One device from Entra ID and/or Intune.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct InventoryDevice {
    pub device_id: Option<String>,
    pub name: String,
    pub platform: Platform,
    /// Latest Entra sign-in or Intune sync.
    pub last_active: Option<Instant>,
}

/// Merge Entra devices and Intune managed devices on Entra device id (or name
/// and platform when there is none). Disabled Entra devices are dropped; the
/// Intune name wins because Entra display names lag behind renames.
pub(crate) fn inventory(entra: &[Value], intune: &[Value]) -> Vec<InventoryDevice> {
    let mut merged: BTreeMap<String, InventoryDevice> = BTreeMap::new();
    let mut add = |id: Option<String>,
                   name: &str,
                   os: Option<&str>,
                   seen: Option<Instant>,
                   from_intune: bool| {
        let platform = os.map(Platform::from_os).unwrap_or(Platform::Other);
        let key = match &id {
            Some(id) => format!("id:{id}"),
            None => format!("name:{}:{}", name_key(name), platform.as_str()),
        };
        let device = merged.entry(key).or_insert_with(|| InventoryDevice {
            device_id: id,
            name: name.to_owned(),
            platform,
            last_active: seen,
        });
        if from_intune {
            device.name = name.to_owned();
        }
        if device.platform == Platform::Other {
            device.platform = platform;
        }
        device.last_active = device.last_active.max(seen);
    };
    for d in entra {
        if d.get("accountEnabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        if let Some(name) = text(d, "displayName") {
            add(
                device_id_key(text(d, "deviceId")),
                name,
                text(d, "operatingSystem"),
                timestamp(d, "approximateLastSignInDateTime"),
                false,
            );
        }
    }
    for d in intune {
        if let Some(name) = text(d, "deviceName") {
            add(
                device_id_key(text(d, "azureADDeviceId")),
                name,
                text(d, "operatingSystem"),
                timestamp(d, "lastSyncDateTime"),
                true,
            );
        }
    }
    merged.into_values().collect()
}

/// Sensor state of an onboarded machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SensorHealth {
    Active,
    ImpairedCommunication,
    NoSensorData,
    /// `Inactive`, or not seen within the threshold.
    Inactive,
}

pub(crate) fn sensor_health(machine: &Value, cutoff: Instant) -> SensorHealth {
    let status = text(machine, "healthStatus")
        .unwrap_or_default()
        .to_ascii_lowercase();
    match status.as_str() {
        "impairedcommunication" => SensorHealth::ImpairedCommunication,
        "nosensordata" | "nosensordataimpairedcommunication" => SensorHealth::NoSensorData,
        "inactive" => SensorHealth::Inactive,
        _ if timestamp(machine, "lastSeen").is_none_or(|t| t < cutoff) => SensorHealth::Inactive,
        _ => SensorHealth::Active,
    }
}

fn truncated(operation: &str) -> Finding {
    Finding::unknown(
        "truncated",
        format!(
            "{operation} returned more items than the run's paging limits allow, so the result would be partial."
        ),
    )
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn sorted(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items.dedup();
    items
}

// ---------------------------------------------------------------------------
// endpoint.onboarding_coverage
// ---------------------------------------------------------------------------

pub const ONBOARDING_COVERAGE: CheckMeta = CheckMeta {
    id: "endpoint.onboarding_coverage",
    title: "Every active device is onboarded to Defender for Endpoint",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Compares enabled Entra ID devices and Intune managed devices active in the last 30 days (Windows, Windows Server, macOS, Linux, iOS and Android) with Defender for Endpoint machines, matching on Entra device id and then on device name. A device without an onboarded machine record has no endpoint detection and response, so attacker activity on it goes unseen. Settings: `active_days` (30) and `platforms`.",
    requires: Requirements {
        apis: &[MACHINES, DEVICES, MANAGED_DEVICES],
        licences: MDE,
    },
    remediation: "Onboard the listed devices: deploy the Defender for Endpoint onboarding package through Intune (Endpoint security > Endpoint detection and response) or Configuration Manager, and on iOS and Android deploy the Microsoft Defender app. Devices listed as discovered but not onboarded appear in the Defender device inventory with 'Can be onboarded'.",
    links: &[
        "https://learn.microsoft.com/defender-endpoint/onboarding",
        "https://learn.microsoft.com/intune/intune-service/protect/advanced-threat-protection-configure",
        "https://learn.microsoft.com/defender-endpoint/device-discovery",
    ],
    references: &[],
    manual: None,
};

crate::check!(
    OnboardingCoverage,
    &ONBOARDING_COVERAGE,
    onboarding_coverage
);

#[derive(Default)]
struct Coverage {
    devices: usize,
    onboarded: usize,
    missing: usize,
}

async fn onboarding_coverage(ctx: &CheckContext) -> Evaluation {
    let id = ONBOARDING_COVERAGE.id;
    let active_days: u64 = ctx.setting(id, "active_days", 30);
    let platforms: Vec<String> = ctx.setting(
        id,
        "platforms",
        [
            "Windows",
            "Windows Server",
            "macOS",
            "Linux",
            "iOS",
            "Android",
        ]
        .map(str::to_owned)
        .to_vec(),
    );
    let wanted: HashSet<Platform> = platforms.iter().map(|p| Platform::from_os(p)).collect();
    let machines = ctx.list(MACHINES.operation, json!({})).await?;
    let entra = ctx.list(DEVICES.operation, json!({})).await?;
    // Without Intune there are no managed devices to read.
    let intune = match ctx.has_feature("intune") {
        Some(false) => None,
        _ => Some(ctx.list(MANAGED_DEVICES.operation, json!({})).await?),
    };
    for (operation, listing) in [
        (MACHINES.operation, Some(&machines)),
        (DEVICES.operation, Some(&entra)),
        (MANAGED_DEVICES.operation, intune.as_ref()),
    ] {
        if listing.is_some_and(|l| l.truncated) {
            return Ok(truncated(operation));
        }
    }
    let since = ctx.now().minus(days(active_days));
    let devices: Vec<InventoryDevice> = inventory(
        &entra.items,
        intune.as_ref().map(|l| l.items.as_slice()).unwrap_or(&[]),
    )
    .into_iter()
    .filter(|d| wanted.contains(&d.platform) && d.last_active.is_some_and(|t| t >= since))
    .collect();
    if devices.is_empty() {
        return Ok(Finding::not_applicable(
            "no_devices",
            format!(
                "No enabled Entra ID or Intune devices on the selected platforms were active in the last {active_days} days."
            ),
        ));
    }
    let index = MachineIndex::new(&machines.items);
    let claimed: HashSet<String> = devices.iter().filter_map(|d| d.device_id.clone()).collect();
    let mut by_platform: BTreeMap<&str, Coverage> = BTreeMap::new();
    let (mut by_id, mut by_name, mut discovered) = (0, 0, 0);
    let mut missing: Vec<&InventoryDevice> = vec![];
    for device in &devices {
        let found = index.find(
            device.device_id.as_deref(),
            &device.name,
            device.platform,
            &claimed,
        );
        let counts = by_platform.entry(device.platform.as_str()).or_default();
        counts.devices += 1;
        match found {
            Some((m, how)) if is_onboarded(m) => {
                counts.onboarded += 1;
                match how {
                    MatchedBy::DeviceId => by_id += 1,
                    MatchedBy::Name => by_name += 1,
                }
            }
            other => {
                counts.missing += 1;
                discovered += usize::from(other.is_some());
                missing.push(device);
            }
        }
    }
    let total = devices.len();
    let desktop = missing.iter().filter(|d| !d.platform.is_mobile()).count();
    let data = json!({
        "active_days": active_days,
        "devices": total,
        "onboarded": total - missing.len(),
        "missing": missing.len(),
        "discovered_not_onboarded": discovered,
        "matched_by": { "device_id": by_id, "name": by_name },
        "by_platform": by_platform.iter().map(|(p, c)| (p.to_string(), json!({
            "devices": c.devices, "onboarded": c.onboarded, "missing": c.missing,
        }))).collect::<serde_json::Map<_, _>>(),
    });
    let finding = if desktop > 0 {
        Finding::fail(format!(
            "{} of {total} active devices have no onboarded Defender for Endpoint record ({} on Windows, macOS or Linux).",
            missing.len(),
            desktop
        ))
    } else if !missing.is_empty() {
        Finding::warn(format!(
            "{} of {total} active devices, all iOS or Android, have no onboarded Defender for Endpoint record.",
            missing.len()
        ))
    } else {
        Finding::pass(format!(
            "All {} are onboarded to Defender for Endpoint.",
            plural(total, "active device", "active devices")
        ))
    };
    Ok(finding
        .data(data)
        .affected(sorted(missing.iter().map(|d| d.name.clone()).collect())))
}

// ---------------------------------------------------------------------------
// endpoint.stale_sensors
// ---------------------------------------------------------------------------

pub const STALE_SENSORS: CheckMeta = CheckMeta {
    id: "endpoint.stale_sensors",
    title: "Defender for Endpoint sensors are active and reporting",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Medium,
    impact: Level::High,
    description: "Reads the health of every onboarded, non-excluded Defender for Endpoint machine. Sensors with impaired communication or no sensor data are online but blind; machines that are Inactive or not seen for 7 days (setting `max_days`) may be offline, decommissioned or have a disabled sensor. Attackers stop or tamper with EDR sensors to hide activity.",
    requires: Requirements {
        apis: &[MACHINES],
        licences: MDE,
    },
    remediation: "For impaired or no-sensor-data machines, follow 'Fix unhealthy sensors': check connectivity to the Defender service URLs, proxy settings and that the Defender for Endpoint service is running. Offboard or exclude decommissioned machines so the inventory stays accurate, and investigate any machine whose sensor stopped unexpectedly.",
    links: &[
        "https://learn.microsoft.com/defender-endpoint/fix-unhealthy-sensors",
        "https://learn.microsoft.com/defender-endpoint/check-sensor-status",
        "https://learn.microsoft.com/defender-endpoint/exclude-devices",
    ],
    references: &[],
    manual: None,
};

crate::check!(StaleSensors, &STALE_SENSORS, stale_sensors);

#[derive(Default)]
struct Health {
    machines: usize,
    active: usize,
    impaired: usize,
    no_sensor_data: usize,
    inactive: usize,
}

impl Health {
    fn add(&mut self, health: SensorHealth) {
        self.machines += 1;
        match health {
            SensorHealth::Active => self.active += 1,
            SensorHealth::ImpairedCommunication => self.impaired += 1,
            SensorHealth::NoSensorData => self.no_sensor_data += 1,
            SensorHealth::Inactive => self.inactive += 1,
        }
    }
    fn json(&self) -> Value {
        json!({
            "machines": self.machines,
            "active": self.active,
            "impaired_communication": self.impaired,
            "no_sensor_data": self.no_sensor_data,
            "inactive": self.inactive,
        })
    }
}

async fn stale_sensors(ctx: &CheckContext) -> Evaluation {
    let max_days: u64 = ctx.setting(STALE_SENSORS.id, "max_days", 7);
    let machines = ctx.list(MACHINES.operation, json!({})).await?;
    if machines.truncated {
        return Ok(truncated(MACHINES.operation));
    }
    let sensors = sensors(&machines.items);
    if sensors.is_empty() {
        return Ok(Finding::not_applicable(
            "no_onboarded_devices",
            "No machines are onboarded to Defender for Endpoint.",
        ));
    }
    let cutoff = ctx.now().minus(days(max_days));
    let mut total = Health::default();
    let mut by_platform: BTreeMap<&str, Health> = BTreeMap::new();
    let mut affected = vec![];
    for m in &sensors {
        let health = sensor_health(m, cutoff);
        total.add(health);
        by_platform
            .entry(machine_platform(m).as_str())
            .or_default()
            .add(health);
        if health != SensorHealth::Active {
            affected.push(machine_name(m).to_owned());
        }
    }
    let mut data = total.json();
    data["max_days"] = json!(max_days);
    data["by_platform"] = by_platform
        .iter()
        .map(|(p, h)| (p.to_string(), h.json()))
        .collect::<serde_json::Map<_, _>>()
        .into();
    let blind = total.impaired + total.no_sensor_data;
    let finding = if blind > 0 {
        Finding::fail(format!(
            "{} of {} report impaired communication or no sensor data; {} inactive or not seen for {max_days} days.",
            blind,
            plural(total.machines, "onboarded machine", "onboarded machines"),
            total.inactive
        ))
    } else if total.inactive > 0 {
        Finding::warn(format!(
            "{} of {} are inactive or not seen for {max_days} days.",
            total.inactive,
            plural(total.machines, "onboarded machine", "onboarded machines")
        ))
    } else {
        Finding::pass(format!(
            "All {} are active and seen within {max_days} days.",
            plural(total.machines, "onboarded machine", "onboarded machines")
        ))
    };
    Ok(finding.data(data).affected(sorted(affected)))
}

// ---------------------------------------------------------------------------
// endpoint.unsupported_os
// ---------------------------------------------------------------------------

const OS_SUPPORT: &str = include_str!("../../../data/os-support.yaml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OsSupportData {
    review_date: String,
    #[allow(dead_code)]
    sources: Vec<String>,
    windows: BTreeMap<String, WindowsRule>,
    macos: MacRule,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsRule {
    #[serde(default)]
    unsupported: Option<String>,
    #[serde(default)]
    builds: Option<Vec<u64>>,
    #[serde(default)]
    min_build: Option<u64>,
    #[serde(default)]
    limited: Option<String>,
    #[serde(default)]
    limited_below: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MacRule {
    min_major: u64,
    note: String,
}

fn os_support_data() -> &'static OsSupportData {
    static DATA: OnceLock<OsSupportData> = OnceLock::new();
    DATA.get_or_init(|| serde_saphyr::from_str(OS_SUPPORT).expect("data/os-support.yaml is valid"))
}

/// Vendor support of a machine's operating system, from `data/os-support.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OsSupport {
    Supported,
    /// Supported only for some editions or with Extended Security Updates.
    Limited(String),
    Unsupported(String),
    /// Unknown platform or build.
    NotAssessed,
}

fn number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Leading major version of a dotted version string (`14.5.1` -> 14).
fn major(version: &str) -> Option<u64> {
    version.trim().split('.').next()?.parse().ok()
}

pub(crate) fn os_support(machine: &Value) -> OsSupport {
    let data = os_support_data();
    let Some(platform) = text(machine, "osPlatform") else {
        return OsSupport::NotAssessed;
    };
    if machine_platform(machine) == Platform::MacOs {
        let version = text(machine, "osVersion").or_else(|| text(machine, "version"));
        return match version.and_then(major) {
            Some(major) if major < data.macos.min_major => OsSupport::Unsupported(format!(
                "macOS {major} is older than macOS {}. {}",
                data.macos.min_major, data.macos.note
            )),
            Some(_) => OsSupport::Supported,
            None => OsSupport::NotAssessed,
        };
    }
    let Some(rule) = data
        .windows
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(platform))
        .map(|(_, r)| r)
    else {
        return OsSupport::NotAssessed;
    };
    if let Some(why) = &rule.unsupported {
        return OsSupport::Unsupported(why.clone());
    }
    let needs_build =
        rule.builds.is_some() || rule.min_build.is_some() || rule.limited_below.is_some();
    let build = machine.get("osBuild").and_then(number);
    let Some(build) = build.or(if needs_build { None } else { Some(0) }) else {
        return OsSupport::NotAssessed;
    };
    if rule.builds.as_ref().is_some_and(|b| !b.contains(&build))
        || rule.min_build.is_some_and(|min| build < min)
    {
        return OsSupport::Unsupported(format!(
            "{platform} build {build} no longer receives security updates."
        ));
    }
    match &rule.limited {
        Some(note) if rule.limited_below.is_none_or(|below| build < below) => {
            OsSupport::Limited(note.clone())
        }
        _ => OsSupport::Supported,
    }
}

pub const UNSUPPORTED_OS: CheckMeta = CheckMeta {
    id: "endpoint.unsupported_os",
    title: "Onboarded devices run a supported operating system",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::High,
    impact: Level::High,
    description: "Reads `osPlatform`, `osBuild` and version of every onboarded Defender for Endpoint machine and compares them with the minimum supported Windows 10, Windows 11 and Windows Server builds and macOS major versions in Junction's `data/os-support.yaml` (with its review date). Unsupported systems get no security updates. Builds serviced only for some editions or with Extended Security Updates are a warning; Linux and unknown platforms are not assessed.",
    requires: Requirements {
        apis: &[MACHINES],
        licences: MDE,
    },
    remediation: "Upgrade or replace the listed devices: move Windows 10 to Windows 11 (or enrol them in Extended Security Updates while you migrate), update Windows 11 to a serviced feature update with Windows Update for Business or Autopatch, upgrade Windows Server 2012 R2 and older, and keep macOS within the three most recent major releases.",
    links: &[
        "https://learn.microsoft.com/windows/release-health/windows11-release-information",
        "https://learn.microsoft.com/windows-server/get-started/windows-server-release-info",
        "https://learn.microsoft.com/windows/whats-new/extended-security-updates",
        "https://learn.microsoft.com/defender-endpoint/microsoft-defender-endpoint-mac",
    ],
    references: &[],
    manual: None,
};

crate::check!(UnsupportedOs, &UNSUPPORTED_OS, unsupported_os);

async fn unsupported_os(ctx: &CheckContext) -> Evaluation {
    let machines = ctx.list(MACHINES.operation, json!({})).await?;
    if machines.truncated {
        return Ok(truncated(MACHINES.operation));
    }
    let mut by_platform: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    let (mut unsupported, mut limited, mut not_assessed) = (vec![], vec![], 0);
    let mut notes = HashSet::new();
    for m in sensors(&machines.items) {
        let support = os_support(m);
        if support == OsSupport::NotAssessed {
            not_assessed += 1;
            continue;
        }
        let platform = text(m, "osPlatform").unwrap_or_default().to_owned();
        let counts = by_platform.entry(platform.clone()).or_default();
        counts.0 += 1;
        let release = m
            .get("osBuild")
            .and_then(number)
            .map(|b| b.to_string())
            .or_else(|| owned(text(m, "osVersion").or_else(|| text(m, "version"))));
        let label = match release {
            Some(release) => format!("{} ({platform} {release})", machine_name(m)),
            None => format!("{} ({platform})", machine_name(m)),
        };
        match support {
            OsSupport::Unsupported(_) => {
                counts.1 += 1;
                unsupported.push(label);
            }
            OsSupport::Limited(note) => {
                counts.2 += 1;
                notes.insert(note);
                limited.push(label);
            }
            _ => {}
        }
    }
    let assessed: usize = by_platform.values().map(|c| c.0).sum();
    if assessed == 0 {
        return Ok(Finding::not_applicable(
            "no_assessable_devices",
            format!(
                "No onboarded Windows or macOS machines to assess ({} other machines are not assessed).",
                not_assessed
            ),
        ));
    }
    let mut notes: Vec<String> = notes.into_iter().collect();
    notes.sort();
    let data = json!({
        "assessed": assessed,
        "unsupported": unsupported.len(),
        "limited_support": limited.len(),
        "not_assessed": not_assessed,
        "support_data_reviewed": os_support_data().review_date,
        "limited_support_notes": notes,
        "by_platform": by_platform.iter().map(|(p, (n, u, l))| (p.clone(), json!({
            "machines": n, "unsupported": u, "limited_support": l,
        }))).collect::<serde_json::Map<_, _>>(),
    });
    let finding = if !unsupported.is_empty() {
        Finding::fail(format!(
            "{} of {assessed} assessed machines run an operating system that no longer receives security updates; {} limited support.",
            unsupported.len(),
            plural(limited.len(), "more has", "more have")
        ))
    } else if !limited.is_empty() {
        Finding::warn(format!(
            "{} of {assessed} assessed machines run a build serviced only for some editions or with Extended Security Updates.",
            limited.len()
        ))
    } else {
        Finding::pass(format!(
            "All {} run a supported operating system.",
            plural(assessed, "assessed machine", "assessed machines")
        ))
    };
    let affected = if unsupported.is_empty() {
        limited
    } else {
        unsupported
    };
    Ok(finding.data(data).affected(sorted(affected)))
}

// ---------------------------------------------------------------------------
// endpoint.linux_macos_health
// ---------------------------------------------------------------------------

pub const LINUX_MACOS_HEALTH: CheckMeta = CheckMeta {
    id: "endpoint.linux_macos_health",
    title: "Linux and macOS Defender sensors are active",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Medium,
    impact: Level::Medium,
    description: "Summarises onboarded Linux and macOS Defender for Endpoint machines by distribution or macOS version and checks that each is Active and seen within 7 days (setting `max_days`). These sensors are deployed and updated outside the Windows tooling, so they fail silently more often. Not applicable when there are none.",
    requires: Requirements {
        apis: &[MACHINES],
        licences: MDE,
    },
    remediation: "On the listed machines run `mdatp health` to see why the sensor is not reporting: check the `mdatp` service, connectivity to the Defender service URLs, proxy settings and that the agent version is current. Redeploy with your configuration management or Intune (macOS) if the agent is missing.",
    links: &[
        "https://learn.microsoft.com/defender-endpoint/linux-support-connectivity",
        "https://learn.microsoft.com/defender-endpoint/mac-support-perf",
        "https://learn.microsoft.com/defender-endpoint/microsoft-defender-endpoint-linux",
        "https://learn.microsoft.com/defender-endpoint/microsoft-defender-endpoint-mac",
    ],
    references: &[],
    manual: None,
};

crate::check!(LinuxMacosHealth, &LINUX_MACOS_HEALTH, linux_macos_health);

/// `Ubuntu 22.04`, `macOS 15` and similar.
fn os_label(machine: &Value) -> String {
    let version = text(machine, "osVersion").or_else(|| text(machine, "version"));
    if machine_platform(machine) == Platform::MacOs {
        return match version.and_then(major) {
            Some(major) => format!("macOS {major}"),
            None => "macOS".to_owned(),
        };
    }
    let platform = text(machine, "osPlatform").unwrap_or("Linux");
    match version {
        Some(v) => format!("{platform} {v}"),
        None => platform.to_owned(),
    }
}

async fn linux_macos_health(ctx: &CheckContext) -> Evaluation {
    let max_days: u64 = ctx.setting(LINUX_MACOS_HEALTH.id, "max_days", 7);
    let machines = ctx.list(MACHINES.operation, json!({})).await?;
    if machines.truncated {
        return Ok(truncated(MACHINES.operation));
    }
    let cutoff = ctx.now().minus(days(max_days));
    let mut by_os: BTreeMap<String, Health> = BTreeMap::new();
    let mut total = Health::default();
    let mut affected = vec![];
    for m in sensors(&machines.items) {
        if !matches!(machine_platform(m), Platform::Linux | Platform::MacOs) {
            continue;
        }
        let health = sensor_health(m, cutoff);
        total.add(health);
        by_os.entry(os_label(m)).or_default().add(health);
        if health != SensorHealth::Active {
            affected.push(machine_name(m).to_owned());
        }
    }
    if total.machines == 0 {
        return Ok(Finding::not_applicable(
            "no_linux_or_macos",
            "No Linux or macOS machines are onboarded to Defender for Endpoint.",
        ));
    }
    let mut data = total.json();
    data["max_days"] = json!(max_days);
    data["by_os"] = by_os
        .iter()
        .map(|(os, h)| (os.clone(), h.json()))
        .collect::<serde_json::Map<_, _>>()
        .into();
    let unhealthy = total.machines - total.active;
    let finding = if unhealthy > 0 {
        Finding::warn(format!(
            "{unhealthy} of {} are not active or not seen for {max_days} days.",
            plural(
                total.machines,
                "Linux or macOS machine",
                "Linux and macOS machines"
            )
        ))
    } else {
        Finding::pass(format!(
            "All {} are active ({}).",
            plural(
                total.machines,
                "Linux or macOS machine",
                "Linux and macOS machines"
            ),
            by_os
                .iter()
                .map(|(os, h)| format!("{os}: {}", h.machines))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    };
    Ok(finding.data(data).affected(sorted(affected)))
}

// ---------------------------------------------------------------------------
// endpoint.servers_covered
// ---------------------------------------------------------------------------

pub const SERVERS_COVERED: CheckMeta = CheckMeta {
    id: "endpoint.servers_covered",
    title: "Azure VMs and Arc servers are onboarded to Defender for Endpoint",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "Lists running Azure virtual machines (Azure Resource Graph) and Azure Arc machines in the subscriptions from `[packs.endpoint] subscriptions` (or every subscription the app can read) and matches each to an onboarded Defender for Endpoint machine by Azure resource id, VM id and then name. Servers without a sensor are a common blind spot. Needs Reader on the subscriptions; set `subscriptions = []` when the organisation has no Azure.",
    requires: Requirements {
        apis: &[MACHINES, RESOURCE_GRAPH, ARC_MACHINES],
        licences: MDE,
    },
    remediation: "Enable Defender for Servers in Microsoft Defender for Cloud on the listed subscriptions so the Defender for Endpoint integration onboards Azure VMs and Arc machines automatically, or deploy the onboarding package to each server. Connect on-premises servers through Azure Arc so they are inventoried.",
    links: &[
        "https://learn.microsoft.com/azure/defender-for-cloud/integration-defender-for-endpoint",
        "https://learn.microsoft.com/azure/defender-for-cloud/plan-defender-for-servers",
        "https://learn.microsoft.com/azure/azure-arc/servers/overview",
    ],
    references: &[],
    manual: None,
};

crate::check!(ServersCovered, &SERVERS_COVERED, servers_covered);

/// Rows of a Resource Graph query, following `$skipToken`. `true` when pages remained.
async fn resource_graph(
    ctx: &CheckContext,
    query: &str,
    subscriptions: Option<&[String]>,
) -> Result<(Vec<Value>, bool), CallFailure> {
    let mut rows = vec![];
    let mut token: Option<String> = None;
    for _ in 0..GRAPH_PAGES {
        let mut body = json!({ "query": query, "options": { "$top": 1000 } });
        if let Some(subscriptions) = subscriptions {
            body["subscriptions"] = json!(subscriptions);
        }
        if let Some(token) = &token {
            body["options"]["$skipToken"] = json!(token);
        }
        let page = ctx
            .get(RESOURCE_GRAPH.operation, json!({ "body": body }))
            .await?;
        rows.extend(
            page.get("data")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        token = text(&page, "$skipToken").map(str::to_owned);
        if token.is_none() {
            return Ok((rows, false));
        }
    }
    Ok((rows, true))
}

/// An Azure VM or Arc machine to find in Defender for Endpoint.
struct Server {
    name: String,
    resource_id: Option<String>,
    vm_id: Option<String>,
    /// Names to try, most specific first.
    names: Vec<String>,
    platform: Platform,
}

/// Onboarded MDE machines indexed by Azure resource id, VM id and name.
struct ServerIndex<'a> {
    by_resource: HashMap<String, &'a Value>,
    by_vm_id: HashMap<String, &'a Value>,
    by_name: HashMap<String, &'a Value>,
}

impl<'a> ServerIndex<'a> {
    fn new(machines: &[&'a Value]) -> Self {
        let mut index = Self {
            by_resource: HashMap::new(),
            by_vm_id: HashMap::new(),
            by_name: HashMap::new(),
        };
        let lower = |m: &Value, key: &str| {
            m.get("vmMetadata")
                .and_then(|v| text(v, key))
                .map(str::to_ascii_lowercase)
        };
        for &m in machines {
            if let Some(id) = lower(m, "resourceId") {
                index.by_resource.insert(id, m);
            }
            if let Some(id) = lower(m, "vmId") {
                index.by_vm_id.insert(id, m);
            }
            if let Some(name) = text(m, "computerDnsName") {
                index.by_name.insert(name_key(name), m);
            }
        }
        index
    }
    fn find(&self, server: &Server) -> Option<&'a Value> {
        let lookup = |map: &HashMap<String, &'a Value>, key: &Option<String>| {
            key.as_ref()
                .and_then(|k| map.get(&k.to_ascii_lowercase()).copied())
        };
        lookup(&self.by_resource, &server.resource_id)
            .or_else(|| lookup(&self.by_vm_id, &server.vm_id))
            .or_else(|| {
                server
                    .names
                    .iter()
                    .find_map(|n| self.by_name.get(&name_key(n)).copied())
            })
    }
}

fn owned(value: Option<&str>) -> Option<String> {
    value.map(str::to_owned)
}

/// Azure VM rows, minus stopped or deallocated VMs (counted separately).
fn azure_vms(rows: &[Value]) -> (Vec<Server>, usize) {
    let mut servers = vec![];
    let mut stopped = 0;
    for row in rows {
        let power = text(row, "powerState")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if power.contains("deallocated") || power.contains("stopped") {
            stopped += 1;
            continue;
        }
        let Some(name) = text(row, "name") else {
            continue;
        };
        servers.push(Server {
            name: name.to_owned(),
            resource_id: owned(text(row, "id")),
            vm_id: owned(text(row, "vmId")),
            names: [text(row, "computerName"), Some(name)]
                .into_iter()
                .flatten()
                .map(str::to_owned)
                .collect(),
            platform: Platform::from_os(text(row, "osType").unwrap_or_default()),
        });
    }
    (servers, stopped)
}

/// Arc machine resources, minus expired ones (counted separately).
fn arc_machines(items: &[Value]) -> (Vec<Server>, usize) {
    let mut servers = vec![];
    let mut expired = 0;
    for item in items {
        let props = item.get("properties").unwrap_or(&Value::Null);
        if text(props, "status").is_some_and(|s| s.eq_ignore_ascii_case("Expired")) {
            expired += 1;
            continue;
        }
        let Some(name) = text(item, "name") else {
            continue;
        };
        servers.push(Server {
            name: name.to_owned(),
            resource_id: owned(text(item, "id")),
            vm_id: owned(text(props, "vmId")),
            names: [
                text(props, "machineFqdn"),
                text(props, "displayName"),
                Some(name),
            ]
            .into_iter()
            .flatten()
            .map(str::to_owned)
            .collect(),
            platform: Platform::from_os(
                text(props, "osType")
                    .or_else(|| text(props, "osName"))
                    .unwrap_or_default(),
            ),
        });
    }
    (servers, expired)
}

/// The resource provider is not registered: the subscription has no Arc machines.
fn not_registered(failure: &CallFailure) -> bool {
    failure
        .error
        .call()
        .is_some_and(|e| e.code.as_deref() == Some("MissingSubscriptionRegistration"))
}

async fn servers_covered(ctx: &CheckContext) -> Evaluation {
    let machines = ctx.list(MACHINES.operation, json!({})).await?;
    if machines.truncated {
        return Ok(truncated(MACHINES.operation));
    }
    let configured: Option<Vec<String>> = ctx.pack_setting("endpoint", "subscriptions", None);
    let subscriptions = match configured {
        Some(list) if list.is_empty() => {
            return Ok(Finding::not_applicable(
                "no_subscriptions",
                "`[packs.endpoint] subscriptions` is empty, so there are no Azure servers to compare.",
            ));
        }
        Some(list) => list,
        None => {
            let (rows, more) = resource_graph(ctx, SUBSCRIPTIONS_KQL, None).await?;
            if more {
                return Ok(truncated(RESOURCE_GRAPH.operation));
            }
            sorted(
                rows.iter()
                    .filter_map(|r| text(r, "subscriptionId").map(str::to_owned))
                    .collect(),
            )
        }
    };
    if subscriptions.is_empty() {
        return Ok(Finding::unknown(
            "no_subscriptions",
            "No Azure subscriptions are visible to the app. Grant Reader on the subscriptions that hold servers, or set `[packs.endpoint] subscriptions = []` if the organisation has none.",
        ));
    }
    let (vm_rows, more) = resource_graph(ctx, VMS_KQL, Some(&subscriptions)).await?;
    if more {
        return Ok(truncated(RESOURCE_GRAPH.operation));
    }
    let mut arc_items = vec![];
    for subscription in &subscriptions {
        match ctx
            .list(
                ARC_MACHINES.operation,
                json!({ "parameters": { "subscriptionId": subscription } }),
            )
            .await
        {
            Ok(listing) if listing.truncated => return Ok(truncated(ARC_MACHINES.operation)),
            Ok(listing) => arc_items.extend(listing.items),
            Err(failure) if not_registered(&failure) => {}
            Err(failure) => return Err(failure),
        }
    }
    let (vms, stopped) = azure_vms(&vm_rows);
    let (arc, expired) = arc_machines(&arc_items);
    if vms.is_empty() && arc.is_empty() {
        return Ok(Finding::not_applicable(
            "no_azure_servers",
            format!(
                "No running Azure VMs or connected Arc machines in {}.",
                plural(subscriptions.len(), "subscription", "subscriptions")
            ),
        ));
    }
    let onboarded = sensors(&machines.items);
    let index = ServerIndex::new(&onboarded);
    let mut matched: HashSet<*const Value> = HashSet::new();
    let mut by_platform: BTreeMap<&str, Coverage> = BTreeMap::new();
    let mut missing = vec![];
    let total = vms.len() + arc.len();
    for server in vms.iter().chain(&arc) {
        let counts = by_platform.entry(server.platform.as_str()).or_default();
        counts.devices += 1;
        match index.find(server) {
            Some(m) => {
                counts.onboarded += 1;
                matched.insert(m as *const Value);
            }
            None => {
                counts.missing += 1;
                missing.push(server.name.clone());
            }
        }
    }
    let outside = onboarded
        .iter()
        .filter(|m| {
            matches!(
                machine_platform(m),
                Platform::WindowsServer | Platform::Linux
            )
        })
        .filter(|m| !matched.contains(&(**m as *const Value)))
        .count();
    let data = json!({
        "subscriptions": subscriptions.len(),
        "azure_vms": vms.len(),
        "arc_machines": arc.len(),
        "stopped_vms_skipped": stopped,
        "expired_arc_machines_skipped": expired,
        "covered": total - missing.len(),
        "missing": missing.len(),
        "mde_servers_without_azure_record": outside,
        "by_platform": by_platform.iter().map(|(p, c)| (p.to_string(), json!({
            "servers": c.devices, "onboarded": c.onboarded, "missing": c.missing,
        }))).collect::<serde_json::Map<_, _>>(),
    });
    let finding = if missing.is_empty() {
        Finding::pass(format!(
            "All {} have an onboarded Defender for Endpoint record.",
            plural(
                total,
                "Azure VM and Arc machine",
                "Azure VMs and Arc machines"
            )
        ))
    } else {
        Finding::warn(format!(
            "{} of {total} Azure VMs and Arc machines have no onboarded Defender for Endpoint record.",
            missing.len()
        ))
    };
    Ok(finding.data(data).affected(sorted(missing)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-10-25T00:00:00Z";

    fn machine(name: &str, aad: Option<&str>, status: &str, seen: &str) -> Value {
        json!({
            "id": format!("m-{name}-{seen}"),
            "computerDnsName": name,
            "aadDeviceId": aad,
            "onboardingStatus": status,
            "healthStatus": "Active",
            "osPlatform": "Windows11",
            "lastSeen": seen,
        })
    }

    const ID_A: &str = "aaaaaaaa-0000-4000-8000-000000000001";
    const ID_B: &str = "bbbbbbbb-0000-4000-8000-000000000002";

    #[test]
    fn platforms_classify_entra_intune_and_mde_values() {
        for (os, platform) in [
            ("Windows", Platform::Windows),
            ("Windows11", Platform::Windows),
            ("WindowsServer2022", Platform::WindowsServer),
            ("Windows Server", Platform::WindowsServer),
            ("MacMDM", Platform::MacOs),
            ("macOS", Platform::MacOs),
            ("iPadOS", Platform::Ios),
            ("IOS", Platform::Ios),
            ("AndroidForWork", Platform::Android),
            ("Ubuntu", Platform::Linux),
            ("RedHatEnterpriseLinux", Platform::Linux),
            ("Linux", Platform::Linux),
            ("ChromeOS", Platform::Other),
        ] {
            assert_eq!(Platform::from_os(os), platform, "{os}");
        }
    }

    #[test]
    fn keys_normalise_names_and_reject_empty_ids() {
        assert_eq!(name_key("PC-01.contoso.example"), "pc-01");
        assert_eq!(name_key(" pc-01 "), "pc-01");
        assert_eq!(
            device_id_key(Some("00000000-0000-0000-0000-000000000000")),
            None
        );
        assert_eq!(device_id_key(Some("")), None);
        assert_eq!(device_id_key(Some(ID_A)), Some(ID_A.to_owned()));
        assert_eq!(
            device_id_key(Some(&ID_A.to_uppercase())),
            Some(ID_A.to_owned())
        );
    }

    #[test]
    fn duplicates_prefer_onboarded_then_most_recent() {
        let machines = vec![
            machine("pc-01", Some(ID_A), "Onboarded", "2026-09-01T00:00:00Z"),
            machine("pc-01", Some(ID_A), "Onboarded", "2026-10-24T00:00:00Z"),
            machine(
                "pc-01",
                Some(ID_A),
                "CanBeOnboarded",
                "2026-10-25T00:00:00Z",
            ),
        ];
        let index = MachineIndex::new(&machines);
        let (found, how) = index
            .find(Some(ID_A), "pc-01", Platform::Windows, &HashSet::new())
            .unwrap();
        assert_eq!(how, MatchedBy::DeviceId);
        assert_eq!(found["lastSeen"], "2026-10-24T00:00:00Z");
    }

    #[test]
    fn renamed_device_matches_on_device_id() {
        let machines = vec![machine(
            "old-name.contoso.example",
            Some(ID_A),
            "Onboarded",
            "2026-10-24T00:00:00Z",
        )];
        let index = MachineIndex::new(&machines);
        let found = index.find(Some(ID_A), "new-name", Platform::Windows, &HashSet::new());
        assert_eq!(found.map(|f| f.1), Some(MatchedBy::DeviceId));
        // Without a device id a renamed device cannot be matched.
        assert!(
            index
                .find(None, "new-name", Platform::Windows, &HashSet::new())
                .is_none()
        );
    }

    #[test]
    fn name_fallback_skips_records_claimed_by_another_device() {
        let machines = vec![
            machine("pc-01", Some(ID_A), "Onboarded", "2026-10-24T00:00:00Z"),
            machine("pc-02", None, "Onboarded", "2026-10-24T00:00:00Z"),
        ];
        let index = MachineIndex::new(&machines);
        let claimed: HashSet<String> = [ID_A.to_owned(), ID_B.to_owned()].into();
        // A second Entra object named pc-01 must not borrow pc-01's record.
        assert!(
            index
                .find(Some(ID_B), "PC-01", Platform::Windows, &claimed)
                .is_none()
        );
        // A record without an Entra id matches by name, case-insensitively.
        let (_, how) = index
            .find(
                Some(ID_B),
                "PC-02.contoso.example",
                Platform::Windows,
                &claimed,
            )
            .unwrap();
        assert_eq!(how, MatchedBy::Name);
        // Names on an incompatible platform do not match.
        assert!(index.find(None, "pc-02", Platform::Ios, &claimed).is_none());
    }

    #[test]
    fn inventory_merges_entra_and_intune_and_keeps_the_intune_name() {
        let entra = vec![
            json!({"deviceId": ID_A, "displayName": "old-name", "operatingSystem": "Windows",
                   "accountEnabled": true, "approximateLastSignInDateTime": "2026-10-01T00:00:00Z"}),
            json!({"deviceId": ID_B, "displayName": "disabled", "operatingSystem": "Windows",
                   "accountEnabled": false}),
        ];
        let intune = vec![
            json!({"azureADDeviceId": ID_A.to_uppercase(), "deviceName": "new-name",
                   "operatingSystem": "Windows", "lastSyncDateTime": "2026-10-20T00:00:00Z"}),
            json!({"azureADDeviceId": "00000000-0000-0000-0000-000000000000",
                   "deviceName": "phone-1", "operatingSystem": "iOS"}),
            json!({"azureADDeviceId": "00000000-0000-0000-0000-000000000000",
                   "deviceName": "PHONE-1", "operatingSystem": "iOS"}),
        ];
        let devices = inventory(&entra, &intune);
        assert_eq!(devices.len(), 2, "{devices:?}");
        let renamed = devices.iter().find(|d| d.device_id.is_some()).unwrap();
        assert_eq!(renamed.name, "new-name");
        assert_eq!(
            renamed.last_active,
            Some(Instant::parse("2026-10-20T00:00:00Z").unwrap())
        );
        assert!(devices.iter().any(|d| d.platform == Platform::Ios));
    }

    #[test]
    fn sensor_health_uses_status_then_last_seen() {
        let cutoff = Instant::parse(NOW).unwrap().minus(days(7));
        let mut m = machine("pc", None, "Onboarded", "2026-10-24T00:00:00Z");
        assert_eq!(sensor_health(&m, cutoff), SensorHealth::Active);
        m["lastSeen"] = json!("2026-10-01T00:00:00Z");
        assert_eq!(sensor_health(&m, cutoff), SensorHealth::Inactive);
        m["healthStatus"] = json!("NoSensorDataImpairedCommunication");
        assert_eq!(sensor_health(&m, cutoff), SensorHealth::NoSensorData);
        m["healthStatus"] = json!("ImpairedCommunication");
        assert_eq!(
            sensor_health(&m, cutoff),
            SensorHealth::ImpairedCommunication
        );
    }

    #[test]
    fn os_support_data_classifies_builds() {
        let m = |platform: &str, build: Value, version: Option<&str>| json!({"osPlatform": platform, "osBuild": build, "version": version});
        assert_eq!(
            os_support(&m("Windows11", json!(26200), None)),
            OsSupport::Supported
        );
        assert!(matches!(
            os_support(&m("Windows11", json!(26100), None)),
            OsSupport::Limited(_)
        ));
        assert!(matches!(
            os_support(&m("Windows11", json!(22621), None)),
            OsSupport::Unsupported(_)
        ));
        assert!(matches!(
            os_support(&m("Windows10", json!("19045"), None)),
            OsSupport::Limited(_)
        ));
        assert!(matches!(
            os_support(&m("Windows10", json!(19042), None)),
            OsSupport::Unsupported(_)
        ));
        assert_eq!(
            os_support(&m("Windows10", Value::Null, None)),
            OsSupport::NotAssessed
        );
        assert!(matches!(
            os_support(&m("WindowsServer2012R2", Value::Null, None)),
            OsSupport::Unsupported(_)
        ));
        assert_eq!(
            os_support(&m("WindowsServer2022", Value::Null, None)),
            OsSupport::Supported
        );
        assert!(matches!(
            os_support(&m("macOS", Value::Null, Some("14.6"))),
            OsSupport::Unsupported(_)
        ));
        assert_eq!(
            os_support(&m("macOS", Value::Null, Some("15.1"))),
            OsSupport::Supported
        );
        assert_eq!(
            os_support(&m("Ubuntu", Value::Null, Some("22.04"))),
            OsSupport::NotAssessed
        );
        assert_eq!(
            os_support(&m("SomethingNew", json!(1), None)),
            OsSupport::NotAssessed
        );
    }
}
