//! Windows release data (`data/windows-builds.yaml`): the monthly security
//! updates of each current release, so a device's OS build can be aged.
use super::parse_date;
use junction_watch::clock::Instant;
use serde::{Deserialize, Serialize};

const DATA: &str = include_str!("../../../data/windows-builds.yaml");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsBuilds {
    /// `YYYY-MM-DD` the data was last checked against Microsoft's release pages.
    pub reviewed: String,
    #[serde(default)]
    pub sources: Vec<String>,
    pub releases: Vec<Release>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub name: String,
    /// The third part of `10.0.<build>.<revision>`.
    pub build: u32,
    /// `client`, `server` or `both`.
    #[serde(default)]
    pub edition: Option<String>,
    /// `YYYY-MM-DD` after which the release gets no more updates.
    #[serde(default)]
    pub end_of_updates: Option<String>,
    pub updates: Vec<Update>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    pub revision: u32,
    /// `YYYY-MM-DD`
    pub released: String,
    #[serde(default)]
    pub kb: Option<String>,
}

/// Where a device's OS build stands.
#[derive(Debug, Clone, PartialEq)]
pub enum BuildState<'a> {
    /// Has every listed security update.
    Current(&'a Release),
    /// Missing updates; the oldest missing one.
    Behind(&'a Release, &'a Update),
    /// Not a Windows 10 or later version string, or a build not in the data.
    Unrecognised,
}

impl WindowsBuilds {
    pub fn embedded() -> Self {
        serde_saphyr::from_str(DATA).expect("data/windows-builds.yaml parses")
    }

    /// Where `os_version` (`10.0.26100.9711`) stands. `server` breaks ties
    /// between client and server releases of one build.
    pub fn locate(&self, os_version: &str, server: bool) -> BuildState<'_> {
        let mut parts = os_version.split('.').map(str::parse::<u32>);
        let (Some(Ok(10)), Some(Ok(0)), Some(Ok(build)), Some(Ok(revision))) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return BuildState::Unrecognised;
        };
        // Releases sharing a build number (Windows 11 24H2 and Server 2025) have
        // far-apart revision ranges: take the nearest, then the matching edition.
        let Some(release) = self
            .releases
            .iter()
            .filter(|r| r.build == build)
            .min_by_key(|r| {
                let distance = r
                    .updates
                    .iter()
                    .map(|u| u.revision.abs_diff(revision))
                    .min()
                    .unwrap_or(u32::MAX);
                let mismatch = match r.edition.as_deref() {
                    Some("server") => !server,
                    Some("client") => server,
                    _ => false,
                };
                (distance, mismatch)
            })
        else {
            return BuildState::Unrecognised;
        };
        match release
            .updates
            .iter()
            .filter(|u| u.revision > revision)
            .min_by_key(|u| u.revision)
        {
            Some(update) => BuildState::Behind(release, update),
            None => BuildState::Current(release),
        }
    }

    pub fn reviewed_at(&self) -> Option<Instant> {
        parse_date(&self.reviewed)
    }
}

impl Release {
    pub fn out_of_support(&self, now: Instant) -> bool {
        self.end_of_updates
            .as_deref()
            .and_then(parse_date)
            .is_some_and(|end| end < now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_data_is_valid() {
        let data = WindowsBuilds::embedded();
        assert!(data.reviewed_at().is_some());
        for r in &data.releases {
            assert!(!r.updates.is_empty(), "{}", r.name);
            for u in &r.updates {
                assert!(
                    parse_date(&u.released).is_some(),
                    "{} {}",
                    r.name,
                    u.released
                );
            }
            if let Some(end) = &r.end_of_updates {
                assert!(parse_date(end).is_some(), "{end}");
            }
        }
    }

    #[test]
    fn locates_builds() {
        let data = WindowsBuilds::embedded();
        let latest = |build: u32, server: bool| {
            data.releases
                .iter()
                .filter(|r| r.build == build)
                .find(|r| r.edition.as_deref() == Some(if server { "server" } else { "client" }))
                .and_then(|r| r.updates.iter().map(|u| u.revision).max())
                .unwrap()
        };
        let client = latest(26100, false);
        assert!(matches!(
            data.locate(&format!("10.0.26100.{client}"), false),
            BuildState::Current(_)
        ));
        let server = latest(26100, true);
        // A server build is matched to the server release by revision even
        // when the operating system name does not say "server".
        assert!(matches!(
            data.locate(&format!("10.0.26100.{server}"), false),
            BuildState::Current(r) if r.edition.as_deref() == Some("server")
        ));
        assert!(matches!(
            data.locate("10.0.26100.1", false),
            BuildState::Behind(r, _) if r.edition.as_deref() == Some("client")
        ));
        assert_eq!(data.locate("10.0.99999.1", false), BuildState::Unrecognised);
        assert_eq!(data.locate("6.3.9600", false), BuildState::Unrecognised);
    }
}
