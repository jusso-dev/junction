//! Framework tags (Essential Eight, ISM, CIS, NIST CSF, MITRE ATT&CK) and the
//! framework dataset they must come from.
//!
//! Tags are data, not code: each pack's tags live in `data/tags/<pack>.yaml` and
//! every id must exist in `data/frameworks/*.yaml`, which is synced one way from
//! crownguard by `scripts/sync-frameworks.sh`.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// One Essential Eight mitigation strategy at one maturity level.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E8Tag {
    /// Strategy id from `data/frameworks/essential-eight.yaml` (for example `mfa`).
    pub strategy: String,
    /// Maturity levels (1 to 3) the check provides evidence for.
    pub levels: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tags {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub essential_eight: Vec<E8Tag>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ism: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cis_m365: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cis_v8: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nist_csf: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre: Vec<String>,
}

impl Tags {
    pub fn is_empty(&self) -> bool {
        self.essential_eight.is_empty()
            && self.ism.is_empty()
            && self.cis_m365.is_empty()
            && self.cis_v8.is_empty()
            && self.nist_csf.is_empty()
            && self.mitre.is_empty()
    }
    /// Does this check carry the tag selected by `filter`?
    pub fn matches(&self, filter: &TagFilter) -> bool {
        let eq = |list: &[String], value: &str| list.iter().any(|v| v.eq_ignore_ascii_case(value));
        match filter {
            TagFilter::E8 { strategy, level } => self.essential_eight.iter().any(|tag| {
                strategy.as_deref().is_none_or(|s| tag.strategy == s)
                    && level.is_none_or(|l| tag.levels.contains(&l))
            }),
            TagFilter::Ism(id) => eq(&self.ism, id),
            TagFilter::CisM365(id) => eq(&self.cis_m365, id),
            TagFilter::CisV8(id) => eq(&self.cis_v8, id),
            TagFilter::Nist(id) => eq(&self.nist_csf, id),
            TagFilter::Mitre(id) => self.mitre.iter().any(|t| {
                // T1003 selects T1003 and its sub-techniques such as T1003.001.
                t.eq_ignore_ascii_case(id)
                    || t.to_ascii_uppercase()
                        .starts_with(&format!("{}.", id.to_ascii_uppercase()))
            }),
        }
    }
}

/// A `--tag` selector: `e8`, `e8:ml2`, `e8:mfa`, `e8:mfa:ml2`, `ism:ISM-1504`,
/// `cis:5.2.2.1` (CIS M365), `cisv8:6.5`, `nist:PR.AA-03`, `mitre:T1078`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagFilter {
    E8 {
        strategy: Option<String>,
        level: Option<u8>,
    },
    Ism(String),
    CisM365(String),
    CisV8(String),
    Nist(String),
    Mitre(String),
}

impl TagFilter {
    pub fn parse(value: &str) -> Result<Self> {
        let (scheme, rest) = value.split_once(':').unwrap_or((value, ""));
        let level = |s: &str| -> Option<u8> {
            let s = s.to_ascii_lowercase();
            let n = s.strip_prefix("ml")?.parse().ok()?;
            (1..=3).contains(&n).then_some(n)
        };
        Ok(match scheme.to_ascii_lowercase().as_str() {
            "e8" => {
                let parts: Vec<&str> = rest.split(':').filter(|p| !p.is_empty()).collect();
                match parts.as_slice() {
                    [] => Self::E8 {
                        strategy: None,
                        level: None,
                    },
                    [one] => match level(one) {
                        Some(l) => Self::E8 {
                            strategy: None,
                            level: Some(l),
                        },
                        None => Self::E8 {
                            strategy: Some((*one).to_owned()),
                            level: None,
                        },
                    },
                    [strategy, l] => Self::E8 {
                        strategy: Some((*strategy).to_owned()),
                        level: Some(level(l).context("maturity level must be ml1, ml2 or ml3")?),
                    },
                    _ => bail!("invalid Essential Eight tag"),
                }
            }
            _ if rest.is_empty() => bail!("tag needs a value, for example ism:ISM-1504"),
            "ism" => Self::Ism(rest.to_owned()),
            "cis" | "cism365" | "cis-m365" => Self::CisM365(rest.to_owned()),
            "cisv8" | "cis-v8" => Self::CisV8(rest.to_owned()),
            "nist" => Self::Nist(rest.to_owned()),
            "mitre" | "attack" => Self::Mitre(rest.to_owned()),
            _ => bail!("unknown tag scheme (use e8, ism, cis, cisv8, nist or mitre)"),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Control {
    pub id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
}

/// One framework file: provenance plus the control ids tags may use.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Framework {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: String,
    /// Licence or terms of the source data and what was copied.
    pub licence: String,
    #[serde(default)]
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Requirement {
    /// ISM control id that states the requirement (for example ISM-1504).
    pub id: String,
    pub levels: Vec<u8>,
    #[serde(default)]
    pub title: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Strategy {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub requirements: Vec<Requirement>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EssentialEight {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub licence: String,
    pub strategies: Vec<Strategy>,
}

/// The whole embedded framework dataset.
#[derive(Debug, Clone)]
pub struct Frameworks {
    pub essential_eight: EssentialEight,
    pub ism: Framework,
    pub cis_m365: Framework,
    pub cis_v8: Framework,
    pub nist_csf: Framework,
    pub mitre: Framework,
}

const E8: &str = include_str!("../data/frameworks/essential-eight.yaml");
const ISM: &str = include_str!("../data/frameworks/ism.yaml");
const CIS_M365: &str = include_str!("../data/frameworks/cis-m365.yaml");
const CIS_V8: &str = include_str!("../data/frameworks/cis-controls-v8.yaml");
const NIST: &str = include_str!("../data/frameworks/nist-csf-2.yaml");
const MITRE: &str = include_str!("../data/frameworks/mitre-attack.yaml");

impl Frameworks {
    pub fn embedded() -> &'static Frameworks {
        static DATA: OnceLock<Frameworks> = OnceLock::new();
        DATA.get_or_init(|| Self::parse().expect("embedded framework data is valid"))
    }

    pub fn parse() -> Result<Self> {
        let framework = |name: &str, text: &str| -> Result<Framework> {
            serde_saphyr::from_str(text).with_context(|| format!("framework data {name}"))
        };
        Ok(Self {
            essential_eight: serde_saphyr::from_str(E8)
                .context("framework data essential-eight")?,
            ism: framework("ism", ISM)?,
            cis_m365: framework("cis-m365", CIS_M365)?,
            cis_v8: framework("cis-controls-v8", CIS_V8)?,
            nist_csf: framework("nist-csf-2", NIST)?,
            mitre: framework("mitre-attack", MITRE)?,
        })
    }

    /// Every unknown framework id in `tags`, as `scheme:id`.
    pub fn unknown_ids(&self, tags: &Tags) -> Vec<String> {
        let ids = |f: &Framework| -> BTreeSet<String> {
            f.controls
                .iter()
                .map(|c| c.id.to_ascii_uppercase())
                .collect()
        };
        let mut unknown = vec![];
        for tag in &tags.essential_eight {
            match self
                .essential_eight
                .strategies
                .iter()
                .find(|s| s.id == tag.strategy)
            {
                None => unknown.push(format!("e8:{}", tag.strategy)),
                Some(_)
                    if tag.levels.is_empty() || tag.levels.iter().any(|l| !(1..=3).contains(l)) =>
                {
                    unknown.push(format!("e8:{}:levels", tag.strategy))
                }
                Some(_) => {}
            }
        }
        for (scheme, list, known) in [
            ("ism", &tags.ism, ids(&self.ism)),
            ("cis", &tags.cis_m365, ids(&self.cis_m365)),
            ("cisv8", &tags.cis_v8, ids(&self.cis_v8)),
            ("nist", &tags.nist_csf, ids(&self.nist_csf)),
            ("mitre", &tags.mitre, ids(&self.mitre)),
        ] {
            for id in list {
                if !known.contains(&id.to_ascii_uppercase()) {
                    unknown.push(format!("{scheme}:{id}"));
                }
            }
        }
        unknown
    }
}

/// Per-pack tag files, keyed by check id.
pub type TagTable = BTreeMap<String, Tags>;

pub fn parse_tag_table(name: &str, text: &str) -> Result<TagTable> {
    serde_saphyr::from_str(text).with_context(|| format!("tag data {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_parse_and_match() {
        let tags = Tags {
            essential_eight: vec![E8Tag {
                strategy: "mfa".into(),
                levels: vec![1, 2],
            }],
            ism: vec!["ISM-1504".into()],
            mitre: vec!["T1003.001".into()],
            ..Tags::default()
        };
        for (filter, expected) in [
            ("e8", true),
            ("e8:ml1", true),
            ("e8:ml3", false),
            ("e8:mfa", true),
            ("e8:mfa:ml2", true),
            ("e8:regular-backups", false),
            ("ism:ism-1504", true),
            ("mitre:T1003", true),
            ("mitre:T1003.002", false),
            ("cis:1.1.1", false),
        ] {
            assert_eq!(
                tags.matches(&TagFilter::parse(filter).unwrap()),
                expected,
                "{filter}"
            );
        }
        for bad in ["ism", "e8:mfa:ml4", "e8:a:b:c", "nope:1"] {
            assert!(TagFilter::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn embedded_frameworks_load_and_reject_unknown_ids() {
        let data = Frameworks::embedded();
        assert_eq!(data.essential_eight.strategies.len(), 8);
        let tags = Tags {
            essential_eight: vec![E8Tag {
                strategy: "not-a-strategy".into(),
                levels: vec![1],
            }],
            ism: vec!["ISM-0000000".into()],
            ..Tags::default()
        };
        assert_eq!(
            data.unknown_ids(&tags),
            ["e8:not-a-strategy", "ism:ISM-0000000"]
        );
    }
}
