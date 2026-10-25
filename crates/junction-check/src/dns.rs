//! DNS lookups for the email pack, behind a trait so tests feed records and CI
//! never touches real DNS.
use crate::gateway::BoxFut;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The name does not exist (NXDOMAIN) or has no records of the type.
    NotFound,
    /// The lookup failed (timeout, server failure, network disabled).
    Failed(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such record"),
            Self::Failed(e) => write!(f, "lookup failed: {e}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordType {
    Txt,
    Cname,
    Mx,
}

pub trait Resolver: Send + Sync {
    /// Record data as strings: TXT strings joined per record, CNAME targets,
    /// MX exchange host names.
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        kind: RecordType,
    ) -> BoxFut<'a, Result<Vec<String>, DnsError>>;
}

/// A resolver that refuses every lookup (no DNS configured).
pub struct NoDns;

impl Resolver for NoDns {
    fn lookup<'a>(
        &'a self,
        _name: &'a str,
        _kind: RecordType,
    ) -> BoxFut<'a, Result<Vec<String>, DnsError>> {
        Box::pin(async { Err(DnsError::Failed("DNS lookups are not configured".into())) })
    }
}

/// Fixed records for tests. Names are matched case-insensitively.
#[derive(Default, Clone)]
pub struct StaticDns {
    records: BTreeMap<(String, RecordType), Vec<String>>,
}

impl StaticDns {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, name: &str, kind: RecordType, values: &[&str]) -> Self {
        self.records.insert(
            (name.to_ascii_lowercase(), kind),
            values.iter().map(|v| (*v).to_owned()).collect(),
        );
        self
    }
}

impl Resolver for StaticDns {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        kind: RecordType,
    ) -> BoxFut<'a, Result<Vec<String>, DnsError>> {
        Box::pin(async move {
            match self.records.get(&(name.to_ascii_lowercase(), kind)) {
                Some(v) if !v.is_empty() => Ok(v.clone()),
                _ => Err(DnsError::NotFound),
            }
        })
    }
}
