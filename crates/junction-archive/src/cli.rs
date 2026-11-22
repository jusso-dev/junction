//! `junction archive ...` commands.
use crate::{
    catalog,
    config::{ArchiveConfig, write_new_private},
    store::{DeleteProbe, ObjectStore, PutOutcome},
};
use anyhow::Result;
use clap::Subcommand;
use junction_watch::clock::Instant;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct ArchiveArgs {
    /// Secret-free archive configuration file.
    #[arg(long, default_value = ".junction/archive/config.toml")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: ArchiveCommand,
}

#[derive(Subcommand)]
pub enum ArchiveCommand {
    /// Write a configuration file (create-only) and print the next steps.
    Init {
        #[arg(long)]
        tenant_id: String,
    },
    /// List every tenant permission and storage role the archive uses, and why.
    Permissions,
    /// Check the configured store: create-only writes, refused deletion and the
    /// retention the service reports. Writes one small canary object.
    Doctor,
}

pub async fn run(args: ArchiveArgs) -> Result<Value> {
    match args.command {
        ArchiveCommand::Init { tenant_id } => init(&args.config, &tenant_id),
        ArchiveCommand::Permissions => Ok(permissions()),
        ArchiveCommand::Doctor => {
            let config = ArchiveConfig::load(&args.config)?;
            let store = config.open_store()?;
            doctor(&config, store.as_ref(), Instant::now()).await
        }
    }
}

fn init(path: &std::path::Path, tenant_id: &str) -> Result<Value> {
    junction_watch::store::validate_tenant(tenant_id)?;
    write_new_private(
        path,
        &ArchiveConfig::example(&tenant_id.to_ascii_lowercase()),
    )?;
    Ok(json!({
        "config": path.display().to_string(),
        "next_steps": [
            "1. Create the storage: deploy examples/archive/archive-storage.bicep (Azure) or follow docs/ARCHIVE.md for an R2 bucket with lock rules.",
            "2. Edit the [storage] section of the configuration. It must never contain a key, SAS token or secret.",
            "3. Grant the tenant permissions from `junction archive permissions` to the collector app and give admin consent.",
            "4. Export the credential environment (AZURE_TENANT_ID, AZURE_CLIENT_ID and certificate paths; for R2 also JUNCTION_ARCHIVE_R2_ACCESS_KEY_ID and JUNCTION_ARCHIVE_R2_SECRET_ACCESS_KEY).",
            "5. Run `junction archive doctor` to confirm the store is create-only and immutable."
        ]
    }))
}

fn permissions() -> Value {
    json!({
        "tenant": catalog::SOURCES,
        "storage": catalog::STORAGE_ROLES,
        "note": "Tenant permissions are application permissions and read-only. The archive never starts audit subscriptions; use `junction watch subscribe` or your existing feed."
    })
}

/// Doctor's verdict for one property of the store.
fn check(name: &str, ok: Option<bool>, detail: impl Into<String>) -> Value {
    json!({
        "check": name,
        "status": match ok { Some(true) => "pass", Some(false) => "fail", None => "unknown" },
        "detail": detail.into(),
    })
}

pub async fn doctor(
    config: &ArchiveConfig,
    store: &dyn ObjectStore,
    now: Instant,
) -> Result<Value> {
    let key = format!(
        "v1/tenant={}/doctor/{}.txt",
        config.tenant_id,
        now.to_rfc3339().replace([':', '.'], "-")
    );
    let body = format!("junction archive doctor canary {}\n", now.to_rfc3339()).into_bytes();
    let mut checks = Vec::new();
    let first = store.put_new(&key, body.clone(), "text/plain").await;
    checks.push(check(
        "write",
        Some(matches!(first, Ok(PutOutcome::Created))),
        match &first {
            Ok(_) => "canary object created".to_owned(),
            Err(e) => format!("{e:#}"),
        },
    ));
    if first.is_ok() {
        let second = store
            .put_new(&key, b"overwrite attempt".to_vec(), "text/plain")
            .await;
        let kept = store
            .get(&key)
            .await
            .ok()
            .flatten()
            .is_some_and(|b| b == body);
        checks.push(check(
            "create_only",
            Some(matches!(second, Ok(PutOutcome::AlreadyExists)) && kept),
            "a second put to the same key must not replace the object",
        ));
        let probe = store.delete_probe(&key).await;
        let (ok, detail) = match probe {
            Ok(DeleteProbe::RefusedByImmutability) => (
                Some(true),
                "the storage service refused to delete the canary because of retention".to_owned(),
            ),
            Ok(DeleteProbe::Deleted) => (
                Some(false),
                "the canary could be deleted: the store is NOT immutable".to_owned(),
            ),
            // A role without delete proves nothing about immutability; the
            // retention check below then decides.
            Ok(DeleteProbe::NotPermitted(why)) => (
                None,
                format!(
                    "this identity may not delete ({why}); immutability is shown by the retention check"
                ),
            ),
            Ok(DeleteProbe::Other(why)) => (Some(false), why),
            Err(e) => (Some(false), format!("{e:#}")),
        };
        let delete_proven = ok == Some(true);
        checks.push(check("delete_refused", ok, detail));
        if let Some(days) = config.retention_days() {
            match store.retention_until(&key).await {
                Ok(Some(until)) => {
                    let ok = httpdate::parse_http_date(&until).ok().map(|t| {
                        let wanted = std::time::SystemTime::UNIX_EPOCH
                            + std::time::Duration::from_millis(now.0 as u64)
                            + std::time::Duration::from_secs(u64::from(days) * 86_400 - 86_400);
                        t >= wanted
                    });
                    checks.push(check(
                        "retention",
                        Some(ok.unwrap_or(false)),
                        format!("service reports retention until {until}; configured {days} days"),
                    ));
                }
                // Azure always reports retention on a protected blob, so its
                // absence means the container has no immutability policy.
                Ok(None) if config.reports_retention() => checks.push(check(
                    "retention",
                    Some(false),
                    "the container reports no immutability policy on the canary: archived objects are NOT protected",
                )),
                // R2 locks are bucket rules; only a refused delete proves them.
                Ok(None) => checks.push(check(
                    "retention",
                    delete_proven.then_some(true),
                    format!("R2 does not report per-object retention; confirm the v1/ bucket lock rule keeps objects for {days} days"),
                )),
                Err(e) => checks.push(check("retention", Some(false), format!("{e:#}"))),
            }
        }
    }
    // Immutability must be shown by at least one check: a refused delete or a
    // reported retention date. Two "unknown" results are not healthy.
    let proven = checks.iter().any(|c| {
        (c["check"] == "delete_refused" || c["check"] == "retention") && c["status"] == "pass"
    });
    let healthy = proven
        && checks
            .iter()
            .all(|c| c["status"] == "pass" || c["status"] == "unknown");
    Ok(json!({
        "store": store.describe(),
        "healthy": healthy,
        "checks": checks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalStore;

    #[tokio::test]
    async fn doctor_flags_a_local_store_as_not_immutable() {
        let dir = tempfile::tempdir().unwrap();
        let config: ArchiveConfig = toml::from_str(&format!(
            "tenant_id = \"11111111-1111-4111-8111-111111111111\"\n[storage]\nkind = \"local\"\npath = \"{}\"\n",
            dir.path().display()
        ))
        .unwrap();
        let store = LocalStore::new(dir.path()).unwrap();
        let report = doctor(
            &config,
            &store,
            Instant::parse("2026-11-22T00:00:00Z").unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(report["healthy"], false);
        let status = |name: &str| {
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["check"] == name)
                .unwrap()["status"]
                .clone()
        };
        assert_eq!(status("write"), "pass");
        assert_eq!(status("create_only"), "pass");
        assert_eq!(status("delete_refused"), "fail");
    }

    #[test]
    fn init_is_create_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        init(&path, "11111111-1111-4111-8111-111111111111").unwrap();
        assert!(init(&path, "11111111-1111-4111-8111-111111111111").is_err());
        assert!(init(&dir.path().join("b.toml"), "not a tenant").is_err());
    }
}
