//! Minimal-data email through an independently configured host MTA. No Microsoft
//! Mail.Send permission, shell execution, recipient supplied by audit events, or
//! email credentials in the database. An accepted MTA handoff is not proof of inbox delivery.
use crate::{clock::Instant, store::Store};
use anyhow::{Result, bail};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{process::Stdio, time::Duration};
use tokio::io::AsyncWriteExt;
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationConfig {
    pub external_email: Option<String>,
    pub from_email: Option<String>,
    /// Explicit operator attestation: mailbox and MTA are independently secured.
    pub independent_destination_confirmed: bool,
}
fn address(s: &str) -> bool {
    s.len() <= 254
        && s.split('@').count() == 2
        && s.contains('.')
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
}
impl NotificationConfig {
    pub fn validate(&self, tenant_domain: &str) -> Result<()> {
        if let Some(to) = &self.external_email {
            if !address(to)
                || !self.from_email.as_deref().is_some_and(address)
                || !self.independent_destination_confirmed
            {
                bail!(
                    "notification setup requires valid addresses and independently secured destination confirmation"
                );
            }
            if to
                .rsplit_once('@')
                .is_some_and(|(_, d)| d.eq_ignore_ascii_case(tenant_domain))
            {
                bail!("notification address must be outside the monitored tenant");
            }
        }
        Ok(())
    }
}
pub async fn deliver(
    store: &Store,
    config: &NotificationConfig,
    domains: &[String],
) -> Result<serde_json::Value> {
    deliver_with(store, config, domains, Instant::now(), send_mail).await
}

pub async fn deliver_with<F, Fut>(
    store: &Store,
    config: &NotificationConfig,
    domains: &[String],
    now: Instant,
    send: F,
) -> Result<serde_json::Value>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(), ()>>,
{
    let Some(to) = &config.external_email else {
        return Ok(
            serde_json::json!({"status":"not_configured","gap":"Critical alerts cannot leave this host until independent email is configured."}),
        );
    };
    config.validate(domains.first().map(String::as_str).unwrap_or(""))?;
    if domains.iter().any(|d| {
        to.rsplit_once('@')
            .is_some_and(|(_, host)| host.eq_ignore_ascii_case(d))
    }) {
        bail!("notification destination belongs to monitored tenant");
    }
    let pending: Vec<(String, i64)> = {
        let db = store.db()?;
        let mut stmt=db.prepare("SELECT id,attempts FROM notification_outbox WHERE delivered_at IS NULL AND next_attempt<=?1 ORDER BY next_attempt LIMIT 20")?;
        stmt.query_map([now.to_rfc3339()], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut accepted = 0;
    let mut failed = 0;
    for (id, attempt) in pending {
        // Lease before handoff; competing processes cannot send the same row.
        let claimed=store.db()?.execute("UPDATE notification_outbox SET next_attempt=?1,attempts=attempts+1 WHERE id=?2 AND delivered_at IS NULL AND next_attempt<=?3",params![now.plus(Duration::from_secs(300)).to_rfc3339(),id,now.to_rfc3339()])?;
        if claimed == 0 {
            continue;
        }
        let alert = store
            .alert(&id)?
            .ok_or_else(|| anyhow::anyhow!("outbox alert missing"))?;
        let body = format!(
            "From: {}\r\nTo: {}\r\nSubject: Junction {} security alert\r\nMessage-ID: <{}@junction.local>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nRule: {}\r\nAlert: {}\r\nOpen the Junction dashboard on the monitoring host. Verify the change through a trusted contact. No personal data or raw evidence is included.\r\n",
            config.from_email.as_deref().unwrap_or_default(),
            to,
            alert.severity,
            id,
            alert.rule_id,
            id
        );
        let result = tokio::time::timeout(Duration::from_secs(30), send(body)).await;
        if matches!(result, Ok(Ok(()))) {
            store.db()?.execute(
                "UPDATE notification_outbox SET delivered_at=?1,last_error=NULL WHERE id=?2",
                params![Instant::now().to_rfc3339(), id],
            )?;
            accepted += 1;
        } else {
            let delay = 60_u64
                .saturating_mul(1_u64.checked_shl(attempt.min(10) as u32).unwrap_or(1024))
                .min(86400);
            store.db()?.execute("UPDATE notification_outbox SET next_attempt=?1,last_error='MTA handoff failed; check host mail configuration' WHERE id=?2",params![now.plus(Duration::from_secs(delay)).to_rfc3339(),id])?;
            failed += 1;
        }
    }
    Ok(
        serde_json::json!({"status":"MTA handoff only; inbox delivery unverified","accepted":accepted,"failed":failed}),
    )
}
async fn send_mail(body: String) -> Result<(), ()> {
    let mut child = tokio::process::Command::new("/usr/sbin/sendmail")
        .args(["-i", "-t"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ())?;
    let mut stdin = child.stdin.take().ok_or(())?;
    stdin.write_all(body.as_bytes()).await.map_err(|_| ())?;
    drop(stdin);
    if child.wait().await.map_err(|_| ())?.success() {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_injection_and_tenant_address() {
        for to in [
            "admin@club.example",
            "admin@outside.example\r\nBcc:other@example.org",
        ] {
            let c = NotificationConfig {
                external_email: Some(to.into()),
                from_email: Some("watch@host.example".into()),
                independent_destination_confirmed: true,
            };
            assert!(c.validate("club.example").is_err());
        }
    }
}
