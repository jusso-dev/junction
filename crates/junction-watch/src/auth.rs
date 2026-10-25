//! Dashboard accounts, roles and sessions.
//!
//! Passwords are Argon2id hashes. Session tokens are 256-bit random values; only
//! their SHA-256 is stored, so a copied database cannot be replayed as a login.
use crate::{clock::Instant, event::sha256_hex, store::Store};
use anyhow::{Result, bail};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant as MonoInstant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Overview and coverage only; no event or evidence detail.
    Viewer,
    /// Everything a viewer sees plus activity, evidence and alert handling.
    Analyst,
    /// Analyst plus tenant settings, re-tests, subscriptions and accounts.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Analyst => "analyst",
            Self::Admin => "admin",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "viewer" => Self::Viewer,
            "analyst" => Self::Analyst,
            "admin" => Self::Admin,
            _ => bail!("role must be viewer, analyst or admin"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: Role,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    pub csrf: String,
}

pub const MIN_PASSWORD_CHARS: usize = 12;

pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
    {
        bail!("username must be 1-64 characters: letters, digits, . _ - @");
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        bail!("password must be at least {MIN_PASSWORD_CHARS} characters");
    }
    if password.len() > 1024 {
        bail!("password too long");
    }
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| anyhow::anyhow!("randomness unavailable"))?;
    let salt =
        SaltString::encode_b64(&salt).map_err(|_| anyhow::anyhow!("salt encoding failed"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("password hashing failed"))?
        .to_string())
}

pub fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("randomness unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn create_user(store: &Store, username: &str, password: &str, role: Role) -> Result<()> {
    validate_username(username)?;
    let hash = hash_password(password)?;
    store.with_conn(|c| {
        c.execute(
            "INSERT INTO users(username, password_hash, role, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![username, hash, role.as_str(), Instant::now().to_rfc3339()],
        )
        .map_err(|_| anyhow::anyhow!("user already exists"))?;
        Ok(())
    })?;
    store.audit(
        "cli",
        "user_create",
        username,
        &format!("{{\"role\":\"{}\"}}", role.as_str()),
    )
}

pub fn set_disabled(store: &Store, username: &str, disabled: bool) -> Result<()> {
    let changed = store.with_conn(|c| {
        let n = c.execute(
            "UPDATE users SET disabled = ?2 WHERE username = ?1",
            params![username, disabled as i64],
        )?;
        if disabled {
            c.execute(
                "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username = ?1)",
                [username],
            )?;
        }
        Ok(n)
    })?;
    if changed == 0 {
        bail!("no such user");
    }
    store.audit(
        "cli",
        if disabled {
            "user_disable"
        } else {
            "user_enable"
        },
        username,
        "{}",
    )
}

pub fn user_count(store: &Store) -> Result<i64> {
    store.with_conn(|c| {
        Ok(
            c.query_row("SELECT COUNT(*) FROM users WHERE disabled = 0", [], |r| {
                r.get(0)
            })?,
        )
    })
}

/// Verify credentials. Unknown users still pay for one Argon2 verification so
/// response time does not reveal which usernames exist.
pub fn verify_login(store: &Store, username: &str, password: &str) -> Result<Option<User>> {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let dummy =
        DUMMY.get_or_init(|| hash_password("timing-equaliser-not-a-password").unwrap_or_default());
    let row: Option<(i64, String, String, i64)> = store.with_conn(|c| {
        Ok(c.query_row(
            "SELECT id, password_hash, role, disabled FROM users WHERE username = ?1",
            [username],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?)
    })?;
    let hash = row.as_ref().map(|r| r.1.as_str()).unwrap_or(dummy);
    let ok = PasswordHash::new(hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    });
    match row {
        Some((id, _, role, 0)) if ok => Ok(Some(User {
            id,
            username: username.to_owned(),
            role: Role::parse(&role)?,
        })),
        _ => Ok(None),
    }
}

/// Returns the raw session token for the cookie; only its hash is stored.
pub fn create_session(store: &Store, user: &User, lifetime: Duration) -> Result<(String, String)> {
    let token = random_token()?;
    let csrf = random_token()?;
    let now = Instant::now();
    store.with_conn(|c| {
        c.execute("DELETE FROM sessions WHERE expires_at < ?1", [now.to_rfc3339()])?;
        c.execute(
            "INSERT INTO sessions(token_hash, user_id, csrf, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![sha256_hex(token.as_bytes()), user.id, csrf, now.to_rfc3339(), now.plus(lifetime).to_rfc3339()],
        )?;
        Ok(())
    })?;
    Ok((token, csrf))
}

pub fn session(store: &Store, token: &str) -> Result<Option<Session>> {
    if token.len() != 43 {
        return Ok(None);
    }
    let now = Instant::now().to_rfc3339();
    store.with_conn(|c| {
        Ok(c.query_row(
            "SELECT u.id, u.username, u.role, s.csrf FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND u.disabled = 0",
            params![sha256_hex(token.as_bytes()), now],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)),
        )
        .optional()?
        .and_then(|(id, username, role, csrf)| {
            Role::parse(&role).ok().map(|role| Session {
                user: User { id, username, role },
                csrf,
            })
        }))
    })
}

pub fn end_session(store: &Store, token: &str) -> Result<()> {
    store.with_conn(|c| {
        c.execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            [sha256_hex(token.as_bytes())],
        )?;
        Ok(())
    })
}

/// Per-username failed-login throttle (in memory; resets on restart,
/// which is acceptable for a loopback-only dashboard).
#[derive(Default)]
pub struct LoginThrottle {
    failures: Mutex<HashMap<String, (u32, MonoInstant)>>,
}

impl LoginThrottle {
    const LIMIT: u32 = 5;
    const LOCKOUT: Duration = Duration::from_secs(15 * 60);

    pub fn locked(&self, username: &str) -> bool {
        let map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        map.get(username)
            .is_some_and(|(n, at)| *n >= Self::LIMIT && at.elapsed() < Self::LOCKOUT)
    }
    pub fn failed(&self, username: &str) {
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 10_000 {
            map.retain(|_, (_, at)| at.elapsed() < Self::LOCKOUT);
        }
        let entry = map
            .entry(username.to_owned())
            .or_insert((0, MonoInstant::now()));
        if entry.1.elapsed() >= Self::LOCKOUT {
            *entry = (0, MonoInstant::now());
        }
        entry.0 += 1;
        entry.1 = MonoInstant::now();
    }
    pub fn succeeded(&self, username: &str) {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(username);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const T: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn login_sessions_and_disable() {
        let store = Store::in_memory(T).unwrap();
        assert!(create_user(&store, "admin", "short", Role::Admin).is_err());
        assert!(create_user(&store, "bad name", "correct horse battery", Role::Admin).is_err());
        create_user(&store, "admin", "correct horse battery", Role::Admin).unwrap();
        assert!(create_user(&store, "admin", "correct horse battery", Role::Admin).is_err());
        assert!(
            verify_login(&store, "admin", "wrong password!!")
                .unwrap()
                .is_none()
        );
        assert!(
            verify_login(&store, "nobody", "correct horse battery")
                .unwrap()
                .is_none()
        );
        let user = verify_login(&store, "admin", "correct horse battery")
            .unwrap()
            .unwrap();
        assert_eq!(user.role, Role::Admin);

        let (token, csrf) = create_session(&store, &user, Duration::from_secs(3600)).unwrap();
        let s = session(&store, &token).unwrap().unwrap();
        assert_eq!(s.csrf, csrf);
        let stored: String = store
            .with_conn(|c| Ok(c.query_row("SELECT token_hash FROM sessions", [], |r| r.get(0))?))
            .unwrap();
        assert_ne!(stored, token, "raw token is never stored");

        set_disabled(&store, "admin", true).unwrap();
        assert!(
            session(&store, &token).unwrap().is_none(),
            "disabling ends sessions"
        );
        assert!(
            verify_login(&store, "admin", "correct horse battery")
                .unwrap()
                .is_none()
        );
        set_disabled(&store, "admin", false).unwrap();
        assert!(session(&store, "x").unwrap().is_none());
        let (token, _) = create_session(&store, &user, Duration::from_secs(3600)).unwrap();
        end_session(&store, &token).unwrap();
        assert!(session(&store, &token).unwrap().is_none());
        let password_hash: String = store
            .with_conn(|c| Ok(c.query_row("SELECT password_hash FROM users", [], |r| r.get(0))?))
            .unwrap();
        assert!(password_hash.starts_with("$argon2id$"));
    }

    #[test]
    fn expired_sessions_are_rejected() {
        let store = Store::in_memory(T).unwrap();
        create_user(&store, "a", "correct horse battery", Role::Viewer).unwrap();
        let user = verify_login(&store, "a", "correct horse battery")
            .unwrap()
            .unwrap();
        let (token, _) = create_session(&store, &user, Duration::ZERO).unwrap();
        assert!(session(&store, &token).unwrap().is_none());
    }

    #[test]
    fn throttle_locks_after_repeated_failures() {
        let t = LoginThrottle::default();
        for _ in 0..4 {
            t.failed("a");
        }
        assert!(!t.locked("a"));
        t.failed("a");
        assert!(t.locked("a"));
        assert!(!t.locked("b"));
        t.succeeded("a");
        assert!(!t.locked("a"));
    }
}
