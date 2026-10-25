//! Optional raw audit evidence. AES-256-GCM binds ciphertext to tenant and event.
//! Keys come from the process secret environment, never SQLite or diagnostic text.
use crate::{event::sha256_hex, store::Store};
use anyhow::{Result, bail};
use base64::Engine;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

pub struct EvidenceKey {
    key: LessSafeKey,
    pub id: String,
}
impl EvidenceKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = UnboundKey::new(&aead::AES_256_GCM, bytes)
            .map_err(|_| anyhow::anyhow!("evidence key must contain 32 random bytes"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            id: sha256_hex(bytes)[..16].into(),
        })
    }
    pub fn environment() -> Result<Option<Self>> {
        let value = match std::env::var("JUNCTION_WATCH_EVIDENCE_KEY") {
            Ok(v) => Zeroizing::new(v),
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(_) => bail!("invalid evidence key environment"),
        };
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(value.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid evidence key encoding"))?,
        );
        Ok(Some(Self::from_bytes(&bytes)?))
    }
    fn aad(tenant: &str, event: &str) -> Vec<u8> {
        format!("junction-evidence-v1\0{tenant}\0{event}").into_bytes()
    }
    pub fn seal(&self, tenant: &str, event: &str, raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if raw.len() > 1024 * 1024 {
            bail!("raw evidence record exceeds one MiB");
        }
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("evidence randomness unavailable"))?;
        let mut ciphertext = raw.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(Self::aad(tenant, event)),
                &mut ciphertext,
            )
            .map_err(|_| anyhow::anyhow!("evidence encryption failed"))?;
        Ok((nonce.to_vec(), ciphertext))
    }
    pub fn open(
        &self,
        tenant: &str,
        event: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid evidence nonce"))?;
        let mut bytes = Zeroizing::new(ciphertext.to_vec());
        let plain = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(Self::aad(tenant, event)),
                &mut bytes,
            )
            .map_err(|_| anyhow::anyhow!("evidence integrity verification failed"))?;
        let len = plain.len();
        bytes.truncate(len);
        Ok(bytes)
    }
}
impl Store {
    pub fn read_evidence(
        &self,
        event: &str,
        key: &EvidenceKey,
        actor: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.audit(actor, "evidence_read", event, "{}")?;
        let row: Option<(String, Vec<u8>, Vec<u8>, String)> = self
            .db()?
            .query_row(
                "SELECT key_id,nonce,ciphertext,sha256 FROM evidence WHERE event_id=?1",
                [event],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((key_id, nonce, ciphertext, hash)) = row else {
            return Ok(None);
        };
        if key_id != key.id {
            bail!("evidence needs a different key version");
        }
        let raw = key.open(self.tenant_id(), event, &nonce, &ciphertext)?;
        if sha256_hex(&raw) != hash {
            bail!("evidence digest mismatch");
        }
        Ok(Some(raw))
    }
    pub fn retain_raw(&self, event: &str, raw: &[u8], key: &EvidenceKey) -> Result<()> {
        let e = self
            .event(event)?
            .ok_or_else(|| anyhow::anyhow!("evidence event missing"))?;
        if sha256_hex(raw) != e.raw_sha256 {
            bail!("raw evidence does not match event digest");
        }
        let (nonce, ciphertext) = key.seal(self.tenant_id(), event, raw)?;
        let mut db = self.db()?;
        let tx = db.transaction()?;
        tx.execute("INSERT OR IGNORE INTO evidence(event_id,key_id,nonce,ciphertext,sha256) VALUES(?1,?2,?3,?4,?5)",params![event,key.id,nonce,ciphertext,e.raw_sha256])?;
        tx.execute(
            "UPDATE events SET raw_evidence_reference=?1 WHERE id=?2",
            params![format!("sqlite:evidence/{event}"), event],
        )?;
        crate::operations::enforce_budget(&tx)?;
        tx.commit()?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_binds_tenant_event_and_key() {
        let k = EvidenceKey::from_bytes(&[7; 32]).unwrap();
        let (n, c) = k.seal("tenant", "event", b"private audit").unwrap();
        assert_eq!(
            &*k.open("tenant", "event", &n, &c).unwrap(),
            b"private audit"
        );
        assert!(k.open("other", "event", &n, &c).is_err());
        assert!(k.open("tenant", "other", &n, &c).is_err());
        let mut altered = c.clone();
        altered[0] ^= 1;
        assert!(k.open("tenant", "event", &n, &altered).is_err());
        assert!(
            EvidenceKey::from_bytes(&[8; 32])
                .unwrap()
                .open("tenant", "event", &n, &c)
                .is_err()
        );
    }
}
