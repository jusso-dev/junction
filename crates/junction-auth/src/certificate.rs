//! Entra certificate client credentials. Signing material never implements Debug/Serialize.
use crate::{AccessToken, AuthFlow, Secret, TokenRequest};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{rand::SystemRandom, signature};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const LIMIT: usize = 64 * 1024;
pub struct CertificateCredentialsProvider {
    client_id: String,
    thumbprint: String,
    private_key: Zeroizing<Vec<u8>>,
}
impl CertificateCredentialsProvider {
    /// DER leaf certificate and unencrypted RSA PKCS#8 DER key.
    /// Entra verifies certificate registration, validity and key correspondence.
    pub fn new(
        client_id: String,
        certificate_der: &[u8],
        private_key_der: Zeroizing<Vec<u8>>,
    ) -> Result<Self> {
        validate_client_id(&client_id)?;
        if certificate_der.is_empty()
            || certificate_der.len() > LIMIT
            || certificate_der.first() != Some(&0x30)
            || private_key_der.is_empty()
            || private_key_der.len() > LIMIT
        {
            bail!("invalid certificate credential encoding or size");
        }
        signature::RsaKeyPair::from_pkcs8(&private_key_der)
            .map_err(|_| anyhow::anyhow!("invalid RSA PKCS8 certificate key"))?;
        Ok(Self {
            client_id,
            thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(certificate_der)),
            private_key: private_key_der,
        })
    }
    fn endpoint(&self, request: &TokenRequest) -> Result<(String, String)> {
        request.validate()?;
        if request.flow != AuthFlow::Certificate {
            bail!("certificate credential flow mismatch");
        }
        let scope = format!("{}/.default", request.audience);
        if !request.scopes.is_empty() && request.scopes != [scope.clone()] {
            bail!("certificate credentials require the audience default scope");
        }
        Ok((
            format!(
                "{}/{}/oauth2/v2.0/token",
                request.authority.trim_end_matches('/'),
                request.tenant
            ),
            scope,
        ))
    }
    fn assertion(&self, endpoint: &str) -> Result<Secret> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow::anyhow!("certificate assertion clock unavailable"))?
            .as_secs();
        let expiry = now
            .checked_add(300)
            .ok_or_else(|| anyhow::anyhow!("invalid certificate assertion expiry"))?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| anyhow::anyhow!("certificate assertion randomness unavailable"))?;
        random[6] = (random[6] & 0x0f) | 0x40;
        random[8] = (random[8] & 0x3f) | 0x80;
        let hex: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let jti = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        let header = json!({"alg":"PS256","typ":"JWT","x5t#S256":self.thumbprint});
        let claims = json!({"aud":endpoint,"iss":self.client_id,"sub":self.client_id,
            "iat":now,"nbf":now,"exp":expiry,"jti":jti});
        let input = Zeroizing::new(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
        ));
        let key = signature::RsaKeyPair::from_pkcs8(&self.private_key)
            .map_err(|_| anyhow::anyhow!("invalid RSA PKCS8 certificate key"))?;
        let mut signed = Zeroizing::new(vec![0u8; key.public().modulus_len()]);
        key.sign(
            &signature::RSA_PSS_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut signed,
        )
        .map_err(|_| anyhow::anyhow!("certificate assertion signing failed"))?;
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(&signed));
        Secret::new(format!("{}.{}", input.as_str(), encoded.as_str()))
    }
    pub async fn acquire(&self, request: &TokenRequest) -> Result<AccessToken> {
        let (exchange, endpoint, scope) = self.exchange(request)?;
        exchange
            .fetch_form(request, &endpoint, &exchange.form(&scope))
            .await
    }
    fn exchange(
        &self,
        request: &TokenRequest,
    ) -> Result<(
        crate::client_credentials::ClientCredentialsProvider,
        String,
        String,
    )> {
        let (endpoint, scope) = self.endpoint(request)?;
        let assertion = self.assertion(&endpoint)?;
        // Share the bounded, redirect-disabled token transport without relabeling
        // the request as workload identity. It remains certificate-bound metadata.
        let exchange =
            crate::client_credentials::ClientCredentialsProvider::with_workload_assertion(
                self.client_id.clone(),
                assertion,
            )?;
        Ok((exchange, endpoint, scope))
    }
}
pub(crate) fn validate_client_id(value: &str) -> Result<()> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        bail!("invalid certificate client identifier");
    }
    Ok(())
}
/// Private, regular files only. Paths and file contents stay out of diagnostics.
pub(crate) fn read_der(path: &std::path::Path, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let before = std::fs::symlink_metadata(path)
        .map_err(|_| anyhow::anyhow!("certificate credential file unavailable"))?;
    if !before.is_file() {
        bail!("certificate credential file must be regular");
    }
    let file = std::fs::File::open(path)
        .map_err(|_| anyhow::anyhow!("certificate credential file unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("certificate credential file unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != metadata.dev() || before.ino() != metadata.ino() {
            bail!("certificate credential file changed during open");
        }
    }
    if !metadata.is_file() || metadata.len() > LIMIT as u64 {
        bail!("invalid certificate credential file");
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("certificate private key file must be private");
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("certificate credential file read failed"))?;
    if bytes.is_empty() || bytes.len() > LIMIT {
        bail!("invalid certificate credential file size");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    const CLIENT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const CERT: &[u8] = include_bytes!("../tests/fixtures/certificate/test-certificate.der");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/certificate/test-key.pkcs8.der");
    const PUBLIC: &[u8] = include_bytes!("../tests/fixtures/certificate/test-public-key.der");
    fn provider() -> CertificateCredentialsProvider {
        CertificateCredentialsProvider::new(CLIENT.into(), CERT, Zeroizing::new(KEY.to_vec()))
            .unwrap()
    }
    fn request() -> TokenRequest {
        TokenRequest {
            tenant: "tenant-a".into(),
            authority: "https://login.example.invalid".into(),
            audience: "https://resource.example.invalid".into(),
            scopes: vec![],
            credential_profile: "certificate-profile".into(),
            flow: AuthFlow::Certificate,
            api_key: None,
        }
    }
    #[test]
    fn assertions_are_signed_short_lived_fresh_and_endpoint_bound() {
        let provider = provider();
        let (endpoint, scope) = provider.endpoint(&request()).unwrap();
        assert_eq!(scope, "https://resource.example.invalid/.default");
        let first = provider.assertion(&endpoint).unwrap();
        let second = provider.assertion(&endpoint).unwrap();
        assert_eq!(format!("{first:?}"), "[REDACTED]");
        let parts: Vec<_> = first.expose().split('.').collect();
        assert_eq!(parts.len(), 3);
        let decode = |part: &str| -> Value {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
        };
        let header = decode(parts[0]);
        assert_eq!(
            header,
            json!({"alg":"PS256","typ":"JWT",
            "x5t#S256":"SnPX8y7jAfy0JFavneR666SxDjO83hi9paNS5BgN2FI"})
        );
        let claims = decode(parts[1]);
        assert_eq!(
            claims["aud"],
            "https://login.example.invalid/tenant-a/oauth2/v2.0/token"
        );
        assert_eq!(claims["iss"], CLIENT);
        assert_eq!(claims["sub"], CLIENT);
        assert_eq!(claims["iat"], claims["nbf"]);
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["nbf"].as_u64().unwrap(),
            300
        );
        validate_client_id(claims["jti"].as_str().unwrap()).unwrap();
        assert_ne!(
            claims["jti"],
            decode(second.expose().split('.').nth(1).unwrap())["jti"]
        );
        let verifier =
            signature::UnparsedPublicKey::new(&signature::RSA_PSS_2048_8192_SHA256, PUBLIC);
        let message = format!("{}.{}", parts[0], parts[1]);
        let signed = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        verifier.verify(message.as_bytes(), &signed).unwrap();
        assert!(verifier.verify(b"altered-assertion", &signed).is_err());
        for authority in [
            "https://login.microsoftonline.us",
            "https://login.chinacloudapi.cn",
        ] {
            let mut request = request();
            request.authority = authority.into();
            request.tenant = "other-tenant".into();
            let (endpoint, _) = provider.endpoint(&request).unwrap();
            let assertion = provider.assertion(&endpoint).unwrap();
            let claims = decode(assertion.expose().split('.').nth(1).unwrap());
            assert_eq!(
                claims["aud"],
                format!("{authority}/other-tenant/oauth2/v2.0/token")
            );
        }
    }
    #[test]
    fn certificate_exchange_form_uses_assertion_and_keeps_resource_scope() {
        let (exchange, endpoint, scope) = provider().exchange(&request()).unwrap();
        let form = exchange.form(&scope);
        let fields: std::collections::BTreeMap<_, _> = form.into_iter().collect();
        assert_eq!(fields["client_id"], CLIENT);
        assert_eq!(fields["grant_type"], "client_credentials");
        assert_eq!(fields["scope"], "https://resource.example.invalid/.default");
        assert_eq!(
            fields["client_assertion_type"],
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
        assert!(!fields.contains_key("client_secret"));
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(fields["client_assertion"].split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["aud"], endpoint);
        let token = crate::client_credentials::decode(
            br#"{"access_token":"test-token","token_type":"Bearer","expires_in":3600}"#,
            &request(),
        )
        .unwrap();
        assert_eq!(token.metadata().tenant, "tenant-a");
        assert_eq!(
            token.metadata().audience,
            "https://resource.example.invalid"
        );
        assert!(token.metadata().roles.is_empty());
    }
    #[test]
    fn wrong_flow_scope_authority_tenant_and_malformed_credentials_are_rejected() {
        let provider = provider();
        for change in 0..4 {
            let mut request = request();
            match change {
                0 => request.flow = AuthFlow::ClientCredentials,
                1 => request.scopes = vec!["User.Read".into()],
                2 => request.authority = "http://login.example.invalid".into(),
                _ => request.tenant = "common".into(),
            }
            assert!(provider.endpoint(&request).is_err());
        }
        for (client, cert, key) in [
            ("private-secret", CERT, KEY),
            (
                CLIENT,
                b"-----BEGIN CERTIFICATE-----private-secret".as_slice(),
                KEY,
            ),
            (CLIENT, CERT, b"private-secret".as_slice()),
            (CLIENT, b"".as_slice(), KEY),
        ] {
            let error = CertificateCredentialsProvider::new(
                client.into(),
                cert,
                Zeroizing::new(key.to_vec()),
            )
            .err()
            .unwrap()
            .to_string();
            assert!(!error.contains("private-secret"));
        }
        assert!(
            CertificateCredentialsProvider::new(
                CLIENT.into(),
                CERT,
                Zeroizing::new(vec![0; LIMIT + 1])
            )
            .is_err()
        );
    }
    #[test]
    fn key_files_are_bounded_private_regular_and_errors_hide_paths() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private-secret-key.der");
        let error = read_der(&path, true).err().unwrap().to_string();
        assert!(!error.contains("private-secret"));
        std::fs::write(&path, KEY).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_der(&path, true).is_err());
            assert!(read_der(&path, false).is_ok());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let symlink = directory.path().join("symlink");
            std::os::unix::fs::symlink(&path, &symlink).unwrap();
            assert!(read_der(&symlink, true).is_err());
        }
        assert_eq!(read_der(&path, true).unwrap().as_slice(), KEY);
        std::fs::write(&path, vec![0; LIMIT + 1]).unwrap();
        assert!(read_der(&path, true).is_err());
        std::fs::write(&path, []).unwrap();
        assert!(read_der(&path, true).is_err());
        assert!(read_der(directory.path(), true).is_err());
    }
}
