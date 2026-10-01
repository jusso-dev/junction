use anyhow::Result;
use serde::Serialize;

/// Only UUID-shaped upstream IDs are retained; arbitrary header text is excluded.
#[derive(Debug, Default, Clone, Serialize)]
pub struct CorrelationIds {
    pub client_request_id: Option<String>,
    pub request_id: Option<String>,
    pub x_ms_request_id: Option<String>,
}
pub(crate) fn new_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("correlation entropy unavailable"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
fn safe_id(value: Option<&reqwest::header::HeaderValue>) -> Option<String> {
    let value = value?.to_str().ok()?;
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}
pub(crate) fn response_ids(
    client_request_id: String,
    headers: &reqwest::header::HeaderMap,
) -> CorrelationIds {
    CorrelationIds {
        client_request_id: Some(client_request_id),
        request_id: safe_id(headers.get("request-id")),
        x_ms_request_id: safe_id(headers.get("x-ms-request-id")),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_ids_are_unique_uuid_v4_and_upstream_text_is_excluded() {
        let first = new_id().unwrap();
        let second = new_id().unwrap();
        assert_ne!(first, second);
        assert_eq!(&first[14..15], "4");
        assert!(matches!(&first[19..20], "8" | "9" | "a" | "b"));
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "request-id",
            "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".parse().unwrap(),
        );
        headers.insert(
            "x-ms-request-id",
            "private-response-secret".parse().unwrap(),
        );
        let ids = response_ids(first.clone(), &headers);
        assert_eq!(ids.client_request_id.as_deref(), Some(first.as_str()));
        assert_eq!(
            ids.request_id.as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
        assert!(ids.x_ms_request_id.is_none());
        assert!(
            !serde_json::to_string(&ids)
                .unwrap()
                .contains("private-response-secret")
        );
    }
}
