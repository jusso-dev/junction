//! Turn a recorded Microsoft API response into a synthetic fixture.
//!
//! Used by `scripts/record-check-fixture.sh` (through `junction check
//! scrub-fixture`). Replacements are consistent within one response, so a user
//! id that appears twice maps to the same synthetic id and joins still work.
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Keys whose string values name a person, device or organisation.
const NAME_KEYS: &[&str] = &[
    "displayname",
    "givenname",
    "surname",
    "devicename",
    "computerdnsname",
    "machinename",
    "jobtitle",
    "department",
    "companyname",
    "officelocation",
    "streetaddress",
    "city",
    "postalcode",
    "mobilephone",
    "businessphones",
    "lastloggedonuser",
    "loggedonusers",
    "serialnumber",
    "imei",
    "phonenumber",
];

/// Keys whose values are secrets or secret-adjacent and are never kept.
const SECRET_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "password",
    "passwordcredentials",
    "keycredentials",
    "secrettext",
    "key",
    "recoverykey",
    "accountpassword",
];

struct Patterns {
    guid: Regex,
    email: Regex,
    ipv4: Regex,
    ipv6: Regex,
    jwt: Regex,
    bearer: Regex,
    domain: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        guid: Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .unwrap(),
        email: Regex::new(r"(?i)\b[a-z0-9._%+'-]+@([a-z0-9-]+\.)+[a-z]{2,}\b").unwrap(),
        ipv4: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
        ipv6: Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b").unwrap(),
        jwt: Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*").unwrap(),
        bearer: Regex::new(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+").unwrap(),
        domain: Regex::new(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b").unwrap(),
    })
}

/// Microsoft service hosts kept as-is: they are not tenant data.
const KEEP_HOSTS: &[&str] = &[
    "microsoft.com",
    "microsoftonline.com",
    "windows.net",
    "azure.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "loganalytics.io",
    "example.org",
    "example.com",
    "example.net",
];

#[derive(Default)]
pub struct Scrubber {
    guids: BTreeMap<String, String>,
    users: BTreeMap<String, String>,
    names: BTreeMap<String, String>,
    ips: BTreeMap<String, String>,
}

impl Scrubber {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scrub(&mut self, value: &Value) -> Value {
        self.value(None, value)
    }

    fn value(&mut self, key: Option<&str>, value: &Value) -> Value {
        let lower = key.map(str::to_ascii_lowercase);
        if let Some(k) = &lower
            && SECRET_KEYS.contains(&k.as_str())
            && !value.is_null()
        {
            return Value::String("[redacted]".into());
        }
        match value {
            Value::Object(map) => {
                let mut out = Map::new();
                for (k, v) in map {
                    out.insert(k.clone(), self.value(Some(k), v));
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(|v| self.value(key, v)).collect()),
            Value::String(s) => {
                if let Some(k) = &lower
                    && NAME_KEYS.contains(&k.as_str())
                {
                    return Value::String(self.name(s));
                }
                Value::String(self.text(s))
            }
            other => other.clone(),
        }
    }

    fn name(&mut self, original: &str) -> String {
        if original.is_empty() {
            return String::new();
        }
        let n = self.names.len() + 1;
        self.names
            .entry(original.to_owned())
            .or_insert_with(|| format!("Synthetic {n}"))
            .clone()
    }

    /// Replace identifiers inside free text.
    pub fn text(&mut self, input: &str) -> String {
        let p = patterns();
        let mut s = p.jwt.replace_all(input, "[redacted-token]").into_owned();
        s = p
            .bearer
            .replace_all(&s, "Bearer [redacted-token]")
            .into_owned();
        s = replace(&p.email, &s, |m| {
            let n = self.users.len() + 1;
            self.users
                .entry(m.to_ascii_lowercase())
                .or_insert_with(|| format!("user{n}@contoso.example"))
                .clone()
        });
        s = replace(&p.guid, &s, |m| {
            let n = self.guids.len() + 1;
            self.guids
                .entry(m.to_ascii_lowercase())
                .or_insert_with(|| format!("00000000-0000-4000-8000-{n:012}"))
                .clone()
        });
        s = replace(&p.ipv4, &s, |m| {
            let n = self.ips.len() + 1;
            self.ips
                .entry(m.to_owned())
                .or_insert_with(|| format!("192.0.2.{}", (n % 254) + 1))
                .clone()
        });
        s = replace(&p.ipv6, &s, |m| {
            let n = self.ips.len() + 1;
            self.ips
                .entry(m.to_ascii_lowercase())
                .or_insert_with(|| format!("2001:db8::{n:x}"))
                .clone()
        });
        replace(&p.domain, &s, |m| {
            let lower = m.to_ascii_lowercase();
            let tld = lower.rsplit('.').next().unwrap_or_default();
            if !crate::testkit::REAL_TLDS.contains(&tld)
                || KEEP_HOSTS
                    .iter()
                    .any(|h| lower == *h || lower.ends_with(&format!(".{h}")))
            {
                m.to_owned()
            } else {
                "contoso.example".to_owned()
            }
        })
    }
}

fn replace(re: &Regex, input: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for m in re.find_iter(input) {
        out.push_str(&input[last..m.start()]);
        out.push_str(&f(m.as_str()));
        last = m.end();
    }
    out.push_str(&input[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identifiers_are_replaced_consistently() {
        let recorded = json!({
            "value": [{
                "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
                "userPrincipalName": "Jane.Citizen@realcorp.com.au",
                "mail": "jane.citizen@realcorp.com.au",
                "displayName": "Jane Citizen",
                "lastIpAddress": "203.45.67.89",
                "ipv6": "2404:6800:4006:80a::200e",
                "note": "token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln and Bearer abc.def-ghi",
                "manager": {"id": "3F2504E0-4F89-41D3-9A0C-0305E82C3301"},
                "website": "https://intranet.realcorp.com.au/x",
                "docs": "https://learn.microsoft.com/graph/api",
                "passwordCredentials": [{"secretText": "s3cret"}]
            }]
        });
        let out = Scrubber::new().scrub(&recorded);
        let text = out.to_string();
        for leaked in [
            "realcorp",
            "Jane",
            "203.45.67.89",
            "2404:6800",
            "eyJ",
            "abc.def-ghi",
            "3f2504e0",
            "s3cret",
        ] {
            assert!(
                !text.to_lowercase().contains(&leaked.to_lowercase()),
                "{leaked} leaked: {text}"
            );
        }
        let user = &out["value"][0];
        assert_eq!(user["userPrincipalName"], user["mail"]);
        assert_eq!(user["userPrincipalName"], "user1@contoso.example");
        assert_eq!(user["id"], user["manager"]["id"]);
        assert_eq!(user["displayName"], "Synthetic 1");
        assert!(
            user["lastIpAddress"]
                .as_str()
                .unwrap()
                .starts_with("192.0.2.")
        );
        assert!(
            user["docs"]
                .as_str()
                .unwrap()
                .contains("learn.microsoft.com")
        );
        assert!(
            crate::testkit::scan_fixture_text("scrubbed", &text).is_empty(),
            "{text}"
        );
    }
}
