//! Endpoint variables are bound by trusted operator context, never operation input.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointVariable {
    pub default: Option<String>,
    #[serde(default)]
    pub choices: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointTemplate {
    pub template: String,
    pub variables: BTreeMap<String, EndpointVariable>,
}

impl EndpointTemplate {
    pub fn validate(&self) -> Result<()> {
        if self.template.is_empty()
            || self.template.len() > 16384
            || self.variables.len() > 128
            || self.template.contains(['\\', '?', '#', '@'])
            || self
                .template
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            bail!("invalid endpoint template");
        }
        let mut remainder = self.template.as_str();
        let mut used = BTreeSet::new();
        while let Some(start) = remainder.find('{') {
            if remainder[..start].contains('}') {
                bail!("invalid endpoint template");
            }
            let suffix = &remainder[start + 1..];
            let end = suffix
                .find('}')
                .ok_or_else(|| anyhow::anyhow!("invalid endpoint template"))?;
            let name = &suffix[..end];
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                bail!("invalid endpoint variable name");
            }
            let variable = self
                .variables
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("undeclared endpoint variable"))?;
            if let Some(default) = &variable.default {
                validate_value(default)?;
                validate_choice(variable, default)?;
            }
            if let Some(choices) = &variable.choices {
                if choices.is_empty() || choices.len() > 1024 {
                    bail!("invalid endpoint variable choices");
                }
                for choice in choices {
                    validate_value(choice)?;
                }
            }
            used.insert(name);
            remainder = &suffix[end + 1..];
        }
        if remainder.contains('}') || used.len() != self.variables.len() {
            bail!("invalid endpoint template variables");
        }
        Ok(())
    }

    pub fn resolve(&self, bindings: &BTreeMap<String, String>) -> Result<String> {
        self.validate()?;
        if bindings
            .keys()
            .any(|name| !self.variables.contains_key(name))
        {
            bail!("unknown endpoint variable binding");
        }
        let mut result = String::new();
        let mut remainder = self.template.as_str();
        while let Some(start) = remainder.find('{') {
            result.push_str(&remainder[..start]);
            let suffix = &remainder[start + 1..];
            let end = suffix
                .find('}')
                .ok_or_else(|| anyhow::anyhow!("invalid endpoint template"))?;
            let variable = &self.variables[&suffix[..end]];
            let value = bindings
                .get(&suffix[..end])
                .or(variable.default.as_ref())
                .ok_or_else(|| anyhow::anyhow!("endpoint variable requires an operator binding"))?;
            validate_value(value)?;
            validate_choice(variable, value)?;
            result.push_str(value);
            if result.len() > 16384 {
                bail!("endpoint size limit exceeded");
            }
            remainder = &suffix[end + 1..];
        }
        result.push_str(remainder);
        validate_url(&result)?;
        Ok(result)
    }
}

fn validate_choice(variable: &EndpointVariable, value: &str) -> Result<()> {
    if variable
        .choices
        .as_ref()
        .is_some_and(|choices| !choices.iter().any(|choice| choice == value))
    {
        bail!("endpoint variable is outside declared choices");
    }
    Ok(())
}
fn validate_value(value: &str) -> Result<()> {
    if value.len() > 4096
        || value.contains(['{', '}', '\\'])
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        bail!("invalid endpoint variable value");
    }
    Ok(())
}
fn validate_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value).map_err(|_| anyhow::anyhow!("endpoint must be absolute"))?;
    if value.len() > 16384
        || value.contains(['{', '}', '\\'])
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("invalid resolved endpoint");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_bindings_are_bounded_and_enumerated() {
        let template = EndpointTemplate {
            template: "https://{account}.{suffix}/v1".into(),
            variables: BTreeMap::from([
                (
                    "account".into(),
                    EndpointVariable {
                        default: None,
                        choices: None,
                    },
                ),
                (
                    "suffix".into(),
                    EndpointVariable {
                        default: Some("vault.azure.net".into()),
                        choices: Some(vec![
                            "vault.azure.net".into(),
                            "vault.usgovcloudapi.net".into(),
                        ]),
                    },
                ),
            ]),
        };
        let mut bindings = BTreeMap::from([("account".into(), "customer-a".into())]);
        assert_eq!(
            template.resolve(&bindings).unwrap(),
            "https://customer-a.vault.azure.net/v1"
        );
        bindings.insert("suffix".into(), "vault.usgovcloudapi.net".into());
        assert_eq!(
            template.resolve(&bindings).unwrap(),
            "https://customer-a.vault.usgovcloudapi.net/v1"
        );
        bindings.insert("suffix".into(), "evil.example".into());
        assert!(template.resolve(&bindings).is_err());
        bindings.remove("suffix");
        for value in [
            "private-secret@evil.example",
            "private-secret?query=",
            "private-secret#fragment",
            "private-secret\\path",
            "private-secret\n",
            "{private-secret}",
        ] {
            bindings.insert("account".into(), value.into());
            let error = template.resolve(&bindings).unwrap_err().to_string();
            assert!(!error.contains("private-secret"));
        }
        bindings.insert("account".into(), "a".repeat(4097));
        assert!(template.resolve(&bindings).is_err());
        bindings.insert("account".into(), "customer-a".into());
        bindings.insert("unknown".into(), "value".into());
        assert!(template.resolve(&bindings).is_err());
    }
}
