use anyhow::{Result, bail};
use junction_core::JunctionOperation;
use serde_json::{Value, json};

pub fn validate(subscription: Option<&str>, resource_group: Option<&str>) -> Result<()> {
    if subscription.is_some_and(|value| {
        value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    }) || resource_group.is_some_and(|value| {
        value.is_empty()
            || value.len() > 256
            || !value
                .chars()
                .all(|c| c.is_alphanumeric() || "._()-".contains(c))
    }) {
        bail!("invalid subscription or resource-group scope");
    }
    Ok(())
}

pub fn apply(
    operation: &JunctionOperation,
    input: &mut Value,
    subscription: Option<&str>,
    resource_group: Option<&str>,
    defaults: (Option<&str>, Option<&str>),
) -> Result<()> {
    validate(subscription, resource_group)?;
    validate(defaults.0, defaults.1)?;
    for (explicit, default, names) in [
        (
            subscription,
            defaults.0,
            &["subscriptionId", "subscription_id", "subscription"][..],
        ),
        (
            resource_group,
            defaults.1,
            &[
                "resourceGroupName",
                "resource_group_name",
                "resourceGroup",
                "resource_group",
            ][..],
        ),
    ] {
        let Some(value) = explicit.or(default) else {
            continue;
        };
        let matches: Vec<_> = operation
            .parameters
            .iter()
            .filter(|parameter| {
                parameter.location == "path" && names.contains(&parameter.name.as_str())
            })
            .collect();
        let name = match matches.as_slice() {
            [parameter] => &parameter.name,
            [] if explicit.is_none() => continue,
            _ => bail!("scope must match exactly one declared path parameter"),
        };
        let object = input
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("input must be an object"))?;
        let parameters = object
            .entry("parameters")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("parameters must be an object"))?;
        if let Some(existing) = parameters.get(name) {
            if explicit.is_some() && existing != &Value::String(value.into()) {
                bail!("explicit scope conflicts with input parameter");
            }
        } else {
            parameters.insert(name.clone(), Value::String(value.into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_defaults_preserve_explicit_targets_and_require_declared_parameters() {
        let mut operation: JunctionOperation = serde_json::from_value(json!({
            "id":"azure.resources.groups.list","product":"azure","service":"resources",
            "resource":"groups","operation":"list","description":"","method":"GET",
            "base_url":"https://example.invalid","path":"/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}",
            "parameters":[{"name":"subscriptionId","location":"path","required":true,"schema":{"type":"string"}},
                {"name":"resourceGroupName","location":"path","required":true,"schema":{"type":"string"}}],
            "responses":{},"security":[],"risk":"read_only","preview":false,
            "source":{"id":"official","upstream":"official","operation_id":"Groups_List"}
        })).unwrap();
        let mut input = json!({"parameters":{"subscriptionId":"explicit-sub"}});
        apply(
            &operation,
            &mut input,
            None,
            Some("cli-group"),
            (Some("default-sub"), Some("default-group")),
        )
        .unwrap();
        assert_eq!(
            input,
            json!({"parameters":{"subscriptionId":"explicit-sub","resourceGroupName":"cli-group"}})
        );
        assert!(
            apply(
                &operation,
                &mut input,
                Some("other-sub"),
                None,
                (None, None)
            )
            .is_err()
        );
        apply(
            &operation,
            &mut input,
            Some("explicit-sub"),
            None,
            (None, None),
        )
        .unwrap();
        operation.parameters.clear();
        let mut empty = json!({});
        apply(
            &operation,
            &mut empty,
            None,
            None,
            (Some("default-sub"), Some("default-group")),
        )
        .unwrap();
        assert_eq!(empty, json!({}));
        assert!(
            apply(
                &operation,
                &mut empty,
                Some("explicit-sub"),
                None,
                (None, None)
            )
            .is_err()
        );
        assert!(validate(Some("../secret"), None).is_err());
        assert!(validate(None, Some("value\nsecret")).is_err());
    }
}
