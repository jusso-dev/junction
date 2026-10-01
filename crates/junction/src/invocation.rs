//! Hierarchical spelling is only a route to the existing canonical executor.
use anyhow::{Result, bail};
use std::ffi::OsString;

pub fn rewrite(arguments: &[OsString], operation: &[OsString]) -> Result<Vec<OsString>> {
    let components = operation
        .iter()
        .take_while(|value| !value.to_str().is_some_and(|value| value.starts_with('-')))
        .collect::<Vec<_>>();
    if components.len() < 3 || components.len() > 16 {
        bail!("operation invocation requires product, resource and action components");
    }
    let mut names = Vec::new();
    for component in &components {
        let Some(component) = component.to_str() else {
            bail!("invalid operation component");
        };
        if component.is_empty()
            || component.len() > 128
            || !component
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
        {
            bail!("invalid operation component");
        }
        names.push(component.replace('-', "_"));
    }
    if names.len() == 3 && names[0] == "azure" && names[1] == "vm" {
        names.splice(1..2, ["compute".into(), "virtual_machines".into()]);
    }
    let Some(prefix) = arguments.len().checked_sub(operation.len()) else {
        bail!("invalid operation invocation");
    };
    if arguments[prefix..] != *operation {
        bail!("invalid operation invocation");
    }
    let mut rewritten = arguments[..prefix].to_vec();
    rewritten.push("execute".into());
    rewritten.push(names.join(".").into());
    rewritten.extend_from_slice(&operation[components.len()..]);
    Ok(rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hierarchical_names_preserve_flags_and_expand_vm_alias() {
        let args: Vec<OsString> = [
            "junction",
            "--context",
            "a",
            "azure",
            "compute",
            "virtual-machines",
            "list",
            "--input",
            "{\"body\":\"private-value\"}",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        let actual = rewrite(&args, &args[3..]).unwrap();
        assert_eq!(actual[4], "azure.compute.virtual_machines.list");
        assert_eq!(&actual[5..], &args[7..]);
        let args: Vec<OsString> = [
            "junction",
            "azure",
            "vm",
            "start",
            "--api-version",
            "latest",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        assert_eq!(
            rewrite(&args, &args[1..]).unwrap()[2],
            "azure.compute.virtual_machines.start"
        );
    }
    #[test]
    fn invalid_components_are_rejected_without_echoing_input() {
        for invalid in ["secret.component", "SECRET", "../private", ""] {
            let args: Vec<OsString> = ["junction", "graph", invalid, "list"]
                .into_iter()
                .map(Into::into)
                .collect();
            let error = rewrite(&args, &args[1..]).unwrap_err();
            assert_eq!(error.to_string(), "invalid operation component");
        }
    }
}
