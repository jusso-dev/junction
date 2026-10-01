//! Deterministic Graph route naming, independent of input order and generated SDK tag names.
use anyhow::{Result, bail};
use junction_core::canonical_component;
use std::collections::BTreeSet;

pub(crate) struct GraphName {
    pub id: String,
    pub service: String,
    pub resource: String,
    pub action: String,
}
fn placeholders(path: &str) -> Result<Vec<String>> {
    let mut remaining = path;
    let mut names = BTreeSet::new();
    while let Some(start) = remaining.find('{') {
        let tail = &remaining[start + 1..];
        let end = tail
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("invalid Graph path template"))?;
        let name = canonical_component(&tail[..end]);
        if name.is_empty() {
            bail!("invalid Graph path parameter name");
        }
        names.insert(name);
        remaining = &tail[end + 1..];
    }
    Ok(names.into_iter().collect())
}
fn crud(action: &str) -> Option<&'static str> {
    for (prefix, verb) in [
        ("List", "list"),
        ("Get", "get"),
        ("Create", "create"),
        ("Update", "update"),
        ("Delete", "delete"),
    ] {
        if let Some(suffix) = action.strip_prefix(prefix)
            && (suffix.is_empty() || suffix.starts_with(|c: char| c.is_ascii_uppercase()))
        {
            return Some(verb);
        }
    }
    None
}
pub(crate) fn graph(path: &str, upstream_id: &str) -> Result<GraphName> {
    let raw_action = upstream_id
        .rsplit_once('.')
        .map(|(_, action)| action)
        .or_else(|| upstream_id.rsplit_once('_').map(|(_, action)| action))
        .unwrap_or(upstream_id);
    let mut resources: Vec<String> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .filter(|segment| !(segment.starts_with('{') && segment.ends_with('}')))
        .map(str::to_owned)
        .collect();
    let last = resources
        .last()
        .ok_or_else(|| anyhow::anyhow!("Graph operation requires a resource route"))?
        .clone();
    let mut verb = crud(raw_action);
    let mut action = verb
        .map(str::to_owned)
        .unwrap_or_else(|| canonical_component(raw_action));
    let leaf = last
        .split('(')
        .next()
        .unwrap_or(&last)
        .rsplit('.')
        .next()
        .unwrap_or(&last);
    if last == "$count" {
        resources.pop();
        action = "count".into();
        verb = None;
    } else if last.contains('(') && verb.is_none()
        || !last.contains('(') && leaf.eq_ignore_ascii_case(raw_action)
    {
        resources.pop();
        action = canonical_component(leaf);
        // A Graph action named create/get/etc. is distinct from CRUD on its parent route.
        if ["list", "get", "create", "update", "delete"].contains(&action.as_str()) {
            action = format!("invoke_{action}");
        }
        verb = None;
    }
    for resource in &mut resources {
        if let Some((name, _)) = resource.split_once('(') {
            let arguments = placeholders(resource)?;
            *resource = format!("{}_by_{}", canonical_component(name), arguments.join("_"));
        } else {
            *resource = canonical_component(resource);
        }
        if resource.is_empty() {
            bail!("invalid Graph route component");
        }
    }
    // An unbound function is a root resource. Alias names distinguish overloads
    // without incorporating caller values into canonical operation names.
    if resources.is_empty() && last.contains('(') {
        resources.push(canonical_component(leaf));
        action = "invoke".into();
        let arguments = last
            .split_once('(')
            .expect("function segment")
            .1
            .trim_end_matches(')');
        let mut names = BTreeSet::new();
        for pair in arguments.split(',').filter(|pair| !pair.is_empty()) {
            let (name, value) = pair
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("unsupported root function arguments"))?;
            if !value.starts_with('@')
                || name.is_empty()
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                bail!("unsupported root function arguments");
            }
            names.insert(canonical_component(name));
        }
        if !names.is_empty() {
            action.push_str(&format!(
                "_by_{}",
                names.into_iter().collect::<Vec<_>>().join("_")
            ));
        }
    }
    // Binding names distinguish collection/entity actions and reference operations.
    // Always include them for these classes: adding a new route cannot rename an existing route.
    if verb.is_none() || last == "$ref" {
        let arguments = placeholders(path)?;
        if !arguments.is_empty() {
            action.push_str(&format!("_by_{}", arguments.join("_")));
        }
    }
    if resources.is_empty() || action.is_empty() {
        bail!("invalid Graph canonical name");
    }
    let service = resources[0].clone();
    let resource = resources.join(".");
    Ok(GraphName {
        id: format!("graph.{resource}.{action}"),
        service,
        resource,
        action,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn common_graph_crud_and_navigation_have_requested_names() {
        for (path, upstream, expected) in [
            ("/users", "users.user.ListUser", "graph.users.list"),
            ("/users/{user-id}", "users.user.GetUser", "graph.users.get"),
            ("/groups", "groups.group.ListGroup", "graph.groups.list"),
            (
                "/users/{user-id}/messages",
                "users.messages.ListMessages",
                "graph.users.messages.list",
            ),
            ("/users", "Users_List", "graph.users.list"),
            (
                "/security/alerts_v2",
                "security.ListAlerts_v2",
                "graph.security.alerts_v2.list",
            ),
            (
                "/security/alerts_v2/{alert-id}",
                "security.UpdateAlerts_v2",
                "graph.security.alerts_v2.update",
            ),
        ] {
            assert_eq!(graph(path, upstream).unwrap().id, expected);
        }
    }
    #[test]
    fn overloads_are_distinct_without_catalog_order_or_random_suffixes() {
        assert_ne!(
            graph("/print/printers", "print.CreatePrinters").unwrap().id,
            graph("/print/printers/create", "print.printers.create")
                .unwrap()
                .id
        );
        let a = graph(
            "/users/{user-id}/memberOf/graph.user",
            "users.memberOf.AsUser",
        )
        .unwrap();
        let b = graph(
            "/users/{user-id}/memberOf/{directoryObject-id}/graph.user",
            "users.memberOf.AsUser",
        )
        .unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(
            graph("/users/$count", "users.GetCount-abc").unwrap().id,
            graph("/users/$count", "users.GetCount-def").unwrap().id
        );
        assert_ne!(
            graph(
                "/applications(appId='{appId}')",
                "applications.GetApplication"
            )
            .unwrap()
            .id,
            graph(
                "/applications(uniqueName='{uniqueName}')",
                "applications.GetApplication"
            )
            .unwrap()
            .id
        );
    }
}
