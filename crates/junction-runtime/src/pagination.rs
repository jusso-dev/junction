use anyhow::{Result, bail};
use serde_json::Value;
use std::collections::BTreeSet;
use url::Url;

/// Opaque continuation includes unconsumed items; no truncation silently loses records.
pub struct Continuation {
    pub(crate) buffered: Vec<Value>,
    pub(crate) next: Option<Url>,
    origin: Url,
    visited: BTreeSet<String>,
    pub(crate) binding: Option<(String, String, String, String)>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredContinuation {
    format_version: u32,
    buffered: Vec<Value>,
    next: Option<String>,
    origin: String,
    visited: BTreeSet<String>,
    binding: Option<(String, String, String, String)>,
}
impl Continuation {
    /// Save sensitive state to a new private file. Never emit these bytes as tool output.
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;
        let stored = StoredContinuation {
            format_version: 1,
            buffered: self.buffered.clone(),
            next: self.next.as_ref().map(ToString::to_string),
            origin: self.origin.to_string(),
            visited: self.visited.clone(),
            binding: self.binding.clone(),
        };
        let bytes = serde_json::to_vec(&stored)?;
        if bytes.len() > 32 * 1024 * 1024 {
            bail!("continuation size limit exceeded");
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error.into());
        }
        Ok(())
    }
    /// Load operator-owned state; request/context binding is enforced by the executor.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        use std::io::Read;
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!("invalid continuation file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!("continuation file must be private");
            }
        }
        let mut bytes = Vec::new();
        file.take(32 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 32 * 1024 * 1024 {
            bail!("continuation size limit exceeded");
        }
        let stored: StoredContinuation = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid continuation state"))?;
        if stored.format_version != 1 || stored.visited.is_empty() || stored.visited.len() > 10000 {
            bail!("invalid continuation state");
        }
        let parse = |value: &str| {
            Url::parse(value).map_err(|_| anyhow::anyhow!("invalid continuation URL"))
        };
        let origin = parse(&stored.origin)?;
        let next = stored.next.as_deref().map(parse).transpose()?;
        let validator =
            PageAccumulator::new(origin.clone(), 1, 1, &junction_policy::Limits::default())?;
        if let Some(next) = &next {
            validator.check_url(next)?;
        }
        for url in &stored.visited {
            validator.check_url(&parse(url)?)?;
        }
        Ok(Self {
            buffered: stored.buffered,
            next,
            origin,
            visited: stored.visited,
            binding: stored.binding,
        })
    }
    pub fn buffered_items(&self) -> usize {
        self.buffered.len()
    }
}
pub struct PageResult {
    pub items: Vec<Value>,
    pub continuation: Option<Continuation>,
    pub pages: usize,
}
pub struct PageAccumulator {
    origin: Url,
    max_items: usize,
    max_pages: usize,
    items: Vec<Value>,
    pages: usize,
    visited: BTreeSet<String>,
    current: Url,
    pending: bool,
    finished: bool,
}
impl PageAccumulator {
    pub fn new(
        origin: Url,
        max_items: usize,
        max_pages: usize,
        limits: &junction_policy::Limits,
    ) -> Result<Self> {
        if max_items == 0
            || max_pages == 0
            || max_items > limits.max_items
            || max_pages > limits.max_pages
        {
            bail!("pagination limits exceed policy");
        }
        if origin.scheme() != "https"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.fragment().is_some()
        {
            bail!("invalid pagination origin");
        }
        Ok(Self {
            current: origin.clone(),
            origin,
            max_items,
            max_pages,
            items: vec![],
            pages: 0,
            visited: BTreeSet::new(),
            pending: false,
            finished: false,
        })
    }
    /// Consume buffered items first, preserving cycle detection across resumes.
    pub(crate) fn resume(
        origin: Url,
        continuation: Continuation,
        max_items: usize,
        max_pages: usize,
        limits: &junction_policy::Limits,
    ) -> Result<(Self, Option<Url>, Option<PageResult>)> {
        if origin != continuation.origin {
            bail!("continuation request mismatch");
        }
        if continuation.visited.is_empty() {
            bail!("invalid continuation request history");
        }
        let mut accumulator = Self::new(origin, max_items, max_pages, limits)?;
        accumulator.visited = continuation.visited;
        let mut buffered = continuation.buffered;
        let remainder = buffered.split_off(buffered.len().min(max_items));
        accumulator.items = buffered;
        let next = continuation.next;
        if let Some(url) = &next {
            accumulator.check_url(url)?;
        }
        if !remainder.is_empty() || accumulator.items.len() >= max_items || next.is_none() {
            let continuation = if !remainder.is_empty() || next.is_some() {
                Some(Continuation {
                    buffered: remainder,
                    next,
                    origin: accumulator.origin.clone(),
                    visited: accumulator.visited.clone(),
                    binding: continuation.binding,
                })
            } else {
                None
            };
            let result = PageResult {
                items: std::mem::take(&mut accumulator.items),
                continuation,
                pages: 0,
            };
            accumulator.finished = true;
            return Ok((accumulator, None, Some(result)));
        }
        Ok((accumulator, next, None))
    }
    /// Only a new accumulator can submit the initial request; resumes retain history.
    pub(crate) fn is_initial_request(&self) -> bool {
        self.visited.is_empty()
    }
    /// Call before every logical page fetch. Repeat URLs and excess requests fail closed.
    pub fn begin_page(&mut self, url: &Url) -> Result<()> {
        if self.pending || self.finished {
            bail!("invalid pagination state");
        }
        self.check_url(url)?;
        if self.visited.len() >= 10000 {
            bail!("pagination continuation request limit reached");
        }
        if self.pages >= self.max_pages || self.items.len() >= self.max_items {
            bail!("pagination limit reached");
        }
        if !self.visited.insert(url.to_string()) {
            bail!("pagination cycle detected");
        }
        self.current = url.clone();
        self.pages += 1;
        self.pending = true;
        Ok(())
    }
    fn check_url(&self, url: &Url) -> Result<()> {
        if url.scheme() != "https"
            || url.origin() != self.origin.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            bail!("unsafe continuation origin");
        }
        Ok(())
    }
    /// Return continuation for the next fetch or a final bounded result.
    pub(crate) fn accept_response(
        &mut self,
        operation: &junction_core::JunctionOperation,
        response: &junction_http::HttpResponse,
    ) -> Result<(Option<Url>, Option<PageResult>)> {
        if let Some(continuation) = &operation.query_continuation {
            continuation.validate(operation)?;
            let declared_link = operation
                .pageable
                .as_ref()
                .and_then(|pageable| pageable.next_link_name.as_deref())
                .and_then(|name| response.body.get(name));
            if declared_link
                .into_iter()
                .chain(response.body.get("nextLink"))
                .chain(response.body.get("@odata.nextLink"))
                .any(|link| !link.is_null())
            {
                bail!("ambiguous pagination metadata");
            }
            let token = match response.body.pointer(&continuation.response_pointer) {
                None | Some(Value::Null) => None,
                Some(Value::String(token)) => Some(token.as_str()),
                _ => bail!("invalid continuation token"),
            };
            let item_name = operation
                .pageable
                .as_ref()
                .map(|pageable| pageable.item_name.as_str())
                .unwrap_or("value");
            return self.accept_token_named(
                &response.body,
                &continuation.query_parameter,
                token,
                item_name,
            );
        }
        if let Some(pageable) = &operation.pageable {
            pageable.validate()?;
            let link = pageable
                .next_link_name
                .as_ref()
                .and_then(|name| response.body.get(name));
            let next = match link {
                Some(Value::String(link)) if !link.is_empty() => Some(
                    self.current
                        .join(link)
                        .map_err(|_| anyhow::anyhow!("invalid continuation link"))?,
                ),
                None | Some(Value::Null) => None,
                _ => bail!("invalid continuation link"),
            };
            if next.is_some() && pageable.operation_name.is_some() {
                bail!("pagination with a named next-page operation is not implemented");
            }
            return self.accept_next_named(&response.body, next, &pageable.item_name);
        }
        let devops = junction_core::canonical_component(&operation.product) == "azure_devops"
            && operation.parameters.iter().any(|parameter| {
                parameter.location == "query" && parameter.name == "continuationToken"
            });
        if devops {
            self.accept_continuation_token(
                &response.body,
                "continuationToken",
                response
                    .continuation_token
                    .as_ref()
                    .map(|token| token.expose()),
            )
        } else if let Some(parameter) = operation.parameters.iter().find(|parameter| {
            parameter.location == "query"
                && matches!(parameter.name.as_str(), "continuationToken" | "skipToken")
                && response.body.get(&parameter.name).is_some()
        }) {
            let token = match &response.body[&parameter.name] {
                Value::String(token) => Some(token.as_str()),
                Value::Null => None,
                _ => bail!("invalid continuation token"),
            };
            if response
                .body
                .get("@odata.nextLink")
                .or_else(|| response.body.get("nextLink"))
                .is_some_and(|link| !link.is_null())
            {
                bail!("ambiguous pagination metadata");
            }
            self.accept_continuation_token(&response.body, &parameter.name, token)
        } else {
            self.accept(&response.body)
        }
    }
    /// Return continuation for the next fetch or a final bounded result.
    pub fn accept(&mut self, body: &Value) -> Result<(Option<Url>, Option<PageResult>)> {
        if !self.pending || self.finished {
            bail!("page must be admitted before accumulation");
        }
        let next = body.get("@odata.nextLink").or_else(|| body.get("nextLink"));
        let next = match next {
            Some(Value::String(link)) if !link.is_empty() => Some(
                self.current
                    .join(link)
                    .map_err(|_| anyhow::anyhow!("invalid continuation link"))?,
            ),
            None | Some(Value::Null) => None,
            _ => bail!("invalid continuation link"),
        };
        self.accept_next(body, next)
    }
    /// Consume a service token using an operator-selected query parameter.
    /// The token is opaque data, never a URL or an extra query fragment.
    pub fn accept_continuation_token(
        &mut self,
        body: &Value,
        query_parameter: &str,
        token: Option<&str>,
    ) -> Result<(Option<Url>, Option<PageResult>)> {
        self.accept_token_named(body, query_parameter, token, "value")
    }
    fn accept_token_named(
        &mut self,
        body: &Value,
        query_parameter: &str,
        token: Option<&str>,
        item_name: &str,
    ) -> Result<(Option<Url>, Option<PageResult>)> {
        if query_parameter.is_empty()
            || query_parameter.len() > 128
            || query_parameter.chars().any(char::is_control)
        {
            bail!("invalid continuation parameter");
        }
        let next = match token {
            None | Some("") => None,
            Some(token) => {
                if token.len() > 16384 || token.chars().any(char::is_control) {
                    bail!("invalid continuation token");
                }
                let mut next = self.current.clone();
                let pairs: Vec<_> = next
                    .query_pairs()
                    .filter(|(name, _)| name != query_parameter)
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect();
                next.query_pairs_mut()
                    .clear()
                    .extend_pairs(pairs)
                    .append_pair(query_parameter, token);
                Some(next)
            }
        };
        self.accept_next_named(body, next, item_name)
    }
    fn accept_next(
        &mut self,
        body: &Value,
        next: Option<Url>,
    ) -> Result<(Option<Url>, Option<PageResult>)> {
        self.accept_next_named(body, next, "value")
    }
    fn accept_next_named(
        &mut self,
        body: &Value,
        next: Option<Url>,
        item_name: &str,
    ) -> Result<(Option<Url>, Option<PageResult>)> {
        if !self.pending || self.finished {
            bail!("page must be admitted before accumulation");
        }
        let values = body
            .get(item_name)
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("expected paginated value array"))?;
        if let Some(url) = &next {
            self.check_url(url)?;
        }
        self.pending = false;
        let available = self.max_items - self.items.len();
        self.items.extend(values.iter().take(available).cloned());
        let buffered = values.iter().skip(available).cloned().collect::<Vec<_>>();
        if next.is_none()
            || !buffered.is_empty()
            || self.items.len() >= self.max_items
            || self.pages >= self.max_pages
        {
            self.finished = true;
            let continuation = if next.is_some() || !buffered.is_empty() {
                Some(Continuation {
                    buffered,
                    next,
                    origin: self.origin.clone(),
                    visited: self.visited.clone(),
                    binding: None,
                })
            } else {
                None
            };
            return Ok((
                None,
                Some(PageResult {
                    items: std::mem::take(&mut self.items),
                    continuation,
                    pages: self.pages,
                }),
            ));
        }
        Ok((next, None))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn marked_custom_tokens_are_opaque_and_preserve_named_items_and_query() {
        let mut operation = crate::tests::operation();
        operation.parameters.push(junction_core::Parameter {
            name: "cursor".into(),
            location: "query".into(),
            required: false,
            schema: json!({"type":"string"}),
            serialization: Default::default(),
        });
        operation.query_continuation = Some(junction_core::QueryContinuation {
            query_parameter: "cursor".into(),
            response_pointer: "/metadata/resume~1key~0value".into(),
        });
        operation.pageable = Some(junction_core::Pageable {
            item_name: "items".into(),
            next_link_name: None,
            operation_name: None,
        });
        let origin =
            Url::parse("https://graph.example/v1.0/users?filter=active&cursor=old").unwrap();
        let mut pages =
            PageAccumulator::new(origin.clone(), 10, 3, &junction_policy::Limits::default())
                .unwrap();
        pages.begin_page(&origin).unwrap();
        let response = junction_http::HttpResponse {
            status: 200,
            body: json!({"items":[1],"metadata":{"resume/key~value":"https://evil.example/?injected=yes&x=1"}}),
            continuation_token: None,
            async_links: Default::default(),
            correlation: Default::default(),
            retry_after: None,
        };
        let (next, result) = pages.accept_response(&operation, &response).unwrap();
        assert!(result.is_none());
        let next = next.unwrap();
        assert_eq!(next.origin(), origin.origin());
        assert_eq!(next.path(), origin.path());
        let pairs: std::collections::BTreeMap<_, _> = next.query_pairs().collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs["filter"], "active");
        assert_eq!(pairs["cursor"], "https://evil.example/?injected=yes&x=1");
        pages.begin_page(&next).unwrap();
        let final_response = junction_http::HttpResponse {
            body: json!({"items":[2],"metadata":{}}),
            ..response
        };
        let (_, result) = pages.accept_response(&operation, &final_response).unwrap();
        assert_eq!(result.unwrap().items, vec![json!(1), json!(2)]);
    }
    #[test]
    fn marked_tokens_reject_ambiguous_links_invalid_types_and_oversized_values() {
        let mut operation = crate::tests::operation();
        operation.parameters.push(junction_core::Parameter {
            name: "cursor".into(),
            location: "query".into(),
            required: false,
            schema: json!({"type":"string"}),
            serialization: Default::default(),
        });
        operation.query_continuation = Some(junction_core::QueryContinuation {
            query_parameter: "cursor".into(),
            response_pointer: "/token".into(),
        });
        for body in [
            json!({"value":[1],"token":42}),
            json!({"value":[1],"token":"x","nextLink":"?next=1"}),
            json!({"value":[1],"token":"x\n"}),
            json!({"value":[1],"token":"x".repeat(16385)}),
        ] {
            let mut pages = accumulator(10, 2);
            let origin = pages.origin.clone();
            pages.begin_page(&origin).unwrap();
            let response = junction_http::HttpResponse {
                status: 200,
                body,
                continuation_token: None,
                async_links: Default::default(),
                correlation: Default::default(),
                retry_after: None,
            };
            assert!(pages.accept_response(&operation, &response).is_err());
        }
    }
    #[test]
    fn imported_pageable_fields_control_collection_and_link_selection() {
        let spec = json!({"swagger":"2.0","host":"graph.microsoft.com","paths":{
            "/items":{"get":{"operationId":"Items_List","x-ms-pageable":{"itemName":"items","nextLinkName":"more"}}}}});
        let mut operation = junction_discovery::ingest(&spec, "azure", "service", "official")
            .unwrap()
            .operations
            .remove(0);
        for (link, valid) in [
            (json!("/second"), true),
            (json!("https://evil.example/secret"), false),
            (json!(42), false),
        ] {
            let mut pages = accumulator(10, 2);
            let origin = pages.origin.clone();
            pages.begin_page(&origin).unwrap();
            let response = junction_http::HttpResponse {
                status: 200,
                body: json!({"items":[1,2],"more":link,"value":[99],"nextLink":"https://ignored.example"}),
                continuation_token: None,
                async_links: Default::default(),
                correlation: Default::default(),
                retry_after: None,
            };
            let result = pages.accept_response(&operation, &response);
            assert_eq!(result.is_ok(), valid);
            if valid {
                let (next, result) = result.unwrap();
                assert!(result.is_none());
                let next = next.unwrap();
                assert_eq!(next.path(), "/second");
                pages.begin_page(&next).unwrap();
                let last = junction_http::HttpResponse {
                    body: json!({"items":[3],"more":null}),
                    ..response
                };
                let (_, result) = pages.accept_response(&operation, &last).unwrap();
                assert_eq!(result.unwrap().items, vec![json!(1), json!(2), json!(3)]);
            }
        }
        operation.pageable.as_mut().unwrap().operation_name = Some("Items_Next".into());
        let mut named_pages = accumulator(10, 2);
        let origin = named_pages.origin.clone();
        named_pages.begin_page(&origin).unwrap();
        let named_response = junction_http::HttpResponse {
            status: 200,
            body: json!({"items":[1],"more":"/second"}),
            continuation_token: None,
            async_links: Default::default(),
            correlation: Default::default(),
            retry_after: None,
        };
        assert!(
            named_pages
                .accept_response(&operation, &named_response)
                .is_err()
        );
        operation.pageable.as_mut().unwrap().next_link_name = None;
        let mut pages = accumulator(1, 2);
        let origin = pages.origin.clone();
        pages.begin_page(&origin).unwrap();
        let response = junction_http::HttpResponse {
            status: 200,
            body: json!({"items":[1,2],"more":"https://ignored.example"}),
            continuation_token: None,
            async_links: Default::default(),
            correlation: Default::default(),
            retry_after: None,
        };
        let (next, result) = pages.accept_response(&operation, &response).unwrap();
        assert!(next.is_none());
        let result = result.unwrap();
        assert_eq!(result.items, vec![json!(1)]);
        assert!(result.continuation.is_some());
    }
    #[test]
    fn body_tokens_require_declared_parameters_and_reject_ambiguity() {
        for name in ["continuationToken", "skipToken"] {
            let spec = json!({"swagger":"2.0","host":"service.example","paths":{
                "/items":{"get":{"operationId":"Items_List","parameters":[
                    {"name":name,"in":"query","type":"string"}],"responses":{}}}
            }});
            let mut operation = junction_discovery::ingest(&spec, "azure", "service", "official")
                .unwrap()
                .operations
                .remove(0);
            for (value, next_link, valid) in [
                (json!("page & two"), json!(null), true),
                (json!(null), json!(null), true),
                (json!(42), json!(null), false),
                (json!("page two"), json!("/other"), false),
            ] {
                let mut pages = accumulator(10, 2);
                let origin = pages.origin.clone();
                pages.begin_page(&origin).unwrap();
                let response = junction_http::HttpResponse {
                    continuation_token: None,
                    status: 200,
                    body: json!({"value":[1],name:value,"nextLink":next_link}),
                    async_links: Default::default(),
                    correlation: Default::default(),
                    retry_after: None,
                };
                let result = pages.accept_response(&operation, &response);
                assert_eq!(result.is_ok(), valid);
                if valid {
                    let (next, result) = result.unwrap();
                    if value.is_null() {
                        assert!(result.unwrap().continuation.is_none());
                    } else {
                        let next = next.unwrap();
                        assert_eq!(next.origin(), origin.origin());
                        assert_eq!(
                            next.query_pairs().collect::<Vec<_>>(),
                            vec![(name.into(), "page & two".into())]
                        );
                    }
                }
            }
            operation.parameters.clear();
            let mut pages = accumulator(10, 2);
            let origin = pages.origin.clone();
            pages.begin_page(&origin).unwrap();
            let response = junction_http::HttpResponse {
                continuation_token: None,
                status: 200,
                body: json!({"value":[1],name:"ignored"}),
                async_links: Default::default(),
                correlation: Default::default(),
                retry_after: None,
            };
            assert!(
                pages
                    .accept_response(&operation, &response)
                    .unwrap()
                    .1
                    .unwrap()
                    .continuation
                    .is_none()
            );
        }
    }
    #[test]
    fn executor_selects_tokens_only_for_declared_devops_pagination() {
        let spec = json!({"swagger":"2.0","host":"dev.azure.com","paths":{
            "/projects":{"get":{"operationId":"Projects_List","parameters":[
                {"name":"continuationToken","in":"query","type":"string"}],"responses":{}}}
        }});
        let mut operation = junction_discovery::ingest(&spec, "azure-devops", "core", "official")
            .unwrap()
            .operations
            .remove(0);
        let response = junction_http::HttpResponse {
            continuation_token: Some(junction_auth::Secret::new("page-two".into()).unwrap()),
            status: 200,
            body: json!({"value":[1],"nextLink":"/other"}),
            async_links: Default::default(),
            correlation: Default::default(),
            retry_after: None,
        };
        for (product, declared, expected) in [
            (
                "azure-devops",
                true,
                "/v1.0/users?continuationToken=page-two",
            ),
            ("graph", true, "/other"),
            ("azure-devops", false, "/other"),
        ] {
            operation.product = product.into();
            operation.parameters = if declared {
                junction_discovery::ingest(&spec, "azure-devops", "core", "official")
                    .unwrap()
                    .operations
                    .remove(0)
                    .parameters
            } else {
                vec![]
            };
            let mut pages = accumulator(10, 2);
            let origin = pages.origin.clone();
            pages.begin_page(&origin).unwrap();
            let (next, result) = pages.accept_response(&operation, &response).unwrap();
            assert!(result.is_none());
            let next = next.unwrap();
            assert_eq!(
                format!(
                    "{}{}",
                    next.path(),
                    next.query()
                        .map(|query| format!("?{query}"))
                        .unwrap_or_default()
                ),
                expected
            );
            pages.begin_page(&next).unwrap();
            let last = junction_http::HttpResponse {
                continuation_token: None,
                status: 200,
                body: json!({"value":[2]}),
                async_links: Default::default(),
                correlation: Default::default(),
                retry_after: None,
            };
            let (_, result) = pages.accept_response(&operation, &last).unwrap();
            assert_eq!(result.unwrap().items, vec![json!(1), json!(2)]);
        }
    }
    fn accumulator(items: usize, pages: usize) -> PageAccumulator {
        PageAccumulator::new(
            Url::parse("https://graph.example/v1.0/users").unwrap(),
            items,
            pages,
            &junction_policy::Limits::default(),
        )
        .unwrap()
    }
    #[test]
    fn token_pagination_encodes_opaque_data_and_preserves_limits() {
        let origin =
            Url::parse("https://service.example/projects?api-version=7.1&continuationToken=old")
                .unwrap();
        let mut pages =
            PageAccumulator::new(origin.clone(), 1, 2, &junction_policy::Limits::default())
                .unwrap();
        pages.begin_page(&origin).unwrap();
        let (_, result) = pages
            .accept_continuation_token(
                &json!({"value":[1,2]}),
                "continuationToken",
                Some("https://other.example/?a=1&api-version=bad"),
            )
            .unwrap();
        let result = result.unwrap();
        assert_eq!(result.items, vec![json!(1)]);
        let continuation = result.continuation.unwrap();
        let next = continuation.next.as_ref().unwrap();
        assert_eq!(next.origin(), origin.origin());
        let pairs: Vec<_> = next.query_pairs().collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("api-version".into(), "7.1".into()));
        assert_eq!(pairs[1].1, "https://other.example/?a=1&api-version=bad");
        assert_eq!(continuation.buffered, vec![json!(2)]);
        let mut pages = accumulator(10, 2);
        let origin = pages.origin.clone();
        pages.begin_page(&origin).unwrap();
        assert!(
            pages
                .accept_continuation_token(
                    &json!({"value":[]}),
                    "continuationToken",
                    Some("private\nvalue")
                )
                .is_err()
        );
        let (next, _) = pages
            .accept_continuation_token(&json!({"value":[]}), "continuationToken", Some("same"))
            .unwrap();
        let next = next.unwrap();
        pages.begin_page(&next).unwrap();
        let (_, result) = pages
            .accept_continuation_token(&json!({"value":[]}), "continuationToken", Some("same"))
            .unwrap();
        let mut resumed = PageAccumulator::resume(
            origin,
            result.unwrap().continuation.unwrap(),
            10,
            2,
            &junction_policy::Limits::default(),
        )
        .unwrap();
        assert!(resumed.0.begin_page(&resumed.1.unwrap()).is_err());
    }
    #[test]
    fn bounded_pages_preserve_remaining_items() {
        let mut a = accumulator(2, 3);
        a.begin_page(&Url::parse("https://graph.example/v1.0/users").unwrap())
            .unwrap();
        let (_,result)=a.accept(&json!({"value":[1,2,3],"@odata.nextLink":"https://graph.example/v1.0/users?$skiptoken=abc"})).unwrap();
        let result = result.unwrap();
        assert_eq!(result.items, vec![json!(1), json!(2)]);
        let continuation = result.continuation.unwrap();
        assert_eq!(continuation.buffered, vec![json!(3)]);
        assert!(continuation.next.is_some());
    }
    #[test]
    fn resume_drains_buffer_without_network_and_retains_next_link() {
        let origin = Url::parse("https://graph.example/v1.0/users").unwrap();
        let mut a = accumulator(1, 3);
        a.begin_page(&origin).unwrap();
        let (_, result) = a
            .accept(&json!({"value":[1,2,3],"nextLink":"?page=2"}))
            .unwrap();
        let continuation = result.unwrap().continuation.unwrap();
        let (_, next, result) = PageAccumulator::resume(
            origin.clone(),
            continuation,
            1,
            3,
            &junction_policy::Limits::default(),
        )
        .unwrap();
        assert!(next.is_none());
        let result = result.unwrap();
        assert_eq!(result.items, vec![json!(2)]);
        assert_eq!(result.pages, 0);
        let continuation = result.continuation.unwrap();
        assert_eq!(continuation.buffered_items(), 1);
        let (mut a, next, result) = PageAccumulator::resume(
            origin.clone(),
            continuation,
            10,
            3,
            &junction_policy::Limits::default(),
        )
        .unwrap();
        assert!(result.is_none());
        let next = next.unwrap();
        a.begin_page(&next).unwrap();
        let (_, result) = a.accept(&json!({"value":[4],"nextLink":null})).unwrap();
        assert_eq!(result.unwrap().items, vec![json!(3), json!(4)]);
        assert!(a.begin_page(&origin).is_err());
    }
    #[test]
    fn relative_links_resolve_from_current_page_and_resume_rejects_other_requests() {
        let origin = Url::parse("https://graph.example/v1.0/users").unwrap();
        let mut a = accumulator(10, 2);
        a.begin_page(&origin).unwrap();
        let (next, _) = a
            .accept(&json!({"value":[],"nextLink":"/v1.0/nested/items?page=2"}))
            .unwrap();
        a.begin_page(&next.unwrap()).unwrap();
        let (_, result) = a.accept(&json!({"value":[],"nextLink":"?page=3"})).unwrap();
        let continuation = result.unwrap().continuation.unwrap();
        assert_eq!(
            continuation.next.as_ref().unwrap().path(),
            "/v1.0/nested/items"
        );
        assert!(
            PageAccumulator::resume(
                Url::parse("https://graph.example/v1.0/groups").unwrap(),
                continuation,
                10,
                2,
                &junction_policy::Limits::default()
            )
            .is_err()
        );
    }
    #[test]
    fn resume_history_is_required_and_total_requests_stay_bounded() {
        let mut pages = accumulator(1, 2);
        let origin = pages.origin.clone();
        pages.begin_page(&origin).unwrap();
        let (_, result) = pages
            .accept(&json!({"value":[1,2],"nextLink":"?page=2"}))
            .unwrap();
        let mut continuation = result.unwrap().continuation.unwrap();
        continuation.visited.clear();
        assert!(
            PageAccumulator::resume(
                origin.clone(),
                continuation,
                1,
                2,
                &junction_policy::Limits::default()
            )
            .is_err()
        );
        let mut pages = accumulator(1, 2);
        pages.visited = (0..10000)
            .map(|page| format!("{origin}?page={page}"))
            .collect();
        assert_eq!(
            pages.begin_page(&origin).err().unwrap().to_string(),
            "pagination continuation request limit reached"
        );
        assert_eq!(pages.pages, 0);
    }
    #[test]
    fn private_checkpoint_roundtrip_preserves_records_and_rejects_unsafe_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("continuation.json");
        let origin = Url::parse("https://graph.example/v1.0/users").unwrap();
        let mut a = accumulator(1, 2);
        a.begin_page(&origin).unwrap();
        let (_, result) = a
            .accept(&json!({"value":[1,2,3],"nextLink":"?page=2"}))
            .unwrap();
        let continuation = result.unwrap().continuation.unwrap();
        continuation.save(&path).unwrap();
        assert!(continuation.save(&path).is_err());
        let restored = Continuation::load(&path).unwrap();
        assert_eq!(restored.buffered_items(), 2);
        assert_eq!(restored.next, continuation.next);
        let mut stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        stored["next"] = json!("https://evil.example/steal");
        std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        assert!(Continuation::load(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Continuation::load(&path).is_err());
        }
    }
    #[test]
    fn unsafe_links_cycles_and_page_limits_fail() {
        let mut a = accumulator(100, 2);
        let first = Url::parse("https://graph.example/v1.0/users").unwrap();
        a.begin_page(&first).unwrap();
        assert!(
            a.accept(&json!({"value":[],"nextLink":"https://evil.example/steal"}))
                .is_err()
        );
        assert!(a.begin_page(&first).is_err());
        let (next, result) = a
            .accept(&json!({"value":[1],"nextLink":"https://graph.example/v1.0/users?page=2"}))
            .unwrap();
        assert!(result.is_none());
        a.begin_page(&next.unwrap()).unwrap();
        let (_, result) = a
            .accept(&json!({"value":[2],"nextLink":"https://graph.example/v1.0/users?page=3"}))
            .unwrap();
        assert!(result.unwrap().continuation.is_some());
        assert!(
            a.begin_page(&Url::parse("https://graph.example/v1.0/users?page=3").unwrap())
                .is_err()
        );
    }
}
