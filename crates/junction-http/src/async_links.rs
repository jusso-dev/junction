use url::Url;

/// Polling links can contain sensitive URL data. Intentionally no Debug/Serialize.
#[derive(Default)]
pub struct AsyncLinks {
    azure_async_operation: Option<Url>,
    operation_location: Option<Url>,
    location: Option<Url>,
    fabric_operation: Option<Url>,
}
impl AsyncLinks {
    pub fn azure_async_operation(&self) -> Option<&Url> {
        self.azure_async_operation.as_ref()
    }
    pub fn operation_location(&self) -> Option<&Url> {
        self.operation_location.as_ref()
    }
    pub fn location(&self) -> Option<&Url> {
        self.location.as_ref()
    }
    pub fn fabric_operation(&self) -> Option<&Url> {
        self.fabric_operation.as_ref()
    }
    /// Read links from a service response, retaining only same-origin HTTPS URLs.
    pub fn from_headers(headers: &reqwest::header::HeaderMap, original: &Url) -> Self {
        let read = |name| {
            let raw = headers.get(name)?.to_str().ok()?;
            if raw.len() > 16384 || raw.chars().any(char::is_control) {
                return None;
            }
            let endpoint = original.join(raw).ok()?;
            if endpoint.scheme() != "https"
                || endpoint.origin() != original.origin()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.fragment().is_some()
            {
                return None;
            }
            Some(endpoint)
        };
        Self {
            azure_async_operation: read("azure-asyncoperation"),
            operation_location: read("operation-location"),
            location: read("location"),
            fabric_operation: headers
                .get("x-ms-operation-id")
                .and_then(|value| value.to_str().ok())
                .filter(|id| {
                    id.len() == 36
                        && id.bytes().enumerate().all(|(index, byte)| {
                            if matches!(index, 8 | 13 | 18 | 23) {
                                byte == b'-'
                            } else {
                                byte.is_ascii_hexdigit()
                            }
                        })
                })
                .filter(|_| {
                    original.scheme() == "https"
                        && original.username().is_empty()
                        && original.password().is_none()
                        && original.fragment().is_none()
                        && original.path().starts_with("/v1/")
                })
                .and_then(|id| original.join(&format!("/v1/operations/{id}")).ok()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fabric_operation_ids_construct_only_bounded_same_origin_paths() {
        let original =
            Url::parse("https://api.fabric.microsoft.com/v1/workspaces/a/items?private=value")
                .unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-ms-operation-id",
            "b80e135a-adca-42e7-aaf0-59849af2ed78".parse().unwrap(),
        );
        let links = AsyncLinks::from_headers(&headers, &original);
        assert_eq!(
            links.fabric_operation().unwrap().as_str(),
            "https://api.fabric.microsoft.com/v1/operations/b80e135a-adca-42e7-aaf0-59849af2ed78"
        );
        for invalid in [
            "../private",
            "a?token=private",
            "b80e135a-adca-42e7-aaf0-59849af2ed7z",
            "b80e135aadca42e7aaf059849af2ed78",
        ] {
            headers.insert("x-ms-operation-id", invalid.parse().unwrap());
            assert!(
                AsyncLinks::from_headers(&headers, &original)
                    .fabric_operation()
                    .is_none()
            );
        }
        headers.insert(
            "x-ms-operation-id",
            "b80e135a-adca-42e7-aaf0-59849af2ed78".parse().unwrap(),
        );
        for invalid in [
            "http://example.invalid/v1/items",
            "https://example.invalid/v2/items",
            "https://user:secret@example.invalid/v1/items",
            "https://example.invalid/v1/items#secret",
        ] {
            assert!(
                AsyncLinks::from_headers(&headers, &Url::parse(invalid).unwrap())
                    .fabric_operation()
                    .is_none()
            );
        }
    }
    #[test]
    fn polling_links_resolve_relative_paths_and_cannot_cross_credential_origins() {
        let original =
            Url::parse("https://management.example.com/resources/vm?api-version=1").unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "azure-asyncoperation",
            "/operations/job?api-version=1".parse().unwrap(),
        );
        headers.insert("operation-location", "../jobs/job".parse().unwrap());
        headers.insert(
            "location",
            "https://other.example.com/private".parse().unwrap(),
        );
        let links = AsyncLinks::from_headers(&headers, &original);
        assert_eq!(
            links.azure_async_operation().unwrap().path(),
            "/operations/job"
        );
        assert_eq!(links.operation_location().unwrap().path(), "/jobs/job");
        assert!(links.location().is_none());
        for bad in [
            "http://management.example.com/job",
            "https://user:private@management.example.com/job",
            "https://management.example.com/job#private",
            "//other.example.com/job",
        ] {
            headers.insert("location", bad.parse().unwrap());
            assert!(
                AsyncLinks::from_headers(&headers, &original)
                    .location()
                    .is_none()
            );
        }
    }
}
