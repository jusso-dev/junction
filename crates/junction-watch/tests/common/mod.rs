//! Scripted Microsoft API double. Routes match on API, method, path fragment and
//! optional query fragment; each route replays its responses in order and then
//! repeats the last one. Every call is recorded for assertions.
#![allow(dead_code)]
use junction_watch::upstream::{Api, CallError, FailureKind, Reply, Upstream};
use serde_json::Value;
use std::{collections::VecDeque, sync::Mutex};
use url::Url;

pub const TENANT: &str = "11111111-1111-4111-8111-111111111111";

pub struct Route {
    api: Api,
    method: &'static str,
    path: String,
    query: Option<String>,
    responses: VecDeque<Result<Reply, CallError>>,
}

#[derive(Default)]
pub struct Mock {
    routes: Mutex<Vec<Route>>,
    pub calls: Mutex<Vec<(Api, String, Url)>>,
    pub graph_roles: Vec<String>,
    pub mgmt_roles: Vec<String>,
}

pub fn ok(body: Value) -> Result<Reply, CallError> {
    Ok(Reply {
        status: 200,
        body,
        next_page: None,
    })
}
pub fn page(body: Value, next: &str) -> Result<Reply, CallError> {
    Ok(Reply {
        status: 200,
        body,
        next_page: Some(Url::parse(next).unwrap()),
    })
}
pub fn err(status: u16, code: &str) -> Result<Reply, CallError> {
    Err(CallError::http(
        status,
        (!code.is_empty()).then_some(code),
        None,
    ))
}
pub fn err_msg(status: u16, code: Option<&str>, message: &str) -> Result<Reply, CallError> {
    Err(CallError::http(status, code, Some(message)))
}
pub fn credential_failure() -> Result<Reply, CallError> {
    Err(CallError {
        kind: FailureKind::Credential,
        status: Some(401),
        code: Some("invalid_client".into()),
        message: Some("AADSTS7000222: The provided client secret keys are expired".into()),
        retry_after: None,
    })
}

impl Mock {
    pub fn new() -> Self {
        Self {
            mgmt_roles: vec!["ActivityFeed.Read".into()],
            graph_roles: vec![
                "AuditLog.Read.All".into(),
                "Organization.Read.All".into(),
                "SharePointTenantSettings.Read.All".into(),
            ],
            ..Default::default()
        }
    }
    pub fn route(
        &self,
        api: Api,
        method: &'static str,
        path: &str,
        query: Option<&str>,
        responses: Vec<Result<Reply, CallError>>,
    ) -> &Self {
        self.routes.lock().unwrap().push(Route {
            api,
            method,
            path: path.to_owned(),
            query: query.map(str::to_owned),
            responses: responses.into(),
        });
        self
    }
    pub fn calls_to(&self, fragment: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, _, u)| u.as_str().contains(fragment))
            .count()
    }
    pub fn total_calls(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
    fn answer(&self, api: Api, method: &str, url: Url) -> Result<Reply, CallError> {
        self.calls
            .lock()
            .unwrap()
            .push((api, method.to_owned(), url.clone()));
        let mut routes = self.routes.lock().unwrap();
        let query = url.query().unwrap_or_default().to_owned();
        let route = routes.iter_mut().find(|r| {
            r.api == api
                && r.method == method
                && url.path().contains(&r.path)
                && r.query.as_ref().is_none_or(|q| query.contains(q.as_str()))
        });
        match route {
            Some(r) if r.responses.len() > 1 => r.responses.pop_front().unwrap(),
            Some(r) => r.responses.front().cloned().unwrap_or_else(|| err(404, "")),
            None => err(404, "NoRoute"),
        }
    }
}

impl Upstream for Mock {
    fn base(&self, api: Api) -> Url {
        match api {
            Api::Graph => Url::parse("https://graph.microsoft.com").unwrap(),
            Api::ManagementActivity => Url::parse("https://manage.office.com").unwrap(),
        }
    }
    fn tenant_id(&self) -> &str {
        TENANT
    }
    async fn get(&self, api: Api, url: Url) -> Result<Reply, CallError> {
        self.answer(api, "GET", url)
    }
    async fn post(&self, api: Api, url: Url, _body: Option<Value>) -> Result<Reply, CallError> {
        self.answer(api, "POST", url)
    }
    async fn granted_roles(&self, api: Api) -> Result<Vec<String>, CallError> {
        Ok(match api {
            Api::Graph => self.graph_roles.clone(),
            Api::ManagementActivity => self.mgmt_roles.clone(),
        })
    }
}

pub fn blob_uri(id: &str) -> String {
    format!("https://manage.office.com/api/v1.0/{TENANT}/activity/feed/audit/{id}")
}

pub fn content(id: &str, created: &str) -> Value {
    serde_json::json!({
        "contentType": "Audit.Exchange",
        "contentId": id,
        "contentUri": blob_uri(id),
        "contentCreated": created,
        "contentExpiration": "2099-01-01T00:00:00.000Z"
    })
}

pub fn exchange_record(id: &str, at: &str, operation: &str) -> Value {
    serde_json::json!({
        "Id": id, "RecordType": 1, "CreationTime": at, "Operation": operation,
        "OrganizationId": TENANT, "UserType": 0, "UserKey": "10032000AAAA",
        "Workload": "Exchange", "ResultStatus": "True", "UserId": "secretary@club.example",
        "ClientIP": "198.51.100.7", "ObjectId": "secretary@club.example\\Rule",
        "Parameters": [{"Name": "ForwardTo", "Value": "outside@evil.example"}]
    })
}
