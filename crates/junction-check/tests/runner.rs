use junction_check::check::{ApiRequirement, Check, CheckMeta, Evaluation, Finding, Requirements};
use junction_check::context::CheckContext;
use junction_check::gateway::{BoxFut, Gateway};
use junction_check::model::{CheckKind, Level, Pack, Severity, Status, TenantStatus};
use junction_check::registry::CheckRegistry;
use junction_check::runner::{RunOptions, TenantPlan, run};
use junction_check::testkit::{FixtureEntry, FixtureGateway, TENANT};
use junction_watch::backoff::Backoff;
use junction_watch::clock::Instant;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const MDE: CheckMeta = CheckMeta {
    id: "endpoint.test_machines",
    title: "Machines are onboarded",
    pack: Pack::Endpoint,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Test check that lists Defender for Endpoint machines.",
    requires: Requirements {
        apis: &[ApiRequirement {
            operation: "defender.endpoint.machines.list",
            permissions: &["Machine.Read.All"],
        }],
        licences: &["defender_endpoint"],
    },
    remediation: "Onboard devices.",
    links: &[],
    references: &[],
    manual: None,
};

struct Machines;
impl Check for Machines {
    fn meta(&self) -> &'static CheckMeta {
        &MDE
    }
    fn evaluate<'a>(&'a self, ctx: &'a CheckContext) -> BoxFut<'a, Evaluation> {
        Box::pin(async move {
            let machines = ctx
                .list("defender.endpoint.machines.list", json!({}))
                .await?;
            Ok(Finding::pass_if(
                !machines.items.is_empty(),
                "Onboarded.",
                "No machines.",
            ))
        })
    }
}

/// Lists users with a distinct filter so calls are not memoised together.
struct Users(&'static CheckMeta, &'static str);
impl Check for Users {
    fn meta(&self) -> &'static CheckMeta {
        self.0
    }
    fn evaluate<'a>(&'a self, ctx: &'a CheckContext) -> BoxFut<'a, Evaluation> {
        Box::pin(async move {
            ctx.list_with("graph.users.list", json!({"$filter": self.1}))
                .await?;
            Ok(Finding::pass("Read users."))
        })
    }
}

const fn users_meta(id: &'static str) -> CheckMeta {
    CheckMeta {
        id,
        requires: Requirements {
            apis: &[ApiRequirement {
                operation: "graph.users.list",
                permissions: &["User.Read.All"],
            }],
            licences: &[],
        },
        pack: Pack::Identity,
        ..MDE
    }
}
const U1: CheckMeta = users_meta("identity.test_u1");
const U2: CheckMeta = users_meta("identity.test_u2");
const U3: CheckMeta = users_meta("identity.test_u3");
const U4: CheckMeta = users_meta("identity.test_u4");
const U5: CheckMeta = users_meta("identity.test_u5");

const TAGS: &str = "
endpoint.test_machines: {mitre: [T1562.001]}
identity.test_u1: {mitre: [T1078]}
identity.test_u2: {mitre: [T1078]}
identity.test_u3: {mitre: [T1078]}
identity.test_u4: {mitre: [T1078]}
identity.test_u5: {mitre: [T1078]}
";

fn registry() -> CheckRegistry {
    CheckRegistry::new(
        vec![
            Arc::new(Machines),
            Arc::new(Users(&U1, "a eq 1")),
            Arc::new(Users(&U2, "a eq 2")),
            Arc::new(Users(&U3, "a eq 3")),
            Arc::new(Users(&U4, "a eq 4")),
            Arc::new(Users(&U5, "a eq 5")),
        ],
        &[("test", TAGS)],
    )
    .unwrap()
}

fn skus(plans: &[&str]) -> Value {
    json!({"value": [{
        "skuPartNumber": "TEST_SKU",
        "capabilityStatus": "Enabled",
        "servicePlans": plans.iter().map(|p| json!({"servicePlanName": p, "provisioningStatus": "Success"})).collect::<Vec<_>>()
    }]})
}

fn options() -> RunOptions {
    RunOptions {
        backoff: Backoff::IMMEDIATE,
        now: Instant::parse("2026-10-25T00:00:00Z").unwrap(),
        run_id: Some("test-run".into()),
        ..RunOptions::default()
    }
}

fn plan(tenant: &str, gateway: FixtureGateway) -> TenantPlan {
    TenantPlan {
        tenant_id: tenant.into(),
        label: Some(format!("label {tenant}")),
        gateway: Ok(Arc::new(gateway) as Arc<dyn Gateway>),
        attestations: BTreeMap::new(),
    }
}

fn users_ok(g: FixtureGateway) -> FixtureGateway {
    g.with("graph.users.list", json!({"value": [{"id": "u"}]}))
}

#[tokio::test]
async fn three_tenants_auth_failure_missing_licence_and_healthy() {
    let auth_fails = FixtureGateway::new("tenant-a");
    auth_fails
        .push(
            serde_json::from_value::<FixtureEntry>(json!({
                "operation": "graph.subscribed_skus.list",
                "responses": [{"status": 401, "error": {"code": "InvalidAuthenticationToken",
                    "message": "Bearer eyJhbGciOiJSUzI1NiJ9.secret client_secret=hunter2"}}]
            }))
            .unwrap(),
        )
        .unwrap();
    let no_mde = users_ok(
        FixtureGateway::new("tenant-b").with("graph.subscribed_skus.list", skus(&["AAD_PREMIUM"])),
    );
    let healthy = users_ok(
        FixtureGateway::new("tenant-c")
            .with(
                "graph.subscribed_skus.list",
                skus(&["AAD_PREMIUM", "MDE_SMB"]),
            )
            .with(
                "defender.endpoint.machines.list",
                json!({"value": [{"id": "m1"}]}),
            ),
    );
    let report = run(
        &registry(),
        vec![
            plan("tenant-a", auth_fails),
            plan("tenant-b", no_mde),
            plan("tenant-c", healthy),
        ],
        &options(),
    )
    .await
    .unwrap();

    let [a, b, c] = &report.tenants[..] else {
        panic!("three tenants")
    };
    assert_eq!(a.status, TenantStatus::Failed);
    assert_eq!(a.error.as_ref().unwrap().code, "credential_rejected");
    assert!(a.results.is_empty());

    assert_eq!(b.status, TenantStatus::Complete);
    let mde = b
        .results
        .iter()
        .find(|r| r.id == "endpoint.test_machines")
        .unwrap();
    assert_eq!(mde.status, Status::NotApplicable);
    assert_eq!(mde.reason.as_ref().unwrap().code, "licence_required");

    assert_eq!(c.status, TenantStatus::Complete);
    assert!(c.results.iter().all(|r| r.status == Status::Pass));
    assert_eq!(c.score.score, Some(100.0));
    assert!(
        report.partial(),
        "a failed tenant makes the run partial (exit 3)"
    );

    let text = serde_json::to_string(&report).unwrap();
    for secret in ["eyJ", "hunter2", "client_secret"] {
        assert!(!text.contains(secret), "{secret} leaked into the report");
    }
    validate_schema(&serde_json::to_value(&report).unwrap());
}

#[tokio::test]
async fn unreadable_licences_still_attempt_every_check() {
    let gateway = users_ok(
        FixtureGateway::new(TENANT)
            .with_error(
                "graph.subscribed_skus.list",
                403,
                "Authorization_RequestDenied",
            )
            .with_error("defender.endpoint.machines.list", 403, "Forbidden"),
    );
    let report = run(&registry(), vec![plan(TENANT, gateway)], &options())
        .await
        .unwrap();
    let tenant = &report.tenants[0];
    assert!(tenant.licences.is_none());
    let mde = tenant
        .results
        .iter()
        .find(|r| r.id == "endpoint.test_machines")
        .unwrap();
    assert_eq!(mde.status, Status::Unknown);
    assert_eq!(
        mde.reason.as_ref().unwrap().missing_permissions,
        ["Machine.Read.All"]
    );
    assert_eq!(tenant.status, TenantStatus::Partial);
    validate_schema(&serde_json::to_value(&report).unwrap());
}

#[tokio::test]
async fn per_host_concurrency_limit_is_respected() {
    let gateway =
        users_ok(FixtureGateway::new(TENANT).with("graph.subscribed_skus.list", skus(&[])))
            .with("defender.endpoint.machines.list", json!({"value": []}))
            .with_delay(Duration::from_millis(30));
    let gateway = Arc::new(gateway);
    let report = run(
        &registry(),
        vec![TenantPlan {
            tenant_id: TENANT.into(),
            label: None,
            gateway: Ok(gateway.clone() as Arc<dyn Gateway>),
            attestations: BTreeMap::new(),
        }],
        &RunOptions {
            per_host: 2,
            check_concurrency: 8,
            ..options()
        },
    )
    .await
    .unwrap();
    assert_eq!(report.tenants[0].results.len(), 6);
    assert!(
        gateway.peak_concurrency() <= 2,
        "peak {}",
        gateway.peak_concurrency()
    );
    assert!(gateway.peak_concurrency() >= 2, "limit was not exercised");
}

#[tokio::test]
async fn tenants_run_in_parallel_up_to_the_bound() {
    let gateways: Vec<Arc<FixtureGateway>> = (0..4)
        .map(|_| {
            Arc::new(
                users_ok(FixtureGateway::new(TENANT).with("graph.subscribed_skus.list", skus(&[])))
                    .with_delay(Duration::from_millis(40)),
            )
        })
        .collect();
    let started = std::time::Instant::now();
    run(
        &registry(),
        gateways
            .iter()
            .map(|g| TenantPlan {
                tenant_id: TENANT.into(),
                label: None,
                gateway: Ok(g.clone() as Arc<dyn Gateway>),
                attestations: BTreeMap::new(),
            })
            .collect(),
        &RunOptions {
            parallel: 4,
            ..options()
        },
    )
    .await
    .unwrap();
    // Sequential would take at least 4 tenants x 2 rounds x 40ms.
    assert!(
        started.elapsed() < Duration::from_millis(320),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn invalid_selection_is_a_run_error() {
    let mut opts = options();
    opts.selection.checks = vec!["identity.does_not_exist".into()];
    assert!(run(&registry(), vec![], &opts).await.is_err());
    opts.selection.checks.clear();
    opts.selection.tags = vec!["bogus:1".into()];
    assert!(run(&registry(), vec![], &opts).await.is_err());
}

pub fn validate_schema(report: &Value) {
    let schema: Value =
        serde_json::from_str(include_str!("../../../docs/check-result.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(report)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "schema violations:\n{}",
        errors.join("\n")
    );
}
