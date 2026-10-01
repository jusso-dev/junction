//! Bounded batch dependency planning. Inputs are not Debug to avoid logging sensitive data.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchOperation {
    pub id: String,
    pub operation: String,
    #[serde(default = "empty_input")]
    pub input: Value,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub api_version: Option<String>,
    #[serde(default)]
    pub allow_preview: bool,
}
fn empty_input() -> Value {
    serde_json::json!({})
}
#[derive(Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BatchRequest {
    pub operations: Vec<BatchOperation>,
    pub max_parallel: usize,
    pub timeout_seconds: u64,
    pub fail_fast: bool,
}
impl Default for BatchRequest {
    fn default() -> Self {
        Self {
            operations: vec![],
            max_parallel: 5,
            timeout_seconds: 300,
            fail_fast: true,
        }
    }
}
pub struct BatchPlan {
    pub request: BatchRequest,
    /// Operation indices grouped by dependency depth, ordered by submitted position.
    pub waves: Vec<Vec<usize>>,
}
impl BatchPlan {
    pub fn build(request: BatchRequest, limits: &junction_policy::Limits) -> Result<Self> {
        if request.operations.is_empty()
            || request.operations.len() > limits.max_batch_operations
            || request.max_parallel == 0
            || request.max_parallel > limits.max_parallel_requests
            || request.timeout_seconds == 0
            || request.timeout_seconds > 3600
        {
            bail!("batch limits exceed policy");
        }
        if serde_json::to_vec(&request)?.len() > 16 * 1024 * 1024 {
            bail!("batch input size limit exceeded");
        }
        let mut ids = BTreeMap::new();
        for (index, operation) in request.operations.iter().enumerate() {
            if operation.id.is_empty()
                || operation.id.len() > 80
                || !operation
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
                || operation.operation.is_empty()
                || !operation.input.is_object()
                || ids.insert(operation.id.as_str(), index).is_some()
            {
                bail!("invalid batch operation");
            }
        }
        let mut dependencies = Vec::new();
        for operation in &request.operations {
            let mut required: BTreeSet<_> =
                operation.depends_on.iter().map(String::as_str).collect();
            references(&operation.input, &mut required, 0)?;
            if required.contains(operation.id.as_str())
                || required.iter().any(|id| !ids.contains_key(id))
            {
                bail!("invalid batch dependency");
            }
            dependencies.push(required);
        }
        let mut completed = BTreeSet::new();
        let mut waves = Vec::new();
        while completed.len() < request.operations.len() {
            let wave: Vec<_> = request
                .operations
                .iter()
                .enumerate()
                .filter(|(_, operation)| !completed.contains(operation.id.as_str()))
                .filter(|(index, _)| dependencies[*index].is_subset(&completed))
                .map(|(index, _)| index)
                .collect();
            if wave.is_empty() {
                bail!("batch dependency cycle");
            }
            for index in &wave {
                completed.insert(request.operations[*index].id.as_str());
            }
            waves.push(wave);
        }
        Ok(Self { request, waves })
    }
    pub(crate) fn has_references(&self, index: usize) -> bool {
        let mut ids = BTreeSet::new();
        references(&self.request.operations[index].input, &mut ids, 0).is_err() || !ids.is_empty()
    }
    /// Resolve {$result: "id", pointer: "/body/value/0/id"} from successful prior results.
    /// Replacement values are copied as data, never recursively interpreted as new references.
    pub fn resolve_input(&self, index: usize, results: &BTreeMap<String, Value>) -> Result<Value> {
        let operation = self
            .request
            .operations
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("unknown batch index"))?;
        substitute(&operation.input, results, 0)
    }
}
fn reference(value: &Value) -> Result<Option<(&str, &str)>> {
    let Some(object) = value
        .as_object()
        .filter(|object| object.contains_key("$result"))
    else {
        return Ok(None);
    };
    if object
        .keys()
        .any(|key| !["$result", "pointer"].contains(&key.as_str()))
    {
        bail!("invalid batch result reference");
    }
    let id = object
        .get("$result")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("invalid batch result reference"))?;
    let pointer = match object.get("pointer") {
        None => "",
        Some(Value::String(pointer)) => pointer.as_str(),
        _ => bail!("invalid batch result pointer"),
    };
    if !pointer.is_empty() && !pointer.starts_with('/') {
        bail!("invalid batch result pointer");
    }
    // Reject malformed JSON Pointer escapes before scheduling any work.
    let bytes = pointer.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'~'
            && !bytes
                .get(index + 1)
                .is_some_and(|next| b"01".contains(next))
        {
            bail!("invalid batch result pointer");
        }
    }
    Ok(Some((id, pointer)))
}
fn references<'a>(value: &'a Value, ids: &mut BTreeSet<&'a str>, depth: usize) -> Result<()> {
    if depth > 128 {
        bail!("batch input depth limit exceeded");
    }
    if let Some((id, _)) = reference(value)? {
        ids.insert(id);
        return Ok(());
    }
    match value {
        Value::Object(object) => {
            for child in object.values() {
                references(child, ids, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                references(child, ids, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn substitute(value: &Value, results: &BTreeMap<String, Value>, depth: usize) -> Result<Value> {
    if depth > 128 {
        bail!("batch input depth limit exceeded");
    }
    if let Some((id, pointer)) = reference(value)? {
        return results
            .get(id)
            .and_then(|result| result.pointer(pointer))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("batch result reference unavailable"));
    }
    Ok(match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, child)| Ok((key.clone(), substitute(child, results, depth + 1)?)))
                .collect::<Result<_>>()?,
        ),
        Value::Array(array) => Value::Array(
            array
                .iter()
                .map(|child| substitute(child, results, depth + 1))
                .collect::<Result<_>>()?,
        ),
        scalar => scalar.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn plan(value: Value) -> Result<BatchPlan> {
        BatchPlan::build(
            serde_json::from_value(value)?,
            &junction_policy::Limits::default(),
        )
    }
    #[test]
    fn dependencies_include_result_references_and_preserve_submission_order() {
        let plan = plan(json!({"operations":[
            {"id":"child","operation":"graph.users.get","input":{"parameters":{"id":{"$result":"parent","pointer":"/body/id"}}}},
            {"id":"parent","operation":"graph.users.list"},
            {"id":"independent","operation":"graph.groups.list"}
        ]})).unwrap();
        assert_eq!(plan.waves, vec![vec![1, 2], vec![0]]);
        let results = BTreeMap::from([(
            "parent".into(),
            json!({"body":{"id":{"$result":"do_not_execute"}}}),
        )]);
        assert_eq!(
            plan.resolve_input(0, &results).unwrap(),
            json!({"parameters":{"id":{"$result":"do_not_execute"}}})
        );
        assert!(plan.resolve_input(0, &BTreeMap::new()).is_err());
    }
    #[test]
    fn rejects_cycles_unknown_ids_duplicates_limits_and_malformed_references() {
        for value in [
            json!({"operations":[]}),
            json!({"max_parallel":11,"operations":[{"id":"a","operation":"x"}]}),
            json!({"timeout_seconds":3601,"operations":[{"id":"a","operation":"x"}]}),
            json!({"operations":[{"id":"a","operation":"x","depends_on":["b"]}]}),
            json!({"operations":[{"id":"a","operation":"x"},{"id":"a","operation":"x"}]}),
            json!({"operations":[{"id":"a","operation":"x","depends_on":["b"]},{"id":"b","operation":"x","depends_on":["a"]}]}),
            json!({"operations":[{"id":"a","operation":"x","input":{"body":{"$result":"a"}}}]}),
            json!({"operations":[{"id":"a","operation":"x","input":{"body":{"$result":"b","pointer":"/~2"}}},{"id":"b","operation":"x"}]}),
        ] {
            assert!(plan(value).is_err());
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BatchOutcome {
    Succeeded { result: Value },
    Failed { error: Value },
    Skipped { reason: &'static str },
    TimedOut,
}
#[derive(Serialize)]
pub struct BatchResult {
    /// Results follow submission order, independent of completion order.
    pub operations: Vec<BatchEntry>,
}
#[derive(Serialize)]
pub struct BatchEntry {
    pub id: String,
    #[serde(flatten)]
    pub outcome: BatchOutcome,
}

pub(crate) async fn run<'a, F, Fut>(plan: &'a BatchPlan, execute: F) -> BatchResult
where
    F: Fn(&'a BatchOperation, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    use futures_util::{StreamExt, stream::FuturesUnordered};
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(plan.request.timeout_seconds);
    let mut outcomes: Vec<Option<BatchOutcome>> =
        (0..plan.request.operations.len()).map(|_| None).collect();
    let mut results = BTreeMap::new();
    let mut stop = false;
    let mut timed_out = false;
    let mut result_bytes = 0usize;
    let mut started = BTreeSet::new();
    for wave in &plan.waves {
        let mut waiting = wave.iter().copied();
        let mut running = FuturesUnordered::new();
        loop {
            while !stop && !timed_out && running.len() < plan.request.max_parallel {
                if tokio::time::Instant::now() >= deadline {
                    timed_out = true;
                    break;
                }
                let Some(index) = waiting.next() else {
                    break;
                };
                let operation = &plan.request.operations[index];
                let mut required = BTreeSet::new();
                let _ = references(&operation.input, &mut required, 0);
                required.extend(operation.depends_on.iter().map(String::as_str));
                if required.iter().any(|id| !results.contains_key(*id)) {
                    outcomes[index] = Some(BatchOutcome::Skipped {
                        reason: "dependency_failed",
                    });
                    continue;
                }
                match plan.resolve_input(index, &results) {
                    Ok(input) => {
                        started.insert(index);
                        let future = execute(operation, input);
                        running.push(async move { (index, future.await) });
                    }
                    Err(_) => {
                        outcomes[index] = Some(BatchOutcome::Failed {
                            error: serde_json::json!({"code":"result_reference_unavailable"}),
                        });
                        stop = plan.request.fail_fast;
                    }
                }
            }
            if running.is_empty() {
                break;
            }
            match tokio::time::timeout_at(deadline, running.next()).await {
                Ok(Some((index, result))) => match result {
                    Ok(result) => {
                        let bytes = serde_json::to_vec(&result)
                            .map(|bytes| bytes.len())
                            .unwrap_or(usize::MAX);
                        if bytes > 64 * 1024 * 1024 - result_bytes {
                            outcomes[index] = Some(BatchOutcome::Failed {
                                error: serde_json::json!({"code":"batch_result_limit"}),
                            });
                            stop |= plan.request.fail_fast;
                        } else {
                            result_bytes += bytes;
                            results
                                .insert(plan.request.operations[index].id.clone(), result.clone());
                            outcomes[index] = Some(BatchOutcome::Succeeded { result });
                        }
                    }
                    Err(error) => {
                        let safe = error
                            .downcast_ref::<crate::ExecutionDenied>()
                            .map(|denial| {
                                serde_json::to_value(&denial.0).expect("policy decisions serialize")
                            })
                            .or_else(|| {
                                error
                                    .downcast_ref::<crate::authorization::AuthorizationFailure>()
                                    .map(|failure| {
                                        serde_json::to_value(failure)
                                            .expect("authorization failures serialize")
                                    })
                            })
                            .unwrap_or_else(|| serde_json::json!({"code":"execution_failed"}));
                        outcomes[index] = Some(BatchOutcome::Failed { error: safe });
                        stop |= plan.request.fail_fast;
                    }
                },
                Err(_) => {
                    timed_out = true;
                    break;
                }
                Ok(None) => break,
            }
        }
        if timed_out {
            break;
        }
    }
    BatchResult {
        operations: outcomes
            .into_iter()
            .enumerate()
            .map(|(index, outcome)| BatchEntry {
                id: plan.request.operations[index].id.clone(),
                outcome: outcome.unwrap_or(if timed_out && started.contains(&index) {
                    BatchOutcome::TimedOut
                } else if timed_out {
                    BatchOutcome::Skipped {
                        reason: "batch_timeout",
                    }
                } else {
                    BatchOutcome::Skipped {
                        reason: "fail_fast",
                    }
                }),
            })
            .collect(),
    }
}

#[cfg(test)]
mod execution_tests {
    use super::*;
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    fn plan(fail_fast: bool, parallel: usize) -> BatchPlan {
        BatchPlan::build(serde_json::from_value(json!({"fail_fast":fail_fast,"max_parallel":parallel,"operations":[
            {"id":"a","operation":"test"}, {"id":"b","operation":"test"},
            {"id":"child","operation":"test","input":{"body":{"$result":"a","pointer":"/id"}}},
            {"id":"c","operation":"test"}
        ]})).unwrap(), &junction_policy::Limits::default()).unwrap()
    }
    #[tokio::test]
    async fn concurrency_is_bounded_results_are_ordered_and_references_resolve() {
        let plan = plan(false, 2);
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let result = run(&plan, |operation, input| {
            let active = active.clone();
            let peak = peak.clone();
            async move {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(if operation.id == "a" {
                    20
                } else {
                    1
                }))
                .await;
                active.fetch_sub(1, Ordering::SeqCst);
                if operation.id == "child" {
                    assert_eq!(input["body"], "a");
                }
                Ok(json!({"id":operation.id}))
            }
        })
        .await;
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_eq!(
            result
                .operations
                .iter()
                .map(|entry| entry.id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b", "child", "c"]
        );
        assert!(
            result
                .operations
                .iter()
                .all(|entry| matches!(entry.outcome, BatchOutcome::Succeeded { .. }))
        );
    }
    #[tokio::test]
    async fn failure_modes_skip_dependents_and_do_not_expose_error_secrets() {
        for fail_fast in [true, false] {
            let plan = plan(fail_fast, 1);
            let result = run(&plan, |operation, _| async move {
                if operation.id == "a" {
                    bail!("secret-token-in-error");
                }
                Ok(json!({}))
            })
            .await;
            let json = serde_json::to_value(result).unwrap();
            assert_eq!(json["operations"][0]["status"], "failed");
            assert_eq!(json["operations"][2]["status"], "skipped");
            assert_eq!(
                json["operations"][1]["status"],
                if fail_fast { "skipped" } else { "succeeded" }
            );
            assert!(!json.to_string().contains("secret-token"));
        }
    }
    #[tokio::test]
    async fn deadline_distinguishes_started_work_from_unsubmitted_work() {
        let mut plan = plan(false, 1);
        plan.request.timeout_seconds = 1;
        let result = run(&plan, |_, _| async {
            std::future::pending::<Result<Value>>().await
        })
        .await;
        assert!(matches!(
            result.operations[0].outcome,
            BatchOutcome::TimedOut
        ));
        assert!(matches!(
            result.operations[1].outcome,
            BatchOutcome::Skipped {
                reason: "batch_timeout"
            }
        ));
    }
}
