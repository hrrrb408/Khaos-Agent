//! Parallel tool execution with timeout control.
//!
//! A self-contained concurrent execution framework. Each task carries a `kind`
//! that selects a built-in pure-Rust handler; the executor runs all tasks
//! concurrently on a tokio runtime, applies a per-task timeout, and returns one
//! result per input (failures never abort sibling tasks). This is intentionally
//! decoupled from Python tool implementations to avoid cross-language GIL
//! deadlocks: Python uses this for the parallelizable, serializable subset of
//! work (e.g. batch token counts, synthetic benchmarks, future pure-compute
//! tools), while real I/O tools keep running on Python's asyncio loop.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::error::Elapsed;

/// One unit of parallel work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    /// Handler selector. Built-ins: `"echo"`, `"sleep"`, `"fail"`, `"sum"`.
    pub kind: String,
    /// Handler-specific payload as a JSON string.
    pub payload: String,
}

/// The outcome of one tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolResult {
    pub call_id: String,
    pub success: bool,
    pub output: String,
    pub error: String,
    pub duration_ms: u64,
}

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("unknown handler kind: {0}")]
    UnknownKind(String),
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
}

/// Run a batch of calls concurrently, each with `timeout_ms` budget.
///
/// Returns one result per call, in input order. A timeout or handler error
/// produces a `success=false` result but never panics or aborts siblings.
/// An empty input returns an empty vec immediately.
pub async fn run_parallel(calls: Vec<ToolCall>, timeout_ms: u64) -> Vec<ToolResult> {
    if calls.is_empty() {
        return Vec::new();
    }
    let timeout = Duration::from_millis(timeout_ms);
    let mut handles = Vec::with_capacity(calls.len());
    for call in calls {
        handles.push(tokio::spawn(run_one(call, timeout)));
    }
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(join_err) => results.push(ToolResult {
                call_id: String::new(),
                success: false,
                output: String::new(),
                error: format!("task join error: {join_err}"),
                duration_ms: 0,
            }),
        }
    }
    results
}

/// Execute a single call with timeout. Public so it can be reused serially.
pub async fn run_one(call: ToolCall, timeout: Duration) -> ToolResult {
    let start = std::time::Instant::now();
    let work = dispatch(&call);
    match tokio::time::timeout(timeout, work).await {
        Ok(Ok(output)) => ToolResult {
            call_id: call.id,
            success: true,
            output,
            error: String::new(),
            duration_ms: start.elapsed().as_millis() as u64,
        },
        Ok(Err(err)) => ToolResult {
            call_id: call.id,
            success: false,
            output: String::new(),
            error: err.to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
        },
        Err(Elapsed { .. }) => ToolResult {
            call_id: call.id,
            success: false,
            output: String::new(),
            error: format!("timeout after {}ms", timeout.as_millis()),
            duration_ms: timeout.as_millis() as u64,
        },
    }
}

async fn dispatch(call: &ToolCall) -> Result<String, ExecutorError> {
    match call.kind.as_str() {
        "echo" => Ok(call.payload.clone()),
        "sleep" => {
            // payload is milliseconds to sleep; returns the slept duration.
            let ms: u64 = call
                .payload
                .parse()
                .map_err(|e| ExecutorError::InvalidPayload(format!("sleep ms: {e}")))?;
            tokio::time::sleep(Duration::from_millis(ms)).await;
            Ok(format!("slept {ms}ms"))
        }
        "fail" => Err(ExecutorError::InvalidPayload(call.payload.clone())),
        "sum" => {
            // payload is a JSON array of numbers; returns their sum.
            let nums: Vec<f64> = serde_json::from_str(&call.payload)
                .map_err(|e| ExecutorError::InvalidPayload(format!("sum array: {e}")))?;
            Ok(format!("{}", nums.iter().sum::<f64>()))
        }
        other => Err(ExecutorError::UnknownKind(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(id: &str, kind: &str, payload: &str) -> ToolCall {
        ToolCall {
            id: id.to_string(),
            kind: kind.to_string(),
            payload: payload.to_string(),
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }

    #[test]
    fn empty_input_returns_empty() {
        let rt = runtime();
        let results = rt.block_on(run_parallel(Vec::new(), 100));
        assert!(results.is_empty());
    }

    #[test]
    fn echo_returns_payload() {
        let rt = runtime();
        let results = rt.block_on(run_parallel(vec![call("1", "echo", "hi")], 500));
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(results[0].output, "hi");
        assert_eq!(results[0].call_id, "1");
    }

    #[test]
    fn parallel_tasks_run_concurrently() {
        // Two 200ms sleeps run in parallel finish well under 400ms total budget,
        // but each within its 500ms timeout.
        let rt = runtime();
        let start = std::time::Instant::now();
        let results = rt.block_on(run_parallel(
            vec![call("a", "sleep", "200"), call("b", "sleep", "200")],
            500,
        ));
        let elapsed = start.elapsed();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.success));
        // Concurrent: total < 350ms (sequential would be >= 400ms).
        assert!(elapsed.as_millis() < 350, "took {}ms", elapsed.as_millis());
    }

    #[test]
    fn timeout_produces_error_result() {
        let rt = runtime();
        let results = rt.block_on(run_parallel(vec![call("1", "sleep", "1000")], 100));
        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert!(results[0].error.contains("timeout"));
    }

    #[test]
    fn failing_task_does_not_abort_siblings() {
        let rt = runtime();
        let results = rt.block_on(run_parallel(
            vec![call("1", "fail", "boom"), call("2", "echo", "ok")],
            500,
        ));
        assert_eq!(results.len(), 2);
        assert!(!results[0].success);
        assert!(results[0].error.contains("boom"));
        assert!(results[1].success);
        assert_eq!(results[1].output, "ok");
    }

    #[test]
    fn sum_handler_aggregates_numbers() {
        let rt = runtime();
        let results = rt.block_on(run_parallel(
            vec![call("1", "sum", "[1.5, 2.5, 3.0]")],
            500,
        ));
        assert!(results[0].success);
        assert_eq!(results[0].output, "7");
    }

    #[test]
    fn unknown_kind_reports_error() {
        let rt = runtime();
        let results = rt.block_on(run_parallel(vec![call("1", "bogus", "")], 500));
        assert!(!results[0].success);
        assert!(results[0].error.contains("unknown handler kind"));
    }

    #[test]
    fn results_preserve_input_order() {
        let rt = runtime();
        let results = rt.block_on(run_parallel(
            vec![
                call("third", "echo", "c"),
                call("first", "echo", "a"),
                call("second", "echo", "b"),
            ],
            500,
        ));
        assert_eq!(
            results.iter().map(|r| r.call_id.as_str()).collect::<Vec<_>>(),
            vec!["third", "first", "second"]
        );
    }
}
