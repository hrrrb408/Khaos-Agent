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
        "read_file" => dispatch_read_file(&call.payload).await,
        "write_file" => dispatch_write_file(&call.payload).await,
        "exec" => dispatch_exec(&call.payload).await,
        other => Err(ExecutorError::UnknownKind(other.to_string())),
    }
}

/// `read_file` payload: `{"path": "...", "offset": 1, "limit": 100}`.
///
/// `offset`/`limit` are 1-based line numbers; omitted means read the whole
/// file. Returns the file content (possibly truncated to `limit` lines).
async fn dispatch_read_file(payload: &str) -> Result<String, ExecutorError> {
    #[derive(serde::Deserialize)]
    struct ReadFileParams {
        path: String,
        #[serde(default)]
        offset: Option<usize>,
        #[serde(default)]
        limit: Option<usize>,
    }
    let params: ReadFileParams = serde_json::from_str(payload)
        .map_err(|e| ExecutorError::InvalidPayload(format!("read_file: {e}")))?;
    let bytes = tokio::fs::read(&params.path)
        .await
        .map_err(|e| ExecutorError::InvalidPayload(format!("read {}: {}", params.path, e)))?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let offset = params.offset.unwrap_or(1).saturating_sub(1);
    if offset == 0 && params.limit.is_none() {
        return Ok(text);
    }
    let lines: Vec<&str> = text.lines().collect();
    let start = offset.min(lines.len());
    let take = params.limit.unwrap_or(usize::MAX);
    let end = (start + take).min(lines.len());
    Ok(lines[start..end].join("\n"))
}

/// `write_file` payload: `{"path": "...", "content": "..."}`.
///
/// Creates parent directories as needed and overwrites any existing file.
/// Returns a short confirmation.
async fn dispatch_write_file(payload: &str) -> Result<String, ExecutorError> {
    #[derive(serde::Deserialize)]
    struct WriteFileParams {
        path: String,
        content: String,
    }
    let params: WriteFileParams = serde_json::from_str(payload)
        .map_err(|e| ExecutorError::InvalidPayload(format!("write_file: {e}")))?;
    let path = std::path::Path::new(&params.path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ExecutorError::InvalidPayload(format!("mkdir {}: {}", parent.display(), e)))?;
        }
    }
    let bytes_written = params.content.len();
    tokio::fs::write(path, &params.content)
        .await
        .map_err(|e| ExecutorError::InvalidPayload(format!("write {}: {}", params.path, e)))?;
    Ok(format!("wrote {} bytes to {}", bytes_written, params.path))
}

/// `exec` payload: `{"command": "...", "args": [...], "timeout_ms": 5000,
/// "workdir": "..."}`.
///
/// Spawns the process, captures stdout/stderr, and enforces the timeout.
/// Returns a JSON object `{"stdout":..., "stderr":..., "exit_code":...}`.
async fn dispatch_exec(payload: &str) -> Result<String, ExecutorError> {
    #[derive(serde::Deserialize)]
    struct ExecParams {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
        #[serde(default)]
        workdir: Option<String>,
    }
    let params: ExecParams = serde_json::from_str(payload)
        .map_err(|e| ExecutorError::InvalidPayload(format!("exec: {e}")))?;

    let mut cmd = tokio::process::Command::new(&params.command);
    cmd.args(&params.args);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    if let Some(workdir) = &params.workdir {
        cmd.current_dir(workdir);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| ExecutorError::InvalidPayload(format!("spawn {}: {}", params.command, e)))?;

    // Take the piped handles so we can read them after the process exits.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let collect = async {
        // Wait for the process to finish (or be killed on timeout below).
        let status = child.wait().await;
        let stdout_bytes = match stdout {
            Some(mut s) => {
                use tokio::io::AsyncReadExt;
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await.ok();
                buf
            }
            None => Vec::new(),
        };
        let stderr_bytes = match stderr {
            Some(mut s) => {
                use tokio::io::AsyncReadExt;
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await.ok();
                buf
            }
            None => Vec::new(),
        };
        (status, stdout_bytes, stderr_bytes)
    };

    let (status, stdout_bytes, stderr_bytes) = if let Some(timeout_ms) = params.timeout_ms {
        match tokio::time::timeout(Duration::from_millis(timeout_ms), collect).await {
            Ok(tuple) => tuple,
            Err(_) => {
                // Timeout: best-effort kill, then report. We can't re-await the
                // moved `collect` future, so just surface the timeout.
                return Err(ExecutorError::InvalidPayload(format!(
                    "exec {}: timeout after {}ms",
                    params.command, timeout_ms
                )));
            }
        }
    } else {
        collect.await
    };

    // On timeout the future was dropped before `child.wait()` resolved; the
    // process is orphaned but tokio will reap it. If status is an error here it
    // is a real spawn/wait failure.
    let (status, exit_code) = match status {
        Ok(s) => (s, s.code().unwrap_or(-1)),
        Err(e) => {
            return Err(ExecutorError::InvalidPayload(format!(
                "exec {}: {}",
                params.command, e
            )))
        }
    };
    let _ = status; // status consumed for exit_code above

    let result = serde_json::json!({
        "stdout": String::from_utf8_lossy(&stdout_bytes).into_owned(),
        "stderr": String::from_utf8_lossy(&stderr_bytes).into_owned(),
        "exit_code": exit_code,
    });
    Ok(result.to_string())
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
        // enable_all turns on time + fs + process + io drivers, so file/exec
        // handler tests share the same helper.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
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

    // --- file_ops handler -------------------------------------------------

    #[test]
    fn read_file_returns_contents() {
        let rt = runtime();
        let dir = tempdir();
        let path = dir.join("hello.txt");
        std::fs::write(&path, "line1\nline2\nline3").unwrap();
        let payload = serde_json::json!({"path": path}).to_string();

        let results = rt.block_on(run_parallel(vec![call("1", "read_file", &payload)], 2000));

        assert!(results[0].success);
        assert_eq!(results[0].output, "line1\nline2\nline3");
    }

    #[test]
    fn read_file_respects_offset_and_limit() {
        let rt = runtime();
        let dir = tempdir();
        let path = dir.join("lines.txt");
        std::fs::write(&path, "a\nb\nc\nd\ne").unwrap();
        let payload =
            serde_json::json!({"path": path, "offset": 2, "limit": 2}).to_string();

        let results = rt.block_on(run_parallel(vec![call("1", "read_file", &payload)], 2000));

        assert!(results[0].success);
        assert_eq!(results[0].output, "b\nc");
    }

    #[test]
    fn read_file_missing_path_reports_error() {
        let rt = runtime();
        let payload = serde_json::json!({"path": "/no/such/path/xyz"}).to_string();

        let results = rt.block_on(run_parallel(vec![call("1", "read_file", &payload)], 2000));

        assert!(!results[0].success);
        assert!(results[0].error.contains("read"));
    }

    #[test]
    fn write_file_creates_file_and_parents() {
        let rt = runtime();
        let dir = tempdir();
        let path = dir.join("sub").join("dir").join("out.txt");
        let payload = serde_json::json!({"path": path, "content": "hi there"}).to_string();

        let results = rt.block_on(run_parallel(vec![call("1", "write_file", &payload)], 2000));

        assert!(results[0].success);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hi there");
    }

    // --- exec handler -----------------------------------------------------

    #[test]
    fn exec_runs_command_and_captures_stdout() {
        let rt = runtime();
        // `echo` exists on every Unix and Windows-POSIX test image we target.
        let payload = serde_json::json!({"command": "echo", "args": ["khaos"]}).to_string();

        let results = rt.block_on(run_parallel(vec![call("1", "exec", &payload)], 5000));

        assert!(results[0].success);
        let parsed: serde_json::Value = serde_json::from_str(&results[0].output).unwrap();
        assert_eq!(parsed["stdout"].as_str().unwrap().trim(), "khaos");
        assert_eq!(parsed["exit_code"].as_i64().unwrap(), 0);
    }

    #[test]
    fn exec_timeout_reports_error() {
        let rt = runtime();
        // `sleep 5` will outlive the 100ms budget.
        let payload =
            serde_json::json!({"command": "sleep", "args": ["5"], "timeout_ms": 100}).to_string();

        let results = rt.block_on(run_parallel(vec![call("1", "exec", &payload)], 1000));

        assert!(!results[0].success);
        assert!(results[0].error.contains("timeout"));
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "khaos-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
