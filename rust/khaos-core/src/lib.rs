//! Khaos performance core.
//!
//! Two modules: [`token`] for approximate BPE token counting, and [`executor`]
//! for bounded parallel task execution. Both are usable from pure Rust; when
//! the `pyo3` feature is enabled they are additionally exposed as a Python
//! extension module named `_khaos_core` (leading underscore avoids clashing
//! with a plain `import`).

pub mod executor;
pub mod token;

pub use executor::{run_parallel, run_one, ToolCall, ToolResult};
pub use token::{count_tokens, count_tokens_batch};

#[cfg(feature = "pyo3")]
#[allow(clippy::useless_conversion)]
mod py {
    use super::{count_tokens, count_tokens_batch, executor::ToolCall};
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    /// `_khaos_core.count_tokens(text: str, encoding: str = "cl100k_base") -> int`
    #[pyfunction]
    #[pyo3(signature = (text, encoding = "cl100k_base"))]
    #[pyo3(name = "count_tokens")]
    fn count_tokens_py(text: &str, encoding: &str) -> usize {
        count_tokens(text, encoding)
    }

    /// `_khaos_core.count_tokens_batch(texts: list[str], encoding: str = "cl100k_base") -> list[int]`
    #[pyfunction]
    #[pyo3(signature = (texts, encoding = "cl100k_base"))]
    #[pyo3(name = "count_tokens_batch")]
    fn count_tokens_batch_py(texts: Vec<String>, encoding: &str) -> Vec<usize> {
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        count_tokens_batch(&refs, encoding)
    }

    /// Serialize/deserialize helpers so Python can call `run_parallel` without a
    /// hand-written PyClass: Python passes a list of JSON-encoded call dicts.
    #[pyfunction]
    fn run_parallel_json(calls_json: String, timeout_ms: u64) -> PyResult<String> {
        let calls: Vec<ToolCall> = serde_json::from_str(&calls_json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid calls: {e}")))?;
        // Run on a dedicated runtime on this thread. run_parallel uses
        // tokio::spawn for concurrency, which requires a current-thread runtime
        // with all drivers enabled.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("runtime: {e}")))?;
        let results = rt.block_on(super::run_parallel(calls, timeout_ms));
        serde_json::to_string(&results)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("serialize: {e}")))
    }

    /// `_khaos_core.version() -> str`
    #[pyfunction]
    fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Module registration. The module is named `_khaos_core` to make the
    /// Python import explicit (and to avoid shadowing any real `khaos_core`).
    #[pymodule]
    pub fn _khaos_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(count_tokens_py, m)?)?;
        m.add_function(wrap_pyfunction!(count_tokens_batch_py, m)?)?;
        m.add_function(wrap_pyfunction!(run_parallel_json, m)?)?;
        m.add_function(wrap_pyfunction!(version, m)?)?;
        // Expose a single attribute indicating build provenance for diagnostics.
        m.add("__rust__", true)?;
        let info = PyDict::new_bound(m.py());
        info.set_item("token_engine", "heuristic")?;
        info.set_item("executor", "tokio")?;
        m.add("build_info", info)?;
        Ok(())
    }
}

#[cfg(feature = "pyo3")]
pub use py::_khaos_core as _py_module_entry;
