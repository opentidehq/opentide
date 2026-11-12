//! The Python SDK's core (UC-5.2, #837): `opentide._native.sdk`, the
//! [`opentide`] facade bound one to one. `opentide.Workspace` (in
//! `src/opentide/sdk.py`) wraps [`Workspace`]; `opentide.run_json` wraps
//! [`run_json`]; `opentide.Connection` wraps [`tenants::Connection`], the
//! facade's tenant operations (UC-5.2b).
//!
//! A thin wrapper (ADR 0005): each method converts its arguments, calls one
//! facade function (with the GIL released) and returns its document as JSON
//! text, keys in the command line's order, which the Python side parses.
//! A tenant operation returns an awaitable instead, which resolves to that
//! text ([`tenants`]).
//! A failure raises [`SdkError`] with `(code, message, detail)`: the
//! facade's stable [`opentide::Error::code`], or `usage_invalid_choice` for
//! an option the command line would refuse; `detail` is the vendor's own
//! words when a tenant gave a reason, else `None`.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyType;
use serde::Serialize;

mod tenants;

use opentide::lint::{LintCheck, LintFinding, LintReport, LintStatus, LintSummary, NextAction};
use opentide::validate::{Check, QueriesMode, Report, Summary, Validation};

create_exception!(
    opentide._native.sdk,
    SdkError,
    PyException,
    "A call the SDK could not run: `args` is `(code, message, detail)`."
);

/// [`SdkError`]'s class, as `opentide._native.sdk` exports it.
///
/// PyO3's introspection cannot describe a `create_exception!` type, so the
/// module exports the class through this value, whose type hint
/// (`type[Exception]`) declares it in the generated stub, as
/// `opentide._native.models` does its `ValidationError`.
#[doc(hidden)]
pub struct SdkErrorClass;

impl<'py> IntoPyObject<'py> for SdkErrorClass {
    type Target = PyType;
    type Output = Bound<'py, PyType>;
    type Error = std::convert::Infallible;

    #[cfg(feature = "stubs")]
    const OUTPUT_TYPE: pyo3::inspect::PyStaticExpr = pyo3::type_hint_subscript!(
        pyo3::type_hint_identifier!("builtins", "type"),
        pyo3::type_hint_identifier!("builtins", "Exception")
    );

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(py.get_type::<SdkError>())
    }
}

/// A failure as [`SdkError`]: its stable code and message, without a detail.
fn failure(code: &str, message: impl Into<String>) -> PyErr {
    SdkError::new_err((code.to_owned(), message.into(), None::<String>))
}

fn usage(message: String) -> PyErr {
    failure("usage_invalid_choice", message)
}

/// The facade's error as [`SdkError`]: its code, its message and, for a
/// tenant's refusal, the vendor's words.
fn from_facade(error: &opentide::Error) -> PyErr {
    let detail = match error {
        opentide::Error::Connector { detail, .. } => detail.clone(),
        _ => None,
    };
    SdkError::new_err((error.code().to_owned(), error.to_string(), detail))
}

fn to_json<T: Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value).map_err(|error| failure("internal_error", error.to_string()))
}

/// A Tide workspace: its configuration, resolved once, and every object file,
/// read and parsed once into one index. Each method reads that index.
#[pyclass(frozen, module = "opentide._native.sdk")]
pub struct Workspace {
    inner: opentide::Workspace,
}

#[pymethods]
impl Workspace {
    /// Opens the workspace at *path* on disk; paths in findings are shown
    /// from *cwd* (default: the workspace's own folder).
    #[staticmethod]
    #[pyo3(signature = (path, cwd=None))]
    fn open(py: Python<'_>, path: String, cwd: Option<String>) -> PyResult<Self> {
        let mut options = opentide::Options::default();
        if let Some(cwd) = cwd {
            options = options.cwd(cwd);
        }
        let inner = py
            .detach(|| opentide::Workspace::open(path, &options))
            .map_err(|error| from_facade(&error))?;
        Ok(Self { inner })
    }

    /// Opens a workspace held in memory, rooted at *root*: each of *files*
    /// is a path (relative to *root*, or absolute) and its text.
    #[staticmethod]
    fn from_files(py: Python<'_>, root: String, files: Vec<(String, String)>) -> PyResult<Self> {
        let inner = py
            .detach(|| opentide::Workspace::from_files(root, files))
            .map_err(|error| from_facade(&error))?;
        Ok(Self { inner })
    }

    /// The workspace folder: the one that holds `.opentide/` and `objects/`.
    #[getter]
    fn root(&self) -> String {
        self.inner.root().to_string_lossy().into_owned()
    }

    /// `opentide validate`: `{checks, report, summary, failed, warned,
    /// exit_code}`, as JSON.
    #[pyo3(signature = (*, check=None, files=Vec::new(), uuids=Vec::new(), types=Vec::new(), strict=false, queries=None))]
    #[expect(
        clippy::too_many_arguments,
        reason = "validate's options, one keyword each, as the command line has them"
    )]
    fn validate(
        &self,
        py: Python<'_>,
        check: Option<String>,
        files: Vec<String>,
        uuids: Vec<String>,
        types: Vec<String>,
        strict: bool,
        queries: Option<String>,
    ) -> PyResult<String> {
        let mut options = opentide::ValidateOptions::default()
            .strict(strict)
            .queries(queries_mode(queries.as_deref())?);
        if let Some(name) = check {
            let check = Check::parse(&name)
                .ok_or_else(|| usage(format!("check: unknown check `{name}`")))?;
            options = options.check(check);
        }
        for file in files {
            options = options.file(file);
        }
        for uuid in uuids {
            options = options.uuid(uuid);
        }
        for family in types {
            options = options.object_type(family);
        }
        let validation = py.detach(|| self.inner.validate(&options));
        to_json(&ValidationJson::from(&validation))
    }

    /// `opentide lint` without `--fix`, as JSON.
    #[pyo3(signature = (*, checks=Vec::new(), files=Vec::new(), strict=false))]
    fn lint(
        &self,
        py: Python<'_>,
        checks: Vec<String>,
        files: Vec<String>,
        strict: bool,
    ) -> PyResult<String> {
        let mut options = opentide::LintOptions::default().strict(strict);
        for name in checks {
            let check = LintCheck::parse(&name)
                .ok_or_else(|| usage(format!("checks: unknown check `{name}`")))?;
            options = options.check(check);
        }
        for file in files {
            options = options.file(file);
        }
        let report = py.detach(|| self.inner.lint(&options));
        to_json(&LintJson::from(&report))
    }

    /// `opentide info`, as JSON.
    fn info(&self, py: Python<'_>) -> PyResult<String> {
        to_json(&py.detach(|| self.inner.info()))
    }

    /// The detection rules: their rows of the catalogue, as JSON.
    fn rules(&self, py: Python<'_>) -> PyResult<String> {
        to_json(&py.detach(|| self.inner.rules()))
    }

    /// The detection objectives: their rows of the catalogue, as JSON.
    fn objectives(&self, py: Python<'_>) -> PyResult<String> {
        to_json(&py.detach(|| self.inner.objectives()))
    }

    /// The threat vectors: their rows of the catalogue, as JSON.
    fn threats(&self, py: Python<'_>) -> PyResult<String> {
        to_json(&py.detach(|| self.inner.threats()))
    }

    /// `opentide info catalog`, as JSON.
    fn catalog(&self, py: Python<'_>) -> PyResult<String> {
        to_json(&py.detach(|| self.inner.catalog()))
    }

    /// `opentide info coverage --technique <technique>`, as JSON.
    fn coverage(&self, py: Python<'_>, technique: String) -> PyResult<String> {
        to_json(&py.detach(|| self.inner.coverage(&technique)))
    }

    /// The tenants the workspace configures for *platform*, in file order;
    /// empty when it configures none.
    fn tenants(&self, py: Python<'_>, platform: String) -> Vec<tenants::TenantConfig> {
        py.detach(|| self.inner.tenants(&platform))
            .into_iter()
            .map(tenants::TenantConfig::from)
            .collect()
    }

    /// `opentide deploy --dry-run`: `(document, summary, ok)`, the documents
    /// as JSON. Nothing is sent and nothing is written.
    #[pyo3(signature = (*, strategies=None, uuids=Vec::new(), files=Vec::new(), platform=None, keep_deprecated=None))]
    fn deploy_plan(
        &self,
        py: Python<'_>,
        strategies: Option<Vec<String>>,
        uuids: Vec<String>,
        files: Vec<String>,
        platform: Option<String>,
        keep_deprecated: Option<bool>,
    ) -> PyResult<(String, Option<String>, bool)> {
        let mut options = opentide::DeployPlanOptions::default();
        for name in strategies.unwrap_or_else(|| vec!["RELEASE".to_owned()]) {
            options = options.strategy(match name.as_str() {
                "PREVIEW" => opentide::Strategy::Preview,
                "RELEASE" => opentide::Strategy::Release,
                other => {
                    return Err(usage(format!(
                        "strategies: `{other}` is not PREVIEW or RELEASE"
                    )));
                }
            });
        }
        for uuid in uuids {
            options = options.uuid(uuid);
        }
        for file in files {
            options = options.file(file);
        }
        if let Some(platform) = platform {
            options = options.platform(platform);
        }
        options.keep_deprecated = keep_deprecated;
        let plan = py
            .detach(|| self.inner.deploy_plan(&options))
            .map_err(|error| from_facade(&error))?;
        Ok((
            plan.document().as_str().to_owned(),
            plan.summary().map(|summary| summary.as_str().to_owned()),
            plan.ok(),
        ))
    }

    fn __repr__(&self) -> String {
        format!("Workspace({:?})", self.inner.root().to_string_lossy())
    }
}

/// Runs `opentide --json <argv>` in this process and returns its document as
/// JSON text: the envelope or, for `commands`, the command tree. Raises
/// [`SdkError`] (`no_json_document`) when the command wrote no document.
#[pyfunction]
pub fn run_json(py: Python<'_>, argv: Vec<String>) -> PyResult<String> {
    py.detach(|| opentide::cli::run_json(argv))
        .map(|document| document.as_str().to_owned())
        .map_err(|error| from_facade(&error))
}

fn queries_mode(name: Option<&str>) -> PyResult<QueriesMode> {
    match name {
        None | Some("error") => Ok(QueriesMode::Error),
        Some("warn") => Ok(QueriesMode::Warn),
        Some("off") => Ok(QueriesMode::Off),
        Some(other) => Err(usage(format!(
            "queries: `{other}` is not error, warn or off"
        ))),
    }
}

/// `Workspace.validate`'s document, in this order.
#[derive(Serialize)]
struct ValidationJson<'a> {
    checks: Checks<'a>,
    report: &'a Report,
    summary: &'a Summary,
    failed: bool,
    warned: bool,
    exit_code: i32,
}

impl<'a> From<&'a Validation> for ValidationJson<'a> {
    fn from(validation: &'a Validation) -> Self {
        Self {
            checks: Checks(&validation.checks),
            report: &validation.report,
            summary: &validation.summary,
            failed: validation.failed,
            warned: validation.warned,
            exit_code: validation.exit_code(),
        }
    }
}

/// `checks` as `validate --json` writes it, in the order the checks ran.
struct Checks<'a>(&'a [(Check, &'static str)]);

impl Serialize for Checks<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (check, status) in self.0 {
            map.serialize_entry(
                check.name(),
                &CheckStatus {
                    check: check.name(),
                    status,
                },
            )?;
        }
        map.end()
    }
}

/// One entry of `checks`.
#[derive(Serialize)]
struct CheckStatus<'a> {
    check: &'a str,
    status: &'a str,
}

/// `Workspace.lint`'s document, in this order.
#[derive(Serialize)]
struct LintJson<'a> {
    path: String,
    checks: Vec<&'static str>,
    findings: &'a [LintFinding],
    status: LintStatus,
    message: &'a str,
    exit_code: i32,
    failure_code: Option<&'static str>,
    summary: Option<&'a LintSummary>,
    outcome: Option<&'a str>,
    unmatched: &'a [String],
    warnings: &'a [String],
    next_actions: &'a [NextAction],
}

impl<'a> From<&'a LintReport> for LintJson<'a> {
    fn from(report: &'a LintReport) -> Self {
        Self {
            path: report.path.to_string_lossy().into_owned(),
            checks: report.checks.iter().map(|check| check.name()).collect(),
            findings: &report.findings,
            status: report.status,
            message: &report.message,
            exit_code: report.exit_code,
            failure_code: report.failure_code,
            summary: report.summary.as_ref(),
            outcome: report.outcome.as_deref(),
            unmatched: &report.unmatched,
            warnings: &report.warnings,
            next_actions: &report.next_actions,
        }
    }
}

/// `opentide._native.sdk`: the facade's `Workspace`, `run_json` and tenant
/// operations, and [`SdkError`].
#[pymodule(submodule, name = "sdk")]
pub mod module {
    #[pymodule_export]
    use super::tenants::{Canceller, Connection, TenantConfig, capabilities, platforms};
    #[pymodule_export]
    use super::{Workspace, run_json};

    /// The error every call raises: `args` is `(code, message, detail)`.
    #[pymodule_export]
    #[allow(
        non_upper_case_globals,
        reason = "the exception's Python name; `expect` is never fulfilled inside the macro"
    )]
    const SdkError: super::SdkErrorClass = super::SdkErrorClass;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_modes_are_the_command_lines() {
        assert!(matches!(queries_mode(None), Ok(QueriesMode::Error)));
        assert!(matches!(queries_mode(Some("warn")), Ok(QueriesMode::Warn)));
        assert!(matches!(queries_mode(Some("off")), Ok(QueriesMode::Off)));
    }
}
