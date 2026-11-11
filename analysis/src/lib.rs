//! Python bindings for the opentide engine (the `opentide-analysis` crate),
//! its language server (`opentide-lsp`) and the differential comparator
//! (`opentide-compare`), compiled into the opentide package as
//! `opentide._native` (hatch_build.py).
//!
//! Positions follow the `opentide` CLI, not LSP: lines and columns are
//! 1-based, columns count Unicode code points, and `end_column` is exclusive.
//! The engine reports LSP positions (0-based, UTF-16 code units); every
//! position is converted here, against the text it points into.

use opentide_analysis::{
    AnalyzeRequest, Catalog, Declaration, IndexedObject, LanguageId, LineStarts, MemoryWorkspace,
    QueryRequest, Range, codes,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::collections::HashMap;
use std::path::PathBuf;

use opentide_cli::env::Env;

mod serve;

/// One finding, in the CLI's coordinates.
#[pyclass(frozen, get_all, module = "opentide._native")]
#[derive(Clone)]
struct Diagnostic {
    /// Stable snake_case code (`kql_unknown_table`).
    code: String,
    /// `error`, `warning`, `information` or `hint`.
    severity: &'static str,
    message: String,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
    /// YAML path of the field the finding is about, when the engine knows it.
    field_path: Option<Vec<String>>,
    /// A replacement or next step, when the engine has one.
    suggestion: Option<String>,
}

#[pymethods]
impl Diagnostic {
    fn __repr__(&self) -> String {
        format!(
            "Diagnostic({}:{}:{} {}[{}] {:?})",
            self.line, self.column, self.end_column, self.severity, self.code, self.message
        )
    }
}

/// One query a Tide object carries, analyzed in its language.
#[pyclass(frozen, get_all, module = "opentide._native")]
#[derive(Clone)]
struct QueryReport {
    /// `kql`, `spl`, `esql`, `eql`, `kuery` or `lucene`.
    language: &'static str,
    /// YAML path of the query (`("configurations", "sentinel", "query")`).
    field_path: Vec<String>,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
    diagnostics: Vec<Diagnostic>,
}

#[pymethods]
impl QueryReport {
    fn __repr__(&self) -> String {
        format!(
            "QueryReport({} at {}:{}, {} diagnostics)",
            self.field_path.join("."),
            self.line,
            self.column,
            self.diagnostics.len()
        )
    }
}

/// The files of one workspace, indexed once for many analyses.
#[pyclass(frozen, module = "opentide._native")]
struct Workspace {
    host: MemoryWorkspace,
    index: Vec<IndexedObject>,
    /// What `validate` reports on the objects of each workspace a file
    /// was analysed in, by the workspace's folder: loaded once (UC-2.6).
    objects: std::sync::Mutex<
        std::collections::HashMap<std::path::PathBuf, std::sync::Arc<opentide_lsp::ObjectFindings>>,
    >,
}

impl Workspace {
    /// `validate`'s findings on the object file at `path`, from the
    /// workspace around it (loaded and validated once per workspace).
    fn object_findings(&self, path: &str, text: &str) -> Vec<opentide_analysis::Diagnostic> {
        let file = std::path::Path::new(path);
        let Some(root) = opentide_lsp::server::workspace_root(file) else {
            return Vec::new();
        };
        let findings = {
            let mut cache = self
                .objects
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::sync::Arc::clone(cache.entry(root.clone()).or_insert_with(|| {
                std::sync::Arc::new(opentide_lsp::ObjectFindings::validate(&root))
            }))
        };
        findings.for_file(file, text)
    }
}

#[pymethods]
impl Workspace {
    /// *files* are `(path, text)` pairs: the object files, and the Elastic
    /// platform configuration when there is one (its tenants' stack versions
    /// decide what ES|QL is checked against).
    #[new]
    #[pyo3(signature = (files=Vec::new()))]
    fn new(py: Python<'_>, files: Vec<(String, String)>) -> Self {
        py.detach(|| {
            let host = MemoryWorkspace { files };
            let index = opentide_analysis::index_workspace(&host);
            Self {
                host,
                index,
                objects: std::sync::Mutex::default(),
            }
        })
    }

    /// How many objects the workspace index holds.
    #[getter]
    fn objects(&self) -> usize {
        self.index.len()
    }

    /// Everything the language server reports for one file: a Tide object
    /// (what `opentide validate` reports on it, when it is in a workspace on
    /// disk, and the engine's query and block checks), or a standalone query
    /// file. *language* defaults to the one the file name implies (`.yaml` is
    /// a Tide object). *objects* false leaves `validate`'s findings out (and
    /// the run that makes them): the engine's own checks alone, for `lint`'s
    /// queries check.
    #[pyo3(signature = (path, text, language=None, objects=true))]
    fn analyze(
        &self,
        py: Python<'_>,
        path: String,
        text: String,
        language: Option<&str>,
        objects: bool,
    ) -> PyResult<Vec<Diagnostic>> {
        let language = match language {
            Some(name) => parse_language(name)?,
            None => language_of(&path).ok_or_else(|| {
                PyValueError::new_err(format!(
                    "cannot tell the language of {path:?} from its name; pass language="
                ))
            })?,
        };
        Ok(py.detach(|| {
            let mut diagnostics = if objects && language == LanguageId::TideYaml {
                self.object_findings(&path, &text)
            } else {
                Vec::new()
            };
            let response = opentide_analysis::analyze_with_index(
                &self.host,
                &self.index,
                AnalyzeRequest {
                    uri: path,
                    language,
                    text: text.clone(),
                },
            );
            diagnostics.extend(response.diagnostics);
            convert_all(&text, diagnostics)
        }))
    }

    /// What the language server's hover shows at a position of *text*, as
    /// Markdown, or `None` where it has nothing: the field's description, a
    /// vocabulary value's meaning, the object a UUID names, a query token. The
    /// same content an editor running `opentide lsp start` shows. *line* and
    /// *column* are 1-based, *column* in code points, as diagnostics report
    /// them; a position past its line or the text is clamped.
    #[pyo3(signature = (path, text, line, column, language=None))]
    fn hover(
        &self,
        py: Python<'_>,
        path: String,
        text: String,
        line: usize,
        column: usize,
        language: Option<&str>,
    ) -> PyResult<Option<String>> {
        let language = match language {
            Some(name) => parse_language(name)?,
            None => language_of(&path).ok_or_else(|| {
                PyValueError::new_err(format!(
                    "cannot tell the language of {path:?} from its name; pass language="
                ))
            })?,
        };
        Ok(py.detach(|| {
            let offset = LineStarts::new(&text).offset(&text, line, column);
            opentide_analysis::hover(&self.host, language, &text, offset)
        }))
    }

    /// Every query the Tide object *text* carries, each with its diagnostics,
    /// including queries with none. CrowdStrike and HarfangLab queries are
    /// never analyzed, so they are not reported.
    fn analyze_queries(&self, py: Python<'_>, text: String) -> Vec<QueryReport> {
        py.detach(|| {
            opentide_analysis::analyze_queries(&self.host, &text)
                .into_iter()
                .map(|report| {
                    let (line, column, end_line, end_column) = convert_range(&text, report.range);
                    QueryReport {
                        language: report.language.as_str(),
                        field_path: report.field_path,
                        line,
                        column,
                        end_line,
                        end_column,
                        diagnostics: convert_all(&text, report.diagnostics),
                    }
                })
                .collect()
        })
    }
}

/// Diagnostics for one query on its own. *platform* is a `configurations` key
/// (`defender_for_endpoint` selects the Defender schema, `carbon_black_cloud`
/// the Carbon Black dialect); *stack* is an Elastic stack (`"9.5"`) for ES|QL.
#[pyfunction]
#[pyo3(signature = (text, language, platform=None, stack=None))]
fn analyze_query(
    py: Python<'_>,
    text: String,
    language: &str,
    platform: Option<String>,
    stack: Option<String>,
) -> PyResult<Vec<Diagnostic>> {
    let language = parse_language(language)?;
    if language == LanguageId::TideYaml {
        return Err(PyValueError::new_err(
            "opentide-yaml is an object file, not a query; use Workspace.analyze",
        ));
    }
    Ok(py.detach(|| {
        let request = QueryRequest {
            language,
            platform,
            stack,
            text: text.clone(),
        };
        convert_all(&text, opentide_analysis::analyze_query(&request))
    }))
}

/// Runs the Rust command line with *argv* (without the program name) in this
/// process, on its standard streams; the exit code. *version* is the
/// package's, which `info` and `--version` print. The commands it has not
/// ported refuse with `engine_not_ported`.
#[pyfunction]
fn cli_main(py: Python<'_>, argv: Vec<String>, version: String) -> i32 {
    opentide_cli::mcp::set_delegate(Box::new(McpBridge));
    opentide_cli::serve::set_delegate_factory(Box::new(serve::BridgeFactory));
    py.detach(|| opentide_cli::main(&argv, &version))
}

/// The Python half of `opentide mcp start` (UC-3.7, #829):
/// `opentide.mcp_server.bridge`, which answers, with the Python server's own
/// handlers, the tools and resources the Rust server has no implementation of
/// yet. Called from the server's thread, which holds no GIL until it attaches.
struct McpBridge;

/// Runs `call` on the module `opentide.mcp_server.bridge`, with the GIL; a
/// Python exception as its text.
fn bridge<T>(call: impl for<'py> FnOnce(Bound<'py, PyModule>) -> PyResult<T>) -> Result<T, String> {
    Python::attach(|py| call(py.import("opentide.mcp_server.bridge")?))
        .map_err(|error| error.to_string())
}

impl opentide_cli::mcp::Delegate for McpBridge {
    fn start(&self, environment: &[(String, String)]) -> Result<(), String> {
        let environment: HashMap<&str, &str> = environment
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        bridge(|module| module.call_method1("start", (environment,)).map(drop))
    }

    fn workspace_problem(&self) -> Option<String> {
        bridge(|module| {
            module
                .call_method0("workspace_problem")?
                .extract::<Option<String>>()
        })
        .ok()
        .flatten()
    }

    fn call_tool(&self, name: &str, arguments: &str) -> Result<String, String> {
        bridge(|module| {
            module
                .call_method1("call_tool", (name, arguments))?
                .extract::<String>()
        })
    }

    fn read_resource(&self, uri: &str) -> Result<String, String> {
        bridge(|module| {
            module
                .call_method1("read_resource", (uri,))?
                .extract::<String>()
        })
    }
}

/// Runs the Rust command line with *argv* (without the program name) in this
/// process, with exactly the variables *env* and from *cwd*, its streams
/// captured as pipes: `(exit_code, stdout, stderr)`. `opentide serve` runs a
/// request this way. *warm*: a workspace the run opens stays loaded for the
/// next warm run, which re-reads only what changed (a read-only run only).
#[pyfunction]
#[pyo3(signature = (argv, env, cwd, version, warm=false))]
fn run_cli(
    py: Python<'_>,
    argv: Vec<String>,
    env: HashMap<String, String>,
    cwd: PathBuf,
    version: String,
    warm: bool,
) -> (i32, Py<PyBytes>, Py<PyBytes>) {
    let captured = py.detach(|| {
        opentide_cli::embed::run_captured(&argv, &Env::from_pairs(env), &cwd, &version, warm)
    });
    (
        captured.exit_code,
        PyBytes::new(py, &captured.stdout).unbind(),
        PyBytes::new(py, &captured.stderr).unbind(),
    )
}

/// Interrupts the `run_cli` in progress as Ctrl-C would (it exits 130);
/// whether one was running.
#[pyfunction]
fn interrupt_cli() -> bool {
    opentide_cli::embed::interrupt()
}

/// Tells the warm workspaces that *paths* changed: each is taken into
/// account at the workspace's next warm run. The number of warm workspaces.
#[pyfunction]
fn invalidate_workspaces(paths: Vec<PathBuf>) -> usize {
    opentide_cli::embed::invalidate_workspaces(&paths)
}

/// Forgets every warm workspace.
#[pyfunction]
fn clear_workspaces() {
    opentide_cli::embed::clear_workspaces();
}

/// What the warm workspaces have done: `opens`, `hits`, `refreshes`, `kept`
/// and `file_reads` (object files the kept ones read).
#[pyfunction]
fn workspace_stats() -> HashMap<&'static str, usize> {
    let stats = opentide_cli::embed::workspace_stats();
    HashMap::from([
        ("opens", stats.opens),
        ("hits", stats.hits),
        ("refreshes", stats.refreshes),
        ("kept", stats.kept),
        ("file_reads", stats.file_reads),
    ])
}

/// `validate` on the workspace *cwd* and *env* place (and *repo*, `--repo`),
/// as JSON: `{"report", "checks", "summary", "failed"}`, the report as
/// `validate --json` writes it, or `{"error": {"code", "message"}}`.
#[pyfunction]
#[pyo3(signature = (cwd, env, *, repo=None, check=None, files=Vec::new(), uuids=Vec::new(), types=Vec::new(), queries=String::from("error"), strict=false))]
#[expect(
    clippy::too_many_arguments,
    reason = "validate's options, one keyword each, as the CLI has them"
)]
fn validate_report(
    py: Python<'_>,
    cwd: PathBuf,
    env: HashMap<String, String>,
    repo: Option<String>,
    check: Option<String>,
    files: Vec<String>,
    uuids: Vec<String>,
    types: Vec<String>,
    queries: String,
    strict: bool,
) -> String {
    let request = opentide_cli::embed::ValidateRequest {
        repo,
        check,
        files,
        uuids,
        types,
        queries,
        strict,
    };
    py.detach(|| opentide_cli::embed::validate_json(&request, &Env::from_pairs(env), &cwd))
}

/// `(line, column, end_line, end_column, capture)`.
type Token = (usize, usize, usize, usize, String);

/// Highlight tokens for *text* read as *language*, as the editor colours it:
/// `(line, column, end_line, end_column, capture)` in the CLI's coordinates,
/// where the capture is a HighlightSpec name (`keyword`, `function`,
/// `string`, ...). A Tide object's injected queries are highlighted in their
/// own language.
#[pyfunction]
fn highlight(py: Python<'_>, text: String, language: &str) -> PyResult<Vec<Token>> {
    let language = parse_language(language)?;
    Ok(py.detach(|| {
        let lines = LineStarts::new(&text);
        opentide_analysis::highlight(language, &text)
            .tokens
            .into_iter()
            .map(|token| {
                let (line, column, end_line, end_column) = lines.convert(&text, token.range);
                (line, column, end_line, end_column, token.capture)
            })
            .collect()
    }))
}

/// Replace the bundled Tide catalogs, for the whole process, with a
/// workspace's (`fields.json`, `deprecations.json` as `opentide generate
/// schemas` writes them), and declare the datasets of its `visibility.toml`
/// (the file's text). `None` goes back to the bundled one; for `visibility`,
/// to none declared. Raises `ValueError`, and changes nothing, when a part
/// does not parse.
#[pyfunction]
#[pyo3(signature = (fields=None, deprecations=None, visibility=None))]
fn install_catalog(
    fields: Option<String>,
    deprecations: Option<String>,
    visibility: Option<String>,
) -> PyResult<()> {
    opentide_analysis::install_catalog(&Catalog {
        fields,
        deprecations,
        visibility,
    })
    .map_err(PyValueError::new_err)
}

/// Use these catalogs wherever the engine would use its bundled ones (no
/// workspace catalog installed), for the whole process: the catalogs opentide
/// generates from its own models. `None` goes back to the bundled one (for
/// `visibility`, to none declared). Raises `ValueError`, and changes nothing,
/// when a part does not parse.
#[pyfunction]
#[pyo3(signature = (fields=None, deprecations=None, visibility=None))]
fn set_default_catalog(
    fields: Option<String>,
    deprecations: Option<String>,
    visibility: Option<String>,
) -> PyResult<()> {
    opentide_analysis::set_default_catalog(&Catalog {
        fields,
        deprecations,
        visibility,
    })
    .map_err(PyValueError::new_err)
}

/// Declare the datasets a workspace's `visibility.toml` (the file's text)
/// names, leaving the Tide catalogs in use as they are. `None` declares none.
/// Raises `ValueError`, and changes nothing, when the text is not TOML.
#[pyfunction]
#[pyo3(signature = (text=None))]
fn install_visibility(text: Option<&str>) -> PyResult<()> {
    opentide_analysis::install_visibility(text).map_err(PyValueError::new_err)
}

/// What the declared datasets in use (the workspace's `visibility.toml`, else
/// the host's) say about `name` on `platform`: a log source's `name` is its
/// dataset, whose kind follows from the system (a table for `sentinel` and
/// `defender_for_endpoint`, a sourcetype for `splunk`, an index pattern for
/// `elastic`). `unchecked` when the platform has no log source (or declares
/// no datasets), else `declared` or `undeclared`.
#[pyfunction]
fn dataset_status(platform: &str, name: &str) -> &'static str {
    match opentide_analysis::declared_datasets().status(platform, name) {
        Declaration::Unchecked => "unchecked",
        Declaration::Declared => "declared",
        Declaration::Undeclared => "undeclared",
    }
}

/// The Tide catalogs compiled into the engine, `(fields, deprecations)`, as
/// their files hold them: opentide compares them with what its models
/// generate (`tests/test_generation/test_bundled_tide_catalog.py`).
#[pyfunction]
fn bundled_catalog() -> (Option<String>, Option<String>) {
    let catalog = opentide_analysis::bundled_catalog();
    (catalog.fields, catalog.deprecations)
}

/// Keep the catalogs set here when the language server initializes: it does
/// not read the workspace's `.opentide/lsp/catalogs/`. Process-wide.
#[pyfunction]
fn use_host_catalogs() {
    opentide_lsp::use_host_catalogs();
}

/// Name the host that runs the language server, process-wide: clients read
/// it at `initialize` (`capabilities.experimental.opentide.host`).
#[pyfunction]
fn set_host_info(name: &str, version: &str) {
    opentide_lsp::set_host_info(name, version);
}

/// The opentide version the Tide field catalog in use was generated from.
#[pyfunction]
fn catalog_version() -> &'static str {
    opentide_analysis::catalog_version()
}

/// Whether a workspace catalog is installed.
#[pyfunction]
fn catalog_is_workspace() -> bool {
    opentide_analysis::catalog_is_workspace()
}

/// One sentence on what a diagnostic code means, or `None` for a code the
/// engine does not emit.
#[pyfunction]
fn describe_code(code: &str) -> Option<&'static str> {
    codes::describe(code)
}

/// The language a file name implies: `opentide-yaml` for `.yaml` and `.yml`,
/// a query language for its extension, else `None`.
#[pyfunction]
fn language_for_path(path: &str) -> Option<&'static str> {
    language_of(path).map(LanguageId::as_str)
}

/// Serve the language server protocol on this process's stdin and stdout until
/// the client exits or closes stdin. Nothing else may write to stdout
/// meanwhile. Runs without the GIL, so other Python threads keep running.
/// Returns whether the client shut the server down before it exited: LSP has
/// the process exit with 0 if so and 1 if not.
#[pyfunction]
fn serve_stdio(py: Python<'_>) -> PyResult<bool> {
    py.detach(opentide_lsp::run_stdio_status)
        .map_err(|err| PyRuntimeError::new_err(format!("{err:#}")))
}

/// One side of a comparison, as `compare_runs` takes it: the exit code,
/// stdout, stderr, the files the run left different (`(path, mode, bytes)`,
/// `mode` and `bytes` `None` for a deleted file), the literal texts that
/// normalise it with their placeholders (its workspace copy's path to `<WS>`),
/// the dates (`YYYY-MM-DD`, UTC) it ran on, and the week before them, whose
/// date-times a command's default window reaches back to.
type RunArgs = (
    i32,
    Py<PyBytes>,
    Py<PyBytes>,
    Vec<(String, Option<u32>, Option<Py<PyBytes>>)>,
    Vec<(String, String)>,
    Vec<String>,
    Vec<String>,
);

fn run_of(
    py: Python<'_>,
    args: RunArgs,
) -> (opentide_compare::Run, opentide_compare::normalise::Volatile) {
    let (exit_code, stdout, stderr, files, literals, dates, recent_dates) = args;
    let bytes = |value: &Py<PyBytes>| value.as_bytes(py).to_vec();
    let files = files
        .iter()
        .map(|(path, mode, contents)| {
            let state = match (mode, contents) {
                (Some(mode), Some(contents)) => opentide_compare::FileState::Written {
                    mode: *mode,
                    bytes: bytes(contents),
                },
                _ => opentide_compare::FileState::Deleted,
            };
            (path.clone(), state)
        })
        .collect();
    let run = opentide_compare::Run {
        exit_code,
        stdout: bytes(&stdout),
        stderr: bytes(&stderr),
        files,
    };
    let volatile = opentide_compare::normalise::Volatile {
        literals,
        dates,
        recent_dates,
        git_version: None,
        // The workspace's texts (`known`) seed the UUIDs that are not fresh.
        known_uuids: std::collections::BTreeSet::new(),
    };
    (run, volatile)
}

/// The comparison of one run of `command` by the oracle and by the
/// candidate, each normalised first with the command's `rules` (`fresh-uuids`,
/// `host-git`), the workspace's texts before the run (`known`) and the host's
/// git version, as the JSON of `opentide-compare`'s `CaseReport`.
#[pyfunction]
#[pyo3(signature = (command, oracle, candidate, rules = Vec::new(), known = Vec::new(), git_version = None))]
fn compare_runs(
    py: Python<'_>,
    command: &str,
    oracle: RunArgs,
    candidate: RunArgs,
    rules: Vec<String>,
    known: Vec<String>,
    git_version: Option<String>,
) -> PyResult<String> {
    let rules = rules
        .iter()
        .map(|rule| match rule.as_str() {
            "fresh-uuids" => Ok(opentide_compare::normalise::Rule::FreshUuids),
            "host-git" => Ok(opentide_compare::normalise::Rule::HostGit),
            other => Err(PyValueError::new_err(format!(
                "unknown normalisation rule: {other}"
            ))),
        })
        .collect::<PyResult<Vec<_>>>()?;
    let (mut oracle, mut candidate) = (run_of(py, oracle), run_of(py, candidate));
    oracle.1.git_version.clone_from(&git_version);
    candidate.1.git_version = git_version;
    let report = py.detach(|| {
        opentide_compare::compare_normalised(
            opentide_compare::Case { command, id: "" },
            (oracle.0, &oracle.1),
            (candidate.0, &candidate.1),
            opentide_compare::Normalisation {
                rules: &rules,
                known: &known,
            },
            &opentide_compare::ledger::Ledger::default(),
        )
    });
    report
        .to_json()
        .map_err(|err| PyRuntimeError::new_err(err.to_string()))
}

fn parse_language(name: &str) -> PyResult<LanguageId> {
    LanguageId::parse(name).ok_or_else(|| {
        PyValueError::new_err(format!(
            "unknown language {name:?}: expected one of {}",
            languages().join(", ")
        ))
    })
}

fn language_of(path: &str) -> Option<LanguageId> {
    let extension = std::path::Path::new(path).extension()?.to_str()?;
    if matches!(extension.to_ascii_lowercase().as_str(), "yaml" | "yml") {
        return Some(LanguageId::TideYaml);
    }
    LanguageId::from_extension(extension)
}

fn languages() -> Vec<&'static str> {
    LanguageId::QUERY_LANGUAGES
        .iter()
        .map(|language| language.as_str())
        .chain([LanguageId::TideYaml.as_str()])
        .collect()
}

fn convert_all(text: &str, diagnostics: Vec<opentide_analysis::Diagnostic>) -> Vec<Diagnostic> {
    let lines = LineStarts::new(text);
    diagnostics
        .into_iter()
        .map(|diagnostic| {
            let (line, column, end_line, end_column) = lines.convert(text, diagnostic.range);
            Diagnostic {
                code: diagnostic.code,
                severity: diagnostic.severity.as_str(),
                message: diagnostic.message,
                line,
                column,
                end_line,
                end_column,
                field_path: diagnostic.field_path,
                suggestion: diagnostic.suggestion,
            }
        })
        .collect()
}

fn convert_range(text: &str, range: Range) -> (usize, usize, usize, usize) {
    LineStarts::new(text).convert(text, range)
}

#[pymodule]
mod _native {
    // `allow`, not `expect`: clippy's glob-import lints never fulfil an expectation.
    #[allow(
        clippy::wildcard_imports,
        reason = "the module's init function uses the PyO3 prelude and the helpers the parent imports"
    )]
    use super::*;

    #[pymodule_export]
    use super::{
        Diagnostic, QueryReport, Workspace, analyze_query, bundled_catalog, catalog_is_workspace,
        catalog_version, clear_workspaces, cli_main, compare_runs, dataset_status, describe_code,
        highlight, install_catalog, install_visibility, interrupt_cli, invalidate_workspaces,
        language_for_path, run_cli, serve_stdio, set_default_catalog, set_host_info,
        use_host_catalogs, validate_report, workspace_stats,
    };

    /// `opentide serve`'s Rust host, driven from Python (UC-3.8, #830).
    #[pymodule_export]
    use super::serve::ServeHost;

    /// The Tide models (UC-1.9, #815): `opentide._native.models`.
    #[pymodule_export]
    use opentide_schema::python::models;

    #[pymodule_init]
    fn init(module: &Bound<'_, PyModule>) -> PyResult<()> {
        module.add("ENGINE_VERSION", opentide_analysis::VERSION)?;
        module.add("CODES", codes::ALL.to_vec())?;
        module.add("LANGUAGES", languages())?;
        // Importable by name, as pickling needs for the classes it rebuilds.
        opentide_schema::python::register(&module.getattr("models")?.cast_into()?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_imply_their_language() {
        assert_eq!(
            language_of("objects/rules/a.YAML"),
            Some(LanguageId::TideYaml)
        );
        assert_eq!(language_of("hunt.esql"), Some(LanguageId::Esql));
        assert_eq!(language_of("notes.txt"), None);
        assert_eq!(language_of("Makefile"), None);
    }
}
