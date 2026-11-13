//! Python bindings for the opentide engine (the `opentide-analysis` crate),
//! the command line (`opentide-cli`), the SDK's core (the `opentide` facade),
//! the Tide models and the platform plugin host, compiled into the opentide
//! package as `opentide._native` (hatch_build.py).
//!
//! Positions follow the `opentide` CLI, not LSP: lines and columns are
//! 1-based, columns count Unicode code points, and `end_column` is exclusive.
//! The engine reports LSP positions (0-based, UTF-16 code units); every
//! position is converted here, against the text it points into.

use opentide_analysis::{
    AnalyzeRequest, IndexedObject, LanguageId, LineStarts, MemoryWorkspace, QueryRequest, Range,
    codes,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

mod plugins;
mod sdk;

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

/// Runs the command line with *argv* (without the program name) in this
/// process, on its standard streams; the exit code. *version* is the
/// package's, which `info` and `--version` print. The `opentide` console
/// script and `python -m opentide` call it (`opentide._cli.main`).
#[pyfunction]
fn cli_main(py: Python<'_>, argv: Vec<String>, version: String) -> i32 {
    py.detach(|| {
        let code = opentide_cli::main(&argv, &version);
        // The process may end in Python's exit, which never flushes Rust's
        // stdout: a last line without its newline would be lost. A reader
        // that has gone (a closed pipe) has nothing left to read.
        let _ignored = std::io::Write::flush(&mut std::io::stdout());
        code
    })
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

/// Declare the datasets a workspace's `visibility.toml` (the file's text)
/// names, leaving the Tide catalogs in use as they are. `None` declares none.
/// Raises `ValueError`, and changes nothing, when the text is not TOML.
#[pyfunction]
#[pyo3(signature = (text=None))]
fn install_visibility(text: Option<&str>) -> PyResult<()> {
    opentide_analysis::install_visibility(text).map_err(PyValueError::new_err)
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
        Diagnostic, QueryReport, Workspace, analyze_query, cli_main, describe_code, highlight,
        install_visibility, language_for_path,
    };

    /// The SDK's core (UC-5.2, #837): `opentide._native.sdk`, the facade's
    /// `Workspace` and `run_json`, which `opentide.Workspace` wraps.
    #[pymodule_export]
    use super::sdk::module;

    /// The Tide models (UC-1.9, #815): `opentide._native.models`.
    #[pymodule_export]
    use opentide_schema::python::models;

    #[pymodule_init]
    fn init(module: &Bound<'_, PyModule>) -> PyResult<()> {
        // Every run of the command line in this process reaches the
        // platforms the Python packages register (UC-4.5, #835).
        opentide_cli::plugins::set_host(Box::new(super::plugins::PythonPlugins::default()));
        module.add("ENGINE_VERSION", opentide_analysis::VERSION)?;
        module.add("CODES", codes::ALL.to_vec())?;
        module.add("LANGUAGES", languages())?;
        // Importable by name, as pickling needs for the classes it rebuilds.
        opentide_schema::python::register(&module.getattr("models")?.cast_into()?)?;
        let sdk = module.getattr("sdk")?;
        sdk.setattr("__name__", "opentide._native.sdk")?;
        module
            .py()
            .import("sys")?
            .getattr("modules")?
            .set_item("opentide._native.sdk", sdk)?;
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
