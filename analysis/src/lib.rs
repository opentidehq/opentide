//! Python bindings for the opentide engine (`opentide-analysis`) and its
//! language server (`opentide-lsp`), imported as `opentide_analysis._native`.
//!
//! Positions follow the `opentide` CLI, not LSP: lines and columns are
//! 1-based, columns count Unicode code points, and `end_column` is exclusive.
//! The engine reports LSP positions (0-based, UTF-16 code units); every
//! position is converted here, against the text it points into.

use opentide_analysis::{
    AnalyzeRequest, Catalog, IndexedObject, LanguageId, MemoryWorkspace, QueryRequest, Range, codes,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

/// One finding, in the CLI's coordinates.
#[pyclass(frozen, get_all, module = "opentide_analysis")]
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
#[pyclass(frozen, get_all, module = "opentide_analysis")]
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
#[pyclass(frozen, module = "opentide_analysis")]
struct Workspace {
    host: MemoryWorkspace,
    index: Vec<IndexedObject>,
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
            Self { host, index }
        })
    }

    /// How many objects the workspace index holds.
    #[getter]
    fn objects(&self) -> usize {
        self.index.len()
    }

    /// Everything the language server reports for one file: a Tide object, or
    /// a standalone query file. *language* defaults to the one the file name
    /// implies (`.yaml` is a Tide object).
    #[pyo3(signature = (path, text, language=None))]
    fn analyze(
        &self,
        py: Python<'_>,
        path: String,
        text: String,
        language: Option<&str>,
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
            let response = opentide_analysis::analyze_with_index(
                &self.host,
                &self.index,
                AnalyzeRequest {
                    uri: path,
                    language,
                    text: text.clone(),
                },
            );
            convert_all(&text, response.diagnostics)
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
/// schemas` writes them). `None` goes back to the bundled one. Raises
/// `ValueError`, and changes nothing, when a part does not parse.
#[pyfunction]
#[pyo3(signature = (fields=None, deprecations=None))]
fn install_catalog(fields: Option<String>, deprecations: Option<String>) -> PyResult<()> {
    opentide_analysis::install_catalog(&Catalog {
        fields,
        deprecations,
    })
    .map_err(PyValueError::new_err)
}

/// Use these catalogs wherever the engine would use its bundled ones (no
/// workspace catalog installed), for the whole process: the catalogs opentide
/// generates from its own models. `None` goes back to the bundled one. Raises
/// `ValueError`, and changes nothing, when a part does not parse.
#[pyfunction]
#[pyo3(signature = (fields=None, deprecations=None))]
fn set_default_catalog(fields: Option<String>, deprecations: Option<String>) -> PyResult<()> {
    opentide_analysis::set_default_catalog(&Catalog {
        fields,
        deprecations,
    })
    .map_err(PyValueError::new_err)
}

/// Keep the catalogs set here when the language server initializes: it does
/// not read the workspace's `.opentide/lsp/catalogs/`. Process-wide.
#[pyfunction]
fn use_host_catalogs() {
    opentide_lsp::use_host_catalogs();
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
#[pyfunction]
fn serve_stdio(py: Python<'_>) -> PyResult<()> {
    py.detach(opentide_lsp::run_stdio)
        .map_err(|err| PyRuntimeError::new_err(format!("{err:#}")))
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

/// Byte offsets where each line starts. Lines end at `\n`, as the engine counts
/// them (a `\r` before it belongs to the line).
struct LineStarts(Vec<usize>);

impl LineStarts {
    fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(at, _)| at + 1));
        Self(starts)
    }

    /// An LSP range as 1-based `(line, column, end_line, end_column)` in code
    /// points. A position past the end of its line or the text is clamped.
    fn convert(&self, text: &str, range: Range) -> (usize, usize, usize, usize) {
        let (line, column) = self.position(text, range.start.line, range.start.character);
        let (end_line, mut end_column) = self.position(text, range.end.line, range.end.character);
        if (end_line, end_column) <= (line, column) {
            // An empty or reversed range still marks one character.
            end_column = column + 1;
            return (line, column, line, end_column);
        }
        (line, column, end_line, end_column)
    }

    fn position(&self, text: &str, line: u32, utf16: u32) -> (usize, usize) {
        let index = (line as usize).min(self.0.len() - 1);
        let start = self.0[index];
        let end = self.0.get(index + 1).map_or(text.len(), |next| next - 1);
        let content = &text[start..end];
        let mut units = 0u32;
        let mut points = 0usize;
        for ch in content.chars() {
            if units >= utf16 {
                break;
            }
            units += ch.len_utf16() as u32;
            points += 1;
        }
        (index + 1, points + 1)
    }
}

#[pymodule]
mod _native {
    use super::*;

    #[pymodule_export]
    use super::{
        Diagnostic, QueryReport, Workspace, analyze_query, catalog_is_workspace, catalog_version,
        describe_code, highlight, install_catalog, language_for_path, serve_stdio,
        set_default_catalog, use_host_catalogs,
    };

    #[pymodule_init]
    fn init(module: &Bound<'_, PyModule>) -> PyResult<()> {
        module.add("ENGINE_VERSION", opentide_analysis::VERSION)?;
        module.add("CODES", codes::ALL.to_vec())?;
        module.add("LANGUAGES", languages())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_analysis::Position;

    fn range(line: u32, start: u32, end_line: u32, end: u32) -> Range {
        Range::new(Position::new(line, start), Position::new(end_line, end))
    }

    #[test]
    fn utf16_columns_become_one_based_code_points() {
        // "🔥" is two UTF-16 units and one code point; "é" is one of each.
        let text = "a: 🔥é x\nnext\n";
        let lines = LineStarts::new(text);
        // `x` starts at UTF-16 unit 7 (a, :, space, 🔥 = 2, é, space).
        assert_eq!(lines.convert(text, range(0, 7, 0, 8)), (1, 7, 1, 8));
        assert_eq!(lines.convert(text, range(1, 0, 1, 4)), (2, 1, 2, 5));
    }

    #[test]
    fn positions_past_the_text_are_clamped_and_empty_ranges_mark_one_character() {
        let text = "only\r\n";
        let lines = LineStarts::new(text);
        assert_eq!(lines.convert(text, range(0, 2, 0, 2)), (1, 3, 1, 4));
        // The \r belongs to the line, as the engine counts it.
        assert_eq!(lines.convert(text, range(0, 0, 0, 99)), (1, 1, 1, 6));
        assert_eq!(lines.convert(text, range(9, 0, 9, 1)), (2, 1, 2, 2));
    }

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
