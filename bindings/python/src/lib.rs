//! Python bindings for the opentide engine (the `opentide-analysis` crate),
//! the command line (`opentide-cli`), the SDK's core (the `opentide` facade),
//! the Tide models and the platform plugin host, compiled into the opentide
//! package as `opentide._native` (maturin, pyproject.toml's `[tool.maturin]`).
//!
//! Positions follow the `opentide` CLI, not LSP: lines and columns are
//! 1-based, columns count Unicode code points, and `end_column` is exclusive.
//! The engine reports LSP positions (0-based, UTF-16 code units); every
//! position is converted here, against the text it points into.

use opentide::analysis::{self, LanguageId, LineStarts, QueryPosition, QueryRequest, codes};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

mod plugins;
mod sdk;

/// The package's version, PEP 440: this crate's Cargo version, which maturin
/// writes into the wheel's metadata the same way (`X.Y.Z-rc.N` is `X.Y.ZrcN`,
/// a CI build's `X.Y.Z-dev.N` is `X.Y.Z.devN`). The console script hands it
/// to the command line without reading the package's metadata, which would
/// cost its start more than the rest of it (UC-3.8b, #960).
fn python_version(cargo: &str) -> String {
    let Some((release, pre)) = cargo.split_once('-') else {
        return cargo.to_owned();
    };
    let (label, number) = pre.split_once('.').unwrap_or((pre, ""));
    match label {
        "alpha" | "a" => format!("{release}a{number}"),
        "beta" | "b" => format!("{release}b{number}"),
        "rc" => format!("{release}rc{number}"),
        "dev" => format!("{release}.dev{number}"),
        _ => cargo.to_owned(),
    }
}

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

/// Diagnostics for one query on its own. *platform* is a `configurations` key
/// (`microsoft_defender` selects the Defender schema, `carbon_black_cloud`
/// the Carbon Black dialect); *stack* is an Elastic stack (`"9.5"`) for ES|QL.
/// *position* is `"search"` (a query file, a hunt) or `"rule"` (the query of
/// *platform*'s rule block, which needs a platform).
#[pyfunction]
#[pyo3(signature = (text, language, platform=None, stack=None, position="search"))]
fn analyze_query(
    py: Python<'_>,
    text: String,
    language: &str,
    platform: Option<String>,
    stack: Option<String>,
    position: &str,
) -> PyResult<Vec<Diagnostic>> {
    let language = parse_language(language)?;
    if language == LanguageId::TideYaml {
        return Err(PyValueError::new_err(
            "opentide-yaml is an object file, not a query; use opentide.Workspace.validate",
        ));
    }
    let position = QueryPosition::parse(position).ok_or_else(|| {
        PyValueError::new_err(format!(
            "unknown position {position:?}: pass \"search\" or \"rule\""
        ))
    })?;
    let request = QueryRequest::new(language, text.clone())
        .with_platform(platform)
        .with_stack(stack)
        .with_position(position);
    let diagnostics = py
        .detach(|| analysis::analyze_query(&request))
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok(convert_all(&text, diagnostics))
}

/// Runs the command line with *argv* (without the program name) in this
/// process, on its standard streams; the exit code. *version* is the
/// package's, which `info` and `--version` print. The `opentide` console
/// script and `python -m opentide` call it (`opentide._cli.main`).
#[pyfunction]
fn cli_main(py: Python<'_>, argv: Vec<String>, version: String) -> i32 {
    py.detach(|| {
        let code = opentide::cli::main_with_version(&argv, &version);
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
        analysis::highlight(language, &text)
            .tokens
            .into_iter()
            .map(|token| {
                let (line, column, end_line, end_column) = lines.convert(&text, token.range);
                (line, column, end_line, end_column, token.capture)
            })
            .collect()
    }))
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

fn convert_all(text: &str, diagnostics: Vec<analysis::Diagnostic>) -> Vec<Diagnostic> {
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

#[pymodule]
mod _native {
    // `allow`, not `expect`: clippy's glob-import lints never fulfil an expectation.
    #[allow(
        clippy::wildcard_imports,
        reason = "the module's init function uses the PyO3 prelude and the helpers the parent imports"
    )]
    use super::*;

    #[pymodule_export]
    use super::{Diagnostic, analyze_query, cli_main, describe_code, highlight, language_for_path};

    /// The SDK's core (UC-5.2, #837): `opentide._native.sdk`, the facade's
    /// `Workspace` and `run_json`, which `opentide.Workspace` wraps.
    #[pymodule_export]
    use super::sdk::module;

    /// The Tide models (UC-1.9, #815): `opentide._native.models`.
    #[pymodule_export]
    use opentide::python::models;

    #[pymodule_init]
    fn init(module: &Bound<'_, PyModule>) -> PyResult<()> {
        // Every run of the command line in this process reaches the
        // platforms the Python packages register (UC-4.5, #835).
        opentide::plugins::set_host(Box::new(super::plugins::PythonPlugins::default()));
        module.add("__version__", python_version(env!("CARGO_PKG_VERSION")))?;
        module.add("ENGINE_VERSION", opentide::analysis::VERSION)?;
        module.add("CODES", codes::ALL.to_vec())?;
        module.add("LANGUAGES", languages())?;
        // Importable by name, as pickling needs for the classes it rebuilds.
        opentide::python::register(&module.getattr("models")?.cast_into()?)?;
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
    fn the_cargo_version_reads_as_maturin_writes_it() {
        assert_eq!(python_version("1.0.0"), "1.0.0");
        assert_eq!(python_version("1.0.0-rc.1"), "1.0.0rc1");
        assert_eq!(python_version("0.12.0-dev.2474"), "0.12.0.dev2474");
        assert_eq!(python_version("2.1.0-beta.3"), "2.1.0b3");
        assert_eq!(python_version("2.1.0-alpha.1"), "2.1.0a1");
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
