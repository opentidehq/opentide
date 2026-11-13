//! The offline query analysis (UC-2.5, #820): the query engines
//! (`opentide-analysis`) behind `opentide-workspace`'s [`QueryCheck`], for
//! the `queries` check of `validate` (and of `lint`, UC-2.3), and the pieces
//! `validate query` reads.
//!
//! Each object's queries are found and checked by the injection table of
//! `opentide-tide` (`docs/engine/ARCHITECTURE.md`, "Injection table"):
//! Sentinel and Defender KQL, Splunk SPL, the Elastic languages by `type` and
//! `language` (`threat.query` included), Carbon Black's Lucene, Sysdig's
//! Falco conditions, macros, lists, outputs and exceptions, CrowdStrike CQL
//! and response hunt queries by `system`. Each query is reported at its own
//! field path with the platform it runs on: a hunt's is its `system`, not a
//! `configurations` key (#696). The profiles are the workspace's: ES|QL is
//! checked against the lowest `setup.version` of a block's target tenants in
//! `platforms/elastic.toml` (8.19 when none says), and the datasets
//! `visibility.toml` declares are the ones the engines know.
//!
//! This module ports the oracle's `opentide.analysis.check_queries`,
//! `opentide.validation.queries` and `diagnostic_from_engine`: a query `opentide
//! new` left as a placeholder is not counted; only the engine's errors are
//! `validate`'s (its warnings and notes are `lint`'s); `--queries warn`
//! reports them as warnings with a note.
//!
//! The datasets a workspace declares are installed process-wide in the
//! engines, as the language server installs them, so one check runs at a
//! time ([`ENGINE`]).

use std::borrow::Cow;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use indexmap::IndexMap;
use opentide_analysis::{LineStarts, MemoryWorkspace, Severity as EngineSeverity};
use opentide_workspace::diagnostic::ContextValue;
use opentide_workspace::validate::annotate::relative_path;
use opentide_workspace::validate::{QueryCheck, QueryFindings, QueryObject};
use opentide_workspace::{Diagnostic, FileSystem, Severity, Workspace};

/// `context.source` of the findings of the queries check.
pub const ENGINE_SOURCE: &str = "engine";

/// The `context` key marking an error `--queries warn` reports as a warning.
pub const REPORTED_AS_WARNING: &str = "reported_as_warning";

/// The note on a query error `--queries warn` reports as a warning.
pub const REPORTED_AS_WARNING_NOTE: &str =
    "the platform rejects this query; --queries warn reports it as a warning";

/// The workspace's log sources, which the engines read for the datasets they
/// know.
pub const VISIBILITY_CONFIGURATION: &str = ".opentide/configurations/visibility.toml";

/// Where the Elastic tenants' stack versions are read from; the engine
/// matches this path's ending, so it is passed as written here.
pub const ELASTIC_CONFIGURATION: &str = ".opentide/configurations/platforms/elastic.toml";

/// The engine's warnings about a dataset `visibility.toml` does not declare:
/// their help is their `opentide explain` page, not a language reference.
pub const DECLARED_DATASET_CODES: [&str; 3] = [
    "kql_table_not_declared",
    "spl_dataset_not_declared",
    "elastic_dataset_not_declared",
];

/// Code prefix, then the language and the reference a finding without a
/// suggestion points at.
pub const ENGINE_REFERENCES: [(&str, &str, &str); 13] = [
    ("kql_", "KQL", "https://learn.microsoft.com/kusto/query/"),
    (
        "spl_",
        "SPL",
        "https://docs.splunk.com/Documentation/Splunk/latest/SearchReference",
    ),
    (
        "esql_",
        "ES|QL",
        "https://www.elastic.co/docs/reference/query-languages/esql",
    ),
    (
        "eql_",
        "EQL",
        "https://www.elastic.co/docs/reference/query-languages/eql",
    ),
    (
        "kuery_",
        "Kibana KQL",
        "https://www.elastic.co/docs/reference/query-languages/kql",
    ),
    (
        "lucene_",
        "Lucene query string",
        "https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query",
    ),
    (
        "ecs_",
        "ECS field",
        "https://www.elastic.co/docs/reference/ecs/ecs-field-reference",
    ),
    (
        "falco_",
        "Falco condition",
        "https://falco.org/docs/concepts/rules/conditions/",
    ),
    (
        "cql_",
        "CQL",
        "https://library.humio.com/crowdstrike-query-language/",
    ),
    (
        "yara_",
        "YARA rule",
        "https://yara.readthedocs.io/en/v4.5.2/writingrules.html",
    ),
    (
        "graylog_",
        "Graylog search query",
        "https://go2docs.graylog.org/current/making_sense_of_your_log_data/writing_search_queries.html",
    ),
    (
        "exabeam_",
        "Exabeam Query Language",
        "https://docs.exabeam.com/en/search/all/search-guide/",
    ),
    (
        "yaral_",
        "YARA-L 2.0",
        "https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax",
    ),
];

/// Whether `opentide lint` reports an engine warning of `code`: a query
/// language's (one with a reference), an Elastic advisory, Sysdig's list
/// self-reference, or an undeclared dataset. 0.28.1 added Graylog's dialect:
/// before, `graylog_analyzed_field` and `graylog_regex_operator` reached the
/// editor alone.
pub fn lint_owned(code: &str) -> bool {
    ENGINE_REFERENCES
        .iter()
        .any(|(prefix, _, _)| code.starts_with(prefix))
        || ELASTIC_ADVISORIES.contains(&code)
        || code == "sysdig_list_self_reference"
        || DECLARED_DATASET_CODES.contains(&code)
}

/// Words in an engine message that make its `suggestion` a replacement name.
const ENGINE_UNKNOWN: [&str; 3] = ["unknown", "deprecated", "not a command"];

/// Engine sentences that promise a step opentide does not offer, and what
/// opentide says instead: the engine asks to "declare" an SPL command an app
/// provides, and no configuration declares one.
const MESSAGE_CORRECTIONS: [(&str, &str, &str); 1] = [(
    "spl_unknown_command",
    "; if an app on the search head provides it, declare it",
    "; an app on the search head may provide it (opentide cannot declare app commands yet)",
)];

/// Held while a workspace's datasets are installed in the engines and its
/// queries checked: the installation is process-wide.
pub static ENGINE: Mutex<()> = Mutex::new(());

/// One engine finding, in the CLI's coordinates (1-based, code points,
/// `end_column` exclusive and on `end_line`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The engine's code.
    pub code: String,
    /// The engine's severity.
    pub severity: EngineSeverity,
    /// One sentence, in opentide's words.
    pub message: String,
    /// Where it starts.
    pub line: usize,
    /// Where it starts.
    pub column: usize,
    /// The line it ends on.
    pub end_line: usize,
    /// Exclusive.
    pub end_column: usize,
    /// The field the finding is about, when the engine names one.
    pub field_path: Vec<String>,
    /// A replacement or the next step.
    pub suggestion: Option<String>,
}

/// One query of one object file and what the engine found in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedQuery {
    /// The platform it runs on, as a `configurations` key: a block's key, or
    /// a hunt's `system`.
    pub platform: String,
    /// `kql`, `spl`, `esql`, ...
    pub language: String,
    /// Its path in the object, list items by index.
    pub field_path: Vec<String>,
    /// Where the query starts.
    pub line: usize,
    /// Where the query starts.
    pub column: usize,
    /// The stand-in `opentide new` wrote: not checked, not counted.
    pub placeholder: bool,
    /// What the engine found.
    pub findings: Vec<Finding>,
}

impl CheckedQuery {
    /// Whether the query runs on a `configurations` block (not a hunt).
    pub fn is_rule_query(&self) -> bool {
        self.field_path.first().map(String::as_str) == Some("configurations")
    }

    /// How many of its findings are errors.
    pub fn errors(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == EngineSeverity::Error)
            .count()
    }
}

/// The profiles of one workspace: its Elastic tenants, read from
/// [`ELASTIC_CONFIGURATION`]. Built by [`Profiles::install`], which also
/// installs the datasets of its [`VISIBILITY_CONFIGURATION`].
pub struct Profiles {
    host: MemoryWorkspace,
    /// Why the declared datasets could not be read, when they could not.
    pub visibility_problem: Option<String>,
}

impl Profiles {
    /// Reads the profiles of the workspace at `root` and installs its
    /// declared datasets in the engines: none when there is no
    /// `visibility.toml`, or it cannot be read or is not TOML (the
    /// configuration check reports that). Hold [`ENGINE`] while the queries
    /// are checked.
    pub fn install(fs: &dyn FileSystem, root: Option<&Path>) -> Self {
        let read = |relative: &str| -> Result<Option<String>, String> {
            let Some(root) = root else {
                return Ok(None);
            };
            let path = root.join(relative);
            if !fs.is_file(&path) {
                return Ok(None);
            }
            let bytes = fs.read(&path).map_err(|error| error.to_string())?;
            decode(&bytes).map(Some)
        };
        let visibility_problem = match read(VISIBILITY_CONFIGURATION)
            .and_then(|text| opentide_analysis::install_visibility(text.as_deref()))
        {
            Ok(()) => None,
            Err(problem) => {
                // Declares nothing; the configuration check reports the file.
                let _ = opentide_analysis::install_visibility(None);
                Some(format!(
                    "the declared datasets could not be read: {problem}"
                ))
            }
        };
        let files = match read(ELASTIC_CONFIGURATION) {
            Ok(Some(text)) => vec![(ELASTIC_CONFIGURATION.to_owned(), text)],
            _ => Vec::new(),
        };
        Self {
            host: MemoryWorkspace { files },
            visibility_problem,
        }
    }

    /// Every query in the object file `text` (as read, after a byte-order
    /// mark), each checked in its language with its platform's profile.
    pub fn check_object(&self, text: &str) -> Vec<CheckedQuery> {
        let text = universal_newlines(text);
        let lines = LineStarts::new(&text);
        opentide_analysis::analyze_queries(&self.host, &text)
            .into_iter()
            .map(|report| {
                let (line, column, _, _) = lines.convert(&text, report.range);
                CheckedQuery {
                    platform: report.platform,
                    language: report.language.as_str().to_owned(),
                    field_path: report.field_path,
                    line,
                    column,
                    placeholder: report.placeholder,
                    findings: report
                        .diagnostics
                        .into_iter()
                        .map(|diagnostic| finding(&text, &lines, diagnostic))
                        .collect(),
                }
            })
            .collect()
    }
}

impl Profiles {
    /// Everything the engine reports for the object file `text` at `path`
    /// (`check_file`): its queries' findings and the platform blocks'
    /// advisories. The language server publishes `validate`'s and `lint`'s
    /// findings instead, and the engine's own analysis leaves the blocks to
    /// `lint` (UC-2.6, #821), so they are asked for here.
    pub fn check_file(&self, path: &Path, text: &str) -> Vec<Finding> {
        let text = universal_newlines(text);
        let lines = LineStarts::new(&text);
        let response = opentide_analysis::analyze(
            &self.host,
            opentide_analysis::AnalyzeRequest {
                uri: path.to_string_lossy().into_owned(),
                language: opentide_analysis::LanguageId::TideYaml,
                text: text.clone().into_owned(),
            },
        );
        response
            .diagnostics
            .into_iter()
            .chain(opentide_analysis::analyze_blocks(&self.host, &text))
            .map(|diagnostic| finding(&text, &lines, diagnostic))
            .collect()
    }
}

/// One query on its own (a query file), in its own coordinates, with
/// `platform`'s profile when one is given (`check_query`). Hold [`ENGINE`]
/// with the workspace's [`Profiles`] installed: the declared datasets apply.
pub fn check_query_text(
    text: &str,
    language: opentide_analysis::LanguageId,
    platform: Option<&str>,
) -> Vec<Finding> {
    check_query_on_stack(text, language, platform, None)
}

/// [`check_query_text`] for an Elastic `stack` (`9.5`), which ES|QL's
/// checks read.
pub fn check_query_on_stack(
    text: &str,
    language: opentide_analysis::LanguageId,
    platform: Option<&str>,
    stack: Option<&str>,
) -> Vec<Finding> {
    let text = universal_newlines(text);
    let lines = LineStarts::new(&text);
    opentide_analysis::analyze_query(&opentide_analysis::QueryRequest {
        language,
        platform: platform.map(str::to_owned),
        stack: stack.map(str::to_owned),
        text: text.clone().into_owned(),
    })
    .into_iter()
    .map(|diagnostic| finding(&text, &lines, diagnostic))
    .collect()
}

/// The marker `opentide new` writes after a value to fill in.
static PLACEHOLDER_MARK: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    #[expect(clippy::expect_used, reason = "a literal pattern")]
    regex::Regex::new(r"\s#\s*opentide:placeholder\s*$").expect("valid regex")
});

/// Whether `line`, from a value's start, is the `...` stand-in `opentide
/// new` writes (`is_stand_in`).
pub fn is_stand_in(line: &str) -> bool {
    PLACEHOLDER_MARK.replace(line, "").trim() == "..."
}

/// Whether `finding` sits in a `...` stand-in under a marked key
/// (`_in_placeholder`); `marked` holds the 1-based marked lines.
fn in_placeholder(finding: &Finding, lines: &[&str], marked: &[usize]) -> bool {
    let line = finding.line;
    if !(marked.contains(&line) || marked.contains(&(line.wrapping_sub(1))))
        || line == 0
        || line > lines.len()
    {
        return false;
    }
    let mut text = lines[line - 1];
    if marked.contains(&line) {
        text = text.split_once(':').map_or(text, |(_, value)| value);
    }
    is_stand_in(text.trim_start())
}

/// The query engines' advisories that are lint's: Elastic's block settings.
const ELASTIC_ADVISORIES: [&str; 5] = [
    "lookback_zero",
    "lookback_long",
    "threshold_lookback",
    "risk_band",
    "technique_not_enterprise",
];

/// `lint`'s queries check on the query engines (`_query_findings`): each
/// object's query warnings and notes and its platform blocks' advisories. A
/// query the engine rejects is `validate`'s; a placeholder query is the
/// placeholders check's. Build it with [`EngineLintQueries::install`] and
/// hold [`ENGINE`] while lint runs.
pub struct EngineLintQueries {
    profiles: Profiles,
}

impl EngineLintQueries {
    /// The profiles of the workspace at `root`, installed.
    pub fn install(fs: &dyn FileSystem, root: &Path) -> Self {
        Self {
            profiles: Profiles::install(fs, Some(root)),
        }
    }
}

impl opentide_workspace::lint::LintQueryCheck for EngineLintQueries {
    fn check(
        &self,
        file: &Path,
        relative: &str,
        uuid: Option<&str>,
        text: &str,
    ) -> Result<Vec<opentide_workspace::lint::LintFinding>, String> {
        let text = universal_newlines(text);
        let lines: Vec<&str> = text.lines().collect();
        let marked: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| PLACEHOLDER_MARK.is_match(line))
            .map(|(number, _)| number + 1)
            .collect();
        let mut out = Vec::new();
        for item in self.profiles.check_file(file, &text) {
            if item.severity == EngineSeverity::Error || in_placeholder(&item, &lines, &marked) {
                continue;
            }
            if !lint_owned(&item.code) {
                continue;
            }
            let severity = if item.severity == EngineSeverity::Warning {
                Severity::Warning
            } else {
                Severity::Info
            };
            let diagnostic = engine_diagnostic(&item, severity, file, relative.to_owned());
            out.push(opentide_workspace::lint::LintFinding::from_engine(
                relative, uuid, diagnostic,
            ));
        }
        out.extend(block_advisories(file, relative, uuid, &text));
        Ok(out)
    }
}

/// The platforms' block advisories of an object file
/// (`_platform_advisory_findings`): each a `queries` warning at its field
/// path. A file that does not load as YAML has none: the parse error is
/// another check's finding.
fn block_advisories(
    file: &Path,
    relative: &str,
    uuid: Option<&str>,
    text: &str,
) -> Vec<opentide_workspace::lint::LintFinding> {
    let Ok(document) = opentide_schema::node::load(text) else {
        return Vec::new();
    };
    let Some(root) = document.root() else {
        return Vec::new();
    };
    let locator = document.locator();
    opentide_schema::objects::platform::block_advisories(root)
        .into_iter()
        .map(|advisory| {
            let mut diagnostic =
                Diagnostic::new(advisory.code, Severity::Warning, advisory.message)
                    .file(file)
                    .at(advisory.field_path);
            diagnostic.yaml_line = locator.yaml_line(&diagnostic.field_path);
            diagnostic.path = Some(relative.to_owned());
            diagnostic.line = diagnostic.yaml_line.map(|line| line + 1);
            opentide_workspace::lint::LintFinding::from_engine(relative, uuid, diagnostic)
        })
        .collect()
}

/// `bytes` as Python's `read_text(encoding="utf-8-sig")` reads them: without
/// a byte-order mark, every line ending a `\n`.
///
/// # Errors
///
/// The bytes are not UTF-8.
pub fn decode(bytes: &[u8]) -> Result<String, String> {
    let body = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    Ok(universal_newlines(text).into_owned())
}

/// `text` with `\r\n` and a lone `\r` read as `\n`, as a text-mode read reads
/// a file: the positions the CLI reports count lines so.
pub fn universal_newlines(text: &str) -> Cow<'_, str> {
    if text.contains('\r') {
        Cow::Owned(text.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        Cow::Borrowed(text)
    }
}

/// An engine finding in the CLI's coordinates: lines and columns from 1,
/// columns in code points (`opentide tui` places the language server's so).
pub fn finding(
    text: &str,
    lines: &LineStarts,
    diagnostic: opentide_analysis::Diagnostic,
) -> Finding {
    let (line, column, end_line, end_column) = lines.convert(text, diagnostic.range);
    let (end_line, end_column) = span_end(line, column, end_line, end_column, text);
    Finding {
        message: corrected_message(&diagnostic.code, diagnostic.message),
        code: diagnostic.code,
        severity: diagnostic.severity,
        line,
        column,
        end_line,
        end_column,
        field_path: diagnostic.field_path.unwrap_or_default(),
        suggestion: diagnostic.suggestion,
    }
}

/// `message`, without a promise of a setting opentide does not have.
fn corrected_message(code: &str, message: String) -> String {
    for (wanted, engine_text, replacement) in MESSAGE_CORRECTIONS {
        if code == wanted
            && let Some(kept) = message.strip_suffix(engine_text)
        {
            return format!("{kept}{replacement}");
        }
    }
    message
}

/// The end of a span on the line of its last character. The engine's end is
/// exclusive, so a span whose last character is a line's newline (an
/// "unexpected end" after `| where (`) ends at column 1 of the next line,
/// which holds none of it: it ends on the line before, after that line's
/// last character.
fn span_end(
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
    text: &str,
) -> (usize, usize) {
    if end_column != 1 || end_line <= line {
        return (end_line, end_column);
    }
    let last = end_line - 1;
    match text.split('\n').nth(last.wrapping_sub(1)) {
        Some(content) if last > 0 => {
            let length = content
                .strip_suffix('\r')
                .unwrap_or(content)
                .chars()
                .count();
            if last == line {
                (last, (length + 1).max(column + 1))
            } else {
                (last, length + 1)
            }
        }
        _ if last == line => (line, column + 1),
        _ => (end_line, end_column),
    }
}

/// The help line of an engine finding: `did you mean …?` for an unknown or
/// deprecated name, the step to take otherwise; without a suggestion, the
/// language reference, or the code's `opentide explain`.
pub fn engine_help(code: &str, message: &str, suggestion: Option<&str>) -> String {
    if let Some(suggestion) = suggestion.filter(|text| !text.is_empty()) {
        let lower = message.to_lowercase();
        if ENGINE_UNKNOWN.iter().any(|word| lower.contains(word)) {
            return format!(
                "did you mean {}?",
                opentide_schema::vocab::quote(suggestion)
            );
        }
        return format!("try: {suggestion}");
    }
    if !DECLARED_DATASET_CODES.contains(&code)
        && let Some((_, language, url)) = ENGINE_REFERENCES
            .iter()
            .find(|(prefix, _, _)| code.starts_with(prefix))
    {
        return format!("the {language} reference: {url}");
    }
    format!("opentide explain {code} describes it")
}

/// An engine finding in `file` as a diagnostic, placed where the engine
/// placed it (`diagnostic_from_engine`).
pub fn engine_diagnostic(
    finding: &Finding,
    severity: Severity,
    file: &Path,
    path: String,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::new(finding.code.clone(), severity, finding.message.clone())
        .file(file)
        .at(finding.field_path.iter().cloned())
        .suggest(finding.suggestion.clone());
    diagnostic.path = Some(path);
    diagnostic.line = Some(finding.line);
    diagnostic.column = Some(finding.column);
    diagnostic.end_line = Some(finding.end_line);
    diagnostic.end_column = Some(finding.end_column);
    diagnostic.help = Some(engine_help(
        &finding.code,
        &finding.message,
        finding.suggestion.as_deref(),
    ));
    diagnostic
}

fn number(value: usize) -> ContextValue {
    ContextValue::Number(serde_json::Number::from(value))
}

/// The queries check of `validate` on the query engines.
#[derive(Debug, Clone, Copy, Default)]
pub struct EngineQueries;

impl QueryCheck for EngineQueries {
    fn check(
        &self,
        ws: &Workspace,
        objects: &[QueryObject<'_>],
        as_warnings: bool,
    ) -> QueryFindings {
        let fs = ws.fs().as_ref();
        let root = ws.root();
        let _engine = ENGINE.lock().unwrap_or_else(PoisonError::into_inner);
        let profiles = Profiles::install(fs, Some(root));
        let mut found = QueryFindings::default();
        let severity = if as_warnings {
            Severity::Warning
        } else {
            Severity::Error
        };
        for object in objects {
            let mut shown = None;
            for query in profiles.check_object(object.source) {
                if query.placeholder {
                    continue;
                }
                found.queries += 1;
                for item in &query.findings {
                    if item.severity != EngineSeverity::Error {
                        // Style: lint's queries check.
                        continue;
                    }
                    let path = shown
                        .get_or_insert_with(|| relative_path(fs, object.path, root))
                        .clone();
                    let mut position = IndexMap::new();
                    position.insert("line".to_owned(), number(item.line));
                    position.insert("column".to_owned(), number(item.column));
                    position.insert("end_line".to_owned(), number(item.end_line));
                    position.insert("end_column".to_owned(), number(item.end_column));
                    let mut diagnostic = engine_diagnostic(item, severity, object.path, path)
                        .object(object.uuid, object.family)
                        .with("source", ENGINE_SOURCE)
                        .with("language", query.language.as_str())
                        .with("platform", query.platform.as_str())
                        .with("position", ContextValue::Map(position));
                    if diagnostic.field_path.is_empty() {
                        diagnostic.field_path.clone_from(&query.field_path);
                    }
                    diagnostic.yaml_line = Some(item.line - 1);
                    if as_warnings {
                        diagnostic = diagnostic.with(REPORTED_AS_WARNING, true);
                        diagnostic
                            .notes
                            .push(("note".to_owned(), REPORTED_AS_WARNING_NOTE.to_owned()));
                        found.warnings.push(diagnostic);
                    } else {
                        found.errors.push(diagnostic);
                    }
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_span_ending_after_a_newline_ends_on_its_own_line() {
        let text = "a\n| where (\nnext\n";
        // From line 2 column 9 to the start of line 3: the `(` and its newline.
        assert_eq!(span_end(2, 9, 3, 1, text), (2, 10));
        // Over several lines: the last line it covers, at its end.
        assert_eq!(span_end(1, 1, 3, 1, text), (2, 10));
        // A span that ends inside a line is kept.
        assert_eq!(span_end(2, 3, 3, 2, text), (3, 2));
        assert_eq!(span_end(2, 3, 2, 5, text), (2, 5));
        // Past the text: one character, where the line is.
        assert_eq!(span_end(9, 2, 10, 1, text), (9, 3));
        assert_eq!(span_end(1, 1, 12, 1, text), (12, 1));
    }

    #[test]
    fn lint_keeps_the_graylog_dialects_warnings() {
        // 0.28.1 (#1015): lint dropped them for want of a reference.
        for code in [
            "graylog_analyzed_field",
            "graylog_regex_operator",
            "graylog_regex_quote",
            "graylog_double_backslash",
        ] {
            assert!(lint_owned(code), "{code}");
        }
        assert!(lint_owned("sysdig_list_self_reference"));
        assert!(!lint_owned("vocab_unknown"));
        // A Graylog finding names Graylog's search syntax page.
        assert!(
            ENGINE_REFERENCES
                .iter()
                .any(|(prefix, language, _)| *prefix == "graylog_"
                    && *language == "Graylog search query")
        );
    }

    #[test]
    fn a_span_on_an_empty_line_still_marks_a_character() {
        assert_eq!(span_end(2, 1, 3, 1, "a\n\nb"), (2, 2));
    }

    #[test]
    fn the_spl_app_command_message_promises_nothing() {
        let said = corrected_message(
            "spl_unknown_command",
            "unknown command `x`; if an app on the search head provides it, declare it".into(),
        );
        assert_eq!(
            said,
            "unknown command `x`; an app on the search head may provide it (opentide cannot \
             declare app commands yet)"
        );
        let other = "x; if an app on the search head provides it, declare it";
        assert_eq!(
            corrected_message("kql_unknown_operator", other.into()),
            other
        );
    }

    #[test]
    fn help_names_the_replacement_the_step_the_reference_or_the_page() {
        assert_eq!(
            engine_help("kql_unknown_table", "unknown table 'X'", Some("Y")),
            "did you mean 'Y'?"
        );
        assert_eq!(
            engine_help("spl_x", "is Not A Command here", Some("stats")),
            "did you mean 'stats'?"
        );
        assert_eq!(
            engine_help("esql_x", "needs a source", Some("FROM logs-*")),
            "try: FROM logs-*"
        );
        assert_eq!(
            engine_help("falco_value_type", "abc is not a number", None),
            "the Falco condition reference: https://falco.org/docs/concepts/rules/conditions/"
        );
        assert_eq!(
            engine_help("kql_table_not_declared", "not declared", None),
            "opentide explain kql_table_not_declared describes it"
        );
        assert_eq!(
            engine_help("sysdig_list_self_reference", "x", None),
            "opentide explain sysdig_list_self_reference describes it"
        );
        assert_eq!(
            engine_help("kql_x", "x", Some("")),
            "the KQL reference: https://learn.microsoft.com/kusto/query/"
        );
    }

    /// A finding of the engine on `line`.
    fn at(line: usize) -> Finding {
        Finding {
            code: "kuery_free_text".into(),
            severity: EngineSeverity::Hint,
            message: String::new(),
            line,
            column: 1,
            end_line: line,
            end_column: 4,
            field_path: Vec::new(),
            suggestion: None,
        }
    }

    #[test]
    fn a_finding_in_a_marked_stand_in_is_the_placeholders_check_s() {
        let text = "a:\n  query: ...  # opentide:placeholder\n  b: |  # opentide:placeholder\n    \
                    ...\n  c: |  # opentide:placeholder\n    written ...\n  d: ...\n";
        let lines: Vec<&str> = text.lines().collect();
        let marked: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| PLACEHOLDER_MARK.is_match(line))
            .map(|(number, _)| number + 1)
            .collect();
        assert_eq!(marked, [2, 3, 5]);
        // Inline: the value after the key; on the next line: the line itself.
        assert!(in_placeholder(&at(2), &lines, &marked));
        assert!(in_placeholder(&at(4), &lines, &marked));
        // The marked key's own line holds `|`, not the stand-in.
        assert!(!in_placeholder(&at(3), &lines, &marked));
        // A value written under a marker, and a stand-in nobody marked.
        assert!(!in_placeholder(&at(6), &lines, &marked));
        assert!(!in_placeholder(&at(7), &lines, &marked));
        // Outside the text.
        assert!(!in_placeholder(&at(0), &lines, &marked));
        assert!(!in_placeholder(&at(9), &lines, &[8]));
    }

    #[test]
    fn files_are_read_as_text_mode_reads_them() {
        assert_eq!(decode(b"\xef\xbb\xbfa\r\nb\rc\n").unwrap(), "a\nb\nc\n");
        assert!(decode(b"\xff").is_err());
        assert!(matches!(universal_newlines("a\nb"), Cow::Borrowed(_)));
    }
}
