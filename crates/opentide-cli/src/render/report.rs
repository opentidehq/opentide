//! Findings as report files: SARIF 2.1.0 for code scanning, Code Climate JSON for GitLab.
//!
//! `validate --format sarif` and `lint --format codequality` build their
//! document here from the same [`Diagnostic`]s the code frames print. SARIF's
//! rules are every code validation and lint can emit, each described by its
//! `opentide explain` page, so an alert links to what the code means and how
//! to fix it. Columns are Unicode code points, and the run says so
//! (`columnKind: unicodeCodePoints`). Paths are relative to the repository
//! (the CI checkout when known, else the workspace), percent-encoded and based
//! on `%SRCROOT%`. A finding that names no file is left out of both reports:
//! code scanning and Code Quality both need a file; the job log and the
//! summary still carry it.

use super::codeframe::{PATH_SAFE, quote, quoted};
use super::diagnostic::{Diagnostic, Severity};
use super::summary::{DIAGNOSTICS_DOCS_URL, explain_url, split_lines};
use crate::envelope::{Failure, code};
use crate::json::Json;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

/// The SARIF schema a log names.
pub const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
/// The SARIF version.
pub const SARIF_VERSION: &str = "2.1.0";
/// The base every `artifactLocation.uri` resolves against: the repository root.
pub const SRCROOT: &str = "%SRCROOT%";

/// `--format`: the code frames people read, or a report file for a CI service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportFormat {
    /// Code frames.
    Text,
    /// SARIF 2.1.0.
    Sarif,
    /// GitLab Code Quality.
    Codequality,
}

impl ReportFormat {
    /// `text`, `sarif` or `codequality`.
    pub fn as_str(self) -> &'static str {
        match self {
            ReportFormat::Text => "text",
            ReportFormat::Sarif => "sarif",
            ReportFormat::Codequality => "codequality",
        }
    }
}

/// `--format`'s help.
pub const FORMAT_HELP: &str = "text: code frames. sarif: SARIF 2.1.0 for code scanning. codequality: GitLab Code Quality (Code Climate JSON). A report goes to --output, or to stdout instead of the text";
/// `--output`'s help.
pub const OUTPUT_HELP: &str =
    "Write the --format report to this file and print the usual text output too";

/// The usage error (exit 2) for report options that would write nothing or break stdout.
///
/// `--output` writes the `--format` report, so it needs a report format;
/// `--json` owns stdout, so a report needs `--output` there.
pub fn check_report_options(format: ReportFormat, output: bool, json: bool) -> Option<Failure> {
    let message = if format == ReportFormat::Text && output {
        "--output needs --format sarif or --format codequality".to_owned()
    } else if json && format != ReportFormat::Text && !output {
        format!(
            "--format {} with --json needs --output: stdout holds the JSON document",
            format.as_str()
        )
    } else {
        return None;
    };
    let mut failure = Failure::new(code::USAGE_INVALID_VALUE, message);
    failure.argument = Some("--output".to_owned());
    Some(failure)
}

/// One code's `opentide explain` page, as a SARIF rule describes it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct RulePage {
    /// The code.
    pub code: String,
    /// Whether nothing reports it any more (it stays explainable, plan §3).
    #[serde(default)]
    pub retired: bool,
    /// The page's one-sentence summary; `None` without a page.
    #[serde(default)]
    pub summary: Option<String>,
    /// The page's Markdown.
    #[serde(default)]
    pub markdown: Option<String>,
}

/// Every code validation and lint can emit, and every code with a page, in code order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleCatalogue {
    /// The pages, sorted by code.
    pub rules: Vec<RulePage>,
}

static PAGE_SEVERITY: LazyLock<Regex> = LazyLock::new(|| {
    #[expect(clippy::expect_used, reason = "a literal pattern")]
    Regex::new(r"(?m)^Severity: (error|warning|note)\b").expect("valid regex")
});
static HEADING: LazyLock<Regex> = LazyLock::new(|| {
    #[expect(clippy::expect_used, reason = "a literal pattern")]
    Regex::new(r"^#{1,6}\s+").expect("valid regex")
});
static LINK: LazyLock<Regex> = LazyLock::new(|| {
    #[expect(clippy::expect_used, reason = "a literal pattern")]
    Regex::new(r"\[([^\]]*)\]\(([^)\s]*)\)").expect("valid regex")
});

/// `**x**` and `__x__`: Markdown's strong emphasis, leftmost first.
static EMPHASIS: LazyLock<Regex> = LazyLock::new(|| {
    #[expect(clippy::expect_used, reason = "a literal pattern")]
    Regex::new(r"\*\*(.+?)\*\*|__(.+?)__").expect("valid regex")
});

/// `**x**` and `__x__` as `x`.
fn drop_emphasis(line: &str) -> String {
    EMPHASIS.replace_all(line, "$1$2").into_owned()
}

/// An explain page as the plain text SARIF wants in `help.text`: no heading
/// marks, code fences, backticks or emphasis, and a link as `text (url)`.
pub fn plain_text(markdown: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    for line in split_lines(markdown) {
        if line.trim_start().starts_with("```") {
            continue;
        }
        let line = HEADING.replace(line, "");
        let line = LINK.replace_all(&line, "$1 ($2)");
        let line = drop_emphasis(&line);
        lines.push(line.replace('`', ""));
    }
    lines.join("\n").trim().to_owned()
}

/// `vocab_unknown` as `VocabUnknown`.
fn rule_name(code: &str) -> String {
    code.split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
            })
        })
        .collect()
}

/// A SARIF `reportingDescriptor` from a code's page.
pub fn sarif_rule(page: &RulePage) -> Json {
    let mut rule = vec![
        ("id", Json::str(&page.code)),
        ("name", Json::str(rule_name(&page.code))),
        ("helpUri", Json::str(explain_url(&page.code))),
    ];
    if page.retired {
        // Kept so a baseline or suppression that names it still resolves (plan §3).
        rule.push((
            "properties",
            Json::object([("tags", Json::Array(vec![Json::str("retired")]))]),
        ));
    }
    if let (Some(summary), Some(markdown)) = (&page.summary, &page.markdown) {
        rule.push((
            "shortDescription",
            Json::object([("text", Json::str(summary))]),
        ));
        rule.push((
            "fullDescription",
            Json::object([("text", Json::str(summary))]),
        ));
        rule.push((
            "help",
            Json::object([
                ("text", Json::str(plain_text(markdown))),
                ("markdown", Json::str(markdown)),
            ]),
        ));
        // A retired code's page names the severity it had while it was
        // reported; nothing reports it now, so it has no level to configure
        // (0.28.1 writes none for these codes).
        if !page.retired
            && let Some(found) = PAGE_SEVERITY.captures(markdown)
        {
            rule.push((
                "defaultConfiguration",
                Json::object([("level", Json::str(&found[1]))]),
            ));
        }
    }
    Json::object(rule)
}

fn int(value: usize) -> Json {
    i64::try_from(value).map_or(Json::UInt(value as u64), Json::Int)
}

/// A repository-relative path as a SARIF `artifactLocation`: a URI reference,
/// so a space, `#` or `%` is percent-encoded and `/` stays a separator.
pub fn artifact_location(path: &str) -> Json {
    Json::object([
        ("uri", Json::str(quote(path, PATH_SAFE))),
        ("uriBaseId", Json::str(SRCROOT)),
    ])
}

/// Stable across runs and line moves; repeated findings get their occurrence number.
fn fingerprint(diagnostic: &Diagnostic, path: &str, seen: &mut HashMap<String, usize>) -> String {
    let key = [
        diagnostic.code.as_str(),
        path,
        &diagnostic.field_path.join("/"),
        diagnostic.message.as_str(),
    ]
    .join("\u{1f}");
    let occurrence = seen.entry(key.clone()).or_insert(0);
    let digest = Sha256::digest(format!("{key}\u{1f}{occurrence}").as_bytes());
    *occurrence += 1;
    digest
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn region(diagnostic: &Diagnostic) -> Option<Json> {
    let line = diagnostic.line?;
    let mut region = vec![("startLine", int(line))];
    if diagnostic.multiline()
        && let Some(last) = diagnostic.last_line()
    {
        region.push(("endLine", int(last)));
    }
    if let Some(column) = diagnostic.column {
        region.push(("startColumn", int(column)));
        if let Some(end_column) = diagnostic.end_column
            && (diagnostic.multiline() || end_column > column)
        {
            // SARIF's endColumn is exclusive, like ours, and on endLine.
            region.push(("endColumn", int(end_column)));
        }
    }
    Some(Json::object(region))
}

fn sarif_fixes(diagnostic: &Diagnostic, path: &str) -> Option<Json> {
    let fix = diagnostic
        .fix
        .as_ref()
        .filter(|fix| !fix.edits.is_empty())?;
    let replacements = fix
        .edits
        .iter()
        .map(|edit| {
            Json::object([
                (
                    "deletedRegion",
                    Json::object([
                        ("startLine", int(edit.line)),
                        ("startColumn", int(edit.column)),
                        ("endLine", int(edit.last_line())),
                        ("endColumn", int(edit.end_column)),
                    ]),
                ),
                (
                    "insertedContent",
                    Json::object([("text", Json::str(&edit.replacement))]),
                ),
            ])
        })
        .collect();
    let values: Vec<String> = fix
        .edits
        .iter()
        .map(|edit| quoted(&edit.replacement))
        .collect();
    let mut description = format!("Replace with {}", values.join(", "));
    if fix.safe {
        description.push_str(" (safe to apply without review)");
    }
    Some(Json::Array(vec![Json::object([
        (
            "description",
            Json::object([("text", Json::str(description))]),
        ),
        (
            "artifactChanges",
            Json::Array(vec![Json::object([
                ("artifactLocation", artifact_location(path)),
                ("replacements", Json::Array(replacements)),
            ])]),
        ),
    ])]))
}

/// The path to report a diagnostic under, or `None` when it names no file.
pub type PathFor<'a> = &'a dyn Fn(&Diagnostic) -> Option<String>;

/// A diagnostic's own workspace path.
pub fn own_path(diagnostic: &Diagnostic) -> Option<String> {
    diagnostic.path.clone()
}

/// One SARIF 2.1.0 log with one run of opentide `command`.
///
/// The driver lists a rule for every code of `catalogue`, then any code a
/// finding carries that is not there. `automationDetails.id` is
/// `opentide/<command>/`, so code scanning keeps `validate` and `lint` apart.
/// A finding about one object names its UUID as a logical location.
pub fn sarif_report(
    diagnostics: &[Diagnostic],
    command: &str,
    version: &str,
    catalogue: &RuleCatalogue,
    path_for: PathFor<'_>,
) -> Json {
    let mut pages: Vec<RulePage> = catalogue.rules.clone();
    let known: BTreeSet<&str> = catalogue
        .rules
        .iter()
        .map(|page| page.code.as_str())
        .collect();
    let extra: BTreeSet<&str> = diagnostics
        .iter()
        .map(|item| item.code.as_str())
        .filter(|code| !known.contains(code))
        .collect();
    pages.extend(extra.into_iter().map(|code| RulePage {
        code: code.to_owned(),
        retired: false,
        summary: None,
        markdown: None,
    }));
    let index: HashMap<&str, usize> = pages
        .iter()
        .enumerate()
        .map(|(position, page)| (page.code.as_str(), position))
        .collect();
    let mut seen = HashMap::new();
    let mut results = Vec::new();
    for diagnostic in diagnostics {
        let Some(path) = path_for(diagnostic) else {
            continue;
        };
        let mut physical = vec![("artifactLocation", artifact_location(&path))];
        if let Some(region) = region(diagnostic) {
            physical.push(("region", region));
        }
        let mut location = vec![("physicalLocation", Json::object(physical))];
        if let Some(uuid) = diagnostic
            .object_uuid
            .as_ref()
            .filter(|uuid| !uuid.is_empty())
        {
            location.push((
                "logicalLocations",
                Json::Array(vec![Json::object([
                    ("name", Json::str(uuid)),
                    ("kind", Json::str("object")),
                ])]),
            ));
        }
        let mut text = diagnostic.message.clone();
        if let Some(help) = diagnostic.help.as_ref().filter(|help| !help.is_empty()) {
            text.push_str(&format!("\nhelp: {help}"));
        }
        let mut result = vec![
            ("ruleId", Json::str(&diagnostic.code)),
            (
                "ruleIndex",
                int(index.get(diagnostic.code.as_str()).copied().unwrap_or(0)),
            ),
            ("level", Json::str(diagnostic.severity.as_str())),
            ("message", Json::object([("text", Json::str(text))])),
            ("locations", Json::Array(vec![Json::object(location)])),
            (
                "partialFingerprints",
                Json::object([(
                    "opentide/v1",
                    Json::str(fingerprint(diagnostic, &path, &mut seen)),
                )]),
            ),
        ];
        if let Some(fixes) = sarif_fixes(diagnostic, &path) {
            result.push(("fixes", fixes));
        }
        results.push(Json::object(result));
    }
    let slug = command.split_whitespace().collect::<Vec<_>>().join("-");
    Json::object([
        ("$schema", Json::str(SARIF_SCHEMA)),
        ("version", Json::str(SARIF_VERSION)),
        (
            "runs",
            Json::Array(vec![Json::object([
                (
                    "tool",
                    Json::object([(
                        "driver",
                        Json::object([
                            ("name", Json::str("opentide")),
                            ("version", Json::str(version)),
                            ("informationUri", Json::str(DIAGNOSTICS_DOCS_URL)),
                            ("rules", Json::Array(pages.iter().map(sarif_rule).collect())),
                        ]),
                    )]),
                ),
                (
                    "automationDetails",
                    Json::object([("id", Json::str(format!("opentide/{slug}/")))]),
                ),
                ("columnKind", Json::str("unicodeCodePoints")),
                ("results", Json::Array(results)),
            ])]),
        ),
    ])
}

/// GitLab Code Quality severities: `info`, `minor`, `major`.
pub fn codequality_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "major",
        Severity::Warning => "minor",
        Severity::Note => "info",
    }
}

/// The array GitLab reads from `artifacts:reports:codequality`.
pub fn codequality_report(diagnostics: &[Diagnostic], path_for: PathFor<'_>) -> Json {
    let mut seen = HashMap::new();
    let mut issues = Vec::new();
    for diagnostic in diagnostics {
        let Some(path) = path_for(diagnostic) else {
            continue;
        };
        let mut description = diagnostic.message.clone();
        if let Some(help) = diagnostic.help.as_ref().filter(|help| !help.is_empty()) {
            description.push_str(&format!(" (help: {help})"));
        }
        let category = if diagnostic.severity == Severity::Error {
            "Bug Risk"
        } else {
            "Style"
        };
        let begin = diagnostic.line.filter(|line| *line != 0).unwrap_or(1);
        issues.push(Json::object([
            ("type", Json::str("issue")),
            ("check_name", Json::str(&diagnostic.code)),
            ("description", Json::str(description)),
            ("categories", Json::Array(vec![Json::str(category)])),
            (
                "severity",
                Json::str(codequality_severity(diagnostic.severity)),
            ),
            (
                "fingerprint",
                Json::str(fingerprint(diagnostic, &path, &mut seen)),
            ),
            (
                "location",
                Json::object([
                    ("path", Json::str(&path)),
                    ("lines", Json::object([("begin", int(begin))])),
                ]),
            ),
        ]));
    }
    Json::Array(issues)
}

/// The report's text, indented by two spaces, ending in one newline: what
/// `--output` writes, and what stdout gets without it. `None` for `text`.
pub fn report_text(
    format: ReportFormat,
    diagnostics: &[Diagnostic],
    command: &str,
    version: &str,
    catalogue: &RuleCatalogue,
    path_for: PathFor<'_>,
) -> Option<String> {
    let document = match format {
        ReportFormat::Text => return None,
        ReportFormat::Sarif => sarif_report(diagnostics, command, version, catalogue, path_for),
        ReportFormat::Codequality => codequality_report(diagnostics, path_for),
    };
    Some(crate::json::document_text(&document, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_drops_markdown() {
        let markdown =
            "# code\n\nA **bold** and __x__ [link](https://x.y) `c`.\n\n```yaml\nk: v\n```\n**open";
        assert_eq!(
            plain_text(markdown),
            "code\n\nA bold and x link (https://x.y) c.\n\nk: v\n**open"
        );
        assert_eq!(drop_emphasis("****"), "****");
        assert_eq!(drop_emphasis("**a**b**"), "ab**");
        assert_eq!(split_lines("a\r\nb\u{2028}c\n"), ["a", "b", "c"]);
    }

    #[test]
    fn rules_and_names() {
        assert_eq!(rule_name("vocab_unknown"), "VocabUnknown");
        assert_eq!(rule_name("kql_PARSE"), "KqlParse");
        let retired = RulePage {
            code: "old_code".into(),
            retired: true,
            summary: None,
            markdown: None,
        };
        let rule = crate::json::document_text(&sarif_rule(&retired), false);
        assert!(
            rule.contains("\"properties\":{\"tags\":[\"retired\"]}"),
            "{rule}"
        );
        // A retired code's page names its old severity; its rule has no level.
        let page = |retired: bool| RulePage {
            code: "old_code".into(),
            retired,
            summary: Some("Retired.".into()),
            markdown: Some(
                "# old_code\n\nRetired.\n\nSeverity: warning, while it was reported.\n".into(),
            ),
        };
        let rule = crate::json::document_text(&sarif_rule(&page(true)), false);
        assert!(!rule.contains("defaultConfiguration"), "{rule}");
        let rule = crate::json::document_text(&sarif_rule(&page(false)), false);
        assert!(
            rule.contains("\"defaultConfiguration\":{\"level\":\"warning\"}"),
            "{rule}"
        );
    }

    #[test]
    fn report_options() {
        assert!(check_report_options(ReportFormat::Text, false, true).is_none());
        assert!(check_report_options(ReportFormat::Sarif, true, true).is_none());
        let failure = check_report_options(ReportFormat::Text, true, false).unwrap();
        assert_eq!(
            failure.message,
            "--output needs --format sarif or --format codequality"
        );
        assert_eq!(failure.code, "usage_invalid_value");
        assert_eq!(
            check_report_options(ReportFormat::Codequality, false, true)
                .unwrap()
                .message,
            "--format codequality with --json needs --output: stdout holds the JSON document"
        );
        assert_eq!(
            report_text(
                ReportFormat::Text,
                &[],
                "x",
                "1",
                &RuleCatalogue::default(),
                &own_path
            ),
            None
        );
    }

    #[test]
    fn codequality_line_defaults_to_one() {
        let mut item = Diagnostic::new("x", Severity::Note, "m");
        item.path = Some("a b.yaml".into());
        let text = crate::json::document_text(&codequality_report(&[item], &own_path), false);
        assert!(text.contains("\"lines\":{\"begin\":1}"), "{text}");
        assert!(text.contains("\"severity\":\"info\""));
    }

    fn parsed(json: &Json) -> serde_json::Value {
        serde_json::from_str(&crate::json::document_text(json, false)).unwrap_or_default()
    }

    #[test]
    fn identical_findings_get_distinct_stable_fingerprints() {
        let mut item = Diagnostic::new("vocab_unknown", Severity::Error, "m");
        item.path = Some("a.yaml".into());
        item.field_path = vec!["tlp".into()];
        let items = [item.clone(), item];
        let sarif = |items: &[Diagnostic]| -> Vec<String> {
            let report = parsed(&sarif_report(
                items,
                "validate",
                "1",
                &RuleCatalogue::default(),
                &own_path,
            ));
            report["runs"][0]["results"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|result| result["partialFingerprints"]["opentide/v1"].to_string())
                .collect()
        };
        let quality = |items: &[Diagnostic]| -> Vec<String> {
            parsed(&codequality_report(items, &own_path))
                .as_array()
                .into_iter()
                .flatten()
                .map(|issue| issue["fingerprint"].to_string())
                .collect()
        };
        for fingerprints in [sarif(&items), quality(&items)] {
            assert_eq!(fingerprints.len(), 2);
            assert_ne!(fingerprints[0], fingerprints[1]);
        }
        // The same input, the same pair: stable across runs.
        assert_eq!(sarif(&items), sarif(&items));
        assert_eq!(quality(&items), quality(&items));
        // The first occurrence is the one a single finding gets.
        assert_eq!(sarif(&items[..1])[0], sarif(&items)[0]);
    }

    #[test]
    fn a_zero_width_region_has_no_end_column() {
        let mut item = Diagnostic::new("x", Severity::Error, "m");
        item.line = Some(3);
        item.column = Some(5);
        item.end_column = Some(5);
        let shown = |item: &Diagnostic| {
            crate::json::document_text(&region(item).unwrap_or(Json::Null), false)
                .trim_end()
                .to_owned()
        };
        assert_eq!(shown(&item), "{\"startLine\":3,\"startColumn\":5}");
        item.end_column = Some(6);
        assert_eq!(
            shown(&item),
            "{\"startLine\":3,\"startColumn\":5,\"endColumn\":6}"
        );
        item.end_column = Some(2);
        item.end_line = Some(4);
        assert_eq!(
            shown(&item),
            "{\"startLine\":3,\"endLine\":4,\"startColumn\":5,\"endColumn\":2}"
        );
    }

    #[test]
    fn emphasis_of_either_kind_is_dropped_leftmost_first() {
        assert_eq!(drop_emphasis("__a__ and **b**"), "a and b");
        assert_eq!(drop_emphasis("**a__b**__"), "a__b__");
        assert_eq!(drop_emphasis("__**a**__"), "**a**");
        assert_eq!(drop_emphasis("a__"), "a__");
    }
}
