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
//! The datasets a workspace declares are its [`Profiles`]': each check
//! enters them on the thread that runs it, so checks of different
//! workspaces run at once and take no lock (#1142).

use std::borrow::Cow;
use std::path::Path;
use std::sync::Mutex;

use crate::{LineStarts, MemoryWorkspace, Severity as EngineSeverity};
use indexmap::IndexMap;
use opentide_schema::objects::platform::graylog::{self, ConfiguredTenant};
use opentide_workspace::diagnostic::ContextValue;
use opentide_workspace::validate::annotate::relative_path;
use opentide_workspace::validate::{QueryCheck, QueryFindings, QueryObject};
use opentide_workspace::{Diagnostic, FileSystem, Severity, Workspace};
use rayon::prelude::*;

/// Graylog's `configurations` key, and the platform of its queries.
const GRAYLOG: &str = "graylog";

/// The engine's code for a leading `*` or `?` in a Graylog query.
const LEADING_WILDCARD: &str = "graylog_leading_wildcard";

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

/// Where the Graylog tenants are read from: their `allow_leading_wildcard`
/// and `streams` decide `graylog_leading_wildcard` and `graylog_all_streams`.
pub const GRAYLOG_CONFIGURATION: &str = ".opentide/configurations/platforms/graylog.toml";

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
    ("yara_", "YARA rule", "https://virustotal.github.io/yara-x/"),
    (
        "graylog_",
        "Graylog search query",
        "https://go2docs.graylog.org/current/making_sense_of_your_log_data/writing_search_queries.html",
    ),
    (
        "exabeam_",
        "Exabeam Query Language",
        "https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-syntax.html",
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
    opentide_schema::objects::platform::harfanglab::yara::ADVISORY_CODES.contains(&code)
        || ENGINE_REFERENCES
            .iter()
            .any(|(prefix, _, _)| code.starts_with(prefix))
        || ELASTIC_ADVISORIES.contains(&code)
        || code == opentide_core::codes::SYSDIG_LIST_SELF_REFERENCE
        || DECLARED_DATASET_CODES.contains(&code)
}

/// Words in an engine message that make its `suggestion` a replacement name.
const ENGINE_UNKNOWN: [&str; 3] = ["unknown", "deprecated", "not a command"];

/// Held by a host while it installs datasets or catalogs for the whole
/// process. Nothing in opentide takes it any more (#1142): the queries
/// checks of [`Profiles`] and the TUI's catalog are scoped to the threads
/// that use them. Never hold it around a thread pool whose jobs could take
/// it, as a pool's thread that waits for its jobs runs other jobs
/// meanwhile, one that takes this lock included.
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
/// [`ELASTIC_CONFIGURATION`], and the datasets its
/// [`VISIBILITY_CONFIGURATION`] declares. Its checks use them on whatever
/// thread runs them, without installing anything for the process (#1142):
/// it needs no lock, and runs on other threads, nested thread pools
/// included, are not affected.
pub struct Profiles {
    host: MemoryWorkspace,
    /// The declared datasets every check of these profiles uses.
    datasets: crate::Datasets,
    /// Why the declared datasets could not be read, when they could not.
    pub visibility_problem: Option<String>,
    /// The workspace's Graylog tenants ([`GRAYLOG_CONFIGURATION`]); none when
    /// the file is missing or is not TOML (the configuration check reports it).
    pub graylog_tenants: Vec<ConfiguredTenant>,
}

impl Profiles {
    /// Reads the profiles of the workspace at `root`: with its declared
    /// datasets, or the host's when there is no `visibility.toml`; none when
    /// it cannot be read or is not TOML (the configuration check reports
    /// that). Nothing is installed: the name says what it replaced.
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
        let (datasets, visibility_problem) = match read(VISIBILITY_CONFIGURATION)
            .and_then(|text| crate::Datasets::of_workspace(text.as_deref()))
        {
            Ok(datasets) => (datasets, None),
            Err(problem) => (
                // The host's; the configuration check reports the file.
                crate::Datasets::of_workspace(None).unwrap_or_default(),
                Some(format!(
                    "the declared datasets could not be read: {problem}"
                )),
            ),
        };
        let files = match read(ELASTIC_CONFIGURATION) {
            Ok(Some(text)) => vec![(ELASTIC_CONFIGURATION.to_owned(), text)],
            _ => Vec::new(),
        };
        let graylog_tenants = match read(GRAYLOG_CONFIGURATION) {
            Ok(Some(text)) => opentide_schema::configuration::toml::parse(&text)
                .map(|config| graylog::tenants_of(Some(&config)))
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        Self {
            host: MemoryWorkspace { files },
            datasets,
            visibility_problem,
            graylog_tenants,
        }
    }

    /// Every query in the object file `text` (as read, after a byte-order
    /// mark), each checked in its language with its platform's profile.
    pub fn check_object(&self, text: &str) -> Vec<CheckedQuery> {
        let text = universal_newlines(text);
        let lines = LineStarts::new(&text);
        let reports = self
            .datasets
            .scope(|| crate::analyze_queries(&self.host, &text));
        let mut checked: Vec<CheckedQuery> = reports
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
            .collect();
        self.allow_leading_wildcards(&text, &mut checked);
        one_secops_rule(checked)
    }

    /// [`check_query_on_stack`] with these profiles' declared datasets.
    pub fn check_query(
        &self,
        text: &str,
        language: crate::LanguageId,
        platform: Option<&str>,
        stack: Option<&str>,
    ) -> Vec<Finding> {
        self.datasets
            .scope(|| check_query_on_stack(text, language, platform, stack))
    }

    /// These profiles' declared datasets in use on this thread until the
    /// guard drops: for engine calls outside the checks above.
    pub fn enter(&self) -> crate::DatasetsScope {
        self.datasets.enter()
    }

    /// The Graylog queries of `text` without `graylog_leading_wildcard` when
    /// every tenant the rule's Graylog block reaches sets
    /// `allow_leading_wildcard = true` (`_graylog_findings`): those servers take
    /// a leading `*` or `?`. With no tenant the code stays an error.
    fn allow_leading_wildcards(&self, text: &str, checked: &mut [CheckedQuery]) {
        let wildcard = |finding: &Finding| finding.code == LEADING_WILDCARD;
        if !checked
            .iter()
            .any(|query| query.platform == GRAYLOG && query.findings.iter().any(wildcard))
        {
            return;
        }
        let Ok(document) = opentide_schema::node::load(text) else {
            return; // an unparsable file keeps every finding
        };
        let Some(block) = document
            .root()
            .and_then(|root| root.get("configurations"))
            .and_then(|configurations| configurations.get("graylog"))
        else {
            return;
        };
        let tenants: Vec<_> = self
            .graylog_tenants
            .iter()
            .map(ConfiguredTenant::view)
            .collect();
        if !graylog::leading_wildcard_allowed(block, &tenants) {
            return;
        }
        for query in checked.iter_mut().filter(|query| query.platform == GRAYLOG) {
            query.findings.retain(|finding| !wildcard(finding));
        }
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
        let (response, blocks) = self.datasets.scope(|| {
            (
                crate::analyze(
                    &self.host,
                    crate::AnalyzeRequest {
                        uri: path.to_string_lossy().into_owned(),
                        language: crate::LanguageId::TideYaml,
                        text: text.clone().into_owned(),
                    },
                ),
                crate::analyze_blocks(&self.host, &text),
            )
        });
        response
            .diagnostics
            .into_iter()
            .chain(blocks)
            .map(|diagnostic| finding(&text, &lines, diagnostic))
            .collect()
    }

    /// [`Profiles::check_file`] on `text` (its line endings `\n`), whose
    /// parse after its byte-order mark is `document`: the queries and the
    /// blocks are read from that one tree (#1233).
    fn check_parsed(
        &self,
        path: &Path,
        text: &str,
        document: &opentide_core::node::Document,
    ) -> Vec<Finding> {
        let lines = LineStarts::new(text);
        // The workspace's datasets, on the thread of lint's job (#1142).
        let (response, blocks) = self.datasets.scope(|| {
            (
                crate::analyze_tide_parsed(&self.host, &path.to_string_lossy(), text, document),
                crate::analyze_blocks_parsed(&self.host, text, document),
            )
        });
        response
            .diagnostics
            .into_iter()
            .chain(blocks)
            .map(|diagnostic| finding(text, &lines, diagnostic))
            .collect()
    }
}

/// One query on its own (a query file), in its own coordinates, with
/// `platform`'s profile when one is given (`check_query`), with the
/// datasets in use on this thread: [`Profiles::check_query`] checks it with
/// a workspace's.
pub fn check_query_text(
    text: &str,
    language: crate::LanguageId,
    platform: Option<&str>,
) -> Vec<Finding> {
    check_query_on_stack(text, language, platform, None)
}

/// [`check_query_text`] for an Elastic `stack` (`9.5`), which ES|QL's
/// checks read.
pub fn check_query_on_stack(
    text: &str,
    language: crate::LanguageId,
    platform: Option<&str>,
    stack: Option<&str>,
) -> Vec<Finding> {
    let text = universal_newlines(text);
    let lines = LineStarts::new(&text);
    crate::analyze_query(&crate::QueryRequest {
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
/// placeholders check's. Build it with [`EngineLintQueries::install`].
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
        Ok(self.findings(file, relative, uuid, text, None))
    }

    fn check_parsed(
        &self,
        file: &Path,
        relative: &str,
        uuid: Option<&str>,
        text: &str,
        document: &opentide_schema::node::Document,
    ) -> Result<Vec<opentide_workspace::lint::LintFinding>, String> {
        Ok(self.findings(file, relative, uuid, text, Some(document)))
    }
}

impl EngineLintQueries {
    /// The queries check's findings on `text`, reading its YAML tree from
    /// `parsed` when lint already parsed it (#1233).
    fn findings(
        &self,
        file: &Path,
        relative: &str,
        uuid: Option<&str>,
        text: &str,
        parsed: Option<&opentide_schema::node::Document>,
    ) -> Vec<opentide_workspace::lint::LintFinding> {
        let text = universal_newlines(text);
        // The tree is `text`'s as the checks read it only when no line ending
        // was rewritten; otherwise they parse the rewritten text, as before.
        let parsed = parsed.filter(|_| matches!(text, Cow::Borrowed(_)));
        let loaded;
        let document = match parsed {
            Some(document) => Some(document),
            None => {
                loaded = opentide_schema::node::load(&text).ok();
                loaded.as_ref()
            }
        };
        let lines: Vec<&str> = text.lines().collect();
        let marked: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| PLACEHOLDER_MARK.is_match(line))
            .map(|(number, _)| number + 1)
            .collect();
        let mut out = Vec::new();
        let harfanglab = HarfangLabAdvisories::of(&text, document);
        // Lint's parse is of the text after its byte-order mark, as the
        // engine reads it; the check's own parse above is the advisories'.
        let checked = match parsed {
            Some(document) => self.profiles.check_parsed(file, &text, document),
            None => self.profiles.check_file(file, &text),
        };
        for item in checked {
            if item.severity == EngineSeverity::Error || in_placeholder(&item, &lines, &marked) {
                continue;
            }
            // One finding per code, form and rule: opentide's, placed by key.
            if harfanglab.reports(&item) {
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
        out.extend(document.map_or_else(Vec::new, |document| {
            block_advisories(
                file,
                relative,
                uuid,
                document,
                &self.profiles.graylog_tenants,
            )
        }));
        out.extend(harfanglab.findings(file, relative, uuid));
        out
    }
}

use opentide_schema::objects::platform::harfanglab::yara::{
    ADVISORY_CODES as HARFANGLAB_ADVISORIES, CONTEXT_PATH, SIGNATURE_PATH,
};

/// The HarfangLab profile's advisories on a rule file (`_harfanglab_yara_findings`):
/// `yara_meta_missing` and `harfanglab_yara_context` are warnings, which
/// HarfangLab takes, but may not scan where the author meant. opentide's own,
/// on a `yara.signature` or the decomposed form's `meta.context`, placed in
/// the file; the engine's finding with the same key gives way to it.
struct HarfangLabAdvisories {
    /// `(code, message, 0-based line, field path, rule)`.
    found: Vec<(&'static str, String, usize, &'static [&'static str], String)>,
    /// The signature's rules, each with the 0-based file line of its header;
    /// `None` in the decomposed form.
    rules: Option<Vec<(String, usize)>>,
}

impl HarfangLabAdvisories {
    /// The advisories on `text`, whose parse is `document` (`None`: it does
    /// not parse).
    fn of(text: &str, document: Option<&opentide_schema::node::Document>) -> Self {
        let none = Self {
            found: Vec::new(),
            rules: None,
        };
        if !text.contains("harfanglab") {
            return none;
        }
        let Some(document) = document else {
            return none;
        };
        let Some(root) = document.root() else {
            return none;
        };
        let yara = SIGNATURE_PATH[..3]
            .iter()
            .try_fold(root.as_ref(), |node, key| node.get(key).map(AsRef::as_ref));
        let Some(yara) = yara else {
            return none;
        };
        if let Some(signature) = yara.get("signature") {
            let Some(value) = signature.value.as_str() else {
                return none;
            };
            let line_of = signature_lines(text, signature, value);
            let found = opentide_schema::objects::platform::harfanglab::yara::advisories(value)
                .into_iter()
                .map(|advisory| {
                    (
                        advisory.code,
                        advisory.message,
                        line_of(advisory.offset),
                        &SIGNATURE_PATH[..],
                        advisory.rule,
                    )
                })
                .collect();
            let rules = opentide_schema::objects::platform::harfanglab::yara::rule_headers(value)
                .into_iter()
                .map(|header| (header.name, line_of(header.start)))
                .collect();
            return Self {
                found,
                rules: Some(rules),
            };
        }
        let Some(entry) = yara.get("meta").and_then(|meta| meta.entry("context")) else {
            return none;
        };
        let os = yara
            .get("meta")
            .and_then(|meta| meta.get("os"))
            .and_then(|os| os.value.as_str());
        let found = opentide_schema::objects::platform::harfanglab::yara::decomposed_advisory(
            &entry.value,
            os,
        )
        .map(|(code, message)| {
            (
                code,
                message,
                entry.key.start.line().saturating_sub(1),
                &CONTEXT_PATH[..],
                String::new(),
            )
        })
        .into_iter()
        .collect();
        Self { found, rules: None }
    }

    /// Whether opentide's own check reports the engine `item`'s advisory:
    /// the same code, form (signature or decomposed) and YARA rule.
    fn reports(&self, item: &Finding) -> bool {
        if !HARFANGLAB_ADVISORIES.contains(&item.code.as_str()) {
            return false;
        }
        // In the signature form the rule is the one whose header is the last
        // at or before the finding's line; before every header, the first.
        let rule = self.rules.as_ref().map_or_else(String::new, |rules| {
            let line = item.line.saturating_sub(1);
            let mut rule = String::new();
            for (name, header) in rules {
                if *header > line && !rule.is_empty() {
                    break;
                }
                rule.clone_from(name);
            }
            rule
        });
        self.found
            .iter()
            .any(|(code, _, _, _, own)| *code == item.code && *own == rule)
    }

    fn findings(
        &self,
        file: &Path,
        relative: &str,
        uuid: Option<&str>,
    ) -> Vec<opentide_workspace::lint::LintFinding> {
        self.found
            .iter()
            .map(|(code, message, line, path, _)| {
                let mut diagnostic = Diagnostic::new(*code, Severity::Warning, message.clone())
                    .file(file)
                    .at(path.iter().map(|key| (*key).to_owned()).collect::<Vec<_>>());
                diagnostic.yaml_line = Some(*line);
                diagnostic.path = Some(relative.to_owned());
                diagnostic.line = Some(line + 1);
                opentide_workspace::lint::LintFinding::from_engine(relative, uuid, diagnostic)
            })
            .collect()
    }
}

/// The 0-based file line of each byte offset into a signature's `value`
/// (`SignatureSite.line_of`): a literal block maps the value's lines one to
/// one onto the lines after its indicator; any other style places every
/// offset on the scalar's first line.
fn signature_lines<'v>(
    text: &str,
    node: &opentide_schema::node::Node,
    value: &'v str,
) -> impl Fn(usize) -> usize + 'v {
    // A block scalar's node starts at its content; its indicator (`|`, `|-`,
    // after any anchor or tag) ends the line before.
    let before: String = text.chars().take(node.start.index()).collect();
    let header = before
        .trim_end_matches([' ', '\t'])
        .strip_suffix('\n')
        .and_then(|head| head.rsplit('\n').next())
        .unwrap_or_default();
    let literal = header
        .split('#')
        .next()
        .and_then(|head| head.split_whitespace().last())
        .is_some_and(|token| token.starts_with('|'));
    let first = node.start.line().saturating_sub(1);
    move |offset: usize| {
        if literal {
            first + value[..offset.min(value.len())].matches('\n').count()
        } else {
            first
        }
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
    document: &opentide_schema::node::Document,
    graylog_tenants: &[ConfiguredTenant],
) -> Vec<opentide_workspace::lint::LintFinding> {
    let Some(root) = document.root() else {
        return Vec::new();
    };
    let locator = document.locator();
    let tenants: Vec<_> = graylog_tenants.iter().map(ConfiguredTenant::view).collect();
    opentide_schema::objects::platform::block_advisories(root, &tenants)
        .into_iter()
        .map(|advisory| {
            let mut diagnostic =
                Diagnostic::new(advisory.code, Severity::Warning, advisory.message)
                    .file(file)
                    .at(advisory.field_path);
            diagnostic.yaml_line = locator.yaml_line(&diagnostic.field_path);
            diagnostic.path = Some(relative.to_owned());
            // Where `validate` points the same finding (its annotate): the
            // block's key, not the line its value starts on (`yaml_line`,
            // from 0), which was a line below it (#922).
            if let Some(span) = locator.span(&diagnostic.field_path, false) {
                diagnostic.line = Some(span.line);
                diagnostic.column = Some(span.column);
                diagnostic.end_line = Some(span.end_line);
                diagnostic.end_column = Some(span.end_column);
            } else {
                diagnostic.line = diagnostic.yaml_line.map(|line| line + 1);
                diagnostic.end_line = diagnostic.line;
            }
            opentide_workspace::lint::LintFinding::from_engine(relative, uuid, diagnostic)
        })
        .collect()
}

/// `bytes` as UTF-8 text: without a leading byte-order mark, every line
/// ending a `\n`.
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
pub fn finding(text: &str, lines: &LineStarts, diagnostic: crate::Diagnostic) -> Finding {
    let (line, column, end_line, end_column) = lines.convert(text, diagnostic.range);
    let (end_line, end_column) = span_end(line, column, end_line, end_column, text);
    Finding {
        message: diagnostic.message,
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

/// Whether `query` is a text section of a Google SecOps block
/// (`configurations.google_secops.<section>`).
fn is_secops_section(query: &CheckedQuery) -> bool {
    matches!(
        query.field_path.as_slice(),
        [configurations, platform, _]
            if configurations == "configurations" && platform == "google_secops"
    )
}

/// `checked` with a Google SecOps block's sections as the one query they
/// are, the rule deploy assembles (0.28.0: "checks a google_secops block's
/// sections as the one rule deploy assembles"): at the block's field path,
/// where its first section's text starts, with every section's findings in
/// source order. Each finding keeps its own section's field path and place.
fn one_secops_rule(checked: Vec<CheckedQuery>) -> Vec<CheckedQuery> {
    let mut out: Vec<CheckedQuery> = Vec::with_capacity(checked.len());
    let mut rule: Option<usize> = None;
    for mut query in checked {
        if !is_secops_section(&query) {
            out.push(query);
            continue;
        }
        // The rule is the placeholder `opentide new` wrote, skipped as
        // 0.28.1 skipped it, while its `events` is the stand-in (B6: `events:
        // ...` beside the template's written `outcome` counted as "1 query
        // valid"). Once `events` is written the rule is checked, and a
        // section still the stand-in keeps the parse error the engine finds
        // in it (opentide-tide's `analyze_queries`): the rule cannot deploy.
        let stand_in_events =
            query.placeholder && query.field_path.last().map(String::as_str) == Some("events");
        match rule {
            Some(index) => {
                let merged = &mut out[index];
                if (query.line, query.column) < (merged.line, merged.column) {
                    (merged.line, merged.column) = (query.line, query.column);
                }
                merged.placeholder |= stand_in_events;
                merged.findings.extend(query.findings);
            }
            None => {
                query.placeholder = stand_in_events;
                query.field_path.truncate(2);
                rule = Some(out.len());
                out.push(query);
            }
        }
    }
    if let Some(index) = rule {
        out[index]
            .findings
            .sort_by_key(|finding| (finding.line, finding.column));
    }
    out
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
        let profiles = Profiles::install(fs, Some(root));
        let mut found = QueryFindings::default();
        let severity = if as_warnings {
            Severity::Warning
        } else {
            Severity::Error
        };
        // The engines analyse the objects on every core, each job with the
        // workspace's datasets; the findings are then gathered in the
        // objects' order.
        let checked: Vec<Vec<CheckedQuery>> = objects
            .par_iter()
            .map(|object| profiles.check_object(object.source))
            .collect();
        for (object, queries) in objects.iter().zip(checked) {
            let mut shown = None;
            for query in queries {
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
    fn a_google_secops_block_is_one_query_at_the_block() {
        let text = "name: A\nconfigurations:\n  google_secops:\n    events: |\n      \
                    $e.metadata.event_type = \"USER_LOGIN\"\n    outcome: |\n      \
                    $risk_score = 10\n    condition: |\n      $e\n  sentinel:\n    query: |\n      \
                    SecurityEvent\n";
        let profiles = Profiles {
            host: MemoryWorkspace { files: Vec::new() },
            datasets: crate::Datasets::of_workspace(None).unwrap(),
            visibility_problem: None,
            graylog_tenants: Vec::new(),
        };
        let queries = profiles.check_object(text);
        assert_eq!(queries.len(), 2, "{queries:?}");
        let rule = &queries[0];
        assert_eq!(rule.field_path, ["configurations", "google_secops"]);
        assert_eq!(rule.language, "yaral");
        // Where the first section's text starts, as 0.28.1 reports it.
        assert_eq!((rule.line, rule.column), (5, 7));
        // A finding keeps its own section's field path.
        let broken = text.replace("$risk_score = 10", "$risk_score = $nowhere");
        let queries = profiles.check_object(&broken);
        let rule = &queries[0];
        assert_eq!(rule.errors(), 1, "{:?}", rule.findings);
        assert_eq!(
            rule.findings[0].field_path,
            ["configurations", "google_secops", "outcome"]
        );
        // A block with a section label in a text is not checked: no queries.
        let header = text.replace("$risk_score = 10", "condition:");
        let queries = profiles.check_object(&header);
        assert!(
            queries
                .iter()
                .all(|query| query.platform != "google_secops"),
            "{queries:?}"
        );
    }

    #[test]
    fn a_google_secops_rule_with_a_stand_in_section_is_a_placeholder() {
        // B6 (smoke test): as `opentide new` writes the block, `events` and
        // `condition` the stand-in, `outcome` a value.
        let text = "name: A\nconfigurations:\n  google_secops:\n    events: |  # opentide:placeholder\n      \
                    ...\n    outcome: |  # opentide:placeholder\n      $risk_score = 40\n    \
                    condition: |  # opentide:placeholder\n      ...\n";
        let profiles = Profiles {
            host: MemoryWorkspace { files: Vec::new() },
            datasets: crate::Datasets::of_workspace(None).unwrap(),
            visibility_problem: None,
            graylog_tenants: Vec::new(),
        };
        let queries = profiles.check_object(text);
        let rule = queries
            .iter()
            .find(|query| query.platform == "google_secops")
            .unwrap_or_else(|| panic!("{queries:?}"));
        assert!(rule.placeholder, "{rule:?}");
        let secops = |text: &str| -> CheckedQuery {
            let queries = profiles.check_object(text);
            queries
                .into_iter()
                .find(|query| query.platform == "google_secops")
                .unwrap_or_else(|| panic!("no google_secops query in {text}"))
        };
        let section = |finding: &Finding| finding.field_path.last().cloned().unwrap_or_default();
        // `events` the stand-in and `condition` written with an error: still
        // the placeholder, skipped as 0.28.1 skipped it.
        let bad_condition = text.replace(
            "condition: |  # opentide:placeholder\n      ...",
            "condition: |\n      $e and and",
        );
        assert!(secops(&bad_condition).placeholder);
        // `events` written with an engine error and `condition` the
        // stand-in: the rule is checked, and the error in the written
        // `events` is reported.
        let events_wrong = text.replace(
            "events: |  # opentide:placeholder\n      ...",
            "events: |\n      $e.metadata.event_type = = \"USER_LOGIN\"",
        );
        let rule = secops(&events_wrong);
        assert!(!rule.placeholder, "{rule:?}");
        assert!(
            rule.findings
                .iter()
                .any(|finding| section(finding) == "events" && finding.code == "yaral_parse_error"),
            "{:?}",
            rule.findings
        );
        // `events` written and right, `condition` still the stand-in: the
        // rule cannot deploy, and 0.28.1 refused it with
        // `yaral_parse_error` at `condition`.
        let events_written = text.replace(
            "events: |  # opentide:placeholder\n      ...",
            "events: |\n      $e.metadata.event_type = \"USER_LOGIN\"",
        );
        let rule = secops(&events_written);
        assert!(!rule.placeholder, "{rule:?}");
        assert!(
            rule.findings
                .iter()
                .any(|finding| section(finding) == "condition"
                    && finding.code == "yaral_parse_error"
                    && finding.severity == EngineSeverity::Error),
            "{:?}",
            rule.findings
        );
        assert!(
            rule.findings
                .iter()
                .all(|finding| section(finding) == "condition"),
            "{:?}",
            rule.findings
        );
        // Written out, it is a query again.
        let written = text
            .replace(
                "      ...\n    outcome",
                "      $e.metadata.event_type = \"USER_LOGIN\"\n    outcome",
            )
            .replace(
                "condition: |  # opentide:placeholder\n      ...",
                "condition: |\n      $e",
            );
        let queries = profiles.check_object(&written);
        assert!(
            queries.iter().all(|query| !query.placeholder),
            "{queries:?}"
        );
    }

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

    /// `[queries.codes]` takes the codes in `opentide_core::codes::ALL`: every
    /// code the queries check can report from outside the engine crates
    /// (the platforms' block advisories, Elastic's, the undeclared datasets
    /// and Sysdig's list self-reference) must be there, or a user cannot
    /// configure it (`graylog_all_streams` was missing, #1802).
    #[test]
    fn every_code_lint_reports_outside_the_engines_is_configurable() {
        use opentide_schema::objects::platform::{
            bitdefender, exabeam, google_secops, graylog, harfanglab, microsoft_defender,
        };
        let reported: Vec<&str> = ELASTIC_ADVISORIES
            .into_iter()
            .chain(DECLARED_DATASET_CODES)
            .chain([opentide_core::codes::SYSDIG_LIST_SELF_REFERENCE])
            .chain(graylog::ADVISORY_CODES)
            .chain(harfanglab::yara::ADVISORY_CODES)
            .chain(bitdefender::advisories::ADVISORY_CODES)
            .chain(exabeam::ADVISORY_CODES)
            .chain(google_secops::advisories::ADVISORY_CODES)
            .chain(microsoft_defender::ADVISORY_CODES)
            .collect();
        for code in reported {
            assert!(
                opentide_core::codes::ALL.contains(&code),
                "{code} is reported by lint but missing from opentide_core::codes::ALL"
            );
        }
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
        assert!(lint_owned(opentide_core::codes::SYSDIG_LIST_SELF_REFERENCE));
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
    fn help_names_the_replacement_the_step_the_reference_or_the_page() {
        assert_eq!(
            engine_help("kql_unknown_table", "unknown table 'X'", Some("Y")),
            "did you mean \"Y\"?"
        );
        assert_eq!(
            engine_help("spl_x", "is Not A Command here", Some("stats")),
            "did you mean \"stats\"?"
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
