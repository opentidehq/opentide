//! A rule's query, as `opentide query --rule` and `--file` run it
//! (UC-4.4c, #834): the rule is read (`cli/services/query.py`
//! `_load_rule`), then the queries a deploy of it sends to the platform are
//! taken from its block, in the order the deploy sends them
//! (`query/rules.py` `rule_queries`).
//!
//! A Sentinel or Defender query takes each tenant's exclusions, compiled as
//! deploy compiles them ([`RuleQuery::text_for`]); a Splunk search is the
//! saved search deploy creates; a SentinelOne correlation runs each
//! sub-query on its own, labelled; an Elastic rule names its language, its
//! indices or data view, and says what its rows are not.

use std::path::{Path, PathBuf};

use opentide_compile::Json as CJson;
use opentide_compile::rule::Rule;

use super::{open, placement};
use crate::env::Env;

/// One query a rule sends to a platform (`RuleQuery`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RuleQuery {
    /// The query.
    pub text: String,
    /// Its language, when the rule says (Elastic).
    pub language: Option<String>,
    /// Elastic's indices.
    pub index: Vec<String>,
    /// Elastic's data view.
    pub data_view: Option<String>,
    /// Which of several queries (a SentinelOne correlation's sub-query).
    pub label: Option<String>,
    /// What the rows are not (a filter or a threshold the query omits).
    pub note: Option<String>,
    /// The KQL exclusions deploy compiles into the query per tenant
    /// (Sentinel, Defender for Endpoint).
    pub exclusions: Option<CJson>,
}

impl RuleQuery {
    /// The query as deploy sends it to `tenant`: with that tenant's
    /// exclusions (`text_for`).
    pub fn text_for(&self, tenant: &str) -> String {
        match &self.exclusions {
            Some(CJson::Array(items)) if !items.is_empty() => {
                opentide_compile::kql::compile_query(&self.text, self.exclusions.as_ref(), tenant)
            }
            _ => self.text.clone(),
        }
    }
}

/// Why the rule cannot be read: the message, the flag at fault and the
/// closest UUID (`_refusal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The message.
    pub message: String,
    /// `--rule` or `--file`.
    pub argument: &'static str,
    /// The closest rule UUID, for a `--rule` that names none.
    pub suggestion: Option<String>,
}

impl Refusal {
    fn file(message: String) -> Self {
        Self {
            message,
            argument: "--file",
            suggestion: None,
        }
    }
}

/// The rule `--rule` (by UUID, in the workspace) or `--file` (a path from
/// the working directory, else from the repository) names (`_load_rule`).
///
/// # Errors
///
/// The rule cannot be read: the refusal.
pub fn load(
    uuid: Option<&str>,
    file: Option<&str>,
    repo: Option<&str>,
    env: &Env,
    cwd: &Path,
) -> Result<Rule, Refusal> {
    if let Some(file) = file {
        let (shown, _) = placement(repo, env, cwd);
        return load_file(file, &cwd.join(shown), cwd);
    }
    load_uuid(uuid.unwrap_or_default(), repo, env, cwd)
}

/// The rule with UUID `wanted` in the workspace; UUIDs compare without case
/// (RFC 9562), so one pasted from a console finds its rule.
fn load_uuid(wanted: &str, repo: Option<&str>, env: &Env, cwd: &Path) -> Result<Rule, Refusal> {
    let (_, options) = placement(repo, env, cwd);
    let folded = wanted.trim().to_lowercase();
    let mut known: Vec<String> = Vec::new();
    let mut found: Option<Rule> = None;
    if let Ok(workspace) = open(options) {
        for object in workspace.index().rules() {
            known.push(object.uuid.clone());
            if found.is_none()
                && object.uuid.to_lowercase() == folded
                && let Some(root) = object.root()
            {
                found = Some(Rule::new(
                    root,
                    Some(object.path.to_string_lossy().into_owned()),
                ));
            }
        }
        crate::app::release(workspace);
    }
    found.ok_or_else(|| Refusal {
        message: format!("no rule with UUID {wanted}"),
        argument: "--rule",
        suggestion: crate::suggest::did_you_mean(wanted, known.iter().map(String::as_str)),
    })
}

/// The rule in `file`: from the working directory, else from the
/// repository root `repo`.
fn load_file(file: &str, repo: &Path, cwd: &Path) -> Result<Rule, Refusal> {
    let given = PathBuf::from(file);
    let mut path = cwd.join(&given);
    if !path.is_file() && !given.is_absolute() && repo.join(&given).is_file() {
        path = repo.join(&given);
    }
    if !path.is_file() {
        return Err(Refusal::file(format!("no rule file at {file}")));
    }
    let unreadable =
        |problem: String| Refusal::file(format!("cannot read the rule in {file}: {problem}"));
    let bytes = std::fs::read(&path).map_err(|error| unreadable(error.to_string()))?;
    let document =
        opentide_schema::node::load_bytes(&bytes).map_err(|error| unreadable(error.to_string()))?;
    let root = match document.root() {
        Some(root) if matches!(root.value, opentide_schema::node::Value::Map(_)) => {
            (**root).clone()
        }
        _ => return Err(unreadable("the file does not hold one rule mapping".into())),
    };
    let read = opentide_schema::revisions::read(&document, "rule")
        .map_err(|rejection| unreadable(rejection.to_string()))?;
    if let Err(errors) = read.result {
        let title = match read.selection.revision().identifier {
            "rule::1.1" => "DetectionRule_v1_1",
            _ => "DetectionRule",
        };
        return Err(unreadable(validation_message(title, &errors)));
    }
    Ok(Rule::new(&root, Some(path.to_string_lossy().into_owned())))
}

/// A model's errors as Pydantic counts and lists them: the count and the
/// class, then each error's location and message with its type.
fn validation_message(title: &str, errors: &[opentide_schema::SchemaError]) -> String {
    let count = errors.len();
    let mut text = format!(
        "{count} validation error{} for {title}",
        if count == 1 { "" } else { "s" }
    );
    for error in errors {
        let location = if error.path.is_empty() {
            "<root>".to_owned()
        } else {
            error.field_path().join(".")
        };
        let kind = error.kind.pydantic_type().unwrap_or("value_error");
        text.push_str(&format!("\n{location}\n  {} [type={kind}]", error.message));
    }
    text
}

/// A block's value at `key`, unless absent or `null`.
fn field<'j>(block: &'j CJson, key: &str) -> Option<&'j CJson> {
    block.get(key).filter(|value| !value.is_null())
}

/// Python's truth of a block's value: a non-empty list, string or mapping.
fn truthy(value: Option<&CJson>) -> bool {
    value.is_some_and(CJson::truthy)
}

/// `_required`: the query, stripped, or the refusal of an empty one.
fn required(text: Option<&CJson>, rule: &Rule, platform: &str) -> Result<String, String> {
    match text.and_then(CJson::as_str).map(str::trim) {
        Some(text) if !text.is_empty() => Ok(text.to_owned()),
        _ => Err(format!(
            "rule {:?} has an empty {platform} query",
            rule.name
        )),
    }
}

/// The queries a deploy of `rule` sends to `platform`, in the order it sends
/// them (`rule_queries`).
///
/// # Errors
///
/// The rule has no block for `platform`, or the block holds nothing a search
/// can run: the message (`RuleQueryError`).
pub fn rule_queries(rule: &Rule, platform: &str) -> Result<Vec<RuleQuery>, String> {
    let name = format!("{:?}", rule.name);
    let Some(block) = rule.block(platform) else {
        return Err(format!("rule {name} has no {platform} configuration"));
    };
    let plain = |text: String| RuleQuery {
        text,
        ..RuleQuery::default()
    };
    match platform {
        "sentinel" | "defender_for_endpoint" => Ok(vec![RuleQuery {
            exclusions: field(block, "exclusions").cloned(),
            ..plain(required(block.get("query"), rule, platform)?)
        }]),
        "crowdstrike" => Ok(vec![plain(required(block.get("query"), rule, platform)?)]),
        // Deploy joins the lines of a multiline Lucene query with spaces.
        "carbon_black_cloud" => Ok(vec![plain(
            required(block.get("query"), rule, platform)?
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        )]),
        "splunk" => {
            required(block.get("query"), rule, platform)?;
            Ok(vec![plain(opentide_compile::splunk::create_query(
                rule, block,
            ))])
        }
        "sentinel_one" => sentinel_one(block, rule),
        "elastic" => elastic(block, rule).map(|query| vec![query]),
        "exabeam" => exabeam(block, rule),
        "harfanglab" => Err(format!(
            "rule {name} is a HarfangLab Sigma or YARA rule, which the agents evaluate: it holds \
             no query to search telemetry with. Pass a telemetry query instead, such as \
             'processes process_name=cmd.exe'"
        )),
        _ => Err(format!("{platform} rules cannot be queried")),
    }
}

/// A SentinelOne rule's query: its single event's, or each correlation
/// sub-query's, labelled.
fn sentinel_one(block: &CJson, rule: &Rule) -> Result<Vec<RuleQuery>, String> {
    let name = format!("{:?}", rule.name);
    let condition = field(block, "condition");
    let kind = condition
        .and_then(|condition| condition.get("type"))
        .and_then(CJson::as_str);
    let part = |key: &str| condition.and_then(|condition| field(condition, key));
    if kind == Some("Single Event")
        && let Some(single) = part("single_event")
    {
        return Ok(vec![RuleQuery {
            text: required(single.get("query"), rule, "sentinel_one")?,
            ..RuleQuery::default()
        }]);
    }
    if kind == Some("Correlation")
        && let Some(correlation) = part("correlation")
    {
        let subs = match correlation.get("sub_queries") {
            Some(CJson::Array(items)) if !items.is_empty() => items,
            _ => return Err(format!("rule {name} has no SentinelOne sub-queries")),
        };
        return subs
            .iter()
            .enumerate()
            .map(|(at, sub)| {
                Ok(RuleQuery {
                    text: required(sub.get("query"), rule, "sentinel_one")?,
                    label: Some(format!("sub-query {}", at + 1)),
                    note: Some(
                        "one correlation sub-query: the correlation itself is not applied".into(),
                    ),
                    ..RuleQuery::default()
                })
            })
            .collect();
    }
    Err(format!("rule {name} has no SentinelOne query"))
}

/// An Exabeam rule's queries: one per sequence, its filter as deploy sends
/// it (exabeam-1.0), with a note when the sequence also has a threshold or a
/// grouping the search leaves out.
fn exabeam(block: &CJson, rule: &Rule) -> Result<Vec<RuleQuery>, String> {
    let sequences = match field(block, "sequences") {
        Some(CJson::Array(items)) if !items.is_empty() => items,
        _ => return Err(format!("rule {:?} has no Exabeam sequences", rule.name)),
    };
    let several = sequences.len() > 1;
    sequences
        .iter()
        .enumerate()
        .map(|(at, sequence)| {
            let filtered =
                field(sequence, "threshold").is_some() || truthy(field(sequence, "group_by"));
            Ok(RuleQuery {
                text: required(sequence.get("query"), rule, "exabeam")?,
                language: Some("exabeam".into()),
                label: several.then(|| format!("sequence {}", at + 1)),
                note: filtered.then(|| {
                    "the sequence's filter only: its condition, window and grouping are not \
                     applied"
                        .into()
                }),
                ..RuleQuery::default()
            })
        })
        .collect()
}

/// An Elastic rule's event query, with its language, indices or data view,
/// and a note on what its rows are not.
fn elastic(block: &CJson, rule: &Rule) -> Result<RuleQuery, String> {
    let kind = block.get("type").and_then(CJson::as_str).unwrap_or("query");
    if kind == "machine_learning" {
        return Err(format!(
            "rule {:?} is an Elastic machine_learning rule, which has no query",
            rule.name
        ));
    }
    let text = required(block.get("query"), rule, "elastic")?;
    let index: Vec<String> = match field(block, "index") {
        Some(CJson::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map_or_else(|| item.to_compact(), str::to_owned)
            })
            .collect(),
        _ => Vec::new(),
    };
    let data_view = field(block, "data_view_id")
        .and_then(CJson::as_str)
        .map(str::to_owned);
    let filtered = truthy(field(block, "filters"));
    let query = RuleQuery {
        text,
        index,
        data_view,
        ..RuleQuery::default()
    };
    if kind == "esql" {
        return Ok(RuleQuery {
            language: Some(kind.to_owned()),
            ..query
        });
    }
    if kind == "eql" {
        return Ok(RuleQuery {
            language: Some(kind.to_owned()),
            note: filtered.then(|| "the rule's filters are not applied".to_owned()),
            ..query
        });
    }
    let language = field(block, "language")
        .and_then(CJson::as_str)
        .filter(|language| !language.is_empty())
        .unwrap_or("kuery");
    let mut notes: Vec<String> = Vec::new();
    if kind != "query" {
        notes.push(format!(
            "the {kind} rule's event query only: the {kind} logic is not applied"
        ));
    }
    if filtered {
        notes.push("the rule's filters are not applied".into());
    }
    Ok(RuleQuery {
        language: Some(language.to_owned()),
        note: (!notes.is_empty()).then(|| notes.join("; ")),
        ..query
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(yaml: &str) -> Rule {
        let document = opentide_schema::node::load(yaml).unwrap();
        Rule::new(document.root().unwrap(), None)
    }

    fn texts(rule: &Rule, platform: &str) -> Vec<String> {
        rule_queries(rule, platform)
            .unwrap()
            .into_iter()
            .map(|query| query.text)
            .collect()
    }

    const HEAD: &str = "name: R\nmetadata:\n  uuid: 00000000-0000-4000-8000-0000000000AA\n";

    #[test]
    fn a_rule_without_the_platform_or_with_an_empty_query_is_refused() {
        let empty = rule(&format!(
            "{HEAD}configurations:\n  crowdstrike:\n    query: '  '\n"
        ));
        assert_eq!(
            rule_queries(&empty, "sentinel").unwrap_err(),
            "rule \"R\" has no sentinel configuration"
        );
        assert_eq!(
            rule_queries(&empty, "crowdstrike").unwrap_err(),
            "rule \"R\" has an empty crowdstrike query"
        );
        let harfanglab = rule(&format!(
            "{HEAD}configurations:\n  harfanglab:\n    maturity: x\n"
        ));
        assert!(
            rule_queries(&harfanglab, "harfanglab")
                .unwrap_err()
                .contains("HarfangLab Sigma or YARA rule")
        );
        let sysdig = rule(&format!(
            "{HEAD}configurations:\n  sysdig:\n    condition: x\n"
        ));
        assert_eq!(
            rule_queries(&sysdig, "sysdig").unwrap_err(),
            "sysdig rules cannot be queried"
        );
    }

    #[test]
    fn kql_takes_each_tenants_exclusions() {
        let sentinel = rule(&format!(
            "{HEAD}configurations:\n  sentinel:\n    query: |\n      SecurityEvent\n    \
             exclusions:\n      - query: Account == 'svc'\n        tenant: lab\n"
        ));
        let queries = rule_queries(&sentinel, "sentinel").unwrap();
        assert_eq!(queries[0].text, "SecurityEvent");
        assert_ne!(queries[0].text_for("lab"), "SecurityEvent");
        assert!(queries[0].text_for("lab").contains("svc"));
        assert_eq!(queries[0].text_for("prod"), queries[0].text_for("prod"));
        let bare = rule(&format!(
            "{HEAD}configurations:\n  defender_for_endpoint:\n    query: DeviceEvents\n"
        ));
        assert_eq!(
            rule_queries(&bare, "defender_for_endpoint").unwrap()[0].text_for("lab"),
            "DeviceEvents"
        );
    }

    #[test]
    fn carbon_black_joins_lines_and_splunk_sends_the_saved_search() {
        let both = rule(&format!(
            "{HEAD}configurations:\n  carbon_black_cloud:\n    query: |\n      a:1\n      \
             AND b:2\n  splunk:\n    status: STAGING\n    query: index=main\n"
        ));
        assert_eq!(texts(&both, "carbon_black_cloud"), ["a:1 AND b:2"]);
        let splunk = texts(&both, "splunk");
        assert!(splunk[0].starts_with("index=main\n| eval MDR_UUID="));
        assert!(splunk[0].contains("00000000-0000-4000-8000-0000000000aa"));
    }

    #[test]
    fn exabeam_runs_each_sequence_filter_and_says_what_it_leaves_out() {
        let two = rule(&format!(
            "{HEAD}configurations:\n  exabeam:\n    sequences:\n      - query: ' a = 1 '\n        threshold: {{function: count, operator: more_than, value: 3}}\n      - query: b = 2\n"
        ));
        let queries = rule_queries(&two, "exabeam").unwrap();
        let note = "the sequence's filter only: its condition, window and grouping are not applied";
        let shown: Vec<String> = queries
            .iter()
            .map(|query| {
                format!(
                    "{}|{}|{}|{}",
                    query.text,
                    query.language.as_deref().unwrap_or(""),
                    query.label.as_deref().unwrap_or(""),
                    query.note.as_deref().unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                format!("a = 1|exabeam|sequence 1|{note}"),
                "b = 2|exabeam|sequence 2|".to_owned(),
            ]
        );
        let one = rule(&format!(
            "{HEAD}configurations:\n  exabeam:\n    sequences:\n      - query: c\n        group_by: [user]\n"
        ));
        let query = rule_queries(&one, "exabeam").unwrap().remove(0);
        assert_eq!((query.label, query.note.as_deref()), (None, Some(note)));
        let no_sequences = rule(&format!(
            "{HEAD}configurations:\n  exabeam:\n    sequences: []\n"
        ));
        assert_eq!(
            rule_queries(&no_sequences, "exabeam").unwrap_err(),
            "rule \"R\" has no Exabeam sequences"
        );
        let empty = rule(&format!(
            "{HEAD}configurations:\n  exabeam:\n    sequences:\n      - query: ''\n"
        ));
        assert_eq!(
            rule_queries(&empty, "exabeam").unwrap_err(),
            "rule \"R\" has an empty exabeam query"
        );
    }

    #[test]
    fn sentinel_one_runs_each_correlation_sub_query() {
        let single = rule(&format!(
            "{HEAD}configurations:\n  sentinel_one:\n    condition:\n      type: Single \
             Event\n      single_event:\n        query: a = 1\n"
        ));
        assert_eq!(texts(&single, "sentinel_one"), ["a = 1"]);
        let correlation = rule(&format!(
            "{HEAD}configurations:\n  sentinel_one:\n    condition:\n      type: Correlation\n      \
             correlation:\n        sub_queries:\n          - query: a\n          - query: b\n"
        ));
        let queries = rule_queries(&correlation, "sentinel_one").unwrap();
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[1].label.as_deref(), Some("sub-query 2"));
        assert!(queries[0].note.as_deref().unwrap().contains("correlation"));
        let none = rule(&format!(
            "{HEAD}configurations:\n  sentinel_one:\n    condition:\n      type: Correlation\n      \
             correlation:\n        sub_queries: []\n"
        ));
        assert_eq!(
            rule_queries(&none, "sentinel_one").unwrap_err(),
            "rule \"R\" has no SentinelOne sub-queries"
        );
        let other = rule(&format!(
            "{HEAD}configurations:\n  sentinel_one:\n    condition:\n      type: Single Event\n"
        ));
        assert_eq!(
            rule_queries(&other, "sentinel_one").unwrap_err(),
            "rule \"R\" has no SentinelOne query"
        );
    }

    #[test]
    fn elastic_names_its_language_indices_and_what_its_rows_are_not() {
        let elastic = |body: &str| {
            rule_queries(
                &rule(&format!("{HEAD}configurations:\n  elastic:\n{body}")),
                "elastic",
            )
        };
        let es_ql = elastic("    type: esql\n    query: FROM logs\n").unwrap();
        assert_eq!(es_ql[0].language.as_deref(), Some("esql"));
        let eql = elastic(
            "    type: eql\n    query: process where true\n    index: [logs-*]\n    filters: \
             [{a: 1}]\n",
        )
        .unwrap();
        assert_eq!(eql[0].index, ["logs-*"]);
        assert_eq!(
            eql[0].note.as_deref(),
            Some("the rule's filters are not applied")
        );
        let threshold = elastic(
            "    type: threshold\n    query: a:1\n    language: lucene\n    data_view_id: dv\n    \
             filters: [{a: 1}]\n",
        )
        .unwrap();
        assert_eq!(threshold[0].language.as_deref(), Some("lucene"));
        assert_eq!(threshold[0].data_view.as_deref(), Some("dv"));
        assert_eq!(
            threshold[0].note.as_deref(),
            Some(
                "the threshold rule's event query only: the threshold logic is not applied; the \
                 rule's filters are not applied"
            )
        );
        let kuery = elastic("    type: query\n    query: a:1\n").unwrap();
        assert_eq!(kuery[0].language.as_deref(), Some("kuery"));
        assert_eq!(kuery[0].note, None);
        assert!(
            elastic("    type: machine_learning\n")
                .unwrap_err()
                .contains("machine_learning rule")
        );
    }

    #[test]
    fn a_rule_file_is_read_from_the_working_directory_else_the_repository() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(repo.join("rules")).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let missing = load_file("rules/r.yaml", &repo, &elsewhere).unwrap_err();
        assert_eq!(missing.message, "no rule file at rules/r.yaml");
        assert_eq!(missing.argument, "--file");
        std::fs::write(repo.join("rules/list.yaml"), "- a\n").unwrap();
        assert_eq!(
            load_file("rules/list.yaml", &repo, &elsewhere)
                .unwrap_err()
                .message,
            "cannot read the rule in rules/list.yaml: the file does not hold one rule mapping"
        );
        std::fs::write(
            repo.join("rules/bad.yaml"),
            "name: R\nmetadata:\n  schema: rule::1.0\n",
        )
        .unwrap();
        let invalid = load_file("rules/bad.yaml", &repo, &elsewhere).unwrap_err();
        assert!(
            invalid
                .message
                .starts_with("cannot read the rule in rules/bad.yaml: "),
            "{}",
            invalid.message
        );
        assert!(
            invalid.message.contains("for DetectionRule"),
            "{}",
            invalid.message
        );
    }
}
