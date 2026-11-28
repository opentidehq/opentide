//! A rule's queries: what a deploy of a rule sends to a platform, taken from
//! the rule's block in the order the deploy sends them, so that a search can
//! run them (`opentide query --rule`, `--file`) and a tenant can check them
//! (`opentide validate query --live`).
//!
//! A Sentinel or Defender query takes each tenant's exclusions, compiled as
//! deploy compiles them ([`RuleQuery::text_for`]); a Splunk search is the
//! saved search deploy creates; a SentinelOne correlation runs each
//! sub-query on its own, labelled; an Elastic rule names its language, its
//! indices or data view, and says what its rows are not.

use opentide_schema::platforms::PlatformId;

use crate::json::Json;
use crate::rule::Rule;

/// One query a rule sends to a platform.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RuleQuery {
    /// The query.
    pub text: String,
    /// Its language, when the rule says (Elastic).
    pub language: Option<String>,
    /// Elastic's indices, or Graylog's stream aliases.
    pub index: Vec<String>,
    /// Elastic's data view.
    pub data_view: Option<String>,
    /// Which of several queries (a SentinelOne correlation's sub-query).
    pub label: Option<String>,
    /// What the rows are not (a filter or a threshold the query omits).
    pub note: Option<String>,
    /// The KQL exclusions deploy compiles into the query per tenant
    /// (Sentinel, Microsoft Defender).
    pub exclusions: Option<Json>,
}

impl RuleQuery {
    /// The query as deploy sends it to `tenant`: with that tenant's
    /// exclusions.
    pub fn text_for(&self, tenant: &str) -> String {
        match &self.exclusions {
            Some(Json::Array(items)) if !items.is_empty() => {
                crate::kql::compile_query(&self.text, self.exclusions.as_ref(), tenant)
            }
            _ => self.text.clone(),
        }
    }
}

/// A block's value at `key`, unless absent or `null`.
fn field<'j>(block: &'j Json, key: &str) -> Option<&'j Json> {
    block.get(key).filter(|value| !value.is_null())
}

/// Whether a block's value holds something: a non-empty list, string or
/// mapping, or a scalar.
fn filled(value: Option<&Json>) -> bool {
    value.is_some_and(Json::is_filled)
}

/// The query, stripped, or the refusal of an empty one.
fn required(text: Option<&Json>, rule: &Rule, platform: &str) -> Result<String, String> {
    match text.and_then(Json::as_str).map(str::trim) {
        Some(text) if !text.is_empty() => Ok(text.to_owned()),
        _ => Err(format!(
            "rule {:?} has an empty {platform} query",
            rule.name
        )),
    }
}

/// The queries a deploy of `rule` sends to `platform`, in the order it sends
/// them. A platform that is not built in (a plugin's), or whose rules hold
/// no query (Sysdig, Bitdefender), cannot be queried.
///
/// # Errors
///
/// The rule has no block for `platform`, or the block holds nothing a search
/// can run: the message, as the command line prints it.
pub fn rule_queries(rule: &Rule, platform: &str) -> Result<Vec<RuleQuery>, String> {
    let name = format!("{:?}", rule.name);
    let Some(block) = rule.block(platform) else {
        return Err(format!("rule {name} has no {platform} configuration"));
    };
    let plain = |text: String| RuleQuery {
        text,
        ..RuleQuery::default()
    };
    let Some(platform_id) = PlatformId::parse(platform) else {
        return Err(cannot_be_queried(platform));
    };
    match platform_id {
        PlatformId::Sentinel | PlatformId::MicrosoftDefender => Ok(vec![RuleQuery {
            exclusions: field(block, "exclusions").cloned(),
            ..plain(required(block.get("query"), rule, platform)?)
        }]),
        PlatformId::Crowdstrike => Ok(vec![plain(required(block.get("query"), rule, platform)?)]),
        // Deploy joins the lines of a multiline Lucene query with spaces.
        PlatformId::CarbonBlackCloud => Ok(vec![plain(
            required(block.get("query"), rule, platform)?
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        )]),
        PlatformId::Splunk => {
            required(block.get("query"), rule, platform)?;
            Ok(vec![plain(crate::splunk::create_query(block))])
        }
        PlatformId::SentinelOne => sentinel_one(block, rule),
        PlatformId::Elastic => elastic(block, rule).map(|query| vec![query]),
        PlatformId::Exabeam => exabeam(block, rule),
        PlatformId::Datadog => datadog(block, rule),
        // The event definition's search: its Lucene query on the block's
        // `streams` (aliases resolved per tenant, as deploy resolves them),
        // else the tenant's own.
        PlatformId::Graylog => Ok(vec![RuleQuery {
            language: Some("lucene".to_owned()),
            index: match field(block, "streams") {
                Some(Json::Str(one)) => vec![one.clone()],
                Some(Json::Array(items)) => items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect(),
                _ => Vec::new(),
            },
            ..plain(required(block.get("query"), rule, platform)?)
        }]),
        PlatformId::Harfanglab => Err(format!(
            "rule {name} is a HarfangLab Sigma or YARA rule, which the agents evaluate: it holds \
             no query to search telemetry with. Pass a telemetry query instead, such as \
             'processes process_name=cmd.exe'"
        )),
        PlatformId::GoogleSecops => Err(format!(
            "rule {name}: --rule is not supported for google_secops. A YARA-L rule runs in the \
             detection engine, whose results differ from a search's, and a retrohunt writes \
             detections; write the search as a hunt (response.procedure.searches) and pass it as \
             QUERY"
        )),
        PlatformId::Sysdig | PlatformId::Bitdefender => Err(cannot_be_queried(platform)),
    }
}

/// The refusal of a platform whose rules hold no query.
fn cannot_be_queried(platform: &str) -> String {
    format!("{platform} rules cannot be queried")
}

/// A SentinelOne rule's query: its single event's, or each correlation
/// sub-query's, labelled.
fn sentinel_one(block: &Json, rule: &Rule) -> Result<Vec<RuleQuery>, String> {
    let name = format!("{:?}", rule.name);
    let condition = field(block, "condition");
    let kind = condition
        .and_then(|condition| condition.get("type"))
        .and_then(Json::as_str);
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
            Some(Json::Array(items)) if !items.is_empty() => items,
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
fn exabeam(block: &Json, rule: &Rule) -> Result<Vec<RuleQuery>, String> {
    let sequences = match field(block, "sequences") {
        Some(Json::Array(items)) if !items.is_empty() => items,
        _ => return Err(format!("rule {:?} has no Exabeam sequences", rule.name)),
    };
    let several = sequences.len() > 1;
    sequences
        .iter()
        .enumerate()
        .map(|(at, sequence)| {
            let filtered =
                field(sequence, "threshold").is_some() || filled(field(sequence, "group_by"));
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

/// A Datadog rule's queries: one per `queries[]` entry, its search as deploy
/// sends it, labelled by the name conditions call it, with a note that the
/// detection and the cases are not applied.
fn datadog(block: &Json, rule: &Rule) -> Result<Vec<RuleQuery>, String> {
    let queries = match field(block, "queries") {
        Some(Json::Array(items)) if !items.is_empty() => items,
        _ => return Err(format!("rule {:?} has no Datadog queries", rule.name)),
    };
    queries
        .iter()
        .enumerate()
        .map(|(at, query)| {
            let name = query
                .get("name")
                .and_then(Json::as_str)
                .filter(|name| !name.is_empty())
                .map_or_else(
                    || opentide_schema::objects::platform::datadog::default_query_name(at),
                    str::to_owned,
                );
            Ok(RuleQuery {
                text: required(query.get("query"), rule, "datadog")?,
                language: Some("datadog".into()),
                label: Some(format!("query {name}")),
                note: Some(
                    "the query's search only: the detection method, its window and the cases \
                     are not applied"
                        .into(),
                ),
                ..RuleQuery::default()
            })
        })
        .collect()
}

/// An Elastic rule's event query, with its language, indices or data view,
/// and a note on what its rows are not.
fn elastic(block: &Json, rule: &Rule) -> Result<RuleQuery, String> {
    let kind = block.get("type").and_then(Json::as_str).unwrap_or("query");
    if kind == "machine_learning" {
        return Err(format!(
            "rule {:?} is an Elastic machine_learning rule, which has no query",
            rule.name
        ));
    }
    let text = required(block.get("query"), rule, "elastic")?;
    let index: Vec<String> = match field(block, "index") {
        Some(Json::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map_or_else(|| item.to_compact(), str::to_owned)
            })
            .collect(),
        _ => Vec::new(),
    };
    let data_view = field(block, "data_view_id")
        .and_then(Json::as_str)
        .map(str::to_owned);
    let filtered = filled(field(block, "filters"));
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
        .and_then(Json::as_str)
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
    fn a_graylog_rule_runs_its_query_on_its_streams() {
        // Smoke E11 (#1654): Graylog's `--rule` runs the definition's query
        // in Lucene, on the block's stream aliases, else the tenant's.
        let listed = rule(&format!(
            "{HEAD}configurations:\n  graylog:\n    query: 'EventID:1'\n    streams: [sysmon, \
             endpoint]\n"
        ));
        assert_eq!(
            rule_queries(&listed, "graylog").unwrap(),
            vec![RuleQuery {
                text: "EventID:1".into(),
                language: Some("lucene".into()),
                index: vec!["sysmon".into(), "endpoint".into()],
                ..RuleQuery::default()
            }]
        );
        let one = rule(&format!(
            "{HEAD}configurations:\n  graylog:\n    query: 'EventID:1'\n    streams: sysmon\n"
        ));
        assert_eq!(rule_queries(&one, "graylog").unwrap()[0].index, ["sysmon"]);
        let none = rule(&format!(
            "{HEAD}configurations:\n  graylog:\n    query: 'EventID:1'\n"
        ));
        assert!(rule_queries(&none, "graylog").unwrap()[0].index.is_empty());
        let empty = rule(&format!(
            "{HEAD}configurations:\n  graylog:\n    query: ' '\n"
        ));
        assert_eq!(
            rule_queries(&empty, "graylog").unwrap_err(),
            "rule \"R\" has an empty graylog query"
        );
    }

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
        let secops = rule(&format!(
            "{HEAD}configurations:\n  google_secops:\n    condition: $e\n"
        ));
        assert!(
            rule_queries(&secops, "google_secops")
                .unwrap_err()
                .starts_with("rule \"R\": --rule is not supported for google_secops.")
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
            "{HEAD}configurations:\n  microsoft_defender:\n    query: DeviceEvents\n"
        ));
        assert_eq!(
            rule_queries(&bare, "microsoft_defender").unwrap()[0].text_for("lab"),
            "DeviceEvents"
        );
    }

    #[test]
    fn carbon_black_joins_lines_and_splunk_sends_its_query_as_written() {
        let both = rule(&format!(
            "{HEAD}configurations:\n  carbon_black_cloud:\n    query: |\n      a:1\n      \
             AND b:2\n  splunk:\n    status: STAGING\n    query: index=main\n"
        ));
        assert_eq!(texts(&both, "carbon_black_cloud"), ["a:1 AND b:2"]);
        let splunk = texts(&both, "splunk");
        assert_eq!(
            splunk,
            ["index=main"],
            "the query as written, nothing appended"
        );
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

    /// Every built-in platform is matched by name, and a plugin's platform
    /// with a block cannot be queried; the rule's name is quoted as written.
    #[test]
    fn a_plugin_or_a_platform_without_queries_is_refused_by_name() {
        let plugin = rule(
            "name: Règle 😀\nmetadata:\n  uuid: 00000000-0000-4000-8000-0000000000AA\n\
             configurations:\n  acme_siem:\n    query: a\n  bitdefender:\n    query: a\n",
        );
        assert_eq!(
            rule_queries(&plugin, "acme_siem").unwrap_err(),
            "acme_siem rules cannot be queried"
        );
        assert_eq!(
            rule_queries(&plugin, "bitdefender").unwrap_err(),
            "bitdefender rules cannot be queried"
        );
        assert_eq!(
            rule_queries(&plugin, "Sentinel").unwrap_err(),
            "rule \"Règle 😀\" has no Sentinel configuration"
        );
    }

    /// An empty `single_event` mapping is the single event's, holding no
    /// query: `query --rule` and `validate query --live` say so alike.
    #[test]
    fn an_empty_sentinel_one_single_event_has_an_empty_query() {
        let empty = rule(&format!(
            "{HEAD}configurations:\n  sentinel_one:\n    condition:\n      type: Single \
             Event\n      single_event: {{}}\n"
        ));
        assert_eq!(
            rule_queries(&empty, "sentinel_one").unwrap_err(),
            "rule \"R\" has an empty sentinel_one query"
        );
    }
}
