//! Production coverage gate: every required named grammar rule must appear
//! in `testdata/corpus/{kql,spl}/` tagged `prod:<rule>`.

use opentide_core::LanguageId;
use opentide_syntax::{has_error, parse};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tags_in(dir: &str) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    let path = repo_root().join(dir);
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let text = fs::read_to_string(entry.path()).unwrap();
        for cap in text.split_whitespace() {
            if let Some(rule) = cap.strip_prefix("prod:") {
                tags.insert(rule.trim_end_matches(',').to_string());
            }
        }
    }
    tags
}

fn named_rules(grammar_json: &str) -> BTreeSet<String> {
    let v: serde_json::Value = serde_json::from_str(grammar_json).unwrap();
    v["rules"].as_object().unwrap().keys().cloned().collect()
}

const KQL_REQUIRED: &[&str] = &[
    "let_statement",
    "where_operator",
    "project_operator",
    "project_away_operator",
    "project_rename_operator",
    "extend_operator",
    "summarize_operator",
    "join_operator",
    "union_operator",
    "parse_operator",
    "lookup_operator",
    "take_operator",
    "limit_operator",
    "sort_operator",
    "distinct_operator",
    "comment",
    "string",
    "number",
];

const SPL_REQUIRED: &[&str] = &[
    "bare_search",
    "search_command",
    "where_command",
    "eval_command",
    "stats_command",
    "rex_command",
    "table_command",
    "rename_command",
    "fields_command",
    "dedup_command",
    "sort_command",
    "head_command",
    "tail_command",
    "join_command",
    "lookup_command",
    "makemv_command",
    "mvexpand_command",
    "tstats_command",
    "fillnull_command",
    "foreach_command",
    "spath_command",
    "tojson_command",
    "inputlookup_command",
    "outputlookup_command",
    "unknown_command",
];

#[test]
fn kql_corpus_tags_cover_required_productions() {
    let tags = tags_in("testdata/corpus/kql");
    for rule in KQL_REQUIRED {
        assert!(
            tags.contains(*rule),
            "missing prod:{rule} in testdata/corpus/kql"
        );
    }
}

#[test]
fn spl_corpus_tags_cover_required_productions() {
    let tags = tags_in("testdata/corpus/spl");
    for rule in SPL_REQUIRED {
        assert!(
            tags.contains(*rule),
            "missing prod:{rule} in testdata/corpus/spl"
        );
    }
}

#[test]
fn kql_named_rules_in_grammar_json_are_known() {
    let json =
        fs::read_to_string(repo_root().join("grammars/tree-sitter-opentide-kql/src/grammar.json"))
            .unwrap();
    let rules = named_rules(&json);
    let tags = tags_in("testdata/corpus/kql");
    let skip: BTreeSet<&str> = [
        "source_file",
        "query",
        "tabular_expression",
        "tabular_primary",
        "tabular_operator",
        "project_item",
        "rename_item",
        "assignment",
        "sort_item",
        "expression",
        "or_expression",
        "and_expression",
        "not_expression",
        "comparison_expression",
        "additive_expression",
        "multiplicative_expression",
        "unary_expression",
        "primary_expression",
        "identifier",
        "boolean",
        "null",
        "timespan",
        "print_operator",
        "unknown_operator",
        "control_command",
        "function_call",
        "render_operator",
        "count_operator",
        "filter_operator",
        "keyword_operator",
        "mv_expand_operator",
        "parse_kv_operator",
        "parse_where_operator",
        "project_keep_operator",
        "project_reorder_operator",
        "top_operator",
        // pieces of the productions above, covered by their fixtures
        "column_item",
        "subquery",
        "type",
        "parameter",
        "json_value",
        "hint_name",
        "parse_column",
        "mv_expand_item",
        "mv_option",
        "series_aggregate",
        "star",
    ]
    .into_iter()
    .collect();
    for rule in &rules {
        if skip.contains(rule.as_str()) {
            continue;
        }
        assert!(
            tags.contains(rule),
            "named grammar rule `{rule}` is untagged in testdata/corpus/kql"
        );
    }
}

#[test]
fn kql_valid_fixtures_parse() {
    let dir = repo_root().join("testdata/corpus/kql");
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        if !name.contains("__valid") {
            continue;
        }
        let src = fs::read_to_string(&path).unwrap();
        let body = src
            .lines()
            .filter(|l| !l.starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let tree = parse(LanguageId::Kql, &body).expect("parser");
        assert!(
            !has_error(&tree),
            "{name} sexp={}",
            tree.root_node().to_sexp()
        );
    }
}

#[test]
fn kql_invalid_fixtures_exist_per_required_rule() {
    let dir = repo_root().join("testdata/corpus/kql");
    let mut invalid = BTreeSet::new();
    for entry in fs::read_dir(dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name.contains("__invalid") {
            invalid.insert(name.split("__").next().unwrap().to_string());
        }
    }
    for rule in KQL_REQUIRED {
        assert!(
            invalid.contains(*rule),
            "missing invalid fixture for {rule}"
        );
    }
}

#[test]
fn spl_valid_fixtures_parse() {
    let dir = repo_root().join("testdata/corpus/spl");
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        if !name.contains("__valid") {
            continue;
        }
        let src = fs::read_to_string(&path).unwrap();
        let body = src
            .lines()
            .filter(|l| !l.starts_with("``` prod:"))
            .collect::<Vec<_>>()
            .join("\n");
        let tree = parse(LanguageId::Spl, &body).expect("parser");
        assert!(
            !has_error(&tree),
            "{name} sexp={}",
            tree.root_node().to_sexp()
        );
    }
}

#[test]
fn spl_valid_bare_search_and_unknown_command_parse() {
    let tree = parse(LanguageId::Spl, "index=main | head 1").unwrap();
    assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
    let tree = parse(LanguageId::Spl, "index=main | bogus foo=bar").unwrap();
    assert!(tree.root_node().to_sexp().contains("unknown_command"));
}

/// One Elastic language's corpus gate: every required production is tagged
/// in a valid and an invalid fixture, every named grammar rule is either
/// tagged or structural, and every valid fixture parses cleanly. Kibana KQL
/// and Lucene have no comments, so the tag sits on a `#` first line that is
/// not part of the query.
struct ElasticGate {
    language: LanguageId,
    id: &'static str,
    structural: &'static [&'static str],
}

fn fixture_body(text: &str) -> String {
    text.lines().skip(1).collect::<Vec<_>>().join("\n")
}

fn check_gate(gate: &ElasticGate) {
    let dir = format!("testdata/corpus/{}", gate.id);
    let tags = tags_in(&dir);
    let json = fs::read_to_string(repo_root().join(format!(
        "grammars/tree-sitter-opentide-{}/src/grammar.json",
        gate.id
    )))
    .unwrap();
    let structural: BTreeSet<&str> = gate.structural.iter().copied().collect();
    let mut required = Vec::new();
    for rule in named_rules(&json) {
        if rule.starts_with('_') || structural.contains(rule.as_str()) {
            continue;
        }
        assert!(
            tags.contains(&rule),
            "named grammar rule `{rule}` is untagged in {dir}"
        );
        required.push(rule);
    }
    let mut kinds: BTreeSet<(String, String)> = BTreeSet::new();
    for entry in fs::read_dir(repo_root().join(&dir)).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let Some((rule, rest)) = name.split_once("__") else {
            continue;
        };
        let kind = rest.split('.').next().unwrap_or("").to_string();
        kinds.insert((rule.to_string(), kind.clone()));
        if kind == "valid" {
            let body = fixture_body(&fs::read_to_string(&path).unwrap());
            let tree = parse(gate.language, &body).expect("parser");
            assert!(
                !has_error(&tree),
                "{dir}/{name} must parse; sexp={}",
                tree.root_node().to_sexp()
            );
            assert!(
                tree.root_node().to_sexp().contains(&format!("({rule}")),
                "{dir}/{name} does not contain a `{rule}` node"
            );
        }
    }
    for rule in &required {
        for kind in ["valid", "invalid"] {
            assert!(
                kinds.contains(&(rule.clone(), kind.to_string())),
                "missing {dir}/{rule}__{kind} fixture"
            );
        }
    }
}

#[test]
fn esql_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Esql,
        id: "esql",
        structural: &[
            "source_file",
            "query",
            "aggregate_field",
            "field_assignment_or_expression",
            "command_option",
            "command_name",
            "index_pattern",
            "index_name",
            "cluster",
            "selector",
            "enrich_policy",
            "enrich_with_clause",
            "rename_clause",
            "order_expression",
            "fork_branch",
            "name_pattern",
            "id_pattern",
            "qualified_name",
            "identifier",
            "quoted_identifier",
            "type_name",
            "map_entry",
            "array",
            "boolean",
            "null",
            "and_expression",
            "or_expression",
            "not_expression",
            "comparison",
            "unary_expression",
            "binary_expression",
            "parenthesized_expression",
        ],
    });
}

#[test]
fn eql_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Eql,
        id: "eql",
        structural: &[
            "source_file",
            "sequence_params",
            "sequence_term",
            "join_keys",
            "join_term",
            "event_category",
            "case_insensitive_name",
            "optional_marker",
            "index",
            "identifier",
            "quoted_identifier",
            "boolean",
            "null",
            "and_expression",
            "or_expression",
            "not_expression",
            "unary_expression",
            "binary_expression",
            "parenthesized_expression",
        ],
    });
}

#[test]
fn kuery_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Kuery,
        id: "kuery",
        structural: &["source_file", "word", "or", "and", "not"],
    });
}

#[test]
fn lucene_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Lucene,
        id: "lucene",
        structural: &[
            "source_file",
            "field_name",
            "term",
            "phrase",
            "regexp",
            "range_term",
            "bare_operator",
            "required",
            "prohibited",
            "or",
            "and",
            "not",
        ],
    });
}
