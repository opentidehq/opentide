//! Production coverage gate: every required named grammar rule must appear
//! in `crates/testdata/corpus/<language>/` tagged `prod:<rule>`.
//!
//! The gate does not know a parser. It names productions, and reads a parsed
//! tree, through a per-language [`KindNames`] table ([`kind_names`]): a
//! language has the tree-sitter names until it moves to `opentide-parse`, and
//! keeps its gate by supplying the names of its `SyntaxKind`s instead (#1219),
//! as CQL does.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

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

/// A body parsed by a language's parser, as the gate reads it.
struct Parsed {
    /// The parser reported an error: an error or missing node, a syntax error.
    has_error: bool,
    /// The names of the node kinds in the tree.
    kinds: BTreeSet<String>,
    /// The tree as text, for a failure message.
    dump: String,
}

impl Parsed {
    fn has_kind(&self, kind: &str) -> bool {
        self.kinds.contains(kind)
    }
}

/// How one language names its productions and reads its trees: the table the
/// gate goes through, so that it does not depend on tree-sitter.
trait KindNames {
    /// The names of the language's named productions: what `prod:<rule>` tags.
    fn productions(&self) -> BTreeSet<String>;
    /// Parses `body` and returns the tree's error flag and its kind names.
    fn parse(&self, body: &str) -> Parsed;
}

/// The tree-sitter names: the rules of the grammar's `grammar.json` and the
/// named nodes of its tree.
struct TreeSitterNames {
    language: LanguageId,
    /// The grammar's directory name: `grammars/tree-sitter-opentide-<id>`.
    id: &'static str,
}

impl KindNames for TreeSitterNames {
    fn productions(&self) -> BTreeSet<String> {
        let json = fs::read_to_string(repo_root().join(format!(
            "grammars/tree-sitter-opentide-{}/src/grammar.json",
            self.id
        )))
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["rules"].as_object().unwrap().keys().cloned().collect()
    }

    fn parse(&self, body: &str) -> Parsed {
        let tree = parse(self.language, body).expect("parser");
        let dump = tree.root_node().to_sexp();
        // `(kind` opens a named node in the s-expression; a field's `name:`
        // is not followed by a parenthesis of its own.
        let kinds = dump
            .split('(')
            .skip(1)
            .map(|rest| {
                rest.split(|c: char| c.is_whitespace() || c == ')')
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        Parsed {
            has_error: has_error(&tree),
            kinds,
            dump,
        }
    }
}

/// The names of CQL's pure-Rust parser: its node kinds in `snake_case`, which
/// are tree-sitter's names of the same productions (`opentide_cql::debug_productions`),
/// and the node and token kinds of a parse (`opentide_cql::debug_kinds`).
struct CqlNames;

impl KindNames for CqlNames {
    fn productions(&self) -> BTreeSet<String> {
        opentide_cql::debug_productions().into_iter().collect()
    }

    fn parse(&self, body: &str) -> Parsed {
        let (has_error, kinds) = opentide_cql::debug_kinds(body);
        Parsed {
            has_error,
            dump: kinds.join(" "),
            kinds: kinds.into_iter().collect(),
        }
    }
}

/// The kind-name table of `language`: the `SyntaxKind` names of a language
/// that moved to `opentide-parse`, else the tree-sitter names.
fn kind_names(language: LanguageId, id: &'static str) -> Box<dyn KindNames> {
    match language {
        LanguageId::Cql => Box::new(CqlNames),
        _ => Box::new(TreeSitterNames { language, id }),
    }
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
    let tags = tags_in("crates/testdata/corpus/kql");
    for rule in KQL_REQUIRED {
        assert!(
            tags.contains(*rule),
            "missing prod:{rule} in crates/testdata/corpus/kql"
        );
    }
}

#[test]
fn spl_corpus_tags_cover_required_productions() {
    let tags = tags_in("crates/testdata/corpus/spl");
    for rule in SPL_REQUIRED {
        assert!(
            tags.contains(*rule),
            "missing prod:{rule} in crates/testdata/corpus/spl"
        );
    }
}

#[test]
fn kql_named_rules_in_grammar_json_are_known() {
    let rules = kind_names(LanguageId::Kql, "kql").productions();
    let tags = tags_in("crates/testdata/corpus/kql");
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
        "_column_name",
        "_column_name_or_pattern",
    ]
    .into_iter()
    .collect();
    for rule in &rules {
        if skip.contains(rule.as_str()) {
            continue;
        }
        assert!(
            tags.contains(rule),
            "named grammar rule `{rule}` is untagged in crates/testdata/corpus/kql"
        );
    }
}

#[test]
fn kql_valid_fixtures_parse() {
    let dir = repo_root().join("crates/testdata/corpus/kql");
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
        let tree = kind_names(LanguageId::Kql, "kql").parse(&body);
        assert!(!tree.has_error, "{name} sexp={}", tree.dump);
    }
}

#[test]
fn kql_invalid_fixtures_exist_per_required_rule() {
    let dir = repo_root().join("crates/testdata/corpus/kql");
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
    let dir = repo_root().join("crates/testdata/corpus/spl");
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
        let tree = kind_names(LanguageId::Spl, "spl").parse(&body);
        assert!(!tree.has_error, "{name} sexp={}", tree.dump);
    }
}

#[test]
fn spl_valid_bare_search_and_unknown_command_parse() {
    let names = kind_names(LanguageId::Spl, "spl");
    let tree = names.parse("index=main | head 1");
    assert!(!tree.has_error, "{}", tree.dump);
    let tree = names.parse("index=main | bogus foo=bar");
    assert!(tree.has_kind("unknown_command"), "{}", tree.dump);
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
    check_gate_with(gate, &*kind_names(gate.language, gate.id));
}

fn check_gate_with(gate: &ElasticGate, names: &dyn KindNames) {
    let dir = format!("crates/testdata/corpus/{}", gate.id);
    let tags = tags_in(&dir);
    let structural: BTreeSet<&str> = gate.structural.iter().copied().collect();
    let mut required = Vec::new();
    for rule in names.productions() {
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
            let tree = names.parse(&body);
            assert!(
                !tree.has_error,
                "{dir}/{name} must parse; sexp={}",
                tree.dump
            );
            assert!(
                tree.has_kind(rule),
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

#[test]
fn falco_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Falco,
        id: "falco",
        structural: &[
            "source_file",
            "identifier",
            "field_name",
            "argument_value",
            "transformer_name",
            "unary_operator",
            "comparison_operator",
            "list_operator",
            "bare_string",
            "number",
        ],
    });
}

#[test]
fn cql_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Cql,
        id: "cql",
        // Keywords and leaf tokens: every fixture that tags a production contains
        // them, so they need no fixture of their own. The names after
        // `argument_list` were never a rule of tree-sitter's grammar: aliases or
        // scanner tokens, which are one-token nodes of the pure-Rust tree, and
        // `parameter_default`, a field of `query_parameter` there and a node of
        // its own here. The fixtures of their parents hold each.
        structural: &[
            "source_file",
            "and",
            "or",
            "not",
            "boolean",
            "number",
            "tag",
            "regex_pattern",
            "regex_flags",
            "saved_query_name",
            "argument_list",
            "argument_name",
            "parameter_name",
            "parameter_default",
            "identifier",
            "function_name",
            "unquoted_pattern",
        ],
    });
}

#[test]
fn yara_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Yara,
        id: "yara",
        // Leaf tokens and keyword choices: every fixture that tags a
        // production contains them.
        structural: &[
            "source_file",
            "identifier",
            "integer",
            "boolean",
            "text_string",
            "string_identifier",
            "tag",
            "hex_byte",
            "hex_jump_bound",
            "hex_alternative_branch",
            "quantifier_keyword",
            "them",
            "loop_variables",
        ],
    });
}

#[test]
fn exabeam_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Exabeam,
        id: "exabeam",
        // Leaf tokens and names: every fixture that tags a production
        // contains them.
        structural: &[
            "source_file",
            "filter",
            "field_name",
            "alias",
            "table_name",
            "string",
            "number",
            "identifier",
            "bare_word",
            "text_word",
            "bound",
        ],
    });
}

#[test]
fn yaral_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Yaral,
        id: "yaral",
        // Leaf tokens and the pieces of the tagged productions: every fixture
        // that tags a production contains them.
        structural: &[
            "source_file",
            "identifier",
            "field_name",
            "integer",
            "float",
            "string",
            "boolean",
            "window_bound",
            "variable",
            "count",
            "arguments",
            "function_name",
            "match_clause",
            "order_item",
            "meta_entry",
            "option_entry",
        ],
    });
}

#[test]
fn tree_sitter_names_read_the_named_nodes_of_a_tree() {
    let names = kind_names(LanguageId::Spl, "spl");
    let tree = names.parse("index=main | bogus foo=bar");
    assert!(!tree.has_error, "{}", tree.dump);
    assert!(tree.has_kind("unknown_command"), "{}", tree.dump);
    // A kind is a whole name: a prefix of one is not a kind.
    assert!(!tree.has_kind("unknown"), "{}", tree.dump);
    assert!(names.parse("index=main | (").has_error);
    assert!(names.productions().contains("unknown_command"));
}

#[test]
fn the_gate_reads_productions_and_trees_only_through_its_table() {
    use std::cell::Cell;

    /// A table that counts its calls and hands them to the tree-sitter names.
    struct Counting {
        inner: Box<dyn KindNames>,
        productions: Cell<usize>,
        parses: Cell<usize>,
    }
    impl KindNames for Counting {
        fn productions(&self) -> BTreeSet<String> {
            self.productions.set(self.productions.get() + 1);
            self.inner.productions()
        }
        fn parse(&self, body: &str) -> Parsed {
            self.parses.set(self.parses.get() + 1);
            self.inner.parse(body)
        }
    }

    let names = Counting {
        inner: kind_names(LanguageId::Kuery, "kuery"),
        productions: Cell::new(0),
        parses: Cell::new(0),
    };
    check_gate_with(
        &ElasticGate {
            language: LanguageId::Kuery,
            id: "kuery",
            structural: &["source_file", "word", "or", "and", "not"],
        },
        &names,
    );
    assert_eq!(names.productions.get(), 1);
    assert!(names.parses.get() > 0);
}

#[test]
fn cql_names_are_the_pure_rust_tree() {
    let names = kind_names(LanguageId::Cql, "cql");
    let tree = names.parse("a=1 or b=2 | groupBy(x) // note");
    assert!(!tree.has_error, "{}", tree.dump);
    for kind in ["or_filter", "field_filter", "function_call", "line_comment"] {
        assert!(tree.has_kind(kind), "{kind}: {}", tree.dump);
    }
    assert!(names.parse("a=1 | (").has_error);
    let productions = names.productions();
    assert!(productions.contains("match_statement"));
    // An enum of the ungram is no node, and no production.
    assert!(!productions.contains("filter") && !productions.contains("expr"));
}
