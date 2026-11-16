//! Production coverage gate: every required named grammar rule must appear
//! in `crates/testdata/corpus/<language>/` tagged `prod:<rule>`.
//!
//! The gate does not know a parser. It names productions, and reads a parsed
//! tree, through a per-language [`KindNames`] table ([`kind_names`]): the
//! names of the language's `SyntaxKind`s (#1219), in `snake_case`, with the
//! few the corpus tags under another name (the tree-sitter rule the fixture
//! was written for) translated.

#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_core::LanguageId;
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
/// gate goes through, so that it depends on no one parser.
trait KindNames {
    /// The names of the language's named productions: what `prod:<rule>` tags.
    fn productions(&self) -> BTreeSet<String>;
    /// Parses `body` and returns the tree's error flag and its kind names.
    fn parse(&self, body: &str) -> Parsed;
}

/// The `snake_case` spelling of a kind's `Debug` name: `FieldValueExpression`
/// and `FIELD_VALUE_EXPRESSION` are both `field_value_expression`.
fn snake_case(name: &str) -> String {
    if !name.chars().any(|c| c.is_ascii_lowercase()) {
        return name.to_ascii_lowercase();
    }
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The names of a language's pure-Rust parser (#1219): its node kinds and the
/// kinds of a parse (`debug_node_kinds`, `debug_kinds` in its crate), in
/// `snake_case`. `tags` translates the kinds the corpus tags under another
/// name (the tree-sitter rule a fixture was written for), and `tokens` are the
/// tags that only a token kind stands for, productions of their own.
struct RustNames {
    node_kinds: fn() -> Vec<String>,
    kinds: fn(&str) -> (bool, Vec<String>),
    tags: &'static [(&'static str, &'static str)],
    tokens: &'static [&'static str],
}

impl RustNames {
    /// The tags of `kind`: the ones [`RustNames::tags`] gives it (a coarse
    /// kind can stand for several tree-sitter productions; a key `*/name`
    /// matches a token `name` under any node), else its name.
    fn tags_of(&self, kind: &str) -> Vec<String> {
        let kind = snake_case(kind);
        let bare = kind.rsplit('/').next().unwrap_or(&kind);
        let tags: Vec<String> = self
            .tags
            .iter()
            .filter(|(k, _)| *k == kind || k.strip_prefix("*/") == Some(bare))
            .map(|(_, tag)| (*tag).to_string())
            .collect();
        if tags.is_empty() { vec![kind] } else { tags }
    }
}

impl KindNames for RustNames {
    fn productions(&self) -> BTreeSet<String> {
        (self.node_kinds)()
            .iter()
            .flat_map(|k| self.tags_of(k))
            .chain(self.tokens.iter().map(ToString::to_string))
            .collect()
    }

    /// A node gives its tags; a token only the ones [`RustNames::tokens`]
    /// lists, so a token spelt like a production (EQL's `|` and its `pipe`
    /// stage) does not stand in for the node.
    fn parse(&self, body: &str) -> Parsed {
        let nodes: BTreeSet<String> = (self.node_kinds)().iter().map(|k| snake_case(k)).collect();
        let (has_error, kinds) = (self.kinds)(body);
        let kinds: Vec<String> = kinds
            .iter()
            .flat_map(|k| {
                let node = nodes.contains(&snake_case(k));
                self.tags_of(k)
                    .into_iter()
                    .filter(move |t| node || self.tokens.contains(&t.as_str()))
            })
            .collect();
        Parsed {
            has_error,
            dump: kinds.join(" "),
            kinds: kinds.into_iter().collect(),
        }
    }
}

/// The ES|QL names of `opentide-esql`'s own parser (#1228): its node kinds,
/// and its trees parsed on a 1 MB stack (the browser WASM module's).
struct EsqlNames;

impl KindNames for EsqlNames {
    fn productions(&self) -> BTreeSet<String> {
        opentide_esql::production_names()
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    fn parse(&self, body: &str) -> Parsed {
        let body = body.to_string();
        let (has_error, kinds) = std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(move || opentide_esql::debug_kinds(&body))
            .unwrap()
            .join()
            .expect("the ES|QL parser overflowed a 1 MB stack or panicked");
        Parsed {
            has_error,
            dump: kinds.join(" "),
            kinds: kinds.into_iter().map(str::to_string).collect(),
        }
    }
}

/// The names of the pure-Rust KQL parser (#1230): its node kinds, lower-case,
/// and the token classes the corpus tags. Four kinds are spelt shorter than
/// the tree-sitter rules the corpus tags, which [`KQL_TAG_NAMES`] maps.
struct KqlNames;

/// A KQL kind and the tag the corpus gives it (its tree-sitter rule's name).
const KQL_TAG_NAMES: &[(&str, &str)] = &[
    ("index_expr", "index_expression"),
    ("member_expr", "member_expression"),
    ("quoted_ident", "quoted_identifier"),
    ("toscalar_expr", "toscalar_expression"),
];

/// The token classes the corpus tags, as productions of their own.
const KQL_TOKEN_PRODUCTIONS: &[&str] = &[
    "comment",
    "string",
    "number",
    "quoted_identifier",
    "typed_literal",
];

fn kql_tag(kind: String) -> String {
    KQL_TAG_NAMES
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or(kind, |(_, tag)| (*tag).to_string())
}

impl KindNames for KqlNames {
    fn productions(&self) -> BTreeSet<String> {
        opentide_kql::inspect::node_kinds()
            .into_iter()
            .filter(|k| k != "error")
            .map(kql_tag)
            .chain(KQL_TOKEN_PRODUCTIONS.iter().map(ToString::to_string))
            .collect()
    }

    fn parse(&self, body: &str) -> Parsed {
        let (has_error, kinds, dump) = opentide_kql::inspect::tree_kinds(body);
        Parsed {
            has_error,
            kinds: kinds.into_iter().map(kql_tag).collect(),
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

/// The kind-name table of `language`.
fn kind_names(language: LanguageId) -> Box<dyn KindNames> {
    let rust = |node_kinds, kinds, tags, tokens| -> Box<dyn KindNames> {
        Box::new(RustNames {
            node_kinds,
            kinds,
            tags,
            tokens,
        })
    };
    match language {
        LanguageId::Cql => Box::new(CqlNames),
        LanguageId::Kql => Box::new(KqlNames),
        LanguageId::Esql => Box::new(EsqlNames),
        LanguageId::Spl => rust(
            opentide_spl::debug_node_kinds,
            opentide_spl::debug_kinds,
            SPL_TAGS,
            SPL_TOKENS,
        ),
        LanguageId::Eql => rust(
            opentide_eql::debug_node_kinds,
            opentide_eql::debug_kinds,
            EQL_TAGS,
            EQL_TOKENS,
        ),
        LanguageId::Kuery => rust(
            opentide_kuery::debug_node_kinds,
            opentide_kuery::debug_kinds,
            KUERY_TAGS,
            KUERY_TOKENS,
        ),
        LanguageId::Lucene => rust(
            opentide_lucene::debug_node_kinds,
            opentide_lucene::debug_kinds,
            LUCENE_TAGS,
            LUCENE_TOKENS,
        ),
        LanguageId::Falco => rust(
            opentide_falco::debug_node_kinds,
            opentide_falco::debug_kinds,
            FALCO_TAGS,
            FALCO_TOKENS,
        ),
        LanguageId::Exabeam => rust(
            opentide_exabeam::debug_node_kinds,
            opentide_exabeam::debug_kinds,
            EXABEAM_TAGS,
            EXABEAM_TOKENS,
        ),
        LanguageId::Yaral => rust(
            opentide_yaral::debug_node_kinds,
            opentide_yaral::debug_kinds,
            YARAL_TAGS,
            YARAL_TOKENS,
        ),
        LanguageId::Yara => rust(
            opentide_yara::debug_node_kinds,
            opentide_yara::debug_kinds,
            YARA_TAGS,
            YARA_TOKENS,
        ),
        other => panic!("no corpus gate for {other:?}"),
    }
}

// SPL, kuery, Lucene, Falco and Exabeam name every kind as the corpus tags it;
// a few productions are tokens.
const SPL_TAGS: &[(&str, &str)] = &[];
const SPL_TOKENS: &[&str] = &["comment"];
const KUERY_TAGS: &[(&str, &str)] = &[];
const KUERY_TOKENS: &[&str] = &["quoted_string"];
const LUCENE_TAGS: &[(&str, &str)] = &[];
const LUCENE_TOKENS: &[&str] = &["boost", "fuzzy", "star", "wildcard_term"];
const FALCO_TAGS: &[(&str, &str)] = &[];
const FALCO_TOKENS: &[&str] = &["quoted_string"];
const EXABEAM_TAGS: &[(&str, &str)] = &[];
const EXABEAM_TOKENS: &[&str] = &[];

/// EQL: a pipe stage is tree-sitter's `pipe`; the two comment tokens its `comment`.
const EQL_TAGS: &[(&str, &str)] = &[
    ("pipe_stage", "pipe"),
    ("line_comment", "comment"),
    ("block_comment", "comment"),
];
const EQL_TOKENS: &[&str] = &["comment"];

/// YARA-L: the expression kinds are spelt shorter than tree-sitter's rules;
/// both graph operations are its `graph_operation`.
const YARAL_TAGS: &[(&str, &str)] = &[
    ("and_expr", "and_expression"),
    ("or_expr", "or_expression"),
    ("not_expr", "not_expression"),
    ("binary_expr", "binary_expression"),
    ("unary_expr", "unary_expression"),
    ("paren_expr", "parenthesized_expression"),
    ("if_expr", "if_expression"),
    ("in_expr", "in_expression"),
    ("of_expr", "of_expression"),
    ("array_expr", "array"),
    ("graph_append", "graph_operation"),
    ("graph_join", "graph_operation"),
    ("regex_lit", "regex"),
];
const YARAL_TOKENS: &[&str] = &["comment", "duration", "raw_string", "regex"];

/// YARA: `yara-x-parser`'s CST (#1225) is coarser than the tree-sitter grammar
/// the fixtures were tagged for. Its blocks and declarations are nodes under
/// other names; an expression is a generic `expr`, `term` or `boolean_term`,
/// told by an operator token and the node it stands in (`opentide_yara::debug_kinds`
/// names a token `parent/token`; a negated hex byte, `~5A`, is `hex_byte_not`).
const YARA_TAGS: &[(&str, &str)] = &[
    ("rule_decl", "rule"),
    ("rule_mods", "rule_modifier"),
    ("rule_tags", "tags"),
    ("meta_blk", "meta_section"),
    ("meta_def", "meta_definition"),
    ("patterns_blk", "strings_section"),
    ("pattern_def", "string_definition"),
    ("pattern_mod", "string_modifier"),
    ("hex_pattern", "hex_string"),
    ("condition_blk", "condition_section"),
    ("import_stmt", "import"),
    ("include_stmt", "include"),
    ("func_call", "call_expression"),
    ("for_expr", "for_expression"),
    ("of_expr", "of_expression"),
    ("expr_tuple", "integer_enumeration"),
    ("pattern_ident_tuple", "string_set"),
    ("boolean_expr_tuple", "rule_set"),
    ("boolean_expr/and_kw", "and_expression"),
    ("boolean_expr/or_kw", "or_expression"),
    ("boolean_term/not_kw", "not_expression"),
    ("expr/add", "arithmetic_expression"),
    ("expr/sub", "arithmetic_expression"),
    ("expr/mul", "arithmetic_expression"),
    ("expr/div", "arithmetic_expression"),
    ("expr/mod", "arithmetic_expression"),
    ("expr/shl", "arithmetic_expression"),
    ("expr/shr", "arithmetic_expression"),
    ("expr/bitwise_and", "arithmetic_expression"),
    ("expr/bitwise_or", "arithmetic_expression"),
    ("expr/bitwise_xor", "arithmetic_expression"),
    ("term/minus", "unary_expression"),
    ("term/bitwise_not", "unary_expression"),
    ("meta_def/minus", "negative_integer"),
    ("hex_sub_pattern/hex_byte_not", "hex_not"),
    ("hex_alternative/hex_byte_not", "hex_not"),
    ("boolean_term/eq", "comparison"),
    ("boolean_term/ne", "comparison"),
    ("boolean_term/lt", "comparison"),
    ("boolean_term/le", "comparison"),
    ("boolean_term/gt", "comparison"),
    ("boolean_term/ge", "comparison"),
    ("boolean_term/contains_kw", "comparison"),
    ("boolean_term/icontains_kw", "comparison"),
    ("boolean_term/startswith_kw", "comparison"),
    ("boolean_term/istartswith_kw", "comparison"),
    ("boolean_term/endswith_kw", "comparison"),
    ("boolean_term/iendswith_kw", "comparison"),
    ("boolean_term/iequals_kw", "comparison"),
    ("boolean_term/matches_kw", "comparison"),
    ("pattern_mod/base64_kw", "base64_modifier"),
    ("pattern_mod/base64wide_kw", "base64_modifier"),
    ("pattern_mod/xor_kw", "xor_modifier"),
    ("term/entrypoint_kw", "entrypoint"),
    ("term/filesize_kw", "filesize"),
    ("term/float_lit", "float"),
    ("term/dot", "member_expression"),
    ("primary_expr/l_bracket", "index_expression"),
    ("term/l_bracket", "indexed_string"),
    ("boolean_term/l_paren", "parenthesized_expression"),
    ("term/l_paren", "parenthesized_primary"),
    ("term/pattern_count", "string_count"),
    ("term/in_kw", "string_count_in_range"),
    ("term/pattern_length", "string_length"),
    ("term/pattern_offset", "string_offset"),
    ("boolean_term/pattern_ident", "string_match"),
    ("pattern_ident_tuple/asterisk", "string_wildcard"),
    ("quantifier/percent", "percent_quantifier"),
    ("*/comment", "comment"),
    ("*/regexp", "regexp"),
];
const YARA_TOKENS: &[&str] = &[
    "and_expression",
    "or_expression",
    "not_expression",
    "arithmetic_expression",
    "unary_expression",
    "negative_integer",
    "hex_not",
    "comparison",
    "base64_modifier",
    "xor_modifier",
    "entrypoint",
    "filesize",
    "float",
    "comment",
    "member_expression",
    "index_expression",
    "indexed_string",
    "parenthesized_expression",
    "parenthesized_primary",
    "string_count",
    "string_count_in_range",
    "string_length",
    "string_offset",
    "string_match",
    "string_wildcard",
    "percent_quantifier",
    "regexp",
];

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
fn kql_named_rules_are_known() {
    let rules = kind_names(LanguageId::Kql).productions();
    let tags = tags_in("crates/testdata/corpus/kql");
    // The kinds of the pure-Rust parser (#1230) the corpus does not tag.
    let skip: BTreeSet<&str> = [
        "source_file",
        "query",
        "tabular_expression",
        "tabular_source",
        "table_ref",
        "paren_tabular",
        "subquery",
        "rename_item",
        "reorder_item",
        "assignment",
        "tuple_assignment",
        "name_tuple",
        "sort_item",
        "or_expr",
        "and_expr",
        "not_expr",
        "comparison_expr",
        "in_expr",
        "between_expr",
        "additive_expr",
        "multiplicative_expr",
        "unary_expr",
        "paren_expr",
        "name_ref",
        "literal",
        "print_operator",
        "unknown_operator",
        "count_operator",
        "keyword_operator",
        "project_keep_operator",
        "project_reorder_operator",
        // pieces of the productions above, covered by their fixtures
        "parameter",
        "type",
        "table_type",
        "table_column",
        "datatable_column",
        "option_value",
        "mv_option",
        "mv_expand_item",
        "parse_piece",
        "parse_column",
        "series_aggregate",
        "series_default",
        "top_nested_of",
        "top_nested_others",
        "top_nested_by",
        "star_arg",
        "json_array",
        "json_object",
        "json_property",
        "json_scalar",
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
        let tree = kind_names(LanguageId::Kql).parse(&body);
        assert!(!tree.has_error, "{name} tree={}", tree.dump);
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
        let tree = kind_names(LanguageId::Spl).parse(&body);
        assert!(!tree.has_error, "{name} kinds={}", tree.dump);
    }
}

#[test]
fn spl_valid_bare_search_and_unknown_command_parse() {
    let names = kind_names(LanguageId::Spl);
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
    /// Valid fixtures of a production the parser does not have, which it
    /// rejects: each with its reason where the gate is declared. They must
    /// stay rejected, so one the parser comes to accept is given back.
    unparsed: &'static [&'static str],
}

fn fixture_body(text: &str) -> String {
    text.lines().skip(1).collect::<Vec<_>>().join("\n")
}

fn check_gate(gate: &ElasticGate) {
    check_gate_with(gate, &*kind_names(gate.language));
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
            if gate.unparsed.contains(&name.as_str()) {
                assert!(
                    tree.has_error,
                    "{dir}/{name} parses now: take it off the gate's `unparsed`"
                );
                continue;
            }
            assert!(
                !tree.has_error,
                "{dir}/{name} must parse; kinds={}",
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
    check_gate(&ESQL_GATE);
}

const ESQL_GATE: ElasticGate = ElasticGate {
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
        // One-token nodes of the pure-Rust parser that tree-sitter kept as
        // tokens: the production around them is what the corpus tags.
        "enrich_mode",
        "metadata_field",
        "policy_name",
        "promql_text",
        "star",
        "time_unit",
        "unknown_text",
    ],
    unparsed: &[],
};

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
        unparsed: &[],
    });
}

#[test]
fn kuery_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Kuery,
        id: "kuery",
        structural: &["source_file"],
        unparsed: &[],
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
            "required",
            "prohibited",
            "or",
            "and",
            "not",
        ],
        unparsed: &[],
    });
}

#[test]
fn falco_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Falco,
        id: "falco",
        structural: &[
            "source_file",
            "argument_value",
            "unary_operator",
            "comparison_operator",
            "list_operator",
            "bare_string",
        ],
        unparsed: &[],
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
        unparsed: &[],
    });
}

#[test]
fn yara_corpus_gate() {
    check_gate(&ElasticGate {
        language: LanguageId::Yara,
        id: "yara",
        // yara-x's grouping nodes, which every fixture that tags an
        // expression contains, and YARA-X's `with` (no fixture yet).
        structural: &[
            "source_file",
            "boolean_expr",
            "boolean_term",
            "expr",
            "term",
            "primary_expr",
            "pattern_mods",
            "hex_sub_pattern",
            "iterable",
            "quantifier",
            "with_expr",
            "with_decls",
            "with_decl",
        ],
        unparsed: &[
            // libyara's rule wildcards (`any of (base*)`): YARA-X 1.23 reads
            // `base*` as a product, which a rule set does not take.
            "rule_wildcard__valid.yar",
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
            "context_table",
        ],
        unparsed: &[],
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
            "window_bound",
            "variable",
            "arguments",
            "function_name",
            "match_clause",
            "order_item",
            "meta_entry",
            "option_entry",
            "argument_name",
            "count_ref",
            "literal",
            "member",
            "meta_key",
            "name_ref",
            "option_key",
            "rule_name",
            "stage_name",
            "time_unit",
        ],
        unparsed: &[],
    });
}

#[test]
fn rust_names_read_the_kinds_of_a_tree() {
    let names = kind_names(LanguageId::Spl);
    let tree = names.parse("index=main | bogus foo=bar");
    assert!(!tree.has_error, "{}", tree.dump);
    assert!(tree.has_kind("unknown_command"), "{}", tree.dump);
    // A kind is a whole name: a prefix of one is not a kind.
    assert!(!tree.has_kind("unknown"), "{}", tree.dump);
    assert!(names.parse("index=main | (").has_error);
    assert!(names.productions().contains("unknown_command"));
}

#[test]
fn snake_case_spells_both_kind_styles() {
    assert_eq!(snake_case("FieldValueExpression"), "field_value_expression");
    assert_eq!(
        snake_case("FIELD_VALUE_EXPRESSION"),
        "field_value_expression"
    );
    assert_eq!(snake_case("BASE64WIDE_KW"), "base64wide_kw");
    assert_eq!(snake_case("Or"), "or");
}

/// A YARA token stands for a production only in the node it stands in: a
/// pattern identifier in a condition is `string_match`, in a definition it
/// is not; a parenthesis in a boolean term is `parenthesized_expression`, in
/// a term `parenthesized_primary`. A kind the table does not list keeps its
/// own name, and a token's own name is never a production.
#[test]
fn yara_tokens_are_told_by_the_node_they_stand_in() {
    let names = kind_names(LanguageId::Yara);
    let tree = names.parse("rule r { strings: $a = \"x\" condition: ($a) and #a > (1 + 2) }");
    assert!(!tree.has_error, "{}", tree.dump);
    for tag in [
        "rule",
        "string_definition",
        "string_match",
        "parenthesized_expression",
        "parenthesized_primary",
        "and_expression",
        "string_count",
        "comparison",
        "arithmetic_expression",
        "boolean_expr",
    ] {
        assert!(tree.has_kind(tag), "{tag}: {}", tree.dump);
    }
    assert!(!tree.has_kind("rule_decl"), "{}", tree.dump);
    assert!(!tree.has_kind("l_paren"), "{}", tree.dump);
    let tree = names.parse("rule r { strings: $a = \"x\" condition: true }");
    assert!(!tree.has_kind("string_match"), "{}", tree.dump);
    assert!(names.parse("rule r { condition: }").has_error);
}

/// A fixture listed as `unparsed` must stay rejected: one the parser accepts
/// fails the gate.
#[test]
fn an_unparsed_fixture_that_parses_fails_the_gate() {
    let gate = std::panic::catch_unwind(|| {
        check_gate(&ElasticGate {
            language: LanguageId::Kuery,
            id: "kuery",
            structural: &["source_file"],
            unparsed: &["group__valid.kuery"],
        });
    });
    assert!(
        gate.is_err(),
        "a listed fixture that parses must fail the gate"
    );
}

#[test]
fn the_gate_reads_productions_and_trees_only_through_its_table() {
    use std::cell::Cell;

    /// A table that counts its calls and hands them to the kuery names.
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
        inner: kind_names(LanguageId::Kuery),
        productions: Cell::new(0),
        parses: Cell::new(0),
    };
    check_gate_with(
        &ElasticGate {
            language: LanguageId::Kuery,
            id: "kuery",
            structural: &["source_file"],
            unparsed: &[],
        },
        &names,
    );
    assert_eq!(names.productions.get(), 1);
    assert!(names.parses.get() > 0);
}

/// The ES|QL table is the pure-Rust parser's: a body it cannot parse is an
/// error, a valid one names its productions, and a production with no tagged
/// fixture fails the gate.
#[test]
fn the_esql_table_flags_what_the_gate_must() {
    let names = kind_names(LanguageId::Esql);
    let valid = names.parse("FROM logs-* | WHERE a == 1 | KEEP a");
    assert!(!valid.has_error, "{}", valid.dump);
    for kind in [
        "from_command",
        "where_command",
        "keep_command",
        "comparison",
    ] {
        assert!(valid.has_kind(kind), "{kind}: {}", valid.dump);
    }
    for broken in ["FROM logs-* | WHERE", "FROM a | KEEP a,", "ROW a = (1"] {
        assert!(names.parse(broken).has_error, "{broken}");
    }

    /// The ES|QL table with one production no fixture is tagged with.
    struct Extra(Box<dyn KindNames>);
    impl KindNames for Extra {
        fn productions(&self) -> BTreeSet<String> {
            let mut out = self.0.productions();
            out.insert("no_such_production".into());
            out
        }
        fn parse(&self, body: &str) -> Parsed {
            self.0.parse(body)
        }
    }
    let gate = std::panic::catch_unwind(|| {
        check_gate_with(&ESQL_GATE, &Extra(kind_names(LanguageId::Esql)));
    });
    // The real table passes; the one extra production alone fails it.
    check_gate_with(&ESQL_GATE, &*kind_names(LanguageId::Esql));
    assert!(gate.is_err(), "an untagged production must fail the gate");
}

#[test]
fn kql_names_read_the_pure_rust_tree() {
    let names = kind_names(LanguageId::Kql);
    let tree = names.parse("T | where a.b == 1 | project ['x y'] // c");
    assert!(!tree.has_error, "{}", tree.dump);
    for kind in [
        "where_operator",
        "member_expression",
        "quoted_identifier",
        "comment",
    ] {
        assert!(tree.has_kind(kind), "{kind}: {}", tree.dump);
    }
    // The parser's spelling is not a tag; the corpus's is.
    assert!(!tree.has_kind("member_expr"), "{}", tree.dump);
    assert!(names.parse("T | where").has_error);
    let productions = names.productions();
    assert!(productions.contains("toscalar_expression"));
    assert!(productions.contains("typed_literal"));
    assert!(!productions.contains("error"));
}

#[test]
fn cql_names_are_the_pure_rust_tree() {
    let names = kind_names(LanguageId::Cql);
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
