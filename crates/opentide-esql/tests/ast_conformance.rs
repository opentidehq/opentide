//! The typed AST of `esql.ungram` (`src/generated/ast.rs`, written by
//! `cargo xtask codegen`, kept current by `codegen --check`) and its
//! conformance: every tree of the corpus that parses without an error has
//! the shape the `.ungram` states, node by node.
//!
//! The parser is private to the crate, so
//! this test includes its source.

#![expect(
    dead_code,
    unused_imports,
    reason = "the included modules are used in part"
)]
#![expect(
    clippy::enum_variant_names,
    clippy::wrong_self_convention,
    reason = "the generated AST names its types and variants as the grammar does"
)]

#[path = "../src/generated/ast.rs"]
mod ast;
#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser/mod.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_parse::ast::AstNode;
use opentide_parse::conformance::{assert_conforms, check};
use std::path::{Path, PathBuf};

pub(crate) use syntax::{Lang, SyntaxKind};
pub(crate) type SyntaxNode = rowan::SyntaxNode<Lang>;
pub(crate) type SyntaxToken = rowan::SyntaxToken<Lang>;

/// The kind of each token of `esql.ungram`.
#[macro_export]
macro_rules! T {
    [from] => { $crate::SyntaxKind::FROM_KW };
    [ts] => { $crate::SyntaxKind::TS_KW };
    [row] => { $crate::SyntaxKind::ROW_KW };
    [show] => { $crate::SyntaxKind::SHOW_KW };
    [info] => { $crate::SyntaxKind::INFO_KW };
    [explain] => { $crate::SyntaxKind::EXPLAIN_KW };
    [promql] => { $crate::SyntaxKind::PROMQL_KW };
    [set] => { $crate::SyntaxKind::SET_KW };
    [metadata] => { $crate::SyntaxKind::METADATA_KW };
    [where] => { $crate::SyntaxKind::WHERE_KW };
    [eval] => { $crate::SyntaxKind::EVAL_KW };
    [keep] => { $crate::SyntaxKind::KEEP_KW };
    [drop] => { $crate::SyntaxKind::DROP_KW };
    [rename] => { $crate::SyntaxKind::RENAME_KW };
    [as] => { $crate::SyntaxKind::AS_KW };
    [sort] => { $crate::SyntaxKind::SORT_KW };
    [asc] => { $crate::SyntaxKind::ASC_KW };
    [desc] => { $crate::SyntaxKind::DESC_KW };
    [nulls] => { $crate::SyntaxKind::NULLS_KW };
    [first] => { $crate::SyntaxKind::FIRST_KW };
    [last] => { $crate::SyntaxKind::LAST_KW };
    [limit] => { $crate::SyntaxKind::LIMIT_KW };
    [stats] => { $crate::SyntaxKind::STATS_KW };
    [inline] => { $crate::SyntaxKind::INLINE_KW };
    [inlinestats] => { $crate::SyntaxKind::INLINESTATS_KW };
    [by] => { $crate::SyntaxKind::BY_KW };
    [dissect] => { $crate::SyntaxKind::DISSECT_KW };
    [grok] => { $crate::SyntaxKind::GROK_KW };
    [enrich] => { $crate::SyntaxKind::ENRICH_KW };
    [on] => { $crate::SyntaxKind::ON_KW };
    [with] => { $crate::SyntaxKind::WITH_KW };
    [mv_expand] => { $crate::SyntaxKind::MV_EXPAND_KW };
    [lookup] => { $crate::SyntaxKind::LOOKUP_KW };
    [left] => { $crate::SyntaxKind::LEFT_KW };
    [right] => { $crate::SyntaxKind::RIGHT_KW };
    [full] => { $crate::SyntaxKind::FULL_KW };
    [join] => { $crate::SyntaxKind::JOIN_KW };
    [change_point] => { $crate::SyntaxKind::CHANGE_POINT_KW };
    [completion] => { $crate::SyntaxKind::COMPLETION_KW };
    [rerank] => { $crate::SyntaxKind::RERANK_KW };
    [sample] => { $crate::SyntaxKind::SAMPLE_KW };
    [fork] => { $crate::SyntaxKind::FORK_KW };
    [fuse] => { $crate::SyntaxKind::FUSE_KW };
    [score] => { $crate::SyntaxKind::SCORE_KW };
    [key] => { $crate::SyntaxKind::KEY_KW };
    [group] => { $crate::SyntaxKind::GROUP_KW };
    [uri_parts] => { $crate::SyntaxKind::URI_PARTS_KW };
    [registered_domain] => { $crate::SyntaxKind::REGISTERED_DOMAIN_KW };
    [user_agent] => { $crate::SyntaxKind::USER_AGENT_KW };
    [ip_location] => { $crate::SyntaxKind::IP_LOCATION_KW };
    [metrics_info] => { $crate::SyntaxKind::METRICS_INFO_KW };
    [ts_info] => { $crate::SyntaxKind::TS_INFO_KW };
    [ts_collapse] => { $crate::SyntaxKind::TS_COLLAPSE_KW };
    [dedup] => { $crate::SyntaxKind::DEDUP_KW };
    [mmr] => { $crate::SyntaxKind::MMR_KW };
    [highlight] => { $crate::SyntaxKind::HIGHLIGHT_KW };
    [dense_vector] => { $crate::SyntaxKind::DENSE_VECTOR_KW };
    [fillnull] => { $crate::SyntaxKind::FILLNULL_KW };
    [and] => { $crate::SyntaxKind::AND_KW };
    [or] => { $crate::SyntaxKind::OR_KW };
    [not] => { $crate::SyntaxKind::NOT_KW };
    [in] => { $crate::SyntaxKind::IN_KW };
    [is] => { $crate::SyntaxKind::IS_KW };
    [like] => { $crate::SyntaxKind::LIKE_KW };
    [rlike] => { $crate::SyntaxKind::RLIKE_KW };
    [null] => { $crate::SyntaxKind::NULL_KW };
    [true] => { $crate::SyntaxKind::TRUE_KW };
    [false] => { $crate::SyntaxKind::FALSE_KW };
    [ident] => { $crate::SyntaxKind::IDENT };
    [id_pattern] => { $crate::SyntaxKind::ID_PATTERN_TEXT };
    [quoted_ident] => { $crate::SyntaxKind::QUOTED_IDENT };
    [param] => { $crate::SyntaxKind::PARAM };
    [number_lit] => { $crate::SyntaxKind::NUMBER_LIT };
    [string_lit] => { $crate::SyntaxKind::STRING_LIT };
    [source_text] => { $crate::SyntaxKind::SOURCE_TEXT };
    [policy_part] => { $crate::SyntaxKind::POLICY_PART };
    [promql_word] => { $crate::SyntaxKind::PROMQL_WORD };
    [unknown_word] => { $crate::SyntaxKind::UNKNOWN_WORD };
    [command_word] => { $crate::SyntaxKind::COMMAND_WORD };
    [|] => { $crate::SyntaxKind::PIPE };
    [,] => { $crate::SyntaxKind::COMMA };
    [;] => { $crate::SyntaxKind::SEMI };
    [.] => { $crate::SyntaxKind::DOT };
    [:] => { $crate::SyntaxKind::COLON };
    [::] => { $crate::SyntaxKind::COLON_COLON };
    [=] => { $crate::SyntaxKind::EQ };
    [==] => { $crate::SyntaxKind::EQ_EQ };
    [!=] => { $crate::SyntaxKind::NOT_EQ };
    [<] => { $crate::SyntaxKind::LT };
    [<=] => { $crate::SyntaxKind::LT_EQ };
    [>] => { $crate::SyntaxKind::GT };
    [>=] => { $crate::SyntaxKind::GT_EQ };
    [+] => { $crate::SyntaxKind::PLUS };
    [-] => { $crate::SyntaxKind::MINUS };
    [*] => { $crate::SyntaxKind::STAR_TOKEN };
    [/] => { $crate::SyntaxKind::SLASH };
    [%] => { $crate::SyntaxKind::PERCENT };
    ['('] => { $crate::SyntaxKind::L_PAREN };
    [')'] => { $crate::SyntaxKind::R_PAREN };
    ['['] => { $crate::SyntaxKind::L_BRACK };
    [']'] => { $crate::SyntaxKind::R_BRACK };
    ['{'] => { $crate::SyntaxKind::L_BRACE };
    ['}'] => { $crate::SyntaxKind::R_BRACE };
}

/// Every `.esql` file under `crates/testdata`.
fn corpus() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "esql") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut out,
    );
    out.sort();
    out
}

#[test]
fn every_corpus_tree_conforms_to_the_ungram() {
    let mut checked = 0;
    let mut bad = Vec::new();
    for path in corpus() {
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        let parse = parser::parse(&source);
        if !parse.errors.is_empty() {
            continue;
        }
        let root = SyntaxNode::new_root(parse.green);
        for mismatch in check(&root, ast::RULES, parser::GRAMMAR) {
            bad.push(format!("{}: {mismatch}", path.display()));
        }
        checked += 1;
    }
    assert!(
        bad.is_empty(),
        "{} mismatches:\n{}",
        bad.len(),
        bad.join("\n")
    );
    assert!(checked > 120, "checked {checked} trees");
}

/// Beyond the corpus: one query per command and per expression form, among
/// them the casts of a primary expression (a `LIKE` pattern, the input of
/// `GROK`, `DISSECT` and the extract commands), which the corpus does not
/// have and which once built an `INLINE_CAST` without its `TYPE_NAME`.
#[test]
fn every_command_and_expression_form_conforms() {
    for source in [
        "ROW a = -1::long, b = x::int::long, c = (1 + 2)::int, d = f(x)::int, e = 1 hour::time_duration",
        "FROM a | WHERE x LIKE \"a\"::keyword::text AND y NOT RLIKE \"b\"::keyword",
        "FROM a | WHERE x LIKE (\"a\", ?p) OR x::keyword : \"q\"",
        "FROM a | GROK x::keyword \"%{WORD:a}\", \"%{NUMBER:b}\"",
        "FROM a | DISSECT a.b::keyword \"%{x}\" APPEND_SEPARATOR = \",\"",
        "FROM a | URI_PARTS p = url.full::keyword",
        "FROM a | REGISTERED_DOMAIN d = TO_LOWER(host.name)",
        "FROM a | USER_AGENT ua = message WITH {\"properties\": [\"name\"]}",
        "FROM a | IP_LOCATION g = source.ip",
        "FROM a | DENSE_VECTOR e = message::keyword WITH {\"inference_id\": \"m\"}",
        "FROM a | HIGHLIGHT \"q\" ON host.*, message WITH {\"k\": 1}",
        "FROM a | MMR ?q ON a LIMIT 10 WITH {\"lambda\": 0.5}",
        "FROM a | RERANK r = \"q\" ON message, b = TO_LOWER(x) WITH {\"inference_id\": \"m\"}",
        "FROM a | COMPLETION r = CONCAT(a, b) WITH {\"inference_id\": \"x\"}",
        "FROM a | WHERE host.name IN (FROM b | KEEP host.name)",
        "FROM a | WHERE (host.name, user.name) NOT IN (FROM b | KEEP host.name, user.name)",
        "FROM a | EVAL ?p = x + 1 | STATS ??q = COUNT(*) WHERE x > 1 BY h = BUCKET(@timestamp, 1 hour)",
        "FROM a | LOOKUP JOIN idx AS q ON a == q.b",
        "FROM a | FUSE LINEAR SCORE BY s KEY BY a, b GROUP BY g WITH {\"w\": 1}",
        "FROM a | ENRICH _remote:policy ON host.name WITH n = x, y",
        "FROM a | CHANGE_POINT v ON t AS ty, pv BY h",
        "FROM a | FORK (WHERE a | EVAL b = 1) (STATS c = COUNT(*)) (LIMIT 1)",
        "FROM a | SORT a ASC NULLS LAST, b DESC | LIMIT 10 BY a, b | FILLNULL 0 ON a, b*",
        "FROM a | KEEP `a b`, a*.b, ?p | DROP a.* | RENAME a AS b, c = d | MV_EXPAND a.b",
        "FROM a, b::failures, c:d, \"e\" METADATA _id, _index | SAMPLE 0.5 | DEDUP",
        "SET a = 1; SET b = {\"x\": \"y\"}; EXPLAIN (FROM a | LIMIT 1)",
    ] {
        let parse = parser::parse(source);
        assert!(parse.errors.is_empty(), "{source}: {:?}", parse.errors);
        let root = SyntaxNode::new_root(parse.green);
        let bad = check(&root, ast::RULES, parser::GRAMMAR);
        assert!(
            bad.is_empty(),
            "{source}: {}",
            bad.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
