//! The typed AST of `esql.ungram` (`src/generated/ast.rs`, written by
//! `cargo xtask codegen`, kept current by `codegen --check`) and its
//! conformance: every tree of the corpus that parses without an error has
//! the shape the `.ungram` states, node by node.
//!
//! The parser is private to the crate (production still runs tree-sitter), so
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
