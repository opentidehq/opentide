//! SPL's grammar as functions over [`opentide_parse::Parser`]: the entry
//! point, the pipeline and its stages. The search terms are in `search`;
//! the commands that have a rule of their own come in later PRs of the
//! series, and until then every command but `search` is read as a command
//! with arguments no rule models yet.

use super::kind::{SyntaxKind as K, SyntaxNode};
use super::lexer::lex;
use super::{expr, rest, search, stats, table};
use opentide_parse::{Grammar, Input, Parse, Parser, TokenSet, build};

/// Nesting (groups, subsearches) deeper than this is one error: the floor
/// of `crates/opentide-analysis/tests/deep_queries.rs`, which tree-sitter
/// met and `NESTING_CEILING` caps.
pub const MAX_DEPTH: u32 = 1_000;

/// What the toolkit needs to know of SPL's kinds.
pub const GRAMMAR: Grammar = Grammar {
    eof: K::EOF.raw(),
    error: K::ERROR.raw(),
    trivia: K::set(&[K::WHITESPACE, K::COMMENT]),
    max_depth: MAX_DEPTH,
};

/// Where a pipeline is: the query, or the body of a `[ ... ]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Context {
    Query,
    Subsearch,
}

/// Parses `source`: the lossless tree and its errors.
pub fn parse(source: &str) -> (SyntaxNode, Parse) {
    let input = Input::new(source, lex(source), GRAMMAR);
    let mut p = Parser::new(&input);
    let root = p.start();
    pipeline(&mut p, Context::Query);
    root.complete(&mut p, K::SOURCE_FILE.raw());
    let parse = build(&input, p.finish());
    (SyntaxNode::new_root(parse.green.clone()), parse)
}

pub(super) fn at(p: &mut Parser<'_>, kind: K) -> bool {
    p.at(kind.raw())
}

/// Whether the current token is the name `text` (no expected-set update).
pub(super) fn at_name(p: &Parser<'_>, text: &str) -> bool {
    p.current() == K::IDENT.raw() && p.current_text() == text
}

/// Consumes the current token as `kind`, in a node of `node`.
pub(super) fn leaf(p: &mut Parser<'_>, node: K, kind: K) {
    let m = p.start();
    p.bump_as(kind.raw());
    m.complete(p, node.raw());
}

/// `)`, `]`: consumed if it is there, else `missing` is an error and nothing
/// is consumed (an enclosing rule takes over at the stray token).
pub(super) fn close(p: &mut Parser<'_>, kind: K, missing: &str) {
    if !p.eat(kind.raw()) {
        p.error(missing);
    }
}

/// A pipeline: stages between pipes. A leading pipe is allowed; so is a
/// trailing one in the query (Splunk ignores an empty last stage), not in a
/// subsearch, and an empty stage anywhere else is an error.
pub(super) fn pipeline(p: &mut Parser<'_>, ctx: Context) {
    let m = p.start();
    let piped = p.eat(K::PIPE.raw());
    first_stage(p, ctx, piped);
    loop {
        if p.at_eof() || (ctx == Context::Subsearch && at(p, K::R_BRACKET)) {
            break;
        }
        if at(p, K::PIPE) {
            p.bump();
            if p.at_eof() || (ctx == Context::Subsearch && at(p, K::R_BRACKET)) {
                if ctx == Context::Subsearch {
                    p.error("missing a command after `|`");
                }
                break;
            }
            command_stage(p, false);
        } else {
            // Something a stage cannot continue with: a stray `)` or `]`, a
            // term after a command that takes none.
            let stop = if ctx == Context::Subsearch {
                K::set(&[K::PIPE, K::R_BRACKET])
            } else {
                K::set(&[K::PIPE])
            };
            p.err_until("unexpected token", stop);
        }
    }
    m.complete(p, K::PIPELINE.raw());
}

/// The first stage. With no leading pipe, a query's first stage is search
/// terms (`tstats count` searches for the word `tstats`); after a pipe it is
/// a command. A subsearch's body runs a leading word as a command and takes
/// anything else as terms.
fn first_stage(p: &mut Parser<'_>, ctx: Context, piped: bool) {
    if p.at_eof() || (ctx == Context::Subsearch && at(p, K::R_BRACKET)) {
        p.error("expected a command or a search");
        return;
    }
    if piped {
        if at(p, K::MACRO_TOKEN) && search::more_terms_after_macro(p) {
            search::bare_search(p, true);
        } else {
            command_stage(p, true);
        }
        return;
    }
    match ctx {
        Context::Query => {
            if at_name(p, "search") {
                search::search_command(p);
            } else if at(p, K::MACRO_TOKEN) && !search::more_terms_after_macro(p) {
                search::macro_call(p);
            } else {
                search::bare_search(p, true);
            }
        }
        Context::Subsearch => {
            if search::starts_bare_head(p) {
                search::bare_search(p, false);
            } else {
                command_stage(p, true);
            }
        }
    }
}

/// The commands of the stats family.
const STATS_COMMANDS: [&str; 9] = [
    "stats",
    "eventstats",
    "streamstats",
    "sistats",
    "chart",
    "timechart",
    "sichart",
    "sitimechart",
    "geostats",
];

/// A stage after a pipe: a command, or a macro that stands for one.
fn command_stage(p: &mut Parser<'_>, first: bool) {
    if at(p, K::MACRO_TOKEN) {
        search::macro_call(p);
    } else if at_name(p, "search") {
        search::search_command(p);
    } else if at_name(p, "where") {
        expr::where_command(p);
    } else if at_name(p, "eval") {
        expr::eval_command(p);
    } else if STATS_COMMANDS.contains(&p.current_text()) && at(p, K::IDENT) {
        stats::stats_command(p);
    } else if at_name(p, "tstats") {
        stats::tstats_command(p);
    } else if at(p, K::IDENT) && table::is_table_command(p.current_text()) {
        table::command(p);
    } else if at(p, K::IDENT) && rest::is_rest_command(p.current_text()) {
        rest::command(p, first);
    } else if at(p, K::IDENT) {
        rest::catalog_or_unknown(p);
    } else {
        let stop = K::set(&[K::PIPE, K::R_BRACKET]);
        if p.at_eof() || stop.contains(p.current()) {
            // An empty stage: the error, with no empty node.
            p.error("expected a command");
        } else {
            p.err_until("expected a command", stop);
        }
    }
}

/// The tokens a search term, and so a stage, cannot continue past.
pub(super) const STAGE_END: TokenSet = K::set(&[K::PIPE, K::R_BRACKET, K::R_PAREN]);

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use opentide_parse::{debug_errors, debug_tree};

    pub(in crate::syntax) fn render(source: &str) -> String {
        let (tree, parse) = parse(source);
        assert_eq!(tree.to_string(), source, "lossless");
        let mut out = debug_tree(&tree, |k: K| format!("{k:?}"));
        out.push_str("--\n");
        out.push_str(&debug_errors(&parse.errors, |k| {
            format!(
                "{:?}",
                <super::super::kind::Lang as rowan::Language>::kind_from_raw(k)
            )
        }));
        out
    }

    #[test]
    fn a_bare_search_is_terms_and_a_field_comparison() {
        let out = render("index=main error");
        assert!(out.contains("FIELD_VALUE@0..10"), "{out}");
        assert!(out.contains("BARE_SEARCH"), "{out}");
        assert!(out.ends_with("--\n"), "no errors: {out}");
    }

    #[test]
    fn deep_nesting_is_one_error_not_a_stack_overflow() {
        let n = 5_000;
        let source = format!("{}a{}", "(".repeat(n), ")".repeat(n));
        let (tree, parse) = parse(&source);
        assert_eq!(tree.to_string(), source);
        assert_eq!(parse.errors.len(), 1, "{:?}", parse.errors);
    }
}
