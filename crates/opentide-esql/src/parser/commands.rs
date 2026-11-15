//! Queries and their commands: the source commands and the pipeline. The
//! processing commands are in `processing.rs`.

use super::expressions::{constant, map_expression};
use super::{at_kw, comma_list, expect_kw, nth_kw, processing, token_node};
use crate::syntax::SyntaxKind as K;
use opentide_parse::{Parser, TokenSet};

/// Where a command that went wrong stops eating tokens.
pub(super) const COMMAND_END: TokenSet = K::set(&[K::PIPE, K::R_PAREN, K::SEMI]);

/// The keyword the current word is, if it is one.
pub(super) fn keyword(p: &Parser<'_>) -> Option<K> {
    (p.current() == K::WORD.raw())
        .then(|| K::from_keyword(p.current_text()))
        .flatten()
}

/// Whether the query or the command ends here.
pub(super) fn at_end(p: &mut Parser<'_>) -> bool {
    p.at_set(K::set(&[K::PIPE, K::R_PAREN])) || p.at_eof()
}

/// `SetCommand = 'set' name:Identifier '=' value:(Constant | MapExpression) ';'`
pub(super) fn set_command(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::SET_KW.raw());
    identifier(p);
    p.expect(K::EQ.raw(), "expected `=`");
    if p.at(K::L_BRACE.raw()) {
        map_expression(p);
    } else {
        constant(p);
    }
    p.expect(K::SEMI.raw(), "expected `;` after the setting");
    m.complete(p, K::SET_COMMAND.raw());
}

/// An identifier node.
pub(super) fn identifier(p: &mut Parser<'_>) {
    if p.at(K::IDENT.raw()) || p.current() == K::WORD.raw() {
        token_node(p, K::IDENT, K::IDENTIFIER);
    } else {
        p.err_recover("expected a name", COMMAND_END);
    }
}

/// `Query = source:SourceCommand ('|' command:ProcessingCommand)*`
pub(super) fn query(p: &mut Parser<'_>) {
    let m = p.start();
    if p.enter() {
        source_command(p);
        pipeline(p);
        p.exit();
    }
    m.complete(p, K::QUERY.raw());
}

/// `('|' command)*`: tokens that are neither are one error, then it goes on.
pub(super) fn pipeline(p: &mut Parser<'_>) {
    loop {
        if p.eat(K::PIPE.raw()) {
            processing::command(p);
        } else if p.at_eof() || p.at(K::R_PAREN.raw()) {
            break;
        } else {
            p.err_until(
                "expected `|` or the end of the query",
                K::set(&[K::PIPE, K::R_PAREN]),
            );
        }
    }
}

fn source_command(p: &mut Parser<'_>) {
    if p.current() == K::COMMAND_WORD.raw() {
        return unknown_command(p);
    }
    match keyword(p) {
        Some(kw @ (K::FROM_KW | K::TS_KW)) => {
            from_command(p, kw);
        }
        Some(K::ROW_KW) => processing::fields_command(p, K::ROW_COMMAND, K::ROW_KW),
        Some(K::SHOW_KW) => {
            let m = p.start();
            p.bump_as(K::SHOW_KW.raw());
            expect_kw(p, K::INFO_KW);
            m.complete(p, K::SHOW_COMMAND.raw());
        }
        Some(K::PROMQL_KW) => promql_command(p),
        Some(K::EXPLAIN_KW) => {
            let m = p.start();
            p.bump_as(K::EXPLAIN_KW.raw());
            p.expect(K::L_PAREN.raw(), "expected `(` after `explain`");
            query(p);
            p.expect(K::R_PAREN.raw(), "expected `)`");
            m.complete(p, K::EXPLAIN_COMMAND.raw());
        }
        _ => {
            let _ = p.at_set(K::set(&[
                K::FROM_KW,
                K::TS_KW,
                K::ROW_KW,
                K::SHOW_KW,
                K::EXPLAIN_KW,
            ]));
            p.err_recover("expected a source command", COMMAND_END);
        }
    }
}

/// `FromCommand`, `TsCommand`: a list of index patterns and subqueries.
fn from_command(p: &mut Parser<'_>, kw: K) {
    let m = p.start();
    p.bump_as(kw.raw());
    comma_list(p, |p| {
        if p.at(K::L_PAREN.raw()) {
            source_subquery(p);
        } else {
            index_pattern(p);
        }
    });
    if at_kw(p, K::METADATA_KW) || (p.at(K::L_BRACK.raw()) && nth_kw(p, 1, K::METADATA_KW)) {
        metadata(p);
    }
    let kind = if kw == K::FROM_KW {
        K::FROM_COMMAND
    } else {
        K::TS_COMMAND
    };
    m.complete(p, kind.raw());
}

/// `IndexPattern = (cluster:Cluster ':')? name:IndexName ('::' selector:Selector)?`
pub(super) fn index_pattern(p: &mut Parser<'_>) {
    let m = p.start();
    if p.at(K::STRING_LIT.raw()) {
        let name = p.start();
        token_node(p, K::STRING_LIT, K::STRING);
        name.complete(p, K::INDEX_NAME.raw());
    } else if p.at(K::SOURCE_TEXT.raw()) {
        if p.nth(1) == K::COLON.raw() {
            token_node(p, K::SOURCE_TEXT, K::CLUSTER);
            p.bump();
        }
        if p.at(K::SOURCE_TEXT.raw()) {
            token_node(p, K::SOURCE_TEXT, K::INDEX_NAME);
        } else {
            p.error("expected an index pattern after the cluster");
        }
        if p.eat(K::COLON_COLON.raw()) {
            if p.at(K::SOURCE_TEXT.raw()) {
                token_node(p, K::SOURCE_TEXT, K::SELECTOR);
            } else {
                p.error("expected a selector after `::`");
            }
        }
    } else {
        p.err_recover("expected an index pattern", COMMAND_END);
    }
    m.complete(p, K::INDEX_PATTERN.raw());
}

/// `( FROM ... | command ... )`.
pub(super) fn source_subquery(p: &mut Parser<'_>) {
    let m = p.start();
    if p.enter() {
        p.bump();
        match keyword(p) {
            Some(kw @ (K::FROM_KW | K::TS_KW)) => from_command(p, kw),
            Some(K::ROW_KW) => processing::fields_command(p, K::ROW_COMMAND, K::ROW_KW),
            _ => {
                let _ = p.at_set(K::set(&[K::FROM_KW, K::TS_KW, K::ROW_KW]));
                p.err_recover("expected `from`, `ts` or `row`", COMMAND_END);
            }
        }
        pipeline(p);
        p.expect(K::R_PAREN.raw(), "expected `)`");
        p.exit();
    }
    m.complete(p, K::SOURCE_SUBQUERY.raw());
}

/// `METADATA _id, ...`, or the 8.19 form `[METADATA _id]`.
fn metadata(p: &mut Parser<'_>) {
    let m = p.start();
    let bracket = p.eat(K::L_BRACK.raw());
    expect_kw(p, K::METADATA_KW);
    comma_list(p, |p| {
        if p.at(K::SOURCE_TEXT.raw()) {
            token_node(p, K::SOURCE_TEXT, K::METADATA_FIELD);
        } else {
            p.error("expected a metadata field");
        }
    });
    if bracket {
        p.expect(K::R_BRACK.raw(), "expected `]`");
    }
    m.complete(p, K::METADATA.raw());
}

/// `PROMQL`: raw text, strings and balanced parentheses, up to the pipe.
fn promql_command(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::PROMQL_KW.raw());
    let mut open = 0usize;
    loop {
        let kind = p.current();
        if kind == K::PROMQL_WORD.raw() {
            token_node(p, K::PROMQL_WORD, K::PROMQL_TEXT);
        } else if kind == K::STRING_LIT.raw() {
            token_node(p, K::STRING_LIT, K::STRING);
        } else if kind == K::L_PAREN.raw() {
            open += 1;
            p.bump();
        } else if kind == K::R_PAREN.raw() && open > 0 {
            open -= 1;
            p.bump();
        } else {
            break;
        }
    }
    if open > 0 {
        p.error("expected `)`");
    }
    m.complete(p, K::PROMQL_COMMAND.raw());
}

/// `UnknownCommand = name:CommandName (String | UnknownText)*`: a command
/// the grammar does not know, kept so the engine can report it.
pub(super) fn unknown_command(p: &mut Parser<'_>) {
    let m = p.start();
    token_node(p, K::COMMAND_WORD, K::COMMAND_NAME);
    loop {
        if p.at(K::STRING_LIT.raw()) {
            token_node(p, K::STRING_LIT, K::STRING);
        } else if p.at(K::UNKNOWN_WORD.raw()) {
            token_node(p, K::UNKNOWN_WORD, K::UNKNOWN_TEXT);
        } else {
            break;
        }
    }
    m.complete(p, K::UNKNOWN_COMMAND.raw());
}
