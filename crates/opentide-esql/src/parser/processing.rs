//! The processing commands: what follows a `|`.

use super::commands::{COMMAND_END, at_end, identifier, index_pattern, keyword, unknown_command};
use super::expressions::{
    constant, expr, map_expression, name_part, name_pattern, primary, qualified_name,
};
use super::{at_kw, comma_list, eat_kw, expect_kw, token_node};
use crate::syntax::SyntaxKind as K;
use opentide_parse::Parser;

/// One command after a pipe (or in a `FORK` branch).
pub(super) fn command(p: &mut Parser<'_>) {
    if p.current() == K::COMMAND_WORD.raw() {
        return unknown_command(p);
    }
    let Some(kw) = keyword(p) else {
        p.err_recover("expected a command", COMMAND_END);
        return;
    };
    let (node, body): (K, fn(&mut Parser<'_>)) = match kw {
        K::WHERE_KW => (K::WHERE_COMMAND, |p| {
            expr(p);
        }),
        K::EVAL_KW => return fields_command(p, K::EVAL_COMMAND, kw),
        K::KEEP_KW => (K::KEEP_COMMAND, names),
        K::DROP_KW => (K::DROP_COMMAND, names),
        K::RENAME_KW => (K::RENAME_COMMAND, |p| comma_list(p, rename_clause)),
        K::SORT_KW => (K::SORT_COMMAND, |p| comma_list(p, order_expression)),
        K::LIMIT_KW => (K::LIMIT_COMMAND, limit),
        K::STATS_KW => (K::STATS_COMMAND, |p| stats(p, false)),
        K::INLINE_KW | K::INLINESTATS_KW => return inline_stats(p),
        K::DISSECT_KW => (K::DISSECT_COMMAND, dissect),
        K::GROK_KW => (K::GROK_COMMAND, |p| {
            primary(p);
            comma_list(p, string);
        }),
        K::ENRICH_KW => (K::ENRICH_COMMAND, enrich),
        K::MV_EXPAND_KW => (K::MV_EXPAND_COMMAND, |p| {
            qualified_name(p);
        }),
        K::LOOKUP_KW | K::LEFT_KW | K::RIGHT_KW | K::FULL_KW => return join(p, kw),
        K::CHANGE_POINT_KW => (K::CHANGE_POINT_COMMAND, change_point),
        K::COMPLETION_KW => (K::COMPLETION_COMMAND, completion),
        K::RERANK_KW => (K::RERANK_COMMAND, rerank),
        K::SAMPLE_KW => (K::SAMPLE_COMMAND, |p| {
            constant(p);
        }),
        K::FORK_KW => (K::FORK_COMMAND, fork),
        K::FUSE_KW => (K::FUSE_COMMAND, fuse),
        K::URI_PARTS_KW => (K::URI_PARTS_COMMAND, extract),
        K::REGISTERED_DOMAIN_KW => (K::REGISTERED_DOMAIN_COMMAND, extract),
        K::USER_AGENT_KW => (K::USER_AGENT_COMMAND, |p| {
            extract(p);
            named_parameters(p);
        }),
        K::IP_LOCATION_KW => (K::IP_LOCATION_COMMAND, |p| {
            extract(p);
            named_parameters(p);
        }),
        K::METRICS_INFO_KW => (K::METRICS_INFO_COMMAND, |_| {}),
        K::TS_INFO_KW => (K::TS_INFO_COMMAND, |_| {}),
        K::TS_COLLAPSE_KW => (K::TS_COLLAPSE_COMMAND, |_| {}),
        K::DEDUP_KW => (K::DEDUP_COMMAND, |_| {}),
        K::MMR_KW => (K::MMR_COMMAND, mmr),
        K::HIGHLIGHT_KW => (K::HIGHLIGHT_COMMAND, highlight),
        K::DENSE_VECTOR_KW => (K::DENSE_VECTOR_COMMAND, dense_vector),
        K::FILLNULL_KW => (K::FILL_NULL_COMMAND, |p| {
            constant(p);
            expect_kw(p, K::ON_KW);
            names(p);
        }),
        _ => {
            p.err_recover("expected a command", COMMAND_END);
            return;
        }
    };
    let m = p.start();
    p.bump_as(kw.raw());
    body(p);
    m.complete(p, node.raw());
}

/// `ROW` and `EVAL`: `name = value` or `value`, comma separated.
pub(super) fn fields_command(p: &mut Parser<'_>, node: K, kw: K) {
    let m = p.start();
    p.bump_as(kw.raw());
    comma_list(p, |p| field(p, K::FIELD_ASSIGNMENT_OR_EXPRESSION, false));
    m.complete(p, node.raw());
}

/// `(name '=')? value ('where' filter)?`
fn field(p: &mut Parser<'_>, node: K, filter: bool) {
    let m = p.start();
    if let Some(lhs) = expr(p) {
        // The name of an assignment: a qualified name, or a bare parameter
        // (`EVAL ?p = 1`: Elasticsearch's identifierOrParameter).
        let name = lhs.kind() == K::QUALIFIED_NAME.raw()
            || (lhs.kind() == K::PARAMETER.raw() && p.at(K::EQ.raw()));
        if name && p.at(K::EQ.raw()) {
            if lhs.kind() == K::PARAMETER.raw() {
                lhs.precede(p).complete(p, K::QUALIFIED_NAME.raw());
            }
            p.bump();
            expr(p);
        }
    }
    if filter && eat_kw(p, K::WHERE_KW) {
        expr(p);
    }
    m.complete(p, node.raw());
}

fn names(p: &mut Parser<'_>) {
    comma_list(p, name_pattern);
}

fn string(p: &mut Parser<'_>) {
    if p.at(K::STRING_LIT.raw()) {
        token_node(p, K::STRING_LIT, K::STRING);
    } else {
        p.err_recover("expected a string", COMMAND_END);
    }
}

fn rename_clause(p: &mut Parser<'_>) {
    let m = p.start();
    name_pattern(p);
    if eat_kw(p, K::AS_KW) || p.eat(K::EQ.raw()) {
        name_pattern(p);
    } else {
        p.error("expected `as` or `=`");
    }
    m.complete(p, K::RENAME_CLAUSE.raw());
}

fn order_expression(p: &mut Parser<'_>) {
    let m = p.start();
    expr(p);
    if !eat_kw(p, K::ASC_KW) {
        eat_kw(p, K::DESC_KW);
    }
    if eat_kw(p, K::NULLS_KW) && !eat_kw(p, K::FIRST_KW) {
        expect_kw(p, K::LAST_KW);
    }
    m.complete(p, K::ORDER_EXPRESSION.raw());
}

fn limit(p: &mut Parser<'_>) {
    constant(p);
    if eat_kw(p, K::BY_KW) {
        comma_list(p, |p| {
            expr(p);
        });
    }
}

/// `STATS aggregates BY fields`: the aggregates are optional unless `required`.
fn stats(p: &mut Parser<'_>, required: bool) {
    if required || !(at_kw(p, K::BY_KW) || at_end(p)) {
        comma_list(p, |p| field(p, K::AGGREGATE_FIELD, true));
    }
    if eat_kw(p, K::BY_KW) {
        comma_list(p, |p| field(p, K::FIELD_ASSIGNMENT_OR_EXPRESSION, false));
    }
}

fn inline_stats(p: &mut Parser<'_>) {
    let m = p.start();
    if !eat_kw(p, K::INLINESTATS_KW) {
        p.bump_as(K::INLINE_KW.raw());
        expect_kw(p, K::STATS_KW);
    }
    stats(p, true);
    m.complete(p, K::INLINE_STATS_COMMAND.raw());
}

fn dissect(p: &mut Parser<'_>) {
    primary(p);
    string(p);
    if p.current() == K::WORD.raw() {
        comma_list(p, |p| {
            let m = p.start();
            identifier(p);
            p.expect(K::EQ.raw(), "expected `=`");
            constant(p);
            m.complete(p, K::COMMAND_OPTION.raw());
        });
    }
}

fn enrich(p: &mut Parser<'_>) {
    let m = p.start();
    if p.at(K::STRING_LIT.raw()) {
        string(p);
    } else if p.at(K::POLICY_PART.raw()) {
        if p.nth(1) == K::COLON.raw() {
            token_node(p, K::POLICY_PART, K::ENRICH_MODE);
            p.bump();
        }
        token_node(p, K::POLICY_PART, K::POLICY_NAME);
    } else {
        p.err_recover("expected an enrich policy", COMMAND_END);
    }
    m.complete(p, K::ENRICH_POLICY.raw());
    if eat_kw(p, K::ON_KW) {
        name_pattern(p);
    }
    if eat_kw(p, K::WITH_KW) {
        comma_list(p, |p| {
            let clause = p.start();
            name_pattern(p);
            if p.eat(K::EQ.raw()) {
                name_pattern(p);
            }
            clause.complete(p, K::ENRICH_WITH_CLAUSE.raw());
        });
    }
}

fn join(p: &mut Parser<'_>, kind: K) {
    let m = p.start();
    p.bump_as(kind.raw());
    expect_kw(p, K::JOIN_KW);
    index_pattern(p);
    let alias = eat_kw(p, K::AS_KW);
    if alias && p.at(K::SOURCE_TEXT.raw()) && p.current_text().eq_ignore_ascii_case("as") {
        // `LOOKUP JOIN t AS AS ON x`: the second `AS` lexes as source text
        // here and read as the qualifier. A keyword is no qualifier.
        p.err_and_bump("expected a qualifier after `AS`, not `AS`");
    } else if p.at(K::SOURCE_TEXT.raw()) {
        token_node(p, K::SOURCE_TEXT, K::JOIN_QUALIFIER);
    } else if alias {
        // `AS` takes a qualifier: `LOOKUP JOIN t AS ON x` parsed with no
        // error, where Elasticsearch's grammar needs `AS qualifier` (#1641).
        p.error("expected a qualifier after `AS`");
    }
    expect_kw(p, K::ON_KW);
    comma_list(p, |p| {
        expr(p);
    });
    m.complete(p, K::JOIN_COMMAND.raw());
}

fn change_point(p: &mut Parser<'_>) {
    qualified_name(p);
    if eat_kw(p, K::ON_KW) {
        qualified_name(p);
    }
    if eat_kw(p, K::AS_KW) {
        qualified_name(p);
        p.expect(K::COMMA.raw(), "expected `,` and the name of the p-value");
        qualified_name(p);
    }
    if eat_kw(p, K::BY_KW) {
        comma_list(p, |p| {
            expr(p);
        });
    }
}

/// Whether `name.name =` is ahead: a target before the command's operand.
fn target_ahead(p: &Parser<'_>) -> bool {
    let mut n = 0;
    while [K::WORD, K::QUOTED_IDENT, K::PARAM]
        .map(K::raw)
        .contains(&p.nth(n))
    {
        if p.nth(n + 1) == K::EQ.raw() {
            return true;
        }
        if p.nth(n + 1) != K::DOT.raw() {
            return false;
        }
        n += 2;
    }
    false
}

fn target(p: &mut Parser<'_>) {
    if target_ahead(p) {
        qualified_name(p);
        p.bump();
    }
}

/// `WITH {map}`.
fn named_parameters(p: &mut Parser<'_>) {
    if at_kw(p, K::WITH_KW) {
        let m = p.start();
        p.bump_as(K::WITH_KW.raw());
        map_expression(p);
        m.complete(p, K::NAMED_PARAMETERS.raw());
    }
}

fn completion(p: &mut Parser<'_>) {
    target(p);
    primary(p);
    if at_kw(p, K::WITH_KW) {
        if p.nth(1) == K::L_BRACE.raw() {
            named_parameters(p);
        } else {
            p.bump_as(K::WITH_KW.raw());
            name_part(p);
        }
    }
}

fn rerank(p: &mut Parser<'_>) {
    target(p);
    constant(p);
    expect_kw(p, K::ON_KW);
    comma_list(p, |p| field(p, K::FIELD_ASSIGNMENT_OR_EXPRESSION, false));
    named_parameters(p);
}

fn fork(p: &mut Parser<'_>) {
    loop {
        let m = p.start();
        if p.enter() {
            p.expect(K::L_PAREN.raw(), "expected `(` before a branch");
            command(p);
            while p.eat(K::PIPE.raw()) {
                command(p);
            }
            p.expect(K::R_PAREN.raw(), "expected `)`");
            p.exit();
        }
        m.complete(p, K::FORK_BRANCH.raw());
        if !p.at(K::L_PAREN.raw()) {
            break;
        }
    }
}

fn fuse(p: &mut Parser<'_>) {
    let clause = [K::SCORE_KW, K::KEY_KW, K::GROUP_KW, K::WITH_KW];
    if p.current() == K::WORD.raw() && !clause.iter().any(|&kw| at_kw(p, kw)) {
        identifier(p);
    }
    loop {
        if eat_kw(p, K::SCORE_KW) || eat_kw(p, K::GROUP_KW) {
            expect_kw(p, K::BY_KW);
            qualified_name(p);
        } else if eat_kw(p, K::KEY_KW) {
            expect_kw(p, K::BY_KW);
            comma_list(p, |p| {
                qualified_name(p);
            });
        } else if at_kw(p, K::WITH_KW) {
            named_parameters(p);
        } else {
            break;
        }
    }
}

/// `target = input`: `URI_PARTS`, `REGISTERED_DOMAIN`, `USER_AGENT`, `IP_LOCATION`.
fn extract(p: &mut Parser<'_>) {
    qualified_name(p);
    p.expect(K::EQ.raw(), "expected `=`");
    primary(p);
}

fn mmr(p: &mut Parser<'_>) {
    if !at_kw(p, K::ON_KW) {
        primary(p);
    }
    expect_kw(p, K::ON_KW);
    qualified_name(p);
    expect_kw(p, K::LIMIT_KW);
    constant(p);
    named_parameters(p);
}

fn highlight(p: &mut Parser<'_>) {
    if !(at_kw(p, K::ON_KW) || at_kw(p, K::WITH_KW) || at_end(p)) {
        expr(p);
    }
    if eat_kw(p, K::ON_KW) {
        names(p);
    }
    named_parameters(p);
}

fn dense_vector(p: &mut Parser<'_>) {
    target(p);
    if !(at_kw(p, K::WITH_KW) || at_end(p)) {
        comma_list(p, primary);
    }
    named_parameters(p);
}
