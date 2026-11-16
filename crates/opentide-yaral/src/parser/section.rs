//! Rules, searches and their sections. A section is its label, `:` and a
//! body that runs to the next label or the closing brace; the grammar takes
//! the sections in any order (the engine reports their order).

use super::{P, expr};
use crate::syntax::SyntaxKind as K;
use opentide_parse::TokenSet;

/// The labels that start a section.
const SECTION_LABELS: [K; 13] = [
    K::META_KW,
    K::SETUP_KW,
    K::EVENTS_KW,
    K::MATCH_KW,
    K::OUTCOME_KW,
    K::CONDITION_KW,
    K::OPTIONS_KW,
    K::EXPORT_KW,
    K::DEDUP_KW,
    K::ORDER_KW,
    K::LIMIT_KW,
    K::SELECT_KW,
    K::UNSELECT_KW,
];

/// Where junk in a body ends: a section label, a closing brace, the next rule.
const BODY_STOP: TokenSet = K::set(&[
    K::META_KW,
    K::SETUP_KW,
    K::EVENTS_KW,
    K::MATCH_KW,
    K::OUTCOME_KW,
    K::CONDITION_KW,
    K::OPTIONS_KW,
    K::EXPORT_KW,
    K::DEDUP_KW,
    K::ORDER_KW,
    K::LIMIT_KW,
    K::SELECT_KW,
    K::UNSELECT_KW,
    K::R_BRACE,
    K::RULE_KW,
]);

fn at_label(p: &P<'_>) -> bool {
    SECTION_LABELS.contains(&p.current())
}

/// `SourceFile`: rules, or else a search.
pub(super) fn source_file(p: &mut P<'_>) {
    let file = p.start();
    if p.at(K::RULE_KW) {
        while p.at(K::RULE_KW) {
            rule(p);
        }
    } else if p.at(K::STAGE_KW) || at_label(p) || expr::at_statement_start(p) {
        search_query(p);
    }
    if !p.at_eof() {
        p.err_until("unexpected text", TokenSet::EMPTY);
    }
    p.done(file, K::SOURCE_FILE);
}

/// `rule name { sections }`. The name may be spelled like a keyword.
fn rule(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    if p.current().is_word() {
        let name = p.start();
        p.bump_name();
        p.done(name, K::RULE_NAME);
    } else {
        p.error("expected a rule name");
    }
    p.expect(K::L_BRACE);
    sections(p);
    p.expect(K::R_BRACE);
    p.done(m, K::RULE_DECLARATION);
}

/// Sections up to a closing brace, the next rule or the end of the input;
/// anything else is one error up to the next label.
fn sections(p: &mut P<'_>) {
    while !p.at_eof() && !p.at(K::R_BRACE) && !p.at(K::RULE_KW) {
        if at_label(p) {
            section(p);
        } else {
            p.err_until("expected a section such as `events:`", BODY_STOP);
        }
    }
}

/// A search: `stage` blocks, the events of the root stage with no `events:`
/// label, then its sections.
fn search_query(p: &mut P<'_>) {
    let m = p.start();
    while p.at(K::STAGE_KW) {
        stage(p);
    }
    if !search_body(p) {
        p.error("expected the events or a section of the search after its stages");
    }
    // The root has no closing brace: junk runs to the end of the input.
    while !p.at_eof() {
        if at_label(p) {
            section(p);
        } else {
            p.err_until("expected a section such as `events:`", BODY_STOP);
            if p.at(K::R_BRACE) || p.at(K::RULE_KW) {
                p.err_until("unexpected text", TokenSet::EMPTY);
            }
        }
    }
    p.done(m, K::SEARCH_QUERY);
}

/// Events with no label, then sections up to a closing brace.
fn search_body(p: &mut P<'_>) -> bool {
    let found = expr::at_statement_start(p) || at_label(p);
    if expr::at_statement_start(p) {
        let events = p.start();
        while expr::at_statement_start(p) {
            expr::statement(p);
        }
        p.done(events, K::SEARCH_EVENTS);
    }
    while at_label(p) {
        section(p);
    }
    found
}

/// `stage name { body }`.
fn stage(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    if p.at(K::IDENT) {
        let name = p.start();
        p.bump();
        p.done(name, K::STAGE_NAME);
    } else {
        p.error("expected a stage name");
    }
    p.expect(K::L_BRACE);
    search_body(p);
    sections(p);
    p.expect(K::R_BRACE);
    p.done(m, K::STAGE);
}

/// One section: its label, `:` and its body.
fn section(p: &mut P<'_>) {
    let m = p.start();
    let kind = p.current();
    p.bump();
    p.expect(K::COLON);
    let node = match kind {
        K::META_KW => {
            meta(p);
            K::META_SECTION
        }
        K::OPTIONS_KW => {
            options(p);
            K::OPTIONS_SECTION
        }
        K::SETUP_KW => {
            setup(p);
            K::SETUP_SECTION
        }
        K::MATCH_KW => {
            match_clause(p);
            K::MATCH_SECTION
        }
        K::DEDUP_KW => {
            expr_list(p);
            K::DEDUP_SECTION
        }
        K::SELECT_KW => {
            expr_list(p);
            K::SELECT_SECTION
        }
        K::UNSELECT_KW => {
            expr_list(p);
            K::UNSELECT_SECTION
        }
        K::ORDER_KW => {
            order(p);
            K::ORDER_SECTION
        }
        K::LIMIT_KW => {
            p.eat(K::INTEGER);
            K::LIMIT_SECTION
        }
        _ => {
            statements(p);
            match kind {
                K::EVENTS_KW => K::EVENTS_SECTION,
                K::OUTCOME_KW => K::OUTCOME_SECTION,
                K::CONDITION_KW => K::CONDITION_SECTION,
                _ => K::EXPORT_SECTION,
            }
        }
    };
    p.done(m, node);
}

fn statements(p: &mut P<'_>) {
    while expr::at_statement_start(p) {
        expr::statement(p);
    }
}

/// A value of `meta` and `options`: a literal, or a bare name.
fn setting_value(p: &mut P<'_>) {
    let m = p.start();
    match p.current() {
        K::STRING
        | K::RAW_STRING
        | K::INTEGER
        | K::FLOAT
        | K::DURATION
        | K::TRUE_KW
        | K::FALSE_KW => {
            p.bump();
            p.done(m, K::LITERAL);
        }
        K::IDENT => {
            p.bump();
            p.done(m, K::NAME_REF);
        }
        _ => {
            p.abandon(m);
            p.error("expected a value: a string, a number, a duration, `true`, `false` or a name");
        }
    }
}

/// `key = value`, a key being any word that is not a section label.
fn meta(p: &mut P<'_>) {
    while p.current().is_word() && !at_label(p) {
        entry(p, K::META_ENTRY, K::META_KEY);
    }
}

fn options(p: &mut P<'_>) {
    while p.at(K::IDENT) {
        entry(p, K::OPTION_ENTRY, K::OPTION_KEY);
    }
}

fn entry(p: &mut P<'_>, node: K, key: K) {
    let m = p.start();
    let k = p.start();
    p.bump_name();
    p.done(k, key);
    p.expect(K::EQ);
    setting_value(p);
    p.done(m, node);
}

/// `graph_override (join)`, `graph_exclude (join)`, `graph_append [..]`, or a
/// statement.
fn setup(p: &mut P<'_>) {
    while expr::at_statement_start(p) {
        if p.at_word(0, "graph_override") || p.at_word(0, "graph_exclude") {
            let m = p.start();
            p.bump_word(if p.at_word(0, "graph_override") {
                K::GRAPH_OVERRIDE_KW
            } else {
                K::GRAPH_EXCLUDE_KW
            });
            p.expect(K::L_PAREN);
            expr::expr(p);
            p.expect(K::R_PAREN);
            p.done(m, K::GRAPH_JOIN);
        } else if p.at_word(0, "graph_append") {
            let m = p.start();
            p.bump_word(K::GRAPH_APPEND_KW);
            if p.at(K::L_BRACK) {
                expr::array(p);
            } else {
                p.error("expected `[`");
            }
            p.done(m, K::GRAPH_APPEND);
        } else {
            expr::statement(p);
        }
    }
}

/// `$a, $b over 5m before $pivot`.
fn match_clause(p: &mut P<'_>) {
    if !(p.at(K::VAR_TOKEN) || (p.at(K::IDENT) && expr::is_accessor(p.nth(1)))) {
        return;
    }
    let m = p.start();
    loop {
        expr::field_ref(p);
        if !p.eat(K::COMMA) {
            break;
        }
    }
    if p.at(K::OVER_KW) || p.at(K::BY_KW) {
        window(p);
    }
    p.done(m, K::MATCH_CLAUSE);
}

/// `over 5m`, `by every 1 hour`, `over 5m after $pivot`.
fn window(p: &mut P<'_>) {
    let m = p.start();
    p.bump();
    if p.at_word(0, "every") {
        p.bump_word(K::EVERY_KW);
    }
    if p.at_word(0, "first") {
        p.bump_word(K::FIRST_KW);
    }
    if !p.eat(K::DURATION) {
        p.eat(K::INTEGER);
        if p.at(K::IDENT) {
            let unit = p.start();
            p.bump();
            p.done(unit, K::TIME_UNIT);
        } else {
            p.error("expected a duration such as `5m`");
        }
    }
    if p.at(K::BEFORE_KW) || p.at(K::AFTER_KW) {
        p.bump();
        if p.at(K::VAR_TOKEN) {
            expr::leaf(p, K::VARIABLE);
        } else {
            p.error("expected a variable such as `$e`");
        }
    }
    p.done(m, K::MATCH_WINDOW);
}

/// `a, b, c`, or nothing.
fn expr_list(p: &mut P<'_>) {
    if !expr::at_statement_start(p) {
        return;
    }
    loop {
        expr::expr(p);
        if !p.eat(K::COMMA) {
            break;
        }
    }
}

/// `a asc, b desc`, or nothing.
fn order(p: &mut P<'_>) {
    if !expr::at_statement_start(p) {
        return;
    }
    loop {
        let m = p.start();
        expr::expr(p);
        if !p.eat(K::ASC_KW) {
            p.eat(K::DESC_KW);
        }
        p.done(m, K::ORDER_ITEM);
        if !p.eat(K::COMMA) {
            break;
        }
    }
}
