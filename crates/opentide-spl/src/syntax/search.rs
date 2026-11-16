//! Search terms: what the base search, `search`, a subsearch and (later)
//! `tstats ... where` share. Adjacent terms are ANDed; `AND` and `OR` sit
//! between two terms and `NOT` before one; the parse is flat, because it only
//! has to accept what Splunk accepts (`grammar.js`: `search_expression`).

use super::kind::SyntaxKind as K;
use super::parser::{Context, SUBSEARCH_WEIGHT_LEVELS, at, at_name, close, leaf, pipeline};
use opentide_parse::{CompletedMarker, Parser, TokenSet};

/// A word that can name a field in a search comparison.
const FIELD_WORDS: TokenSet = K::set(&[
    K::IDENT,
    K::STRING_TOKEN,
    K::FIELD_WORD,
    K::SEARCH_WORD_TOKEN,
    K::CALL_WORD,
]);
/// Search words that are neither names, numbers nor wildcards.
const WORDS: TokenSet = K::set(&[K::FIELD_WORD, K::SEARCH_WORD_TOKEN, K::CALL_WORD]);
/// What can be compared (`=`, `<`, ...) with a field and a value.
const COMPARISONS: TokenSet = K::set(&[K::EQ, K::NE, K::LT, K::GT, K::LE, K::GE]);
/// Splunk parses these too, with or without a term on either side.
const LOOSE: TokenSet = K::set(&[K::EQ2, K::LT_GT, K::EQ_GT, K::EQ_LT, K::BANG_TILDE]);
/// What starts a term.
const TERM_START: TokenSet = K::set(&[
    K::IDENT,
    K::NUMBER_TOKEN,
    K::STRING_TOKEN,
    K::GLOB_TOKEN,
    K::FIELD_WORD,
    K::SEARCH_WORD_TOKEN,
    K::CALL_WORD,
    K::MACRO_TOKEN,
    K::L_PAREN,
    K::L_BRACKET,
]);
/// What a comparison's value can be.
const VALUE: TokenSet = K::set(&[
    K::IDENT,
    K::NUMBER_TOKEN,
    K::STRING_TOKEN,
    K::GLOB_TOKEN,
    K::FIELD_WORD,
    K::SEARCH_WORD_TOKEN,
    K::CALL_WORD,
    K::MACRO_TOKEN,
]);

/// The upper-case boolean operators, reserved in search: `a AND OR b` is an
/// error, and lower-case `and`, `or` and `not` are plain terms.
fn boolean(p: &Parser<'_>) -> Option<K> {
    if p.current() != K::IDENT.raw() {
        return None;
    }
    match p.current_text() {
        "AND" => Some(K::AND_KW),
        "OR" => Some(K::OR_KW),
        "NOT" => Some(K::NOT_KW),
        _ => None,
    }
}

/// A `TERM(`, `CASE(` or `PREFIX(`.
fn directive(p: &Parser<'_>) -> Option<(K, K)> {
    if p.current() != K::IDENT.raw() {
        return None;
    }
    match p.current_text() {
        "TERM" => Some((K::TERM_CLAUSE, K::TERM_KW)),
        "CASE" => Some((K::CASE_CLAUSE, K::CASE_KW)),
        _ => None,
    }
}

/// Whether the current token starts a search term (a reserved boolean does
/// not).
fn starts_term(p: &Parser<'_>) -> bool {
    let kind = p.current();
    (TERM_START.contains(kind) || LOOSE.contains(kind)) && boolean(p).is_none()
}

/// Whether a macro at the current token is followed by more terms (then the
/// stage is a search that starts with the macro; alone, it is the stage).
pub(super) fn more_terms_after_macro(p: &Parser<'_>) -> bool {
    let next = p.nth(1);
    TERM_START.contains(next) || LOOSE.contains(next) || {
        next == K::IDENT.raw() && matches!(p.nth_text(1), "AND" | "OR" | "NOT")
    }
}

/// Whether a subsearch body that starts here is search terms, not a command:
/// anything but a bare name or a macro (`[ foo ... ]` runs `foo`; `[ a=1 ]`
/// searches).
pub(super) fn starts_bare_head(p: &Parser<'_>) -> bool {
    let kind = p.current();
    if boolean(p) == Some(K::NOT_KW) || directive(p).is_some() {
        return true;
    }
    // A macro followed by more terms starts a search; alone it is a command.
    if kind == K::MACRO_TOKEN.raw() && more_terms_after_macro(p) {
        return true;
    }
    if kind == K::IDENT.raw() {
        if super::rest::is_known_command(p.current_text()) {
            return false;
        }
        let next = p.nth(1);
        return COMPARISONS.contains(next)
            || LOOSE.contains(next)
            || (next == K::IDENT.raw() && p.nth_text(1) == "IN" && p.nth(2) == K::L_PAREN.raw());
    }
    kind != K::MACRO_TOKEN.raw() && starts_term(p) && boolean(p).is_none()
}

/// `search [expression]`.
pub(super) fn search_command(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::SEARCH_KW.raw());
    if starts_term(p) || boolean(p).is_some() {
        search_expression(p, K::SEARCH_EXPRESSION, false);
    }
    m.complete(p, K::SEARCH_COMMAND.raw());
}

/// Terms with no `search` keyword. A query's first stage may start with a
/// bare word (`error`, `tstats count`); a subsearch's may not.
pub(super) fn bare_search(p: &mut Parser<'_>) {
    search_expression(p, K::BARE_SEARCH, false);
}

/// `NOT`s and terms, `AND` and `OR` between them, as the children of one
/// node of `kind`.
fn search_expression(p: &mut Parser<'_>, kind: K, stop_by: bool) {
    let m = p.start();
    let mut first = true;
    let mut after_operator = false;
    loop {
        // `by` is a term when nothing precedes it (`where by x` searches for
        // the word), and ends the terms otherwise.
        if stop_by && !first && !after_operator && at_by(p) {
            break;
        }
        let operator = boolean(p);
        match operator {
            Some(K::NOT_KW) => {
                boolean_node(p, K::NOT_KW);
                while boolean(p) == Some(K::NOT_KW) {
                    boolean_node(p, K::NOT_KW);
                }
                if !starts_term(p) {
                    p.error("expected a search term after `NOT`");
                    break;
                }
            }
            Some(op) => {
                if first {
                    p.err_and_bump("expected a search term before the operator");
                } else {
                    boolean_node(p, op);
                }
                if !starts_term(p) && boolean(p) != Some(K::NOT_KW) {
                    p.error("expected a search term");
                    break;
                }
                after_operator = true;
                continue;
            }
            None => {}
        }
        if !term(p, stop_by) {
            if !first || boolean(p).is_some() {
                p.error("expected a search term");
            }
            break;
        }
        first = false;
        after_operator = false;
        if !(starts_term(p) || boolean(p).is_some()) || (stop_by && at_by(p)) {
            break;
        }
    }
    m.complete(p, kind.raw());
}

/// `by`, which ends the `where` of a `tstats` (any case).
fn at_by(p: &Parser<'_>) -> bool {
    p.current() == K::IDENT.raw() && p.current_text().eq_ignore_ascii_case("by")
}

/// Whether a search expression can start at the current token.
pub(super) fn starts_expression(p: &Parser<'_>) -> bool {
    starts_term(p) || boolean(p).is_some()
}

/// A search expression: terms to the end of the stage.
pub(super) fn search_expression_plain(p: &mut Parser<'_>) {
    search_expression(p, K::SEARCH_EXPRESSION, false);
}

/// A search expression that stops at `by` (tstats's `where`).
pub(super) fn search_expression_before_by(p: &mut Parser<'_>) {
    search_expression(p, K::SEARCH_EXPRESSION, true);
}

fn boolean_node(p: &mut Parser<'_>, kind: K) {
    leaf(p, K::SEARCH_BOOLEAN, kind);
}

/// One search term; `false` when the current token starts none.
fn term(p: &mut Parser<'_>, stop_by: bool) -> bool {
    if let Some((node, keyword)) = directive(p) {
        let m = p.start();
        p.bump_as(keyword.raw());
        raw_arguments(p);
        m.complete(p, node.raw());
        return true;
    }
    match p.current() {
        k if k == K::L_PAREN.raw() => group(p),
        k if k == K::L_BRACKET.raw() => {
            subsearch(p);
        }
        k if k == K::MACRO_TOKEN.raw() => macro_call(p),
        k if LOOSE.contains(k) => {
            // A comparison with no field: `==1`.
            let m = p.start();
            p.bump();
            optional_value(p, stop_by);
            m.complete(p, K::FIELD_VALUE.raw());
        }
        k if TERM_START.contains(k) => {
            let atom = atom(p);
            if FIELD_WORDS.contains(atom.kind_token) {
                after_field(p, atom.node, stop_by);
            }
        }
        _ => return false,
    }
    true
}

/// What a search term's first token became.
struct Atom {
    node: CompletedMarker,
    kind_token: rowan::SyntaxKind,
}

/// A name, number, string, wildcard or other word, as its node. The kind
/// returned is the lexed one, which says whether it can name a field.
fn atom(p: &mut Parser<'_>) -> Atom {
    let lexed = p.current();
    let node = value_atom(p);
    Atom {
        node,
        kind_token: lexed,
    }
}

/// A leaf node for the current token, which must be one of [`VALUE`] or
/// [`FIELD_WORDS`].
fn value_atom(p: &mut Parser<'_>) -> CompletedMarker {
    let kind = p.current();
    let node = if kind == K::IDENT.raw() {
        K::IDENTIFIER
    } else if kind == K::NUMBER_TOKEN.raw() {
        K::NUMBER
    } else if kind == K::STRING_TOKEN.raw() {
        K::STR
    } else if kind == K::GLOB_TOKEN.raw() {
        K::GLOB
    } else if kind == K::MACRO_TOKEN.raw() {
        K::MACRO_CALL
    } else {
        K::SEARCH_WORD
    };
    let m = p.start();
    p.bump();
    m.complete(p, node.raw())
}

/// After a word that can be a field: a comparison, `IN (...)`, or nothing
/// (the word is a term).
fn after_field(p: &mut Parser<'_>, field: CompletedMarker, stop_by: bool) {
    let next = p.current();
    if COMPARISONS.contains(next) {
        let field = wrap_field(p, field);
        let m = field.precede(p);
        p.bump();
        if VALUE.contains(p.current()) && boolean(p).is_none() {
            let rhs = p.start();
            value_atom(p);
            rhs.complete(p, K::FIELD_VALUE_RHS.raw());
        } else if at(p, K::L_PAREN) {
            let rhs = p.start();
            value_list(p);
            rhs.complete(p, K::FIELD_VALUE_RHS.raw());
        } else {
            p.error("missing the value of the comparison");
        }
        m.complete(p, K::FIELD_VALUE.raw());
    } else if LOOSE.contains(next) {
        let field = wrap_field(p, field);
        let m = field.precede(p);
        p.bump();
        optional_value(p, stop_by);
        m.complete(p, K::FIELD_VALUE.raw());
    } else if at_name(p, "IN") {
        // After a word that can be a field, `IN` is a keyword: it wants its list.
        let field = wrap_field(p, field);
        let m = field.precede(p);
        p.bump_as(K::IN_KW.raw());
        if at(p, K::L_PAREN) {
            value_list(p);
        } else {
            p.error("expected `(` after `IN`");
        }
        m.complete(p, K::IN_CLAUSE.raw());
    }
}

/// The word that is compared, as a `FIELD_REF`.
fn wrap_field(p: &mut Parser<'_>, field: CompletedMarker) -> CompletedMarker {
    field.precede(p).complete(p, K::FIELD_REF.raw())
}

/// A loose comparison's value, if there is one.
fn optional_value(p: &mut Parser<'_>, stop_by: bool) {
    // A directive after a loose operator is a term of its own, and so is the
    // `by` that ends a tstats where.
    if VALUE.contains(p.current())
        && boolean(p).is_none()
        && directive(p).is_none()
        && !(stop_by && at_by(p))
    {
        let rhs = p.start();
        value_atom(p);
        rhs.complete(p, K::FIELD_VALUE_RHS.raw());
    }
}

/// `( a, "b" c )`: one or more values, one comma at most between two.
pub(super) fn value_list(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    let mut any = false;
    loop {
        let comma = any && p.eat(K::COMMA.raw());
        if VALUE.contains(p.current()) && boolean(p).is_none() {
            value_atom(p);
            any = true;
        } else {
            if comma {
                p.error("expected a value after the comma");
            }
            break;
        }
    }
    if !any {
        p.error("expected a value");
    }
    close(p, K::R_PAREN, "missing `)`");
    m.complete(p, K::VALUE_LIST.raw());
}

/// `( terms )`.
fn group(p: &mut Parser<'_>) {
    if !p.enter() {
        return;
    }
    let m = p.start();
    p.bump();
    if starts_term(p) || boolean(p).is_some() {
        search_expression(p, K::SEARCH_EXPRESSION, false);
    } else {
        p.error("expected a search term");
    }
    close(p, K::R_PAREN, "missing `)`");
    m.complete(p, K::SEARCH_GROUP.raw());
    p.exit();
}

/// `[ pipeline ]`.
/// How many levels of `max_depth` a subsearch costs: a level of it is
/// a pipeline, a stage, a command and a term, a few KB of stack in a debug
/// build, so a 1 MB stack holds fewer of them than of groups.
const SUBSEARCH_WEIGHT: u32 = SUBSEARCH_WEIGHT_LEVELS;

pub(super) fn subsearch(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    for entered in 0..SUBSEARCH_WEIGHT {
        if !p.enter() {
            for _ in 0..entered {
                p.exit();
            }
            return None;
        }
    }
    let m = p.start();
    p.bump();
    pipeline(p, Context::Subsearch);
    close(p, K::R_BRACKET, "missing `]`");
    let done = m.complete(p, K::SUBSEARCH.raw());
    for _ in 0..SUBSEARCH_WEIGHT {
        p.exit();
    }
    Some(done)
}

pub(super) fn macro_call(p: &mut Parser<'_>) {
    leaf(p, K::MACRO_CALL, K::MACRO_TOKEN);
}

/// The `(` and the raw text of a directive, and its `)` when it has one
/// (`TERM(EventID=4688` before a pipe is accepted, as Splunk does).
fn raw_arguments(p: &mut Parser<'_>) {
    if !p.eat(K::L_PAREN.raw()) {
        p.error("expected `(` after the directive");
        return;
    }
    if at(p, K::TERM_TEXT_TOKEN) {
        leaf(p, K::TERM_TEXT, K::TERM_TEXT_TOKEN);
    }
    p.eat(K::R_PAREN.raw());
}

#[cfg(test)]
mod tests {
    use super::super::parser::tests::render;

    #[test]
    fn terms_booleans_and_groups() {
        let out = render("search a AND (b OR c) NOT d");
        assert!(out.ends_with("--\n"), "{out}");
        assert_eq!(out.matches("SEARCH_BOOLEAN@").count(), 3, "{out}");
        assert_eq!(out.matches("SEARCH_GROUP@").count(), 1, "{out}");
    }

    #[test]
    fn comparisons_in_and_directives() {
        let out = render(r#"app IN ("a", "b") TERM(x=y) a==b c>=1 CASE(Ab"#);
        assert!(out.ends_with("--\n"), "{out}");
        for node in [
            "IN_CLAUSE",
            "VALUE_LIST",
            "TERM_CLAUSE",
            "TERM_TEXT",
            "CASE_CLAUSE",
        ] {
            assert!(out.contains(node), "{node} in {out}");
        }
        assert_eq!(out.matches("FIELD_VALUE@").count(), 2, "{out}");
    }

    #[test]
    fn a_subsearch_runs_a_leading_word_as_a_command() {
        let out = render("a [ foo b | c ] [ x=1 ]");
        assert_eq!(out.matches("UNKNOWN_COMMAND@").count(), 2, "{out}");
        assert_eq!(out.matches("BARE_SEARCH@").count(), 2, "{out}");
    }

    #[test]
    fn a_missing_close_is_one_error() {
        let out = render("a (b");
        assert!(out.contains("missing `)`"), "{out}");
    }
}
