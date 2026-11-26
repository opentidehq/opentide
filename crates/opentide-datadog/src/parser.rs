//! The grammar of `datadog.ungram` as functions over [`opentide_parse::Parser`]
//! (docs/internal/rfc-datadog-cloud-siem.md, §6.3).
//!
//! Precedence: a modifier binds tightest, then AND (written or implied), then OR, the same
//! inside a value group (VRL's reading; unverified on Cloud SIEM, RFC open question 2). Runs of
//! AND and runs of OR are each one flat node. Every rule that recurses (a group) calls
//! [`Parser::enter`].
//!
//! The lexer cuts small pieces; the parser glues the ones that touch into a term, a field, a
//! CIDR block or a range bound, and re-kinds the words its grammar reads (`AND`, `OR`, `NOT`,
//! `TO`, `CIDR`, `&&`, `||`, numbers).

use crate::lexer::{self, is_number};
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_parse::{Grammar, Input, Parse, Parser, TokenSet, build};

/// Nesting deeper than this is one error: the floor every new language keeps
/// (`deep_queries`' `NESTING_CEILING`). A group opens at most four nodes a level (a `NOT`, an
/// AND run, an OR run and the group), so 1,000 levels stay under the toolkit's `TREE_BUDGET`.
pub(crate) const MAX_DEPTH: u32 = 1_000;

pub(crate) const UNEXPECTED: &str = "unexpected";
pub(crate) const MISSING_PAREN: &str = "missing `)`";
pub(crate) const MISSING_RANGE_CLOSE: &str = "the range is never closed: missing `]` or `}`";
pub(crate) const EXPECTED_RANGE_CLOSE: &str =
    "expected `]` or `}` after the range's upper bound: a range holds two bounds";
pub(crate) const EMPTY_GROUP: &str = "an empty group: put a clause between the parentheses";
pub(crate) const EXPECTED_CLAUSE: &str = "expected a search term after the operator";
pub(crate) const EXPECTED_MODIFIED: &str = "expected a search term after the modifier";
pub(crate) const TWO_MODIFIERS: &str =
    "two modifiers in a row: `-`, `+` and `NOT` do not stack (write one, or group)";
pub(crate) const EXPECTED_VALUE: &str = "expected a value after `:`";
pub(crate) const EXPECTED_COMPARED: &str =
    "expected a number or a term right after the comparison operator";
pub(crate) const UNCLOSED_PHRASE: &str = "the phrase is never closed: missing `\"`";
pub(crate) const EXPECTED_LOWER: &str = "expected the range's lower bound";
pub(crate) const EXPECTED_TO: &str = "expected `TO` between the range's bounds";
pub(crate) const EXPECTED_UPPER: &str = "expected the range's upper bound";
pub(crate) const EXPECTED_CIDR_FIELD: &str = "expected an attribute: `CIDR(@attribute, block)`";
pub(crate) const EXPECTED_CIDR_BLOCK: &str = "expected a CIDR block after `,`";
pub(crate) const EXPECTED_CIDR_NEXT: &str = "expected `,` or `)` in `CIDR(…)`";

/// The toolkit's kinds for the search syntax.
pub(crate) const GRAMMAR: Grammar = Grammar {
    eof: K::EOF.raw(),
    error: K::ERROR.raw(),
    trivia: K::set(&[K::WHITESPACE]),
    max_depth: MAX_DEPTH,
};

/// The tokens a clause can start with.
const CLAUSE_START: TokenSet = K::set(&[
    K::WORD,
    K::NUMBER,
    K::ESCAPE,
    K::PHRASE_TOKEN,
    K::UNCLOSED_PHRASE,
    K::STAR,
    K::QUESTION,
    K::COMMA,
    K::MINUS,
    K::PLUS,
    K::BANG,
    K::TILDE,
    K::CARET,
    K::LT,
    K::LT_EQ,
    K::GT,
    K::GT_EQ,
    K::L_PAREN,
    K::L_BRACK,
    K::L_BRACE,
]);

/// The tokens a field may be made of before its colon.
const FIELD_PIECES: TokenSet = K::set(&[
    K::WORD,
    K::NUMBER,
    K::ESCAPE,
    K::STAR,
    K::QUESTION,
    K::MINUS,
    K::PLUS,
    K::EQ,
    K::COMMA,
]);

/// The tokens a CIDR block is made of (`fc00::/7` holds colons).
const CIDR_PIECES: TokenSet = K::set(&[K::WORD, K::NUMBER, K::COLON, K::ESCAPE]);

/// The tokens the attribute of `CIDR(…)` is made of: a field's, but a comma ends it.
const CIDR_FIELD_PIECES: TokenSet = K::set(&[
    K::WORD,
    K::NUMBER,
    K::ESCAPE,
    K::STAR,
    K::QUESTION,
    K::MINUS,
    K::PLUS,
    K::EQ,
]);

/// The most pieces a field is looked for in before its colon: far above any real field
/// (`@user.first\ name` is three), and few enough that the lookahead never nears the fuel.
const MAX_FIELD_PIECES: usize = 1_024;

const COMPARE: TokenSet = K::set(&[K::GT, K::GT_EQ, K::LT, K::LT_EQ]);
const CLOSERS: TokenSet = K::set(&[K::R_BRACK, K::R_BRACE]);

/// Parses `source`.
pub(crate) fn parse(source: &str) -> (SyntaxNode, Parse) {
    let input = Input::new(source, lexer::lex(source), GRAMMAR);
    let mut p = Parser::new(&input);
    let root = p.start();
    if starts_clause(&p) {
        or_expr(&mut p, false);
    }
    // What no clause takes (`)`, `:`, `]`, an operator with nothing before it): an error, and
    // the clauses after it parse again for the highlight. Only the first error is reported.
    while !p.at_eof() {
        p.err_and_bump(UNEXPECTED);
        if starts_clause(&p) {
            or_expr(&mut p, false);
        }
    }
    root.complete(&mut p, K::QUERY.raw());
    let parse = build(&input, p.finish());
    (SyntaxNode::new_root(parse.green.clone()), parse)
}

// ---- Helpers -------------------------------------------------------------------------------

fn kind(p: &Parser<'_>, n: usize) -> K {
    K::from_raw(p.nth(n))
}

/// Whether the `n`th significant token ends where the one after it starts: no whitespace
/// between them.
fn touches(p: &Parser<'_>, n: usize) -> bool {
    match (p.nth_range(n), p.nth_range(n + 1)) {
        (Some(a), Some(b)) => a.end() == b.start(),
        _ => false,
    }
}

/// Whether the `n`th token is the word `text`, exactly.
fn word(p: &Parser<'_>, n: usize, text: &str) -> bool {
    kind(p, n) == K::WORD && p.nth_text(n) == text
}

/// `OR` or `||` at the current token: the kind it is read as.
fn or_at(p: &Parser<'_>) -> Option<K> {
    if word(p, 0, "OR") {
        Some(K::OR_KW)
    } else if word(p, 0, "||") {
        Some(K::PIPE_PIPE)
    } else {
        None
    }
}

/// `AND` or `&&` at the current token: the kind it is read as.
fn and_at(p: &Parser<'_>) -> Option<K> {
    if word(p, 0, "AND") {
        Some(K::AND_KW)
    } else if word(p, 0, "&&") {
        Some(K::AMP_AMP)
    } else {
        None
    }
}

/// A modifier at the current token: `-`, `NOT`, and at the top level `+` (in a value group a
/// leading `+` is part of the value, as Datadog's docs write `@process.args:+x`).
fn modifier_at(p: &Parser<'_>, value: bool) -> Option<K> {
    match kind(p, 0) {
        K::MINUS => Some(K::MINUS),
        K::PLUS if !value => Some(K::PLUS),
        K::WORD if p.nth_text(0) == "NOT" => Some(K::NOT_KW),
        _ => None,
    }
}

/// Whether a clause starts at the current token: not an operator, a closer or the end.
fn starts_clause(p: &Parser<'_>) -> bool {
    let k = kind(p, 0);
    CLAUSE_START.contains(k.raw()) && or_at(p).is_none() && and_at(p).is_none()
}

#[cold]
#[inline(never)]
fn err(p: &mut Parser<'_>, message: &'static str) {
    p.error(message);
}

// ---- Boolean structure ---------------------------------------------------------------------

/// `and_expr (OR and_expr)*`, one flat node when there is an OR.
fn or_expr(p: &mut Parser<'_>, value: bool) {
    let m = p.start();
    and_expr(p, value);
    let mut ors = 0;
    while let Some(op) = or_at(p) {
        p.bump_as(op.raw());
        ors += 1;
        if starts_clause(p) {
            and_expr(p, value);
        } else {
            err(p, EXPECTED_CLAUSE);
            break;
        }
    }
    if ors > 0 {
        m.complete(p, if value { K::VALUE_OR_EXPR } else { K::OR_EXPR }.raw());
    } else {
        m.abandon(p);
    }
}

/// `unary (AND? unary)*`, one flat node when there are two or more.
fn and_expr(p: &mut Parser<'_>, value: bool) {
    let m = p.start();
    unary(p, value);
    let mut more = 0;
    loop {
        if let Some(op) = and_at(p) {
            p.bump_as(op.raw());
            more += 1;
            if !starts_clause(p) {
                err(p, EXPECTED_CLAUSE);
                break;
            }
            unary(p, value);
        } else if starts_clause(p) {
            more += 1;
            unary(p, value);
        } else {
            break;
        }
    }
    if more > 0 {
        m.complete(
            p,
            if value {
                K::VALUE_AND_EXPR
            } else {
                K::AND_EXPR
            }
            .raw(),
        );
    } else {
        m.abandon(p);
    }
}

/// One modifier and its operand, or a primary. Called only where a clause starts, so it always
/// consumes a token.
fn unary(p: &mut Parser<'_>, value: bool) {
    let Some(op) = modifier_at(p, value) else {
        primary(p, value);
        return;
    };
    let m = p.start();
    p.bump_as(op.raw());
    // Modifiers do not stack (`--a`, `NOT NOT a`, `-NOT a`): one error, and the extra ones are
    // read as if they were not there, so the operand still parses for the highlight.
    if modifier_at(p, value).is_some() {
        err(p, TWO_MODIFIERS);
        while let Some(extra) = modifier_at(p, value) {
            p.bump_as(extra.raw());
        }
    }
    if starts_clause(p) {
        primary(p, value);
    } else {
        err(p, EXPECTED_MODIFIED);
    }
    m.complete(
        p,
        if value {
            K::VALUE_NOT_EXPR
        } else {
            K::NOT_EXPR
        }
        .raw(),
    );
}

/// A group, `*:*`, `CIDR(…)`, a field clause or a value (free text). Called only where a clause
/// starts.
fn primary(p: &mut Parser<'_>, value: bool) {
    if kind(p, 0) == K::L_PAREN {
        group(p, value);
        return;
    }
    if !value {
        if word(p, 0, "CIDR") && touches(p, 0) && kind(p, 1) == K::L_PAREN {
            cidr_call(p);
            return;
        }
        if match_all_at(p) {
            let m = p.start();
            p.bump();
            p.bump();
            p.bump();
            m.complete(p, K::MATCH_ALL.raw());
            return;
        }
        if let Some(pieces) = field_at(p) {
            field_clause(p, pieces);
            return;
        }
    }
    value_node(p);
}

/// `( or_expr )`: a group, or a value group inside a value.
fn group(p: &mut Parser<'_>, value: bool) {
    if !p.enter() {
        return;
    }
    let m = p.start();
    p.bump();
    if kind(p, 0) == K::R_PAREN {
        err(p, EMPTY_GROUP);
    } else if starts_clause(p) {
        or_expr(p, value);
    }
    close_paren(p);
    p.exit();
    m.complete(p, if value { K::VALUE_GROUP } else { K::GROUP }.raw());
}

/// The `)` of a group or a call. Where it is not, the token there says which fault it is: the
/// end of the text is a missing `)`; anything else is a token that does not fit.
fn close_paren(p: &mut Parser<'_>) {
    if p.eat(K::R_PAREN.raw()) {
        return;
    }
    err(
        p,
        if p.at_eof() {
            MISSING_PAREN
        } else {
            UNEXPECTED
        },
    );
}

// ---- Clauses -------------------------------------------------------------------------------

/// `*:*` that ends there (`*:*abc` is the field `*` and the term `*abc`).
fn match_all_at(p: &Parser<'_>) -> bool {
    kind(p, 0) == K::STAR
        && touches(p, 0)
        && kind(p, 1) == K::COLON
        && touches(p, 1)
        && kind(p, 2) == K::STAR
        && !(touches(p, 2) && kind(p, 3).is_term_piece())
}

/// The number of tokens of a field at the current token, if a colon touches them: a field is
/// everything before the first unescaped `:` of a term.
fn field_at(p: &Parser<'_>) -> Option<usize> {
    match kind(p, 0) {
        // A quoted field name (Observability Pipelines) and `*:` are one token.
        K::PHRASE_TOKEN | K::STAR if touches(p, 0) && kind(p, 1) == K::COLON => return Some(1),
        K::PHRASE_TOKEN => return None,
        k if FIELD_PIECES.contains(k.raw()) && !matches!(k, K::MINUS | K::PLUS | K::EQ) => {}
        _ => return None,
    }
    // The lookahead consumes nothing, so it is bounded: a run longer than any field name is a
    // term, read as one (a colon past the bound is then a colon in a value). Unbounded, a
    // multi-megabyte term ran the parser's fuel out (2^24 lookups without progress).
    let mut n = 0;
    loop {
        if n >= MAX_FIELD_PIECES || !touches(p, n) {
            return None;
        }
        let next = kind(p, n + 1);
        if next == K::COLON {
            return Some(n + 1);
        }
        if !FIELD_PIECES.contains(next.raw()) {
            return None;
        }
        n += 1;
    }
}

/// `field : value` or `field : ( value_expr )`.
fn field_clause(p: &mut Parser<'_>, pieces: usize) {
    let m = p.start();
    field(p, pieces);
    p.bump(); // `:`
    let touching = touches_previous(p);
    if kind(p, 0) == K::L_PAREN {
        group(p, true);
    } else if starts_value(p) && (touching || !next_clause_at(p)) {
        value_node(p);
    } else {
        err(p, EXPECTED_VALUE);
    }
    m.complete(p, K::FIELD_CLAUSE.raw());
}

/// After a space that follows a field's colon: whether what comes is the next clause rather
/// than the value (`@a: OR b`, `@a: NOT b`, `@a: @b:c`), which leaves the field with no value.
fn next_clause_at(p: &Parser<'_>) -> bool {
    or_at(p).is_some() || and_at(p).is_some() || word(p, 0, "NOT") || field_at(p).is_some()
}

/// Whether a value starts at the current token (after a colon: a `-` is part of the value
/// there, and a check refuses it unescaped).
fn starts_value(p: &Parser<'_>) -> bool {
    CLAUSE_START.contains(kind(p, 0).raw()) && kind(p, 0) != K::L_PAREN
}

/// The `pieces` tokens before the colon, as the field kind its first character says.
fn field(p: &mut Parser<'_>, pieces: usize) {
    let node = match kind(p, 0) {
        K::PHRASE_TOKEN => K::QUOTED_FIELD,
        K::STAR if pieces == 1 => K::ALL_ATTRIBUTES,
        K::WORD if p.nth_text(0).starts_with('@') => K::ATTRIBUTE,
        K::WORD if p.nth_text(0).starts_with('#') => K::CALCULATED_FIELD,
        _ => K::TAG_KEY,
    };
    let m = p.start();
    for _ in 0..pieces {
        p.bump();
    }
    m.complete(p, node.raw());
}

/// `CIDR ( attribute (, block)* )`.
fn cidr_call(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::CIDR_KW.raw());
    p.bump(); // `(`
    if CIDR_PIECES.contains(kind(p, 0).raw()) && kind(p, 0) != K::COLON {
        let node = if p.current_text().starts_with('@') {
            K::ATTRIBUTE
        } else {
            K::TAG_KEY
        };
        let f = p.start();
        glue(p, CIDR_FIELD_PIECES);
        f.complete(p, node.raw());
    } else {
        err(p, EXPECTED_CIDR_FIELD);
    }
    while p.eat(K::COMMA.raw()) {
        if CIDR_PIECES.contains(kind(p, 0).raw()) {
            let b = p.start();
            glue(p, CIDR_PIECES);
            b.complete(p, K::CIDR_BLOCK.raw());
        } else {
            err(p, EXPECTED_CIDR_BLOCK);
            break;
        }
    }
    if !p.eat(K::R_PAREN.raw()) {
        err(
            p,
            if p.at_eof() {
                MISSING_PAREN
            } else {
                EXPECTED_CIDR_NEXT
            },
        );
    }
    m.complete(p, K::CIDR_CALL.raw());
}

/// Consumes the current token and the tokens of `pieces` that touch it, one after another.
fn glue(p: &mut Parser<'_>, pieces: TokenSet) {
    p.bump();
    while touches_previous(p) && pieces.contains(kind(p, 0).raw()) {
        p.bump();
    }
}

/// Whether the current token touches the token consumed before it.
fn touches_previous(p: &Parser<'_>) -> bool {
    let Some(here) = p.nth_range(0) else {
        return false;
    };
    let at = usize::from(here.start());
    // The token before has no trivia after it when the byte before this one is not whitespace.
    // A byte-order mark is whitespace only at the start of the text (the lexer's rule).
    let bom = at == '\u{feff}'.len_utf8() && p.source().starts_with('\u{feff}');
    at > 0 && !bom && !p.source()[..at].ends_with([' ', '\t', '\r', '\n'])
}

// ---- Values --------------------------------------------------------------------------------

/// A comparison, a range, a phrase or a term. Called only where a clause or a value starts.
fn value_node(p: &mut Parser<'_>) {
    match kind(p, 0) {
        k if COMPARE.contains(k.raw()) => comparison(p),
        K::L_BRACK | K::L_BRACE => range(p),
        K::PHRASE_TOKEN | K::UNCLOSED_PHRASE if !(touches(p, 0) && kind(p, 1).is_term_piece()) => {
            let m = p.start();
            if kind(p, 0) == K::UNCLOSED_PHRASE {
                err(p, UNCLOSED_PHRASE);
            }
            p.bump();
            m.complete(p, K::PHRASE.raw());
        }
        _ => term(p),
    }
}

/// The pieces that touch, from the current token: a term. A word alone, or a word after a
/// leading `-` (`>-1`), that reads as a number is a number.
fn term(p: &mut Parser<'_>) {
    let m = p.start();
    let mut first = true;
    let mut after_sign = false;
    loop {
        let k = kind(p, 0);
        let last = !(touches(p, 0) && kind(p, 1).is_term_piece());
        if k == K::UNCLOSED_PHRASE {
            err(p, UNCLOSED_PHRASE);
        }
        if k == K::WORD && (first || after_sign) && last && is_number(p.current_text()) {
            p.bump_as(K::NUMBER.raw());
        } else {
            p.bump();
        }
        after_sign = first && k == K::MINUS;
        first = false;
        if last {
            break;
        }
    }
    m.complete(p, K::TERM.raw());
}

/// `>=` and the operand that touches it.
fn comparison(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    if touches_previous(p) && kind(p, 0).is_term_piece() && !COMPARE.contains(kind(p, 0).raw()) {
        term(p);
    } else {
        err(p, EXPECTED_COMPARED);
    }
    m.complete(p, K::COMPARISON.raw());
}

/// `[ lower TO upper ]`, with `{ }` for exclusive bounds.
fn range(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    let to = |p: &Parser<'_>| kind(p, 0) == K::WORD && p.current_text().eq_ignore_ascii_case("to");
    if p.at_eof() || p.at_set(CLOSERS) || to(p) {
        err(p, EXPECTED_LOWER);
    } else {
        range_bound(p);
    }
    if to(p) {
        p.bump_as(K::TO_KW.raw());
        if p.at_eof() || p.at_set(CLOSERS) {
            err(p, EXPECTED_UPPER);
        } else {
            range_bound(p);
        }
    } else if !p.at_eof() {
        err(p, EXPECTED_TO);
    }
    if p.at_set(CLOSERS) {
        p.bump();
    } else {
        err(
            p,
            if p.at_eof() {
                MISSING_RANGE_CLOSE
            } else {
                EXPECTED_RANGE_CLOSE
            },
        );
    }
    m.complete(p, K::RANGE.raw());
}

/// A bound: the tokens that touch, up to whitespace or a closing bracket.
fn range_bound(p: &mut Parser<'_>) {
    let m = p.start();
    let mut first = true;
    loop {
        let last = !touches(p, 0) || CLOSERS.contains(p.nth(1));
        if first && last && kind(p, 0) == K::WORD && is_number(p.current_text()) {
            p.bump_as(K::NUMBER.raw());
        } else {
            p.bump();
        }
        first = false;
        if last {
            break;
        }
    }
    m.complete(p, K::RANGE_BOUND.raw());
}
