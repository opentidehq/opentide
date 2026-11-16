//! CQL's grammar as functions over [`opentide_parse::Parser`]. It follows
//! `grammars/tree-sitter-opentide-cql/grammar.js` and `cql.ungram`.
//!
//! Precedence, from CrowdStrike's grammar subset: `not`/`!` binds tightest, then `or`, then
//! `and` and juxtaposition, then `|`. Runs of `and` (or juxtaposed filters), runs of `or`, and
//! runs of one level of binary operators are each one flat node, so a 20,000-term chain is not
//! 20,000 levels deep. Every rule that recurses calls [`Parser::enter`].
//!
//! The lexer (`lexer.rs`) has already told words from patterns, calls and assignment fields
//! by the grammar's mode, so the parser reads token kinds and re-kinds a word as a keyword
//! where the grammar expects one (`case`, `match`, `like`, `true`, `false`, and `and`, `or`,
//! `not` in any case).

use crate::lexer;
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_parse::{CompletedMarker, Grammar, Input, Parse, Parser, TokenSet, build};

/// Nesting deeper than this is one error. tree-sitter took 10,000 levels; the floor every
/// language keeps is `deep_queries`' `NESTING_CEILING` (1,000).
pub(crate) const MAX_DEPTH: u32 = 1_024;

pub(crate) const UNEXPECTED: &str = "unexpected";
pub(crate) const MISSING_PAREN: &str = "missing `)`";
pub(crate) const MISSING_BRACE: &str = "missing `}`";
pub(crate) const MISSING_BRACK: &str = "missing `]`";
pub(crate) const EXPECTED_FILTER: &str = "expected a filter";
pub(crate) const EXPECTED_STEP: &str = "expected a step";
pub(crate) const EXPECTED_VALUE: &str = "expected a value";
pub(crate) const EXPECTED_EXPR: &str = "expected an expression";
pub(crate) const EXPECTED_CALL: &str = "expected a function call";
pub(crate) const EXPECTED_FIELD: &str = "expected a field";
pub(crate) const EXPECTED_ARGUMENT: &str = "expected an argument";
pub(crate) const EXPECTED_REGEX: &str = "expected a regular expression";
pub(crate) const EXPECTED_NAME: &str = "expected a name";
pub(crate) const FILTER_AFTER_ASSIGNMENT: &str =
    "a filter cannot follow an assignment without a pipe";

/// What can follow a pipeline step inside brackets.
const NESTED_END: TokenSet = K::set(&[K::R_PAREN, K::R_BRACE, K::R_BRACK, K::SEMI]);
const COMPARE: TokenSet = K::set(&[K::EQ, K::NOT_EQ, K::LT, K::LT_EQ, K::GT, K::GT_EQ]);
const BINARY_COMPARE: TokenSet = K::set(&[
    K::EQ_EQ,
    K::NOT_EQ,
    K::LT,
    K::LT_EQ,
    K::GT,
    K::GT_EQ,
    K::LT_EQ_GT,
]);
const ADDITIVE: TokenSet = K::set(&[K::PLUS, K::MINUS]);
const MULTIPLICATIVE: TokenSet = K::set(&[K::STAR, K::SLASH, K::PERCENT]);
const PATTERN_TOKENS: TokenSet = K::set(&[K::PATTERN, K::WORD, K::TAG_TOKEN, K::NUMBER_TOKEN]);

/// The toolkit's kinds for CQL.
pub(crate) const GRAMMAR: Grammar = Grammar {
    eof: K::EOF.raw(),
    error: K::ERROR.raw(),
    trivia: K::set(&[K::WHITESPACE, K::LINE_COMMENT, K::BLOCK_COMMENT]),
    max_depth: MAX_DEPTH,
};

/// Parses `source`.
pub(crate) fn parse(source: &str) -> (SyntaxNode, Parse) {
    let input = Input::new(source, lexer::lex(source), GRAMMAR);
    let mut p = Parser::new(&input);
    let root = p.start();
    if !p.at_eof() {
        pipeline(&mut p, true);
    }
    while !p.at_eof() {
        p.err_and_bump(UNEXPECTED);
    }
    root.complete(&mut p, K::SOURCE_FILE.raw());
    let parse = build(&input, p.finish());
    (SyntaxNode::new_root(parse.green.clone()), parse)
}

/// Levels a rule on the long recursion path (calls, expressions, bodies) costs: a frame chain
/// of about 1.5 KB per level in a debug build, so a 1 MB stack holds ~680 of them. Charging two
/// keeps `MAX_DEPTH` safe; the nesting floor (1,000) is for parentheses of filters, one level.
const HEAVY: u32 = 2;

fn enter_heavy(p: &mut Parser<'_>) -> bool {
    (0..HEAVY).all(|_| p.enter())
}

fn exit_heavy(p: &mut Parser<'_>) {
    for _ in 0..HEAVY {
        p.exit();
    }
}

// ---- Helpers -------------------------------------------------------------------------------

fn kind(p: &Parser<'_>, n: usize) -> K {
    K::from_raw(p.nth(n))
}

fn at(p: &mut Parser<'_>, k: K) -> bool {
    p.at(k.raw())
}

fn eat(p: &mut Parser<'_>, k: K) -> bool {
    p.eat(k.raw())
}

fn expect(p: &mut Parser<'_>, k: K, message: &str) -> bool {
    p.expect(k.raw(), message)
}

/// A node `node` that wraps the current token, read as `token`.
fn wrap(p: &mut Parser<'_>, node: K, token: K) {
    let m = p.start();
    p.bump_as(token.raw());
    m.complete(p, node.raw());
}

/// Whether the `n`th token is the word `text` (lower case: CQL's `case`, `match`, `like`,
/// `true` and `false` are not case-insensitive).
fn word(p: &Parser<'_>, n: usize, text: &str) -> bool {
    kind(p, n) == K::WORD && p.nth_text(n) == text
}

/// `and`, `or` or `not` at the `n`th token, in any case: reserved in every position.
fn reserved(p: &Parser<'_>, n: usize) -> Option<K> {
    if kind(p, n) != K::WORD {
        return None;
    }
    let text = p.nth_text(n);
    [("and", K::AND_KW), ("or", K::OR_KW), ("not", K::NOT_KW)]
        .into_iter()
        .find(|(kw, _)| text.eq_ignore_ascii_case(kw))
        .map(|(_, k)| k)
}

/// A word that may be a field, argument or identifier name: not `and`, `or`, `not`.
fn plain_word(p: &Parser<'_>, n: usize) -> bool {
    kind(p, n) == K::WORD && reserved(p, n).is_none()
}

/// A field followed by `:=`: the scanner reads any word there as the field of an assignment,
/// `and`, `or`, `not`, `like`, `match`, `true` and `false` included.
fn assign_at(p: &Parser<'_>) -> bool {
    matches!(
        kind(p, 0),
        K::WORD | K::ASSIGN_FIELD_TOKEN | K::TAG_TOKEN | K::STRING_TOKEN
    ) && kind(p, 1) == K::COLON_EQ
}

/// A field at the `n`th token: a word, a tag or a quoted string.
fn field_at(p: &Parser<'_>, n: usize) -> bool {
    plain_word(p, n)
        || matches!(
            kind(p, n),
            K::ASSIGN_FIELD_TOKEN | K::TAG_TOKEN | K::STRING_TOKEN
        )
}

/// `!` or `not` at the current token.
fn negation(p: &Parser<'_>) -> bool {
    kind(p, 0) == K::BANG || reserved(p, 0) == Some(K::NOT_KW)
}

fn boolean_at(p: &Parser<'_>, n: usize) -> bool {
    word(p, n, "true") || word(p, n, "false")
}

/// A field (`field_name`, `tag` or `string`).
fn field(p: &mut Parser<'_>) -> bool {
    match kind(p, 0) {
        K::WORD if plain_word(p, 0) => wrap(p, K::FIELD_NAME, K::WORD),
        K::ASSIGN_FIELD_TOKEN => wrap(p, K::FIELD_NAME, K::WORD),
        K::TAG_TOKEN => wrap(p, K::TAG, K::TAG_TOKEN),
        K::STRING_TOKEN => wrap(p, K::STRING, K::STRING_TOKEN),
        _ => {
            p.error(EXPECTED_FIELD);
            return false;
        }
    }
    true
}

/// `!` or `not` of a negation.
fn negation_token(p: &mut Parser<'_>) {
    if at(p, K::BANG) {
        p.bump();
    } else {
        wrap(p, K::NOT, K::NOT_KW);
    }
}

/// What follows a field at the current token, which decides the step.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Follow {
    Assign,
    Shorthand,
    Link,
    Match,
    Compare,
    Plain,
}

fn follow(p: &Parser<'_>) -> Follow {
    if kind(p, 1) == K::COLON_EQ {
        return Follow::Assign;
    }
    // `true` and `false` are keywords: they name no field for these steps. `like :=` and
    // `match :=` are assignments, which the lexer reads as an assignment field, not a word.
    let named = !boolean_at(p, 0);
    match kind(p, 1) {
        K::EQ_TILDE if named => Follow::Shorthand,
        K::LT_EQ_GT if named => Follow::Link,
        k if COMPARE.contains(k.raw()) => Follow::Compare,
        K::WORD if named && word(p, 1, "match") => Follow::Match,
        K::WORD if word(p, 1, "like") => Follow::Compare,
        _ => Follow::Plain,
    }
}

// ---- Pipelines and steps -------------------------------------------------------------------

/// What a step was, for the rule that an assignment is followed only by an assignment or a
/// call when no pipe separates them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Filter,
    Call,
    Assign,
}

/// `|`? step (`|` step)*. The whole query may end with `|` (`top`); a nested pipeline may not.
fn pipeline(p: &mut Parser<'_>, top: bool) {
    let m = p.start();
    let end = if top { TokenSet::EMPTY } else { NESTED_END };
    let mut steps = false;
    eat(p, K::PIPE);
    loop {
        if run(p, end) {
            steps = true;
        } else if !(top && steps && p.at_eof()) {
            p.error(EXPECTED_STEP);
        }
        if !eat(p, K::PIPE) {
            break;
        }
    }
    m.complete(p, K::PIPELINE.raw());
}

/// Steps with no pipe between them; whether there was one.
fn run(p: &mut Parser<'_>, end: TokenSet) -> bool {
    let mut any = false;
    let mut prev = None;
    while !p.at_eof() && !end.contains(p.current()) && !at(p, K::PIPE) {
        any = true;
        prev = Some(step(p, prev));
    }
    any
}

/// One step, after `prev` (none at the start of a run).
fn step(p: &mut Parser<'_>, prev: Option<Step>) -> Step {
    let pending_assign = prev == Some(Step::Assign);
    // After a filter only a plain word is an assignment's field, and only where the scanner
    // read it as one (a quoted or indexed name is more free text there).
    let after_filter = prev == Some(Step::Filter);
    if assign_at(p) && !(after_filter && kind(p, 0) != K::ASSIGN_FIELD_TOKEN) {
        assignment(p);
        return Step::Assign;
    }
    match kind(p, 0) {
        K::FUNCTION_NAME_TOKEN => {
            function_call(p);
        }
        K::L_BRACK => {
            array(p, K::STATS_SHORTHAND);
        }
        K::DOLLAR => saved_query(p),
        K::BANG | K::WORD if negation(p) && kind(p, 1) == K::FUNCTION_NAME_TOKEN => {
            negated_call(p);
        }
        K::WORD if word(p, 0, "case") => case_statement(p),
        _ if field_at(p, 0) => match follow(p) {
            Follow::Shorthand => field_shorthand(p),
            Follow::Link => link_constraint(p),
            Follow::Match => match_statement(p),
            Follow::Assign | Follow::Compare | Follow::Plain => {
                return filter_step(p, pending_assign);
            }
        },
        _ => return filter_step(p, pending_assign),
    }
    Step::Call
}

/// A filter as a step; at the end of a token nothing else can start, one token is an error.
fn filter_step(p: &mut Parser<'_>, pending_assign: bool) -> Step {
    if pending_assign {
        p.error(FILTER_AFTER_ASSIGNMENT);
    }
    if and_chain(p, true).is_none() {
        p.err_and_bump(UNEXPECTED);
    }
    Step::Filter
}

// ---- Filters -------------------------------------------------------------------------------

/// Whether a filter operand may follow the last one with nothing between (an implicit `and`):
/// not where an assignment or `case` starts. A negated call, `match`, `<=>` and `=~` after a
/// filter are read as filters (and fail there), as tree-sitter reads them. `steps`: a step
/// may follow (not inside parentheses).
fn continues_chain(p: &Parser<'_>, steps: bool) -> bool {
    match kind(p, 0) {
        K::ASSIGN_FIELD_TOKEN => false,
        K::WORD => {
            // `case` starts a step; inside parentheses there are no steps, it is a word.
            if reserved(p, 0).is_some_and(|k| k != K::NOT_KW) || (steps && word(p, 0, "case")) {
                return false;
            }
            true
        }
        K::BANG
        | K::TAG_TOKEN
        | K::STRING_TOKEN
        | K::PATTERN
        | K::SLASH
        | K::QUESTION
        | K::QUESTION_L_BRACE
        | K::L_PAREN => true,
        _ => false,
    }
}

/// `or`-runs joined by `and` or by juxtaposition: one flat node per run.
fn and_chain(p: &mut Parser<'_>, steps: bool) -> Option<CompletedMarker> {
    let first = or_chain(p)?;
    if !(continues_chain(p, steps) || is_word(p, K::AND_KW)) {
        return Some(first);
    }
    let m = first.precede(p);
    loop {
        if is_word(p, K::AND_KW) {
            wrap(p, K::AND, K::AND_KW);
        } else if !continues_chain(p, steps) {
            break;
        }
        if or_chain(p).is_none() {
            p.error(EXPECTED_FILTER);
            break;
        }
    }
    Some(m.complete(p, K::AND_FILTER.raw()))
}

fn is_word(p: &Parser<'_>, k: K) -> bool {
    reserved(p, 0) == Some(k)
}

fn or_chain(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let first = unary(p)?;
    if !is_word(p, K::OR_KW) {
        return Some(first);
    }
    let m = first.precede(p);
    while is_word(p, K::OR_KW) {
        wrap(p, K::OR, K::OR_KW);
        if unary(p).is_none() {
            p.error(EXPECTED_FILTER);
            break;
        }
    }
    Some(m.complete(p, K::OR_FILTER.raw()))
}

/// `not`* then a primary filter. A negated call is a step, not an operand.
fn unary(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    if negation(p) {
        if kind(p, 1) == K::FUNCTION_NAME_TOKEN || !p.enter() {
            return None;
        }
        let m = p.start();
        negation_token(p);
        if unary(p).is_none() {
            p.error(EXPECTED_FILTER);
        }
        p.exit();
        return Some(m.complete(p, K::NOT_FILTER.raw()));
    }
    primary_filter(p)
}

fn primary_filter(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    match kind(p, 0) {
        K::L_PAREN => paren_filter(p),
        K::WORD if boolean_at(p, 0) => {
            let m = p.start();
            let kw = if word(p, 0, "true") {
                K::TRUE_KW
            } else {
                K::FALSE_KW
            };
            p.bump_as(kw.raw());
            Some(m.complete(p, K::BOOLEAN.raw()))
        }
        _ if field_at(p, 0) && follow(p) == Follow::Compare => Some(field_filter(p)),
        K::WORD if !plain_word(p, 0) => None,
        K::WORD
        | K::TAG_TOKEN
        | K::STRING_TOKEN
        | K::PATTERN
        | K::SLASH
        | K::QUESTION
        | K::QUESTION_L_BRACE => {
            let m = p.start();
            free_value(p);
            Some(m.complete(p, K::FREE_TEXT.raw()))
        }
        _ => None,
    }
}

fn paren_filter(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    if !p.enter() {
        return None;
    }
    let m = p.start();
    p.bump();
    if and_chain(p, false).is_none() {
        p.error(EXPECTED_FILTER);
    }
    expect(p, K::R_PAREN, MISSING_PAREN);
    p.exit();
    Some(m.complete(p, K::PARENTHESIZED_FILTER.raw()))
}

/// `field (= | != | like | < | <= | > | >=) value`.
fn field_filter(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    field(p);
    let op = kind(p, 0);
    if op == K::WORD {
        p.bump_as(K::LIKE_KW.raw());
        free_value(p);
    } else {
        p.bump();
        if matches!(op, K::EQ | K::NOT_EQ) {
            free_value(p);
        } else {
            compare_value(p);
        }
    }
    m.complete(p, K::FIELD_FILTER.raw())
}

/// The value of a free-text filter or after `=`, `!=` and `like`: a pattern, a string, a
/// regex or a parameter.
fn free_value(p: &mut Parser<'_>) {
    match kind(p, 0) {
        K::STRING_TOKEN => wrap(p, K::STRING, K::STRING_TOKEN),
        K::SLASH => {
            regex(p);
        }
        K::QUESTION | K::QUESTION_L_BRACE => {
            parameter(p);
        }
        K::WORD if reserved(p, 0).is_some() => p.error(EXPECTED_VALUE),
        k if PATTERN_TOKENS.contains(k.raw()) => unquoted_pattern(p),
        _ => p.error(EXPECTED_VALUE),
    }
}

/// The value after `<`, `<=`, `>` and `>=`: a number, a string or a parameter.
fn compare_value(p: &mut Parser<'_>) {
    match kind(p, 0) {
        K::NUMBER_TOKEN => wrap(p, K::NUMBER, K::NUMBER_TOKEN),
        K::STRING_TOKEN => wrap(p, K::STRING, K::STRING_TOKEN),
        K::QUESTION | K::QUESTION_L_BRACE => {
            parameter(p);
        }
        _ => p.error(EXPECTED_VALUE),
    }
}

fn unquoted_pattern(p: &mut Parser<'_>) {
    let token = p.current();
    let m = p.start();
    p.bump_as(token);
    m.complete(p, K::UNQUOTED_PATTERN.raw());
}

/// `/pattern/flags`.
fn regex(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    if at(p, K::REGEX_PATTERN_TOKEN) {
        wrap(p, K::REGEX_PATTERN, K::REGEX_PATTERN_TOKEN);
    } else {
        p.error(EXPECTED_REGEX);
    }
    if expect(p, K::SLASH, "the regular expression is never closed") && at(p, K::REGEX_FLAGS_TOKEN)
    {
        wrap(p, K::REGEX_FLAGS, K::REGEX_FLAGS_TOKEN);
    }
    m.complete(p, K::REGEX.raw())
}

/// `?name`, `?"quoted name"`, `?{name=default}`.
fn parameter(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    let braced = at(p, K::QUESTION_L_BRACE);
    let sigil_end = p.current_range().map(|r| r.end());
    p.bump();
    // `?name` and `?"name"` touch the `?`.
    if !braced && p.current_range().map(|r| r.start()) != sigil_end {
        p.error(EXPECTED_NAME);
    } else {
        parameter_name(p, braced);
    }
    if braced {
        let default = p.start();
        expect(p, K::EQ, "expected `=` and a default value");
        match kind(p, 0) {
            K::STRING_TOKEN => wrap(p, K::STRING, K::STRING_TOKEN),
            K::WORD if reserved(p, 0).is_some() => p.error(EXPECTED_VALUE),
            k if PATTERN_TOKENS.contains(k.raw()) => unquoted_pattern(p),
            _ => p.error(EXPECTED_VALUE),
        }
        expect(p, K::R_BRACE, MISSING_BRACE);
        default.complete(p, K::PARAMETER_DEFAULT.raw());
    }
    m.complete(p, K::QUERY_PARAMETER.raw())
}

/// The name after `?` or `?{`.
fn parameter_name(p: &mut Parser<'_>, braced: bool) {
    match kind(p, 0) {
        K::STRING_TOKEN => wrap(p, K::STRING, K::STRING_TOKEN),
        K::PARAMETER_NAME_TOKEN => wrap(p, K::PARAMETER_NAME, K::PARAMETER_NAME_TOKEN),
        K::WORD | K::PATTERN if braced && reserved(p, 0).is_none() => {
            let token = p.current();
            let name = p.start();
            p.bump_as(token);
            name.complete(p, K::PARAMETER_NAME.raw());
        }
        _ => p.error(EXPECTED_NAME),
    }
}

// ---- Steps other than filters --------------------------------------------------------------

fn assignment(p: &mut Parser<'_>) {
    let m = p.start();
    field(p);
    p.bump();
    if expr(p).is_none() {
        p.error(EXPECTED_EXPR);
    }
    m.complete(p, K::ASSIGNMENT.raw());
}

fn field_shorthand(p: &mut Parser<'_>) {
    let m = p.start();
    field(p);
    p.bump();
    call_step(p);
    m.complete(p, K::FIELD_SHORTHAND.raw());
}

/// A function call, or a negated one.
fn call_step(p: &mut Parser<'_>) {
    if at(p, K::FUNCTION_NAME_TOKEN) {
        function_call(p);
    } else if negation(p) && kind(p, 1) == K::FUNCTION_NAME_TOKEN {
        negated_call(p);
    } else {
        p.error(EXPECTED_CALL);
    }
}

fn negated_call(p: &mut Parser<'_>) {
    let m = p.start();
    negation_token(p);
    function_call(p);
    m.complete(p, K::NEGATED_FUNCTION_CALL.raw());
}

fn link_constraint(p: &mut Parser<'_>) {
    let m = p.start();
    field(p);
    p.bump();
    if field_at(p, 0) {
        field(p);
    } else {
        p.error(EXPECTED_FIELD);
    }
    m.complete(p, K::LINK_CONSTRAINT.raw());
}

/// `case { branch (; branch)* ;? }`; an empty body parses.
fn case_statement(p: &mut Parser<'_>) {
    if !enter_heavy(p) {
        return;
    }
    let m = p.start();
    p.bump_as(K::CASE_KW.raw());
    if expect(p, K::L_BRACE, "expected `{` after `case`") && !at(p, K::R_BRACE) {
        loop {
            let branch = p.start();
            pipeline(p, false);
            branch.complete(p, K::CASE_BRANCH.raw());
            if !eat(p, K::SEMI) || at(p, K::R_BRACE) || p.at_eof() {
                break;
            }
        }
    }
    expect(p, K::R_BRACE, MISSING_BRACE);
    exit_heavy(p);
    m.complete(p, K::CASE_STATEMENT.raw());
}

/// `field match { guard => pipeline; ... }`.
fn match_statement(p: &mut Parser<'_>) {
    if !enter_heavy(p) {
        return;
    }
    let m = p.start();
    field(p);
    p.bump_as(K::MATCH_KW.raw());
    if expect(p, K::L_BRACE, "expected `{` after `match`") {
        loop {
            match_branch(p);
            if !eat(p, K::SEMI) || at(p, K::R_BRACE) || p.at_eof() {
                break;
            }
        }
    }
    expect(p, K::R_BRACE, MISSING_BRACE);
    exit_heavy(p);
    m.complete(p, K::MATCH_STATEMENT.raw());
}

fn match_branch(p: &mut Parser<'_>) {
    let m = p.start();
    match kind(p, 0) {
        K::STRING_TOKEN => wrap(p, K::STRING, K::STRING_TOKEN),
        K::SLASH => {
            regex(p);
        }
        K::QUESTION | K::QUESTION_L_BRACE => {
            parameter(p);
        }
        K::FUNCTION_NAME_TOKEN => {
            function_call(p);
        }
        K::BANG | K::WORD if negation(p) => call_step(p),
        K::WORD if boolean_at(p, 0) => {
            let kw = if word(p, 0, "true") {
                K::TRUE_KW
            } else {
                K::FALSE_KW
            };
            let b = p.start();
            p.bump_as(kw.raw());
            b.complete(p, K::BOOLEAN.raw());
        }
        K::WORD if reserved(p, 0).is_some() => p.error(EXPECTED_VALUE),
        k if PATTERN_TOKENS.contains(k.raw()) => unquoted_pattern(p),
        _ => p.error(EXPECTED_VALUE),
    }
    expect(p, K::FAT_ARROW, "expected `=>`");
    pipeline(p, false);
    m.complete(p, K::MATCH_BRANCH.raw());
}

/// `$name(argument=value, ...)`.
fn saved_query(p: &mut Parser<'_>) {
    if !enter_heavy(p) {
        return;
    }
    let m = p.start();
    p.bump();
    let name_end = p.current_range().map(|r| r.end());
    match kind(p, 0) {
        K::SAVED_QUERY_NAME_TOKEN => wrap(p, K::SAVED_QUERY_NAME, K::SAVED_QUERY_NAME_TOKEN),
        K::STRING_TOKEN => wrap(p, K::STRING, K::STRING_TOKEN),
        _ => p.error(EXPECTED_NAME),
    }
    // The `(` must touch the name: `$name (x)` is not a saved query.
    if p.current_range().map(|r| r.start()) != name_end {
        p.error("expected `(` directly after the saved query name");
    }
    if expect(p, K::L_PAREN, "expected `(` after the saved query name") {
        if !at(p, K::R_PAREN) {
            loop {
                saved_query_argument(p);
                if !eat(p, K::COMMA) {
                    break;
                }
            }
        }
        expect(p, K::R_PAREN, MISSING_PAREN);
    }
    exit_heavy(p);
    m.complete(p, K::SAVED_QUERY.raw());
}

fn saved_query_argument(p: &mut Parser<'_>) {
    let m = p.start();
    match kind(p, 0) {
        K::STRING_TOKEN => wrap(p, K::STRING, K::STRING_TOKEN),
        K::WORD if plain_word(p, 0) => wrap(p, K::ARGUMENT_NAME, K::WORD),
        _ => p.error(EXPECTED_ARGUMENT),
    }
    expect(p, K::EQ, "expected `=` after the argument name");
    match kind(p, 0) {
        K::STRING_TOKEN => wrap(p, K::STRING, K::STRING_TOKEN),
        K::QUESTION | K::QUESTION_L_BRACE => {
            parameter(p);
        }
        K::L_BRACK => {
            array(p, K::ARRAY);
        }
        K::WORD if reserved(p, 0).is_some() => p.error(EXPECTED_VALUE),
        k if PATTERN_TOKENS.contains(k.raw()) => unquoted_pattern(p),
        _ => p.error(EXPECTED_VALUE),
    }
    m.complete(p, K::SAVED_QUERY_ARGUMENT.raw());
}

// ---- Function calls and expressions --------------------------------------------------------

fn function_call(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    if !enter_heavy(p) {
        return None;
    }
    let m = p.start();
    wrap(p, K::FUNCTION_NAME, K::FUNCTION_NAME_TOKEN);
    if expect(p, K::L_PAREN, "expected `(` after the function name") {
        if !at(p, K::R_PAREN) {
            argument_list(p);
        }
        expect(p, K::R_PAREN, MISSING_PAREN);
    }
    exit_heavy(p);
    Some(m.complete(p, K::FUNCTION_CALL.raw()))
}

/// `argument (, argument)*`; at most one unnamed argument is a semantic check.
fn argument_list(p: &mut Parser<'_>) {
    let m = p.start();
    loop {
        argument(p);
        if !eat(p, K::COMMA) {
            break;
        }
    }
    m.complete(p, K::ARGUMENT_LIST.raw());
}

fn argument(p: &mut Parser<'_>) {
    let m = p.start();
    let named = kind(p, 1) == K::EQ
        && ((plain_word(p, 0) && !boolean_at(p, 0)) || kind(p, 0) == K::STRING_TOKEN);
    if named {
        if at(p, K::STRING_TOKEN) {
            wrap(p, K::STRING, K::STRING_TOKEN);
        } else {
            wrap(p, K::ARGUMENT_NAME, K::WORD);
        }
        p.bump();
    }
    if attributed_expr(p).is_none() {
        p.error(if named {
            EXPECTED_EXPR
        } else {
            EXPECTED_ARGUMENT
        });
    }
    m.complete(
        p,
        if named {
            K::NAMED_ARGUMENT
        } else {
            K::ARGUMENT
        }
        .raw(),
    );
}

/// An expression and the `name: value` attributes after it (correlate()).
fn attributed_expr(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let first = expr(p)?;
    if !attribute_at(p) {
        return Some(first);
    }
    let m = first.precede(p);
    while attribute_at(p) {
        let attr = p.start();
        wrap(p, K::IDENTIFIER, K::WORD);
        p.bump();
        if expr(p).is_none() {
            p.error(EXPECTED_EXPR);
        }
        attr.complete(p, K::EXPRESSION_ATTRIBUTE.raw());
    }
    Some(m.complete(p, K::ATTRIBUTED_EXPRESSION.raw()))
}

fn attribute_at(p: &Parser<'_>) -> bool {
    plain_word(p, 0) && kind(p, 1) == K::COLON
}

/// The comparative expression: `== != < <= > >= <=>`, then `+ -`, then `* / %`, then a unary.
/// Nesting without operators takes the short path, so a deep `((((a))))` costs few frames.
fn expr(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let first = unary_expr(p)?;
    let cur = p.current();
    if !(BINARY_COMPARE.contains(cur) || ADDITIVE.contains(cur) || MULTIPLICATIVE.contains(cur)) {
        return Some(first);
    }
    let first = binary_tail(p, first, MULTIPLICATIVE, unary_expr);
    let first = binary_tail(p, first, ADDITIVE, multiplicative);
    Some(binary_tail(p, first, BINARY_COMPARE, additive))
}

fn additive(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let first = multiplicative(p)?;
    Some(binary_tail(p, first, ADDITIVE, multiplicative))
}

fn multiplicative(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let first = unary_expr(p)?;
    Some(binary_tail(p, first, MULTIPLICATIVE, unary_expr))
}

/// The operators `ops` after `first`, with `operand` between them, as one flat node.
fn binary_tail(
    p: &mut Parser<'_>,
    first: CompletedMarker,
    ops: TokenSet,
    operand: fn(&mut Parser<'_>) -> Option<CompletedMarker>,
) -> CompletedMarker {
    if !ops.contains(p.current()) {
        return first;
    }
    let m = first.precede(p);
    while ops.contains(p.current()) {
        p.bump();
        if operand(p).is_none() {
            p.error(EXPECTED_EXPR);
            break;
        }
    }
    m.complete(p, K::BINARY_EXPRESSION.raw())
}

fn unary_expr(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    if matches!(kind(p, 0), K::MINUS | K::BANG) {
        let m = p.start();
        p.bump();
        if primary_expr(p).is_none() {
            p.error(EXPECTED_EXPR);
        }
        return Some(m.complete(p, K::UNARY_EXPRESSION.raw()));
    }
    primary_expr(p)
}

fn primary_expr(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    // The recursive arms only: the frame of a rule on the recursion path stays small, which
    // is what a 1 MB stack holds 1,000 levels of.
    match kind(p, 0) {
        K::L_PAREN => paren_expr(p),
        K::L_BRACE => subquery(p),
        K::FUNCTION_NAME_TOKEN => function_call(p),
        K::L_BRACK => array(p, K::ARRAY),
        K::WORD
            if kind(p, 1) == K::COLON
                && kind(p, 2) == K::L_BRACE
                && reserved(p, 0).is_none()
                && !boolean_at(p, 0) =>
        {
            named_subquery(p)
        }
        _ => leaf_expr(p),
    }
}

/// An expression with no nested rule inside.
#[inline(never)]
fn leaf_expr(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    Some(match kind(p, 0) {
        K::QUESTION | K::QUESTION_L_BRACE => parameter(p),
        K::NUMBER_TOKEN => node_of(p, K::NUMBER, K::NUMBER_TOKEN),
        K::STRING_TOKEN => node_of(p, K::STRING, K::STRING_TOKEN),
        K::TAG_TOKEN => node_of(p, K::TAG, K::TAG_TOKEN),
        K::PATTERN => node_of(p, K::UNQUOTED_PATTERN, K::PATTERN),
        K::WORD if boolean_at(p, 0) => {
            let kw = if word(p, 0, "true") {
                K::TRUE_KW
            } else {
                K::FALSE_KW
            };
            node_of(p, K::BOOLEAN, kw)
        }
        K::WORD if reserved(p, 0).is_some() => return None,
        K::WORD => node_of(p, K::FIELD_NAME, K::WORD),
        _ => return None,
    })
}

/// `( expression )`.
fn paren_expr(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    if !enter_heavy(p) {
        return None;
    }
    let m = p.start();
    p.bump();
    if attributed_expr(p).is_none() {
        p.error(EXPECTED_EXPR);
    }
    expect(p, K::R_PAREN, MISSING_PAREN);
    exit_heavy(p);
    Some(m.complete(p, K::PARENTHESIZED_EXPRESSION.raw()))
}

/// `{ pipeline? }`.
fn subquery(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    if !enter_heavy(p) {
        return None;
    }
    let m = p.start();
    p.bump();
    if !at(p, K::R_BRACE) {
        pipeline(p, false);
    }
    expect(p, K::R_BRACE, MISSING_BRACE);
    exit_heavy(p);
    Some(m.complete(p, K::SUBQUERY.raw()))
}

/// `name: { ... }` (correlate()).
fn named_subquery(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let m = p.start();
    wrap(p, K::IDENTIFIER, K::WORD);
    p.bump();
    subquery(p);
    Some(m.complete(p, K::NAMED_SUBQUERY.raw()))
}

/// `[ element (, element)* ]`: an array in an expression (`node` = `ARRAY`) or a stats
/// shorthand step (`STATS_SHORTHAND`). An element is an assignment or an expression.
fn array(p: &mut Parser<'_>, node: K) -> Option<CompletedMarker> {
    if !enter_heavy(p) {
        return None;
    }
    let m = p.start();
    p.bump();
    if !at(p, K::R_BRACK) {
        loop {
            if field_at(p, 0) && kind(p, 1) == K::COLON_EQ {
                assignment(p);
            } else if attributed_expr(p).is_none() {
                p.error(EXPECTED_EXPR);
            }
            if !eat(p, K::COMMA) {
                break;
            }
        }
    }
    expect(p, K::R_BRACK, MISSING_BRACK);
    exit_heavy(p);
    Some(m.complete(p, node.raw()))
}

/// A node that wraps the current token, as a completed marker.
fn node_of(p: &mut Parser<'_>, node: K, token: K) -> CompletedMarker {
    let m = p.start();
    p.bump_as(token.raw());
    m.complete(p, node.raw())
}
