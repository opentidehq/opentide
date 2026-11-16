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
/// language keeps is `deep_queries`' `NESTING_CEILING` (1,000), and no more: a call with a
/// negated call in its argument (`f(!`) opens four tree nodes per level, so 1,000 such levels
/// stay under the toolkit's `MAX_TREE_DEPTH` (4,096 nodes). Binary operators are not levels
/// (a chain is one flat node), so a call in an operand of each precedence in turn
/// (`f(a == b + c * !`) is up to seven nodes a level and reaches `MAX_TREE_DEPTH` first, at
/// about 580 levels: one `TreeTooDeep` error, never an overflow (`parser_depth`).
pub(crate) const MAX_DEPTH: u32 = 1_000;

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
pub(crate) const EXPECTED_BRANCH: &str = "expected a match branch (`guard => pipeline`)";
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

/// A cold path that records `message`: the call sites of a recursive rule stay small (a debug
/// build gives every temporary of every call its own stack slot, and the recursion path is
/// what a 1 MB stack holds 1,000 levels of).
/// Consumes the closing token, or records `message`.
fn close(p: &mut Parser<'_>, k: K, message: &'static str) {
    if !p.eat(k.raw()) {
        err(p, message);
    }
}

#[cold]
#[inline(never)]
fn err(p: &mut Parser<'_>, message: &'static str) {
    p.error(message);
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
    pipeline_in(p, top, false);
}

/// [`pipeline`]; `subquery`: the body of `{ ... }`.
fn pipeline_in(p: &mut Parser<'_>, top: bool, subquery: bool) {
    let m = p.start();
    let mut steps = false;
    eat(p, K::PIPE);
    loop {
        if run(p, top, subquery) {
            steps = true;
        } else if !(top && steps && p.at_eof()) {
            err(p, EXPECTED_STEP);
        }
        if !eat(p, K::PIPE) {
            break;
        }
    }
    m.complete(p, K::PIPELINE.raw());
}

/// Steps with no pipe between them; whether there was one.
fn run(p: &mut Parser<'_>, top: bool, subquery: bool) -> bool {
    let end = if top { TokenSet::EMPTY } else { NESTED_END };
    let mut any = false;
    let mut prev = None;
    // `kind`, not `at`: an empty step expects a step, not the `|` it found.
    while !p.at_eof() && !end.contains(p.current()) && kind(p, 0) != K::PIPE {
        any = true;
        // A `,` starts no step: in a subquery (`join({ a | b, field=x)`) it is where the `}`
        // was due. The comma is skipped as any stray token is, so the subquery still ends at
        // the `}` the lexer's modes expect, and nothing after it is misread.
        if subquery && kind(p, 0) == K::COMMA {
            p.err_and_bump(MISSING_BRACE);
            prev = Some(Step::Filter);
            continue;
        }
        prev = Some(step(p, prev));
    }
    any
}

/// What a step is, decided without recursing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Assignment,
    Call,
    Stats,
    Saved,
    Negated,
    Case,
    Shorthand,
    Link,
    Match,
    Filter,
}

/// What the step at the current token is, after `prev` (none at the start of a run).
#[inline(never)]
fn classify(p: &Parser<'_>, prev: Option<Step>) -> Next {
    // After a filter only a plain word is an assignment's field, and only where the scanner
    // read it as one (a quoted or indexed name is more free text there).
    let after_filter = prev == Some(Step::Filter);
    if assign_at(p) && !(after_filter && kind(p, 0) != K::ASSIGN_FIELD_TOKEN) {
        return Next::Assignment;
    }
    match kind(p, 0) {
        K::FUNCTION_NAME_TOKEN => Next::Call,
        K::L_BRACK => Next::Stats,
        K::DOLLAR => Next::Saved,
        K::BANG | K::WORD if negation(p) && kind(p, 1) == K::FUNCTION_NAME_TOKEN => Next::Negated,
        K::WORD if word(p, 0, "case") => Next::Case,
        _ if field_at(p, 0) => match follow(p) {
            Follow::Shorthand => Next::Shorthand,
            Follow::Link => Next::Link,
            Follow::Match => Next::Match,
            Follow::Assign | Follow::Compare | Follow::Plain => Next::Filter,
        },
        _ => Next::Filter,
    }
}

/// One step, after `prev` (none at the start of a run).
fn step(p: &mut Parser<'_>, prev: Option<Step>) -> Step {
    match classify(p, prev) {
        Next::Assignment => {
            assignment(p);
            return Step::Assign;
        }
        Next::Call => {
            function_call(p);
        }
        Next::Stats => {
            array(p, K::STATS_SHORTHAND);
        }
        Next::Saved => saved_query(p),
        Next::Negated => negated_call(p),
        Next::Case => case_statement(p),
        Next::Shorthand => field_shorthand(p),
        Next::Link => link_constraint(p),
        Next::Match => match_statement(p),
        Next::Filter => return filter_step(p, prev == Some(Step::Assign)),
    }
    Step::Call
}

/// A filter as a step; at the end of a token nothing else can start, one token is an error.
fn filter_step(p: &mut Parser<'_>, pending_assign: bool) -> Step {
    if pending_assign {
        err(p, FILTER_AFTER_ASSIGNMENT);
    }
    if and_chain(p, true).is_none() {
        unexpected(p);
    }
    Step::Filter
}

#[cold]
#[inline(never)]
fn unexpected(p: &mut Parser<'_>) {
    p.err_and_bump(UNEXPECTED);
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
    Some(and_rest(p, first, steps))
}

#[inline(never)]
fn and_rest(p: &mut Parser<'_>, first: CompletedMarker, steps: bool) -> CompletedMarker {
    let m = first.precede(p);
    loop {
        if is_word(p, K::AND_KW) {
            wrap(p, K::AND, K::AND_KW);
        } else if !continues_chain(p, steps) {
            break;
        }
        if or_chain(p).is_none() {
            err(p, EXPECTED_FILTER);
            break;
        }
    }
    m.complete(p, K::AND_FILTER.raw())
}

fn is_word(p: &Parser<'_>, k: K) -> bool {
    reserved(p, 0) == Some(k)
}

fn or_chain(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let first = unary(p)?;
    if !is_word(p, K::OR_KW) {
        return Some(first);
    }
    Some(or_rest(p, first))
}

#[inline(never)]
fn or_rest(p: &mut Parser<'_>, first: CompletedMarker) -> CompletedMarker {
    let m = first.precede(p);
    while is_word(p, K::OR_KW) {
        wrap(p, K::OR, K::OR_KW);
        if unary(p).is_none() {
            err(p, EXPECTED_FILTER);
            break;
        }
    }
    m.complete(p, K::OR_FILTER.raw())
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
            err(p, EXPECTED_FILTER);
        }
        p.exit();
        return Some(m.complete(p, K::NOT_FILTER.raw()));
    }
    primary_filter(p)
}

fn primary_filter(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    if kind(p, 0) == K::L_PAREN {
        return paren_filter(p);
    }
    leaf_filter(p)
}

/// A filter with no nested rule inside.
#[inline(never)]
fn leaf_filter(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    match kind(p, 0) {
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
        err(p, EXPECTED_FILTER);
    }
    // A `,` in a group of filters is the fault, not a `)` missing before it: `rdns (a=1, b)`
    // (a space before the call's `(`) is a group, and `)` would be the wrong fix.
    if kind(p, 0) == K::COMMA {
        err(p, UNEXPECTED);
    } else {
        close(p, K::R_PAREN, MISSING_PAREN);
    }
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
    if expr(p, false).is_none() {
        err(p, EXPECTED_EXPR);
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
    if !p.enter() {
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
    p.exit();
    m.complete(p, K::CASE_STATEMENT.raw());
}

/// `field match { guard => pipeline; ... }`.
fn match_statement(p: &mut Parser<'_>) {
    if !p.enter() {
        return;
    }
    let m = p.start();
    field(p);
    p.bump_as(K::MATCH_KW.raw());
    if expect(p, K::L_BRACE, "expected `{` after `match`") {
        // `x match { }`: one error, not a guard, a `=>` and a body missing.
        if kind(p, 0) == K::R_BRACE {
            err(p, EXPECTED_BRANCH);
        } else {
            loop {
                match_branch(p);
                if !eat(p, K::SEMI) || at(p, K::R_BRACE) || p.at_eof() {
                    break;
                }
            }
        }
    }
    expect(p, K::R_BRACE, MISSING_BRACE);
    p.exit();
    m.complete(p, K::MATCH_STATEMENT.raw());
}

/// `guard => pipeline`. A missing guard is the branch's one error: where the branch ends there
/// (`x match { ; }`) nothing more is read, and otherwise what follows is read as its body, with
/// no second error for the `=>` (`x match { a => b ; => c }`: the `=>` after `;` lexes as `=`).
fn match_branch(p: &mut Parser<'_>) {
    let m = p.start();
    let guard = match_guard(p);
    let ends = |p: &Parser<'_>| p.at_eof() || NESTED_END.contains(p.current());
    if !guard && kind(p, 0) != K::FAT_ARROW && ends(p) {
        m.complete(p, K::MATCH_BRANCH.raw());
        return;
    }
    if !p.eat(K::FAT_ARROW.raw()) && guard {
        err(p, "expected `=>`");
        // `x match { a }`: no body either, and that is the same error.
        if ends(p) {
            m.complete(p, K::MATCH_BRANCH.raw());
            return;
        }
    }
    pipeline(p, false);
    m.complete(p, K::MATCH_BRANCH.raw());
}

/// The guard of a match branch: `*` and `**` (patterns), a string, a regex, a call, a parameter;
/// whether there was one.
#[inline(never)]
fn match_guard(p: &mut Parser<'_>) -> bool {
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
        K::WORD if reserved(p, 0).is_some() => {
            p.error(EXPECTED_VALUE);
            return false;
        }
        k if PATTERN_TOKENS.contains(k.raw()) => unquoted_pattern(p),
        _ => {
            p.error(EXPECTED_VALUE);
            return false;
        }
    }
    true
}

/// `$name(argument=value, ...)`.
fn saved_query(p: &mut Parser<'_>) {
    if !p.enter() {
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
    p.exit();
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
    if !p.enter() {
        return None;
    }
    let m = p.start();
    wrap(p, K::FUNCTION_NAME, K::FUNCTION_NAME_TOKEN);
    if p.eat(K::L_PAREN.raw()) {
        // `f( | ...`: a `|` starts no argument; it is the `)` that is missing.
        if !at(p, K::R_PAREN) && kind(p, 0) != K::PIPE {
            argument_list(p);
        }
        close(p, K::R_PAREN, MISSING_PAREN);
    } else {
        err(p, "expected `(` after the function name");
    }
    p.exit();
    Some(m.complete(p, K::FUNCTION_CALL.raw()))
}

/// `argument (, argument)*`; at most one unnamed argument is a semantic check.
fn argument_list(p: &mut Parser<'_>) {
    let m = p.start();
    loop {
        argument(p);
        if !p.eat(K::COMMA.raw()) {
            break;
        }
    }
    m.complete(p, K::ARGUMENT_LIST.raw());
}

fn argument(p: &mut Parser<'_>) {
    let m = p.start();
    let named = argument_name(p);
    if expr(p, true).is_none() {
        err(
            p,
            if named {
                EXPECTED_EXPR
            } else {
                EXPECTED_ARGUMENT
            },
        );
    }
    let node = if named {
        K::NAMED_ARGUMENT
    } else {
        K::ARGUMENT
    };
    m.complete(p, node.raw());
}

/// The `name =` of a named argument, if there is one.
#[inline(never)]
fn argument_name(p: &mut Parser<'_>) -> bool {
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
    named
}

fn attribute_at(p: &Parser<'_>) -> bool {
    plain_word(p, 0) && kind(p, 1) == K::COLON
}

/// The precedence level of a binary operator: 3 `* / %`, 2 `+ -`, 1 the comparisons, else 0.
fn level(k: K) -> u8 {
    match k {
        k if MULTIPLICATIVE.contains(k.raw()) => 3,
        k if ADDITIVE.contains(k.raw()) => 2,
        k if BINARY_COMPARE.contains(k.raw()) => 1,
        _ => 0,
    }
}

/// An expression: binary operators (`== != < <= > >= <=>`, then `+ -`, then `* / %`) over unary
/// operands, and with `attributes` the `name: value` attributes after it (correlate()). The
/// frame of this rule is on the recursion path of every bracket: it stays small, and the rest
/// is in rules that do not recurse through it.
fn expr(p: &mut Parser<'_>, attributes: bool) -> Option<CompletedMarker> {
    let first = primary_expr(p)?;
    if level(K::from_raw(p.current())) != 0 {
        let first = binary_rest(p, first);
        return Some(if attributes && attribute_at(p) {
            attribute_rest(p, first)
        } else {
            first
        });
    }
    if attributes && attribute_at(p) {
        return Some(attribute_rest(p, first));
    }
    Some(first)
}

/// The operators after `first`, as one flat node per run of one level, nested by precedence
/// (`a + b * c - d` is `a + (b * c) - d`). One frame whatever the operators: the open nodes
/// are on a heap stack, not in recursion.
#[inline(never)]
fn binary_rest(p: &mut Parser<'_>, first: CompletedMarker) -> CompletedMarker {
    let mut open: Vec<(u8, opentide_parse::Marker)> = Vec::new();
    let mut cur = first;
    loop {
        let lvl = level(K::from_raw(p.current()));
        // A looser operator ends the tighter runs before it.
        while open.last().is_some_and(|&(l, _)| l > lvl) {
            if let Some((_, m)) = open.pop() {
                cur = m.complete(p, K::BINARY_EXPRESSION.raw());
            }
        }
        if lvl == 0 {
            break;
        }
        if open.last().is_none_or(|&(l, _)| l != lvl) {
            open.push((lvl, cur.precede(p)));
        }
        p.bump();
        match primary_expr(p) {
            Some(operand) => cur = operand,
            None => {
                err(p, EXPECTED_EXPR);
                break;
            }
        }
    }
    while let Some((_, m)) = open.pop() {
        cur = m.complete(p, K::BINARY_EXPRESSION.raw());
    }
    cur
}

/// The `name: value` attributes after `first`.
#[inline(never)]
fn attribute_rest(p: &mut Parser<'_>, first: CompletedMarker) -> CompletedMarker {
    let m = first.precede(p);
    while attribute_at(p) {
        let attr = p.start();
        wrap(p, K::IDENTIFIER, K::WORD);
        p.bump();
        if expr(p, false).is_none() {
            err(p, EXPECTED_EXPR);
        }
        attr.complete(p, K::EXPRESSION_ATTRIBUTE.raw());
    }
    m.complete(p, K::ATTRIBUTED_EXPRESSION.raw())
}

/// A unary operator (`-`, `!`) and its operand, or a primary expression. The recursive arms
/// only: the frame of a rule on the recursion path stays small, which is what a 1 MB stack
/// holds 1,000 levels of.
fn primary_expr(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    match kind(p, 0) {
        K::L_PAREN => paren_expr(p),
        K::L_BRACE => subquery(p),
        K::FUNCTION_NAME_TOKEN => function_call(p),
        K::L_BRACK => array(p, K::ARRAY),
        K::MINUS | K::BANG => Some(unary_expr(p)),
        K::WORD if named_subquery_at(p) => named_subquery(p),
        _ => leaf_expr(p),
    }
}

#[inline(never)]
fn named_subquery_at(p: &Parser<'_>) -> bool {
    kind(p, 1) == K::COLON
        && kind(p, 2) == K::L_BRACE
        && reserved(p, 0).is_none()
        && !boolean_at(p, 0)
}

/// `-x` or `!x`: the operand is a primary expression.
#[inline(never)]
fn unary_expr(p: &mut Parser<'_>) -> CompletedMarker {
    let m = p.start();
    p.bump();
    // The operand is not itself unary (`- - x` is an error): one error, then the operators
    // and the operand are read into this node, so `x := !!a` is not a second error too.
    if matches!(kind(p, 0), K::MINUS | K::BANG) {
        err(p, EXPECTED_EXPR);
        while matches!(kind(p, 0), K::MINUS | K::BANG) {
            p.bump();
        }
        primary_expr(p);
    } else if primary_expr(p).is_none() {
        err(p, EXPECTED_EXPR);
    }
    m.complete(p, K::UNARY_EXPRESSION.raw())
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
    if !p.enter() {
        return None;
    }
    let m = p.start();
    p.bump();
    if expr(p, true).is_none() {
        err(p, EXPECTED_EXPR);
    }
    close(p, K::R_PAREN, MISSING_PAREN);
    p.exit();
    Some(m.complete(p, K::PARENTHESIZED_EXPRESSION.raw()))
}

/// `{ pipeline? }`.
fn subquery(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    if !p.enter() {
        return None;
    }
    let m = p.start();
    p.bump();
    if !at(p, K::R_BRACE) {
        pipeline_in(p, false, true);
    }
    close(p, K::R_BRACE, MISSING_BRACE);
    p.exit();
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
    if !p.enter() {
        return None;
    }
    let m = p.start();
    p.bump();
    if !at(p, K::R_BRACK) {
        loop {
            if field_at(p, 0) && kind(p, 1) == K::COLON_EQ {
                assignment(p);
            } else if expr(p, true).is_none() {
                err(p, EXPECTED_EXPR);
            }
            if !p.eat(K::COMMA.raw()) {
                break;
            }
        }
    }
    close(p, K::R_BRACK, MISSING_BRACK);
    p.exit();
    Some(m.complete(p, node.raw()))
}

/// A node that wraps the current token, as a completed marker.
fn node_of(p: &mut Parser<'_>, node: K, token: K) -> CompletedMarker {
    let m = p.start();
    p.bump_as(token.raw());
    m.complete(p, node.raw())
}
