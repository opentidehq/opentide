//! The Exabeam Query Language's concrete syntax tree: a parser over
//! [`opentide_parse`] that accepts what `grammars/tree-sitter-opentide-exabeam`
//! accepts, and the highlight captures read from the tree.
//!
//! Diagnostics do not come from here: [`crate::check`] is the port of the
//! specification's reference checker, and its verdicts decide what is an
//! error. The tree is for highlighting, so it recovers rather than reports.
//!
//! The grammar lexes by what its state expects ([`crate::syntax`]): each rule
//! here names the tokens valid where it reads one ([`T`]), and [`next`] picks
//! among them as tree-sitter does: the longest match, then a literal over a
//! pattern, then the token the grammar defines first. A run of `AND` (or `OR`)
//! is one flat node, so a 20,000-term chain is not 20,000 levels deep.

use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken, lex};
use opentide_core::ByteSpan;
use opentide_parse::{Grammar, Input, Parse, Parser, build, debug_errors, debug_tree};
use regex::Regex;
use rowan::{NodeOrToken, TextSize, WalkEvent};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;

/// Nesting deeper than this is one error. The analysis' own limit is 200
/// levels ([`crate::check`]), and the floor this parser keeps is
/// `deep_queries`' `EXABEAM_NEST_FLOOR` (199), below `NESTING_CEILING`; 512
/// is Falco's limit too. A level of parentheses is five frames of this
/// descent (`group`, `expression`, `and_chain`, `unary`, `primary`): 512
/// levels take about 750 KB of a debug build's stack, under the 1 MB of the
/// browser module (`tests/long_runs.rs` highlights 500 levels there).
pub(crate) const MAX_DEPTH: u32 = 512;

/// A token of the grammar, as its parser states expect them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum T {
    /// A keyword, upper case; it matches in any case.
    Kw(&'static str),
    /// A literal: punctuation or an operator.
    Lit(&'static str),
    Str,
    Num,
    Ident,
    Bare,
    Text,
    Bound,
}

impl T {
    /// Tree-sitter's order among tokens of one length: a literal first, then
    /// the token defined first (the keywords, then `string` to `bound`).
    fn rank(self) -> u8 {
        match self {
            T::Lit(_) => 0,
            T::Kw(_) => 1,
            T::Str => 2,
            T::Num => 3,
            T::Ident => 4,
            T::Bare => 5,
            T::Text => 6,
            T::Bound => 7,
        }
    }
}

const NOT: T = T::Kw("NOT");
const AND: T = T::Kw("AND");
const OR: T = T::Kw("OR");
const IN: T = T::Kw("IN");
const TO: T = T::Kw("TO");
const AS: T = T::Kw("AS");
const LIMIT: T = T::Kw("LIMIT");
const FOREACH: T = T::Kw("FOREACH");
const DISTINCT: T = T::Kw("DISTINCT");
const ASC: T = T::Kw("ASC");
const DESC: T = T::Kw("DESC");
const LPAREN: T = T::Lit("(");
const RPAREN: T = T::Lit(")");
const LBRACKET: T = T::Lit("[");
const RBRACKET: T = T::Lit("]");
const LBRACE: T = T::Lit("{");
const RBRACE: T = T::Lit("}");
const COMMA: T = T::Lit(",");
const PIPE: T = T::Lit("|");
const DOT: T = T::Lit(".");
const STAR: T = T::Lit("*");

/// What starts a term.
const UNARY: [T; 5] = [NOT, LPAREN, T::Str, T::Ident, T::Text];
/// The clause keywords of a statement.
const CLAUSES: [T; 7] = [
    T::Kw("SELECT"),
    T::Kw("FROM"),
    T::Kw("WHERE"),
    AS,
    T::Kw("GROUP-BY"),
    T::Kw("ORDER-BY"),
    LIMIT,
];
/// What follows a statement.
const STATEMENT_END: [T; 2] = [PIPE, RBRACKET];
/// The operators of a field term.
const FIELD_OPERATORS: [T; 8] = [
    T::Lit(":"),
    T::Lit("="),
    T::Lit("=="),
    T::Lit("<"),
    T::Lit(">"),
    T::Lit("<="),
    T::Lit(">="),
    T::Lit("!="),
];
const COMPARISONS: [T; 4] = [T::Lit("<"), T::Lit(">"), T::Lit("<="), T::Lit(">=")];
const VALUE: [T; 7] = [T::Str, T::Num, T::Ident, T::Bare, LPAREN, LBRACKET, LBRACE];
const SCALAR: [T; 4] = [T::Str, T::Num, T::Ident, T::Bare];

/// The tokens valid after a term: another term, `AND`, `OR`, and what ends
/// the filter (`)` in a group; a clause or the statement's end elsewhere).
fn after_term(top: bool, more: &[T]) -> Valid {
    let v = Valid::default().with(&[AND, OR]).with(&UNARY);
    let v = if top {
        v.with(&CLAUSES).with(&STATEMENT_END)
    } else {
        v.with(&[RPAREN])
    };
    v.with(more)
}

fn after_clause(more: &[T]) -> Valid {
    Valid::default()
        .with(more)
        .with(&CLAUSES)
        .with(&STATEMENT_END)
}

/// The tokens a parser state expects, on the stack: the parser builds one
/// for each token it reads, where a `Vec` was an allocation each time
/// (ADR 0014). Its capacity holds the largest set the grammar builds (25).
#[derive(Clone, Copy)]
struct Valid {
    items: [T; 32],
    len: usize,
}

impl Default for Valid {
    fn default() -> Self {
        Self {
            items: [NOT; 32],
            len: 0,
        }
    }
}

impl Valid {
    fn with(mut self, more: &[T]) -> Self {
        for &t in more {
            let slot = self.items.get_mut(self.len);
            debug_assert!(slot.is_some(), "a token set past its capacity");
            if let Some(slot) = slot {
                *slot = t;
                self.len += 1;
            }
        }
        self
    }
}

impl std::ops::Deref for Valid {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.items.get(..self.len).unwrap_or_default()
    }
}

/// The length of the number `text` starts with: `[+-]?[0-9]+(\.[0-9]+)?`.
fn number_len(text: &[u8]) -> usize {
    let digits = |s: &[u8]| s.iter().take_while(|b| b.is_ascii_digit()).count();
    let sign = usize::from(matches!(text.first(), Some(b'+' | b'-')));
    let rest = text.get(sign..).unwrap_or_default();
    let whole = digits(rest);
    if whole == 0 {
        return 0;
    }
    let mut len = sign + whole;
    if text.get(len) == Some(&b'.') {
        let fraction = digits(text.get(len + 1..).unwrap_or_default());
        if fraction > 0 {
            len += 1 + fraction;
        }
    }
    len
}

fn ident_len(text: &[u8]) -> usize {
    let start = |b: &u8| b.is_ascii_alphabetic() || *b == b'_';
    let part = |s: &[u8]| {
        if !s.first().is_some_and(start) {
            return 0;
        }
        s.iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_' || **b == b'-')
            .count()
    };
    let mut len = part(text);
    if len == 0 {
        return 0;
    }
    while text.get(len) == Some(&b'.') {
        let more = part(text.get(len + 1..).unwrap_or_default());
        if more == 0 {
            break;
        }
        len += 1 + more;
    }
    len
}

/// The length of a run of characters none of which is in `stop` (or ASCII
/// whitespace).
fn run_len(text: &str, stop: &[u8]) -> usize {
    text.bytes()
        .take_while(|b| !b.is_ascii_whitespace() && *b != 0x0b && !stop.contains(b))
        .count()
}

/// How long a match of `t` at the start of `rest` is (`0`: none). `string`
/// is the current piece, closed or not.
fn match_len(t: T, rest: &str, string: Option<usize>) -> usize {
    let bytes = rest.as_bytes();
    match t {
        T::Kw(k) | T::Lit(k) => {
            let head = bytes.get(..k.len()).unwrap_or_default();
            if head.eq_ignore_ascii_case(k.as_bytes()) {
                k.len()
            } else {
                0
            }
        }
        T::Str => string.unwrap_or(0),
        T::Num => number_len(bytes),
        T::Ident => ident_len(bytes),
        T::Bare => run_len(rest, b"()[]{},\"'|=<>!"),
        T::Text => run_len(rest, b"()[]{},\"'|=<>!:"),
        T::Bound => run_len(rest, b"]}\"'"),
    }
}

/// The token tree-sitter reads at the current piece where `valid` are the
/// tokens its state expects, and where it ends.
fn next(p: &Parser<'_>, valid: &[T]) -> Option<(T, TextSize)> {
    let range = p.current_range()?;
    let rest = p.source().get(usize::from(range.start())..)?;
    let string = (p.nth(0) == K::String.raw()).then(|| usize::from(range.len()));
    let mut best: Option<(T, usize)> = None;
    for &t in valid {
        let len = match_len(t, rest, string);
        if len == 0 {
            continue;
        }
        if best.is_none_or(|(b, l)| len > l || (len == l && t.rank() < b.rank())) {
            best = Some((t, len));
        }
    }
    let (t, len) = best?;
    Some((t, range.start() + TextSize::try_from(len).ok()?))
}

/// Whether the token at the current piece, among `valid`, is `t`.
fn at(p: &Parser<'_>, valid: &[T], t: T) -> bool {
    next(p, valid).is_some_and(|(found, _)| found == t)
}

/// Consumes the token `t` that ends at `end`: its pieces, under one node
/// unless it is one piece of its own kind.
fn take(p: &mut Parser<'_>, t: T, end: TextSize) {
    let kind = match t {
        T::Kw(_) => Some(K::Keyword),
        T::Lit("==") => Some(K::EqEq),
        T::Lit("<=") => Some(K::LtEq),
        T::Lit(">=") => Some(K::GtEq),
        T::Lit("!=") => Some(K::NotEqual),
        T::Lit(_) | T::Str => None,
        T::Num => Some(K::Number),
        T::Ident => Some(K::Identifier),
        T::Bare => Some(K::BareWord),
        T::Text => Some(K::TextWord),
        T::Bound => Some(K::Bound),
    };
    let m = kind.map(|_| p.start());
    while p.current_range().is_some_and(|r| r.end() <= end) {
        p.bump();
    }
    if let (Some(m), Some(kind)) = (m, kind) {
        m.complete(p, kind.raw());
    }
}

/// Consumes the token among `valid` if it is `t`.
fn eat(p: &mut Parser<'_>, valid: &[T], t: T) -> bool {
    match next(p, valid) {
        Some((found, end)) if found == t => {
            take(p, t, end);
            true
        }
        _ => false,
    }
}

/// Consumes one of `wanted` (read among `wanted`), or records `message`.
fn expect(p: &mut Parser<'_>, wanted: &[T], message: &str) -> Option<T> {
    if let Some((t, end)) = next(p, wanted) {
        take(p, t, end);
        Some(t)
    } else {
        p.error(message);
        None
    }
}

/// An identifier wrapped in `kind`, or an error.
fn name(p: &mut Parser<'_>, kind: K, message: &str) {
    if let Some((T::Ident, end)) = next(p, &[T::Ident]) {
        let m = p.start();
        take(p, T::Ident, end);
        m.complete(p, kind.raw());
    } else {
        p.error(message);
    }
}

/// A tree and its parse.
pub(crate) type Parsed = (SyntaxNode, Parse);

/// The parse of `source`, shared by the queries on one text: the last parse
/// on this thread is kept.
pub(crate) fn parse_memo(source: &str) -> Rc<Parsed> {
    thread_local! {
        static LAST: RefCell<Option<(String, Rc<Parsed>)>> = const { RefCell::new(None) };
    }
    LAST.with(|last| {
        let mut last = last.borrow_mut();
        if let Some((text, parsed)) = last.as_ref()
            && text == source
        {
            return Rc::clone(parsed);
        }
        let parsed = Rc::new(parse(source));
        // A text past the cap is not kept: an idle thread would hold it and
        // its tree until its next query.
        *last = (source.len() <= MEMO_MAX).then(|| (source.to_owned(), Rc::clone(&parsed)));
        parsed
    })
}

/// The largest text [`parse_memo`] keeps, in bytes.
const MEMO_MAX: usize = 64 * 1024;

/// Parses `source`.
pub(crate) fn parse(source: &str) -> Parsed {
    let grammar = Grammar {
        eof: K::Eof.raw(),
        error: K::Error.raw(),
        trivia: K::set(&[K::Whitespace]),
        max_depth: MAX_DEPTH,
    };
    let input = Input::new(source, lex(source), grammar);
    let mut p = Parser::new(&input);
    source_file(&mut p);
    let parse = build(&input, p.finish());
    (SyntaxNode::new_root(parse.green.clone()), parse)
}

/// `source`'s tree and its errors as text, for snapshots.
#[must_use]
pub fn debug_parse(source: &str) -> String {
    let (root, parse) = parse(source);
    let mut out = debug_tree(&root, K::name);
    let errors = debug_errors(&parse.errors, |k| K::from_raw(k).name());
    if !errors.is_empty() {
        out.push_str("errors:\n");
        out.push_str(&errors);
    }
    out
}

// ---------------------------------------------------------------------------
// The grammar.

fn source_file(p: &mut Parser<'_>) {
    let m = p.start();
    if !p.at_eof() {
        statement_or_foreach(p);
    }
    while !p.at_eof() {
        if eat(p, &[PIPE], PIPE) {
            statement_or_foreach(p);
            continue;
        }
        // What cannot continue a statement: skip a piece, and read on.
        p.err_and_bump("unexpected");
        if next(p, &statement_start(true)).is_some() {
            statement_or_foreach(p);
        }
    }
    m.complete(p, K::SourceFile.raw());
}

fn statement_start(top: bool) -> Valid {
    let v = Valid::default().with(&UNARY).with(&CLAUSES);
    if top { v.with(&[FOREACH]) } else { v }
}

fn statement_or_foreach(p: &mut Parser<'_>) {
    match next(p, &statement_start(true)) {
        Some((FOREACH, _)) => foreach(p),
        Some(_) => statement(p),
        None => p.error("expected a statement"),
    }
}

fn foreach(p: &mut Parser<'_>) {
    let m = p.start();
    eat(p, &[FOREACH], FOREACH);
    name(p, K::FieldName, "expected a field");
    if expect(p, &[LBRACKET], "missing `[`").is_some() {
        let inner = statement_start(false).with(&[RBRACKET]);
        if next(p, &inner).is_some_and(|(t, _)| t != RBRACKET) {
            statement(p);
        }
        expect(p, &[RBRACKET], "missing `]`");
        if at(p, &[LIMIT, PIPE], LIMIT) {
            limit(p);
        }
    }
    m.complete(p, K::ForeachStatement.raw());
}

/// A filter then clauses, or clauses alone.
fn statement(p: &mut Parser<'_>) {
    let m = p.start();
    if next(p, &statement_start(false)).is_some_and(|(t, _)| UNARY.contains(&t)) {
        filter(p, true);
    }
    while let Some((t, _)) = next(p, &after_clause(&[])) {
        if !CLAUSES.contains(&t) {
            break;
        }
        clause(p, t);
    }
    m.complete(p, K::Statement.raw());
}

fn clause(p: &mut Parser<'_>, t: T) {
    let m = p.start();
    eat(p, &CLAUSES, t);
    let kind = match t {
        T::Kw("SELECT") => {
            eat(p, &[DISTINCT, STAR, T::Ident], DISTINCT);
            loop {
                column(p);
                if !eat(p, &after_clause(&[COMMA, AS]), COMMA) {
                    break;
                }
            }
            K::SelectClause
        }
        T::Kw("FROM") => {
            name(p, K::TableName, "expected a table");
            let v = Valid::default().with(&UNARY).with(&after_clause(&[]));
            if next(p, &v).is_some_and(|(t, _)| UNARY.contains(&t)) {
                filter(p, true);
            }
            K::FromClause
        }
        T::Kw("WHERE") => {
            filter(p, true);
            K::WhereClause
        }
        T::Kw("AS") => {
            name(p, K::TableName, "expected a table");
            K::AsClause
        }
        T::Kw("GROUP-BY") => {
            loop {
                name(p, K::FieldName, "expected a field");
                if !eat(p, &after_clause(&[COMMA]), COMMA) {
                    break;
                }
            }
            K::GroupByClause
        }
        T::Kw("ORDER-BY") => {
            loop {
                name(p, K::FieldName, "expected a field");
                if let Some((t @ (ASC | DESC), end)) = next(p, &after_clause(&[ASC, DESC, COMMA])) {
                    take(p, t, end);
                }
                if !eat(p, &after_clause(&[COMMA]), COMMA) {
                    break;
                }
            }
            K::OrderByClause
        }
        _ => {
            expect(p, &[T::Num], "expected a number");
            K::LimitClause
        }
    };
    m.complete(p, kind.raw());
}

fn limit(p: &mut Parser<'_>) {
    let m = p.start();
    eat(p, &[LIMIT], LIMIT);
    expect(p, &[T::Num], "expected a number");
    m.complete(p, K::LimitClause.raw());
}

/// `*`, a field or an aggregate, then `AS alias`.
fn column(p: &mut Parser<'_>) {
    let m = p.start();
    match next(p, &[STAR, T::Ident]) {
        Some((STAR, end)) => take(p, STAR, end),
        Some((T::Ident, end)) => {
            let inner = p.start();
            take(p, T::Ident, end);
            if at(p, &after_clause(&[LPAREN, COMMA, AS]), LPAREN) {
                arguments(p, &[STAR, T::Ident, T::Str, T::Bare], true);
                inner.complete(p, K::Aggregate.raw());
            } else {
                inner.complete(p, K::FieldName.raw());
            }
        }
        _ => p.error("expected a column"),
    }
    if eat(p, &after_clause(&[COMMA, AS]), AS) {
        name(p, K::Alias, "expected a name");
    }
    m.complete(p, K::Column.raw());
}

/// `(` arguments `)`: of a call (`fields` false) or an aggregate, whose
/// identifiers are fields.
fn arguments(p: &mut Parser<'_>, args: &[T], fields: bool) {
    eat(p, &[LPAREN], LPAREN);
    let mut first = args.to_vec();
    first.push(RPAREN);
    if eat(p, &first, RPAREN) {
        return;
    }
    loop {
        match next(p, args) {
            Some((T::Ident, end)) if fields => {
                let m = p.start();
                take(p, T::Ident, end);
                m.complete(p, K::FieldName.raw());
            }
            Some((t, end)) => take(p, t, end),
            None => {
                p.error("expected an argument");
                return;
            }
        }
        if !eat(p, &[COMMA, RPAREN], COMMA) {
            break;
        }
    }
    expect(p, &[RPAREN], "missing `)`");
}

fn filter(p: &mut Parser<'_>, top: bool) {
    let m = p.start();
    expression(p, top);
    m.complete(p, K::Filter.raw());
}

fn expression(p: &mut Parser<'_>, top: bool) {
    let m = p.start();
    and_chain(p, top);
    let mut chained = false;
    while eat(p, &after_term(top, &[]), OR) {
        and_chain(p, top);
        chained = true;
    }
    if chained {
        m.complete(p, K::OrExpression.raw());
    } else {
        m.abandon(p);
    }
}

/// Terms joined by `AND`, or side by side.
fn and_chain(p: &mut Parser<'_>, top: bool) {
    let m = p.start();
    unary(p, top);
    let mut chained = false;
    loop {
        match next(p, &after_term(top, &[])) {
            Some((AND, end)) => {
                take(p, AND, end);
                unary(p, top);
            }
            Some((t, _)) if UNARY.contains(&t) => unary(p, top),
            _ => break,
        }
        chained = true;
    }
    if chained {
        m.complete(p, K::AndExpression.raw());
    } else {
        m.abandon(p);
    }
}

/// `NOT` (any number) then a term, as one node.
fn unary(p: &mut Parser<'_>, top: bool) {
    if !at(p, &UNARY, NOT) {
        primary(p, top);
        return;
    }
    let m = p.start();
    while eat(p, &UNARY, NOT) {}
    primary(p, top);
    m.complete(p, K::NotExpression.raw());
}

fn primary(p: &mut Parser<'_>, top: bool) {
    match next(p, &UNARY) {
        Some((LPAREN, _)) => group(p),
        Some((t @ (T::Str | T::Text), end)) => {
            let m = p.start();
            take(p, t, end);
            m.complete(p, K::FreeText.raw());
        }
        Some((T::Ident, end)) => {
            let m = p.start();
            let field = p.start();
            take(p, T::Ident, end);
            let v = Valid::default().with(&FIELD_OPERATORS).with(&[IN]);
            match next(p, &after_term(top, &v)) {
                Some((op, end)) if FIELD_OPERATORS.contains(&op) => {
                    field.complete(p, K::FieldName.raw());
                    take(p, op, end);
                    field_value(p, op, top);
                    m.complete(p, K::FieldTerm.raw());
                }
                Some((IN, end)) => {
                    field.complete(p, K::FieldName.raw());
                    take(p, IN, end);
                    context_table(p, top);
                    m.complete(p, K::ContextTerm.raw());
                }
                Some((LPAREN, _)) => {
                    field.abandon(p);
                    arguments(p, &SCALAR, false);
                    m.complete(p, K::Call.raw());
                }
                _ => {
                    field.abandon(p);
                    m.complete(p, K::FreeText.raw());
                }
            }
        }
        _ => p.error("expected a term"),
    }
}

fn group(p: &mut Parser<'_>) {
    if !p.enter() {
        return;
    }
    let m = p.start();
    eat(p, &[LPAREN], LPAREN);
    expression(p, false);
    expect(p, &[RPAREN], "missing `)`");
    m.complete(p, K::Group.raw());
    p.exit();
}

/// What follows a field term's operator `op`.
fn field_value(p: &mut Parser<'_>, op: T, top: bool) {
    let comparison = |p: &mut Parser<'_>| {
        expect(p, &[T::Num, T::Str, T::Bare, T::Ident], "expected a value");
    };
    if COMPARISONS.contains(&op) {
        comparison(p);
        return;
    }
    let mut v = Valid::default().with(&VALUE);
    if matches!(op, T::Lit(":" | "=")) {
        v = v.with(&COMPARISONS);
    }
    match next(p, &v) {
        Some((cmp, end)) if COMPARISONS.contains(&cmp) => {
            take(p, cmp, end);
            comparison(p);
        }
        Some((LPAREN, _)) => list(p),
        Some((LBRACKET | LBRACE, _)) => range(p),
        Some((T::Ident, end)) => {
            let m = p.start();
            take(p, T::Ident, end);
            if at(p, &after_term(top, &[]), LPAREN) {
                arguments(p, &SCALAR, false);
                m.complete(p, K::Call.raw());
            } else {
                m.abandon(p);
            }
        }
        Some((t, end)) => take(p, t, end),
        None => p.error("expected a value"),
    }
}

fn list(p: &mut Parser<'_>) {
    let m = p.start();
    eat(p, &[LPAREN], LPAREN);
    loop {
        if expect(p, &SCALAR, "expected a value").is_none() {
            break;
        }
        if !eat(p, &[COMMA, RPAREN], COMMA) {
            expect(p, &[RPAREN], "missing `)`");
            break;
        }
    }
    m.complete(p, K::List.raw());
}

fn range(p: &mut Parser<'_>) {
    let m = p.start();
    let open = expect(p, &[LBRACKET, LBRACE], "expected a range");
    let low = expect(p, &[T::Str, T::Bound], "expected a bound");
    // `[10.0.0.0/8]`: a CIDR block.
    let block = open == Some(LBRACKET) && low == Some(T::Bound);
    let after_low: &[T] = if block { &[TO, RBRACKET] } else { &[TO] };
    if low.is_some() && !(block && eat(p, after_low, RBRACKET)) {
        if eat(p, after_low, TO) {
            if expect(p, &[T::Str, T::Bound], "expected a bound").is_some() {
                expect(p, &[RBRACKET, RBRACE], "missing `]`");
            }
        } else {
            p.error("expected `TO`");
        }
    }
    m.complete(p, K::Range.raw());
}

/// `"Table"` then `."Column"`, after `IN`.
fn context_table(p: &mut Parser<'_>, top: bool) {
    let table = |p: &mut Parser<'_>| {
        if let Some((T::Str, end)) = next(p, &[T::Str]) {
            let m = p.start();
            take(p, T::Str, end);
            m.complete(p, K::ContextTable.raw());
            true
        } else {
            p.error("expected a context table");
            false
        }
    };
    if table(p) && eat(p, &after_term(top, &[DOT]), DOT) {
        table(p);
    }
}

// ---------------------------------------------------------------------------
// What the editor reads from the tree.

fn span(range: rowan::TextRange) -> ByteSpan {
    ByteSpan::new(usize::from(range.start()), usize::from(range.end()))
}

/// An IPv4 or IPv6 address, as `highlights.scm` matches one.
fn is_address(text: &str) -> bool {
    static ADDRESS: OnceLock<Regex> = OnceLock::new();
    #[expect(
        clippy::expect_used,
        reason = "a regex literal: an invalid pattern fails every test that reaches it"
    )]
    let address = ADDRESS.get_or_init(|| {
        Regex::new(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}|([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]*(%[^%]+)?)$")
            .expect("regex")
    });
    address.is_match(text)
}

/// A value that is a name: `true`, `false`, `null`, or a string.
fn name_value(text: &str) -> &'static str {
    if text.eq_ignore_ascii_case("true") || text.eq_ignore_ascii_case("false") {
        "boolean"
    } else if text.eq_ignore_ascii_case("null") {
        "constant"
    } else {
        "string"
    }
}

/// A bare value: `@field`, an address, or a string.
fn bare_value(text: &str) -> &'static str {
    if text.starts_with('@') {
        "variable"
    } else if is_address(text) {
        "constant"
    } else {
        "string"
    }
}

fn is_one_of(text: &str, names: &[&str]) -> bool {
    names.iter().any(|n| text.eq_ignore_ascii_case(n))
}

/// What to do with a node: one capture for all of it, none for any of it,
/// or look inside.
enum Read {
    Capture(&'static str),
    Skip,
    Inside,
}

fn node_read(node: &SyntaxNode) -> Read {
    let parent = node.parent().map(|p| p.kind());
    let text = || node.text().to_string();
    Read::Capture(match node.kind() {
        K::Keyword => "keyword",
        K::EqEq | K::LtEq | K::GtEq => "operator",
        K::NotEqual => "error",
        K::FieldName => "property",
        K::TableName | K::ContextTable => "type",
        K::Alias => "variable",
        // `highlights.scm` marks a free-text `*` as an error, but the
        // free text's own capture, on the same span, comes first.
        K::FreeText => "string",
        K::Identifier => match parent {
            Some(K::Call) if node.prev_sibling().is_none() => {
                if is_one_of(&text(), &["rgx", "rgxi", "wld", "wldi"]) {
                    "function.builtin"
                } else {
                    "error"
                }
            }
            Some(K::Aggregate) => {
                if is_one_of(
                    &text(),
                    &["count", "min", "max", "sum", "avg", "rgx_extract"],
                ) {
                    "function.builtin"
                } else {
                    "error"
                }
            }
            Some(K::Call) => "error",
            Some(K::FieldTerm | K::List) => name_value(&text()),
            _ => return Read::Skip,
        },
        K::Number => {
            if parent == Some(K::Call) {
                "error"
            } else {
                "number"
            }
        }
        K::BareWord => match parent {
            Some(K::FieldTerm | K::List) => bare_value(&text()),
            Some(K::Call) => "error",
            _ => return Read::Skip,
        },
        K::Bound => {
            let t = text();
            if number_len(t.as_bytes()) == t.len() {
                "number"
            } else {
                "constant"
            }
        }
        K::TextWord => return Read::Skip,
        _ => return Read::Inside,
    })
}

fn token_capture(token: &SyntaxToken) -> Option<&'static str> {
    Some(match token.kind() {
        K::String => "string",
        K::Colon | K::Eq | K::Lt | K::Gt | K::Star => "operator",
        K::Pipe => "operator.pipe",
        K::LParen | K::RParen | K::LBracket | K::RBracket | K::LBrace | K::RBrace => {
            "punctuation.bracket"
        }
        K::Comma | K::Dot => "punctuation.delimiter",
        _ => return None,
    })
}

fn captures_of(root: &SyntaxNode) -> Vec<(ByteSpan, &'static str)> {
    let mut out = Vec::new();
    let mut walk = root.preorder_with_tokens();
    while let Some(event) = walk.next() {
        match event {
            WalkEvent::Enter(NodeOrToken::Node(node)) => match node_read(&node) {
                Read::Capture(capture) => {
                    out.push((span(node.text_range()), capture));
                    walk.skip_subtree();
                }
                Read::Skip => walk.skip_subtree(),
                Read::Inside => {}
            },
            WalkEvent::Enter(NodeOrToken::Token(token)) => {
                if let Some(capture) = token_capture(&token) {
                    out.push((span(token.text_range()), capture));
                }
            }
            WalkEvent::Leave(_) => {}
        }
    }
    out
}

/// The highlight spans of `source`'s tree, in source order and not
/// overlapping: `(span, HighlightSpec capture)`.
#[must_use]
pub fn highlight_captures(source: &str) -> Vec<(ByteSpan, &'static str)> {
    captures_of(&parse_memo(source).0)
}

/// Whether the parser found a syntax error in `source`. Not the verdict of
/// the analysis (that is [`check`](mod@crate::check)): whether the tree is clean.
#[must_use]
pub fn tree_has_error(source: &str) -> bool {
    !parse_memo(source).1.errors.is_empty()
}
