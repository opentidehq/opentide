//! The Exabeam Query Language's concrete syntax tree: a parser over
//! [`opentide_parse`] that accepts what `grammars/tree-sitter-opentide-exabeam`
//! accepts.
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

use crate::syntax::{SyntaxKind as K, SyntaxNode, lex};
use opentide_parse::{Grammar, Input, Parse, Parser, build, debug_errors, debug_tree};
use rowan::TextSize;

/// Nesting deeper than this is one error. The analysis' own limit is 200
/// levels ([`crate::check`]); the floor every language keeps is
/// `deep_queries`' `NESTING_CEILING`. A level of parentheses is five frames of
/// this descent (`group`, `expression`, `and_chain`, `unary`, `primary`).
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
fn after_term(top: bool, more: &[T]) -> Vec<T> {
    let mut v = vec![AND, OR];
    v.extend(UNARY);
    if top {
        v.extend(CLAUSES);
        v.extend(STATEMENT_END);
    } else {
        v.push(RPAREN);
    }
    v.extend_from_slice(more);
    v
}

fn after_clause(more: &[T]) -> Vec<T> {
    let mut v = more.to_vec();
    v.extend(CLAUSES);
    v.extend(STATEMENT_END);
    v
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

fn statement_start(top: bool) -> Vec<T> {
    let mut v = UNARY.to_vec();
    v.extend(CLAUSES);
    if top {
        v.push(FOREACH);
    }
    v
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
        let mut inner = statement_start(false);
        inner.push(RBRACKET);
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
            let mut v = UNARY.to_vec();
            v.extend(after_clause(&[]));
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
            let mut v = FIELD_OPERATORS.to_vec();
            v.push(IN);
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
    let mut v = VALUE.to_vec();
    if matches!(op, T::Lit(":" | "=")) {
        v.extend(COMPARISONS);
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
