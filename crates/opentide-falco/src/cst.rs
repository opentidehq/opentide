//! Falco's concrete syntax tree: a parser over [`opentide_parse`] that
//! follows `grammars/tree-sitter-opentide-falco/grammar.js` (libsinsp's
//! condition grammar), and what the editor reads from the tree: the highlight
//! captures and the field names.
//!
//! Diagnostics do not come from here: [`crate::parser`] is the port of
//! libsinsp's parser, and its verdicts decide what is an error. The tree is
//! for highlighting and fields, so it recovers rather than reports.
//!
//! `or` < `and` < `not`; a run of `and` (or `or`) is one flat node, so a
//! 20,000-term chain is not 20,000 levels deep.

use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken, lex};
use opentide_core::ByteSpan;
use opentide_parse::{Grammar, Input, Parse, Parser, TokenSet, build, debug_errors, debug_tree};
use rowan::{NodeOrToken, TextSize, WalkEvent};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

/// Nesting deeper than this is one error. libsinsp's own limit is 100 and
/// stays an analysis check ([`crate::parser`]); the floor every language keeps
/// is `deep_queries`' `NESTING_CEILING`. A level of parentheses is six frames of
/// this descent (`group`, `expression`, the `or` and `and` `chain`s, `unary`,
/// `check`) and a transformer one (`call`, `transformer_argument`).
pub(crate) const MAX_DEPTH: u32 = 512;

const UNEXPECTED: &str = "unexpected";

/// What ends a bare string: delimiters, `=`, quotes. A transformer's name
/// holds its `(`.
const VALUE_STOP: TokenSet = K::set(&[
    K::LParen,
    K::RParen,
    K::Comma,
    K::Eq,
    K::QuotedString,
    K::ErrorToken,
    K::TransformerName,
]);
/// What ends a field argument's value: brackets and quotes.
const ARGUMENT_STOP: TokenSet = K::set(&[K::LBracket, K::RBracket, K::QuotedString, K::ErrorToken]);
const OPERAND_START: TokenSet =
    K::set(&[K::LParen, K::FieldName, K::TransformerName, K::Identifier]);

/// The string operators (a modifier may follow them).
const COMPARISON_WORDS: [&str; 9] = [
    "contains",
    "icontains",
    "bcontains",
    "startswith",
    "bstartswith",
    "endswith",
    "glob",
    "iglob",
    "regex",
];
const LIST_WORDS: [&str; 3] = ["in", "intersects", "pmatch"];

/// A tree and its parse.
pub(crate) type Parsed = (SyntaxNode, Parse);

/// The parse of `source`, shared by the highlighting and the fields of one
/// text (one parse per text, epic #1219): the last parse on this thread is
/// kept.
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

fn word(p: &Parser<'_>, text: &str) -> bool {
    p.nth(0) == K::Identifier.raw() && p.nth_text(0) == text
}

fn at(p: &Parser<'_>, kind: K) -> bool {
    p.nth(0) == kind.raw()
}

/// Whether the current token is `kind` and starts at `end`: libsinsp reads
/// `[` and the operator's second `=` only when nothing comes between.
fn adjacent(p: &Parser<'_>, end: TextSize, kind: K) -> bool {
    at(p, kind) && p.current_range().is_some_and(|r| r.start() == end)
}

/// The end of the current token, which the caller is about to consume.
fn end_of_current(p: &Parser<'_>) -> TextSize {
    p.current_range()
        .map_or_else(|| TextSize::from(0), |r| r.end())
}

fn source_file(p: &mut Parser<'_>) {
    let m = p.start();
    if !p.at_eof() {
        if word(p, "and") || word(p, "or") {
            // A tuning's condition is a fragment that starts with `and` or `or`.
            let f = p.start();
            let kw = if word(p, "and") { K::AndKw } else { K::OrKw };
            p.bump_as(kw.raw());
            expression(p);
            f.complete(p, K::AppendFragment.raw());
        } else {
            expression(p);
        }
    }
    // What follows a complete condition cannot continue it: skip a token, and
    // read on.
    while !p.at_eof() {
        p.err_and_bump(UNEXPECTED);
        if p.at_set(OPERAND_START) {
            expression(p);
        }
    }
    m.complete(p, K::SourceFile.raw());
}

fn expression(p: &mut Parser<'_>) {
    chain(p, "or", K::OrKw, K::OrExpression, |p| {
        chain(p, "and", K::AndKw, K::AndExpression, unary);
    });
}

/// `operand (word operand)*` as one node of `node` when a `word` follows.
fn chain(p: &mut Parser<'_>, text: &str, kw: K, node: K, operand: fn(&mut Parser<'_>)) {
    let m = p.start();
    operand(p);
    if !word(p, text) {
        m.abandon(p);
        return;
    }
    while word(p, text) {
        p.bump_as(kw.raw());
        operand(p);
    }
    m.complete(p, node.raw());
}

/// `not` (any number) then a check, as one node.
fn unary(p: &mut Parser<'_>) {
    if !word(p, "not") {
        check(p);
        return;
    }
    let m = p.start();
    while word(p, "not") {
        p.bump_as(K::NotKw.raw());
    }
    check(p);
    m.complete(p, K::NotExpression.raw());
}

fn check(p: &mut Parser<'_>) {
    match p.nth(0) {
        k if k == K::LParen.raw() => group(p),
        k if k == K::FieldName.raw() || k == K::TransformerName.raw() => comparison(p),
        // A name alone is a macro (`and` and `or` too, where no operator can
        // follow a check).
        k if k == K::Identifier.raw() => {
            let m = p.start();
            p.bump();
            m.complete(p, K::MacroReference.raw());
        }
        _ => p.err_recover("expected a condition", K::set(&[K::RParen])),
    }
}

fn group(p: &mut Parser<'_>) {
    if !p.enter() {
        return;
    }
    let m = p.start();
    p.bump();
    expression(p);
    close(p, "missing `)`");
    m.complete(p, K::ParenthesizedExpression.raw());
    p.exit();
}

/// `)`; anything else before it is one error node.
fn close(p: &mut Parser<'_>, missing: &str) {
    if p.eat(K::RParen.raw()) {
        return;
    }
    if !p.at_eof() {
        p.err_until(UNEXPECTED, K::set(&[K::RParen]));
        if p.eat(K::RParen.raw()) {
            return;
        }
    }
    p.error(missing);
}

fn comparison(p: &mut Parser<'_>) {
    let m = p.start();
    operand(p);
    match operator(p) {
        Operator::Unary => {}
        Operator::Compare => value(p),
        Operator::List => list_value(p, true),
        Operator::Missing => p.error("expected an operator"),
    }
    m.complete(p, K::Comparison.raw());
}

fn operand(p: &mut Parser<'_>) {
    if at(p, K::FieldName) {
        field(p);
    } else if is_val(p) {
        p.err_and_bump(VAL_ONLY_RIGHT);
    } else {
        call(p);
    }
}

const VAL_ONLY_RIGHT: &str = "`val(` takes a field on the right of an operator only";

/// `val(`, which libsinsp reads on the right of an operator only.
fn is_val(p: &Parser<'_>) -> bool {
    at(p, K::TransformerName) && p.nth_text(0) == "val("
}

/// `name`, with its `[argument]` when the `[` follows at once.
fn field(p: &mut Parser<'_>) {
    let m = p.start();
    let end = end_of_current(p);
    p.bump();
    if adjacent(p, end, K::LBracket) {
        field_argument(p);
    }
    m.complete(p, K::Field.raw());
}

fn field_argument(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    if !p.eat(K::QuotedString.raw()) {
        let value = p.start();
        if glue(p, ARGUMENT_STOP) {
            value.complete(p, K::ArgumentValue.raw());
        } else {
            value.abandon(p);
            p.error("expected a field argument");
        }
    }
    p.expect(K::RBracket.raw(), "missing `]`");
    m.complete(p, K::FieldArgument.raw());
}

/// A run of tokens that touch, none of them in `stop`: what libsinsp reads as
/// one bare string. `false` when there is none.
fn glue(p: &mut Parser<'_>, stop: TokenSet) -> bool {
    let mut end = match p.current_range() {
        Some(r) if !stop.contains(p.nth(0)) => r.start(),
        _ => return false,
    };
    while let Some(r) = p.current_range() {
        if r.start() != end || stop.contains(p.nth(0)) {
            break;
        }
        end = r.end();
        p.bump();
    }
    true
}

enum Operator {
    Unary,
    Compare,
    List,
    Missing,
}

/// The operator after a field: `exists`, `=`, `==`, `!=`, `<`, `<=`, `>`,
/// `>=`, a string operator, or a list operator.
fn operator(p: &mut Parser<'_>) -> Operator {
    let kind = p.nth(0);
    if kind == K::Identifier.raw() {
        let (node, op) = match p.nth_text(0) {
            "exists" => (K::UnaryOperator, Operator::Unary),
            w if COMPARISON_WORDS.contains(&w) => (K::ComparisonOperator, Operator::Compare),
            w if LIST_WORDS.contains(&w) => (K::ListOperator, Operator::List),
            _ => return Operator::Missing,
        };
        let m = p.start();
        p.bump();
        m.complete(p, node.raw());
        return op;
    }
    // A symbol, with an `=` that touches it: `==`, `!=`, `<=`, `>=`.
    let text = p.nth_text(0);
    if kind != K::Eq.raw() && !(kind == K::Other.raw() && matches!(text, "<" | ">" | "!")) {
        return Operator::Missing;
    }
    let bang = text == "!";
    let m = p.start();
    let end = end_of_current(p);
    p.bump();
    let touching = adjacent(p, end, K::Eq);
    if touching {
        p.bump();
    }
    if bang && !touching {
        // A lone `!` is no operator.
        m.complete(p, K::Error.raw());
        p.error("expected `!=`");
        return Operator::Missing;
    }
    m.complete(p, K::ComparisonOperator.raw());
    Operator::Compare
}

/// A string operator's right side: a value, or a modifier and a list.
fn value(p: &mut Parser<'_>) {
    if at(p, K::TransformerName) {
        call(p);
    } else if !p.eat(K::QuotedString.raw()) {
        let m = p.start();
        if !glue(p, VALUE_STOP) {
            m.abandon(p);
            p.error("expected a value");
            return;
        }
        // libsinsp reads a modifier only when a list or a list name follows.
        let modifier =
            at(p, K::LParen) || (at(p, K::Identifier) && !word(p, "and") && !word(p, "or"));
        m.complete(
            p,
            if modifier {
                K::OperatorModifier
            } else {
                K::BareString
            }
            .raw(),
        );
        if modifier {
            list_value(p, false);
        }
    }
}

/// A list: `(a, b)`, or a list's name; after a list operator also a transformer.
fn list_value(p: &mut Parser<'_>, transformers: bool) {
    let kind = p.nth(0);
    if kind == K::LParen.raw() {
        value_list(p);
    } else if kind == K::Identifier.raw() {
        let m = p.start();
        p.bump();
        m.complete(p, K::ListReference.raw());
    } else if transformers && kind == K::TransformerName.raw() {
        call(p);
    } else {
        p.error("expected a list");
    }
}

fn value_list(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    if !at(p, K::RParen) {
        loop {
            list_item(p);
            if !p.eat(K::Comma.raw()) {
                break;
            }
        }
    }
    p.expect(K::RParen.raw(), "missing `)`");
    m.complete(p, K::ValueList.raw());
}

fn list_item(p: &mut Parser<'_>) {
    if p.eat(K::QuotedString.raw()) {
        return;
    }
    let m = p.start();
    if glue(p, VALUE_STOP) {
        m.complete(p, K::BareString.raw());
    } else {
        m.abandon(p);
        p.err_recover("expected a value", K::set(&[K::Comma, K::RParen]));
    }
}

/// A transformer: `name(` arguments `)`, with an optional `[argument]`.
/// `val(` takes one field and makes a value transformer.
fn call(p: &mut Parser<'_>) {
    if !at(p, K::TransformerName) {
        p.err_recover("expected a transformer", K::set(&[K::Comma, K::RParen]));
        return;
    }
    if !p.enter() {
        return;
    }
    let value = p.nth_text(0) == "val(";
    let m = p.start();
    p.bump();
    if value {
        if at(p, K::FieldName) {
            field(p);
        } else {
            p.error("expected a field");
        }
    } else {
        loop {
            transformer_argument(p);
            if !p.eat(K::Comma.raw()) {
                break;
            }
        }
    }
    let end = end_of_current(p);
    if p.expect(K::RParen.raw(), "missing `)`") && adjacent(p, end, K::LBracket) {
        field_argument(p);
    }
    m.complete(
        p,
        if value {
            K::ValueTransformer
        } else {
            K::FieldTransformer
        }
        .raw(),
    );
    p.exit();
}

fn transformer_argument(p: &mut Parser<'_>) {
    match p.nth(0) {
        k if k == K::FieldName.raw() => field(p),
        _ if is_val(p) => p.err_and_bump(VAL_ONLY_RIGHT),
        k if k == K::TransformerName.raw() => call(p),
        k if k == K::LParen.raw() => transformer_list(p),
        k if k == K::QuotedString.raw() || k == K::Number.raw() => p.bump(),
        _ => p.err_recover(
            "expected a transformer argument",
            K::set(&[K::Comma, K::RParen]),
        ),
    }
}

fn transformer_list(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump();
    if !at(p, K::RParen) {
        loop {
            match p.nth(0) {
                k if k == K::FieldName.raw() => field(p),
                _ if is_val(p) => p.err_and_bump(VAL_ONLY_RIGHT),
                k if k == K::TransformerName.raw() => call(p),
                k if k == K::QuotedString.raw() || k == K::Number.raw() => p.bump(),
                _ => p.err_recover("expected a list item", K::set(&[K::Comma, K::RParen])),
            }
            if !p.eat(K::Comma.raw()) {
                break;
            }
        }
    }
    p.expect(K::RParen.raw(), "missing `)`");
    m.complete(p, K::TransformerList.raw());
}

// ---------------------------------------------------------------------------
// What the editor reads from the tree.

fn span(range: rowan::TextRange) -> ByteSpan {
    ByteSpan::new(usize::from(range.start()), usize::from(range.end()))
}

/// A bare string's capture: `true` and `false`, a number, or a string.
fn bare_string_capture(text: &str) -> &'static str {
    if text == "true" || text == "false" {
        "boolean"
    } else if is_number(text.as_bytes()) {
        "number"
    } else {
        "string"
    }
}

/// Whether `text` is all of `[+-]?[0-9]+([.][0-9]*)?([eE][+-][0-9]+)?` or
/// `0[xX][0-9a-fA-F]+`: the grammar's `number`.
fn is_number(text: &[u8]) -> bool {
    if let [b'0', b'x' | b'X', hex @ ..] = text
        && !hex.is_empty()
        && hex.iter().all(u8::is_ascii_hexdigit)
    {
        return true;
    }
    let digits = |s: &[u8]| s.iter().take_while(|b| b.is_ascii_digit()).count();
    let mut rest = text
        .strip_prefix(b"+")
        .or_else(|| text.strip_prefix(b"-"))
        .unwrap_or(text);
    let n = digits(rest);
    if n == 0 {
        return false;
    }
    rest = &rest[n..];
    if let Some(fraction) = rest.strip_prefix(b".") {
        rest = &fraction[digits(fraction)..];
    }
    if let [b'e' | b'E', b'+' | b'-', exponent @ ..] = rest {
        let n = digits(exponent);
        if n == 0 {
            return false;
        }
        rest = &exponent[n..];
    }
    rest.is_empty()
}

/// The capture of a node that is one highlighted span: its tokens are not
/// captured on their own.
fn node_capture(node: &SyntaxNode) -> Option<&'static str> {
    Some(match node.kind() {
        K::ComparisonOperator => "operator",
        K::ListOperator | K::UnaryOperator | K::OperatorModifier => "keyword",
        K::ArgumentValue => "string",
        K::BareString => bare_string_capture(&node.text().to_string()),
        _ => return None,
    })
}

fn token_capture(token: &SyntaxToken) -> Option<&'static str> {
    let parent = token.parent().map(|p| p.kind());
    Some(match token.kind() {
        K::FieldName if parent == Some(K::Field) => "property",
        K::TransformerName => "function.builtin",
        K::Identifier => match parent {
            Some(K::MacroReference) => "macro",
            Some(K::ListReference) => "variable",
            _ => return None,
        },
        K::Number => "number",
        K::QuotedString => "string",
        K::AndKw | K::OrKw | K::NotKw => "keyword",
        K::LParen | K::RParen | K::LBracket | K::RBracket => "punctuation.bracket",
        K::Comma => "punctuation.delimiter",
        _ => return None,
    })
}

fn captures_of(root: &SyntaxNode) -> Vec<(ByteSpan, &'static str)> {
    let mut out = Vec::new();
    let mut walk = root.preorder_with_tokens();
    while let Some(event) = walk.next() {
        match event {
            WalkEvent::Enter(NodeOrToken::Node(node)) => {
                if let Some(capture) = node_capture(&node) {
                    out.push((span(node.text_range()), capture));
                    walk.skip_subtree();
                }
            }
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
/// the analysis (that is libsinsp's parser): whether the tree is clean.
#[must_use]
pub fn tree_has_error(source: &str) -> bool {
    !parse_memo(source).1.errors.is_empty()
}

/// Every field a condition mentions, in source order, once.
#[must_use]
pub fn tree_fields(source: &str) -> Vec<String> {
    field_names_of(&parse_memo(source).0)
}

fn field_names_of(root: &SyntaxNode) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for token in root
        .descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .filter(|t| t.kind() == K::FieldName && t.parent().is_some_and(|p| p.kind() == K::Field))
    {
        let name = token.text().to_string();
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }
    out
}

/// What hover reads at byte `offset` of `source`: the kind of the smallest
/// piece of the tree that holds the byte there (`field_name`, `identifier`,
/// `bare_string`, or `other`) and its text. A bare string, an operator, an
/// operator modifier and a field argument's value are one piece, as they were
/// one token of the tree-sitter grammar; whitespace, and the end of the text,
/// give the node around them.
#[must_use]
pub fn hover_target(source: &str, offset: usize) -> Option<(&'static str, String)> {
    let parsed = parse_memo(source);
    let root = &parsed.0;
    let Ok(at) = u32::try_from(offset) else {
        return None;
    };
    // Tree-sitter's root starts after the leading whitespace, and is what
    // holds the end of the text and whitespace outside every other node.
    let whole = || {
        let blank = [' ', '\t', '\r', '\n', '\x0c', '\x08'];
        Some(("other", source.trim_start_matches(blank).to_owned()))
    };
    if offset >= source.len() {
        return whole();
    }
    let token = root.token_at_offset(TextSize::from(at)).right_biased()?;
    let parent = token.parent()?;
    if token.kind() == K::Whitespace {
        if parent.parent().is_none() {
            return whole();
        }
        return Some(("other", parent.text().to_string()));
    }
    Some(match parent.kind() {
        K::BareString => ("bare_string", parent.text().to_string()),
        K::OperatorModifier
        | K::ArgumentValue
        | K::ComparisonOperator
        | K::UnaryOperator
        | K::ListOperator => ("other", parent.text().to_string()),
        _ => (
            match token.kind() {
                K::FieldName => "field_name",
                K::Identifier => "identifier",
                _ => "other",
            },
            token.text().to_owned(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::is_number;

    /// The grammar's `number`, byte for byte: what its regex accepts and what
    /// it does not.
    #[test]
    fn numbers_are_the_grammars() {
        for yes in [
            "0", "+1", "-12", "1.", "1.5", "-1.5e+3", "2E-1", "0x1F", "0XaB",
        ] {
            assert!(is_number(yes.as_bytes()), "{yes}");
        }
        for no in [
            "", "+", "-", ".5", "1e5", "1e+", "1.5.", "0x", "0xg", "1x", "1 ", "1e+3x", "x1",
        ] {
            assert!(!is_number(no.as_bytes()), "{no}");
        }
    }
}
