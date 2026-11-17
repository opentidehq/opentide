//! Highlighting from the rowan tree: each token's capture from its kind and the node it stands
//! in, by the patterns of the old `highlights.scm` in their order (the first that matches
//! wins), and the expression-depth pre-scan Elasticsearch runs over the same tokens.

use crate::lexical;
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use opentide_core::ByteSpan;
use rowan::NodeOrToken;

/// A node that stands for one token (`identifier`, `string`, `any`, ...): it is captured as a
/// whole, by its kind and its place in its parent. (`boolean` is not one: its `true` or `false`
/// is captured as a token.)
pub(crate) fn is_leaf(kind: K) -> bool {
    matches!(
        kind,
        K::ANY
            | K::MISSING_EVENT_OPEN
            | K::CASE_INSENSITIVE_NAME
            | K::OPTIONAL_MARKER
            | K::INDEX
            | K::IDENTIFIER
            | K::QUOTED_IDENTIFIER
            | K::NULL
            | K::NUMBER
            | K::STRING
    )
}

/// The name of a token outside a leaf node: its text for a keyword or punctuation, or what it
/// is when it stands in an error region (a name or a literal with no node of its own).
pub(crate) fn token_name(kind: K, text: &str) -> &'static str {
    match kind {
        K::IN_TILDE => "in~",
        K::LIKE_TILDE => "like~",
        K::REGEX_TILDE => "regex~",
        K::PIPE => "|",
        K::EQ => "=",
        K::EQ_EQ => "==",
        K::NOT_EQ => "!=",
        K::LT => "<",
        K::LT_EQ => "<=",
        K::GT => ">",
        K::GT_EQ => ">=",
        K::PLUS => "+",
        K::MINUS => "-",
        K::STAR => "*",
        K::SLASH => "/",
        K::PERCENT => "%",
        K::L_PAREN => "(",
        K::R_PAREN => ")",
        K::L_BRACK => "[",
        K::R_BRACK => "]",
        K::COMMA => ",",
        K::DOT => ".",
        K::COLON => ":",
        K::QUESTION => "?",
        K::BANG_L_BRACK => "![",
        // A keyword is lower case: its text is its name.
        _ if let Some(keyword) = crate::KEYWORD_WORDS.iter().find(|k| **k == text) => keyword,
        K::WORD => ERROR_WORD,
        K::TILDE_WORD => ERROR_TILDE_WORD,
        K::QUOTED_IDENT_TOKEN => ERROR_QUOTED,
        K::STRING_TOKEN => ERROR_STRING,
        K::NUMBER_TOKEN => ERROR_NUMBER,
        _ => "ERROR",
    }
}

/// Tokens in an error region, by what the lexer cut.
pub(crate) const ERROR_WORD: &str = "ERROR word";
pub(crate) const ERROR_TILDE_WORD: &str = "ERROR tilde_word";
pub(crate) const ERROR_QUOTED: &str = "ERROR quoted_identifier";
pub(crate) const ERROR_STRING: &str = "ERROR string";
pub(crate) const ERROR_NUMBER: &str = "ERROR number";

/// Each captured token of the tree, in document order, with its span and capture.
pub(crate) fn captures(root: &SyntaxNode) -> Vec<(ByteSpan, &'static str)> {
    let mut out = Vec::new();
    for token in visible_tokens(root) {
        let span = span_of(&token);
        let Some(parent) = token.parent() else {
            continue;
        };
        let capture = if matches!(token.kind(), K::LINE_COMMENT | K::BLOCK_COMMENT) {
            Some("comment")
        } else if is_leaf(parent.kind()) {
            leaf_capture(&parent)
        } else {
            token_capture(&token, parent.kind())
        };
        if let Some(capture) = capture {
            out.push((span, capture));
        }
    }
    out
}

/// The tokens a reader sees: everything but whitespace, with a length.
fn visible_tokens(root: &SyntaxNode) -> impl Iterator<Item = SyntaxToken> {
    root.descendants_with_tokens()
        .filter_map(NodeOrToken::into_token)
        .filter(|t| t.kind() != K::WHITESPACE && !t.text().is_empty())
}

fn span_of(token: &SyntaxToken) -> ByteSpan {
    let r = token.text_range();
    ByteSpan::new(usize::from(r.start()), usize::from(r.end()))
}

/// A token outside a leaf node: a keyword or punctuation by the keyword table, a boolean, or a
/// name or a literal in an error region as it would read in a query that parses.
fn token_capture(token: &SyntaxToken, parent: K) -> Option<&'static str> {
    match token_name(token.kind(), token.text()) {
        ERROR_WORD | ERROR_QUOTED => Some("variable"),
        ERROR_TILDE_WORD => Some("function"),
        ERROR_STRING => Some("string"),
        ERROR_NUMBER => Some("number"),
        _ if parent == K::BOOLEAN => Some("boolean"),
        name => opentide_highlight::keywords(opentide_core::LanguageId::Eql)?
            .iter()
            .find(|(token, _)| *token == name)
            .map(|(_, capture)| capture.name()),
    }
}

/// A leaf node, by its kind and its place in its parent.
fn leaf_capture(leaf: &SyntaxNode) -> Option<&'static str> {
    let kind = leaf.kind();
    let parent = leaf.parent().map(|p| p.kind());
    let first_named = leaf
        .parent()
        .and_then(|p| p.first_child())
        .is_some_and(|first| &first == leaf);
    // The grammar's fields that change a leaf's capture, by its place in its parent.
    let relation = parent == Some(K::RELATIONSHIP) && kind != K::SUBQUERY;
    let pipe_name = parent == Some(K::PIPE_STAGE) && first_named;
    let option_key = parent == Some(K::TERM_OPTION) && kind != K::NUMBER;
    let time_unit = parent == Some(K::TIME_UNIT) && kind != K::NUMBER;
    let call_name = parent == Some(K::FUNCTION_CALL) && first_named;
    Some(match kind {
        K::IDENTIFIER if relation => "error",
        K::IDENTIFIER if pipe_name || option_key => "keyword",
        K::IDENTIFIER if time_unit => "constant",
        K::IDENTIFIER | K::STRING if parent == Some(K::EVENT_CATEGORY) => "type",
        K::ANY => "type",
        K::IDENTIFIER | K::CASE_INSENSITIVE_NAME if call_name => "function",
        K::IDENTIFIER | K::QUOTED_IDENTIFIER if parent == Some(K::FIELD) => "property",
        K::INDEX | K::NUMBER => "number",
        K::OPTIONAL_MARKER | K::MISSING_EVENT_OPEN => "operator",
        K::IDENTIFIER | K::QUOTED_IDENTIFIER => "variable",
        K::STRING => "string",
        K::NULL => "constant",
        _ => return None,
    })
}

/// `EqlParser` scans the tokens before parsing: `(` and `)` move a depth counter, and a run of
/// prefix-capable `not`, `-`, `+` tokens adds to it; any other visible token ends the run.
/// Whitespace and comments do not. Returns the token where `depth + run` first exceeds the
/// limit.
pub(crate) fn expression_depth_exceeded(root: &SyntaxNode) -> Option<ByteSpan> {
    let mut depth: i64 = 0;
    let mut chain: i64 = 0;
    for token in visible_tokens(root) {
        // A leaf node is one token to the scan, whatever its kind.
        let in_leaf = token.parent().is_some_and(|p| is_leaf(p.kind()));
        match token.kind() {
            K::L_PAREN if !in_leaf => depth += 1,
            K::R_PAREN if !in_leaf => depth -= 1,
            K::NOT_KW | K::MINUS | K::PLUS if !in_leaf => chain += 1,
            K::LINE_COMMENT | K::BLOCK_COMMENT => {}
            _ => chain = 0,
        }
        if depth + chain > lexical::MAX_EXPRESSION_DEPTH {
            return Some(span_of(&token));
        }
    }
    None
}
