//! What the editor reads from `yara-x-parser`'s CST: highlighting, folding
//! and parenthesis pairs (#1225).
//!
//! The CST is lossless (whitespace and comments are tokens) and recovers from
//! errors, so every function here accepts any text. Verdicts do not come from
//! here: they are the AST's (`lib.rs`).
//!
//! An editor asks for highlighting, folding and diagnostics (which read the
//! parenthesis pairs) of one buffer in a row, so the last parse is kept per
//! thread ([`parsed`]): the same text is parsed once.

use std::cell::RefCell;
use std::rc::Rc;

use opentide_core::ByteSpan;
use opentide_highlight::Capture;
use yara_x_parser::cst::{CST, Immutable, Node, NodeOrToken, SyntaxKind, Token};

/// The last text parsed on this thread and its tree.
struct Memo {
    source: Box<str>,
    cst: Rc<CST>,
}

thread_local! {
    static LAST: RefCell<Option<Memo>> = const { RefCell::new(None) };
    #[cfg(test)]
    static PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The CST of `source`: the last one parsed on this thread when the text is
/// the same, else a new parse, which replaces it. One tree is kept, so the
/// memo holds at most the size of the last buffer.
fn parsed(source: &str) -> Rc<CST> {
    if let Some(cst) = LAST.with_borrow(|last| {
        last.as_ref()
            .filter(|m| &*m.source == source)
            .map(|m| Rc::clone(&m.cst))
    }) {
        return cst;
    }
    #[cfg(test)]
    PARSES.set(PARSES.get() + 1);
    let cst = Rc::new(CST::from(source));
    LAST.set(Some(Memo {
        source: source.into(),
        cst: Rc::clone(&cst),
    }));
    cst
}

type Tok = Token<Immutable>;
type Elem = NodeOrToken<Immutable>;

const KEYWORD: Capture = Capture::new("keyword");
const OPERATOR: Capture = Capture::new("operator");
const NUMBER: Capture = Capture::new("number");
const STRING: Capture = Capture::new("string");
const VARIABLE: Capture = Capture::new("variable");
const TYPE: Capture = Capture::new("type");
const CONSTANT: Capture = Capture::new("constant");
const PROPERTY: Capture = Capture::new("property");
const FUNCTION: Capture = Capture::new("function");
const BUILTIN: Capture = Capture::new("function.builtin");
const BRACKET: Capture = Capture::new("punctuation.bracket");
const DELIMITER: Capture = Capture::new("punctuation.delimiter");

/// The capture of a token whose kind alone decides it. `IDENT` is none: the
/// tree around it decides ([`ident_capture`]). A trivia kind is none.
const fn capture(kind: SyntaxKind) -> Option<Capture> {
    use SyntaxKind as K;
    Some(match kind {
        K::ALL_KW
        | K::AND_KW
        | K::ANY_KW
        | K::ASCII_KW
        | K::AT_KW
        | K::BASE64_KW
        | K::BASE64WIDE_KW
        | K::CONDITION_KW
        | K::CONTAINS_KW
        | K::DEFINED_KW
        | K::ENDSWITH_KW
        | K::FOR_KW
        | K::FULLWORD_KW
        | K::GLOBAL_KW
        | K::ICONTAINS_KW
        | K::IENDSWITH_KW
        | K::IEQUALS_KW
        | K::IMPORT_KW
        | K::IN_KW
        | K::INCLUDE_KW
        | K::ISTARTSWITH_KW
        | K::MATCHES_KW
        | K::META_KW
        | K::NOCASE_KW
        | K::NONE_KW
        | K::NOT_KW
        | K::OF_KW
        | K::OR_KW
        | K::PRIVATE_KW
        | K::RULE_KW
        | K::STARTSWITH_KW
        | K::STRINGS_KW
        | K::THEM_KW
        | K::WIDE_KW
        | K::XOR_KW
        | K::WITH_KW => KEYWORD,
        K::TRUE_KW | K::FALSE_KW => Capture::new("boolean"),
        K::FILESIZE_KW | K::ENTRYPOINT_KW => CONSTANT,
        K::ADD
        | K::SUB
        | K::MUL
        | K::DIV
        | K::MOD
        | K::MINUS
        | K::SHL
        | K::SHR
        | K::BITWISE_AND
        | K::BITWISE_OR
        | K::BITWISE_XOR
        | K::BITWISE_NOT
        | K::EQ
        | K::NE
        | K::LT
        | K::LE
        | K::GT
        | K::GE
        | K::AMPERSAND
        | K::ASTERISK
        | K::CARET
        | K::BACKSLASH
        | K::EQUAL
        | K::HYPHEN
        | K::PERCENT
        | K::PIPE
        | K::PLUS
        | K::TILDE => OPERATOR,
        K::COMMA | K::COLON | K::DOT => DELIMITER,
        K::L_BRACE | K::R_BRACE | K::L_BRACKET | K::R_BRACKET | K::L_PAREN | K::R_PAREN => BRACKET,
        K::INTEGER_LIT | K::FLOAT_LIT | K::HEX_BYTE => NUMBER,
        K::STRING_LIT | K::REGEXP => STRING,
        K::PATTERN_IDENT | K::PATTERN_COUNT | K::PATTERN_OFFSET | K::PATTERN_LENGTH => VARIABLE,
        K::COMMENT => Capture::new("comment"),
        _ => return None,
    })
}

/// Every token of the tree, in source order, trivia included.
fn leaves(cst: &CST) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut stack = vec![cst.root().children_with_tokens()];
    while let Some(top) = stack.last_mut() {
        match top.next() {
            Some(Elem::Token(t)) => out.push(t),
            Some(Elem::Node(n)) => stack.push(n.children_with_tokens()),
            None => {
                stack.pop();
            }
        }
    }
    out
}

/// The end of the last token of `source` that is not a blank or a comment:
/// where a signature that stops too early stops.
pub(crate) fn significant_end(source: &str) -> usize {
    leaves(&parsed(source))
        .iter()
        .rev()
        .find(|t| !is_trivia(t.kind()))
        .map_or(0, |t| t.span().end())
}

fn is_trivia(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::WHITESPACE | SyntaxKind::NEWLINE | SyntaxKind::COMMENT
    )
}

/// The sibling after `elem`, past trivia.
fn next_significant(elem: &Elem) -> Option<Elem> {
    let mut next = elem.next_sibling_or_token();
    while let Some(e) = next {
        if !is_trivia(e.kind()) {
            return Some(e);
        }
        next = e.next_sibling_or_token();
    }
    None
}

/// The sibling before `elem`, past trivia.
fn prev_significant(elem: &Elem) -> Option<Elem> {
    let mut prev = elem.prev_sibling_or_token();
    while let Some(e) = prev {
        if !is_trivia(e.kind()) {
            return Some(e);
        }
        prev = e.prev_sibling_or_token();
    }
    None
}

/// libyara's integer readers (`uint16`, `int32be`), the only plain calls the
/// highlighter colours as built-ins.
fn is_reader(name: &str) -> bool {
    let name = name.strip_suffix("be").unwrap_or(name);
    let digits = name
        .strip_prefix("uint")
        .or_else(|| name.strip_prefix("int"));
    matches!(digits, Some("8" | "16" | "32"))
}

/// The capture of an identifier, by the node it is in and its place in a
/// `module.member` chain.
fn ident_capture(token: &Tok) -> Capture {
    use SyntaxKind as K;
    let Some(parent) = token.parent() else {
        return VARIABLE;
    };
    match parent.kind() {
        K::RULE_DECL => TYPE,
        K::RULE_TAGS => CONSTANT,
        K::META_DEF => PROPERTY,
        K::FUNC_CALL => {
            let member = parent
                .parent()
                .and_then(|p| prev_significant(&Elem::Node(p)))
                .is_some_and(|e| e.kind() == K::DOT);
            if !member && is_reader(token.text()) {
                BUILTIN
            } else {
                FUNCTION
            }
        }
        K::PRIMARY_EXPR => {
            let this = Elem::Node(parent.clone());
            if prev_significant(&this).is_some_and(|e| e.kind() == K::DOT) {
                return PROPERTY;
            }
            // `pe` in `pe.number_of_sections`, not `a` in `a[0].b`.
            let alone = parent.span() == token.span();
            if alone && next_significant(&this).is_some_and(|e| e.kind() == K::DOT) {
                return TYPE;
            }
            if alone && names_a_rule(&parent) {
                return TYPE;
            }
            VARIABLE
        }
        _ => VARIABLE,
    }
}

/// Whether `node` (an expression that is one bare name) is an item of an
/// `of (rule_a, rule_b)` set.
fn names_a_rule(node: &Node<Immutable>) -> bool {
    let span = node.span();
    let mut up = node.parent();
    while let Some(n) = up {
        if n.span() != span {
            return n.kind() == SyntaxKind::BOOLEAN_EXPR_TUPLE
                && n.parent().is_some_and(|p| p.kind() == SyntaxKind::OF_EXPR);
        }
        up = n.parent();
    }
    false
}

fn adjacent(a: &Tok, b: &Tok) -> bool {
    a.span().end() == b.span().start()
}

/// The highlight spans of `source`, sorted and not overlapping: the token
/// spans with their capture names.
pub(crate) fn highlight_spans(source: &str) -> Vec<(ByteSpan, &'static str)> {
    let cst = parsed(source);
    let leaves = leaves(&cst);
    let mut out = Vec::new();
    let mut i = 0;
    while i < leaves.len() {
        let t = &leaves[i];
        let (start, end) = (t.span().start(), t.span().end());
        let next = leaves.get(i + 1);
        let mut take = 1;
        match t.kind() {
            // `..`: the tree has two dots.
            SyntaxKind::DOT
                if next.is_some_and(|n| n.kind() == SyntaxKind::DOT && adjacent(t, n)) =>
            {
                take = 2;
                out.push((ByteSpan::new(start, end + 1), OPERATOR.name()));
            }
            // `$a*`: one variable, as it is one string set item.
            SyntaxKind::PATTERN_IDENT
                if next.is_some_and(|n| n.kind() == SyntaxKind::ASTERISK && adjacent(t, n)) =>
            {
                take = 2;
                out.push((ByteSpan::new(start, end + 1), VARIABLE.name()));
            }
            // `~00`: the operator, then the byte.
            SyntaxKind::HEX_BYTE if t.text().starts_with('~') => {
                out.push((ByteSpan::new(start, start + 1), OPERATOR.name()));
                if end > start + 1 {
                    out.push((ByteSpan::new(start + 1, end), NUMBER.name()));
                }
            }
            SyntaxKind::IDENT => out.push((ByteSpan::new(start, end), ident_capture(t).name())),
            kind => {
                if let Some(c) = capture(kind).filter(|_| end > start) {
                    out.push((ByteSpan::new(start, end), c.name()));
                }
            }
        }
        i += take;
    }
    out
}

/// Every `(`..`)` pair of the CST, as the byte offsets of the two
/// parentheses. They are its tokens, so a parenthesis inside a string, a
/// regexp or a comment is none; pairs are matched in order.
pub(crate) fn paren_pairs(source: &str) -> Vec<(usize, usize)> {
    let cst = parsed(source);
    let mut pairs = Vec::new();
    let mut open = Vec::new();
    for t in leaves(&cst) {
        match t.kind() {
            SyntaxKind::L_PAREN => open.push(t.span().start()),
            SyntaxKind::R_PAREN => {
                if let Some(o) = open.pop() {
                    pairs.push((o, t.span().start()));
                }
            }
            _ => {}
        }
    }
    pairs
}

/// Fold ranges as byte spans: each rule, each section, and each multi-line
/// hex string or comment.
pub(crate) fn folding(source: &str) -> Vec<(usize, usize)> {
    let cst = parsed(source);
    let mut out = Vec::new();
    let mut stack = vec![cst.root().children_with_tokens()];
    while let Some(top) = stack.last_mut() {
        match top.next() {
            Some(Elem::Token(t)) => {
                if t.kind() == SyntaxKind::COMMENT && t.text().contains('\n') {
                    out.push((t.span().start(), t.span().end()));
                }
            }
            Some(Elem::Node(n)) => {
                if matches!(
                    n.kind(),
                    SyntaxKind::RULE_DECL
                        | SyntaxKind::META_BLK
                        | SyntaxKind::PATTERNS_BLK
                        | SyntaxKind::CONDITION_BLK
                        | SyntaxKind::HEX_PATTERN
                ) && source
                    .get(n.span().range())
                    .is_some_and(|text| text.contains('\n'))
                {
                    out.push((n.span().start(), n.span().end()));
                }
                stack.push(n.children_with_tokens());
            }
            None => {
                stack.pop();
            }
        }
    }
    out.sort_unstable();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentide_core::LanguageId;

    fn spans(source: &str) -> Vec<(usize, usize, &'static str)> {
        highlight_spans(source)
            .into_iter()
            .map(|(s, c)| (s.start, s.end, c))
            .collect()
    }

    /// The `KEYWORDS` table feeds the generated TextMate grammar and
    /// `capture` colours the editor's tokens: they must say the same.
    #[test]
    fn the_keywords_table_is_what_the_cst_colours() {
        let table = opentide_highlight::keywords(LanguageId::Yara).expect("a YARA table");
        assert!(table.len() > 40, "{} entries", table.len());
        for (token, expected) in table {
            if *token == ".." {
                assert_eq!(spans("(1..2)")[2], (2, 4, "operator"));
                continue;
            }
            let cst = CST::from(*token);
            let first = leaves(&cst)
                .into_iter()
                .next()
                .unwrap_or_else(|| panic!("`{token}` has no token"));
            assert_eq!(first.text(), *token, "`{token}` is one token");
            assert_eq!(
                capture(first.kind()),
                Some(*expected),
                "`{token}` ({:?})",
                first.kind()
            );
        }
    }

    #[test]
    fn a_hex_not_is_an_operator_then_a_byte() {
        assert_eq!(
            spans("{ ~00 }"),
            [
                (0, 1, "punctuation.bracket"),
                (2, 3, "operator"),
                (3, 5, "number"),
                (6, 7, "punctuation.bracket")
            ]
        );
    }

    #[test]
    fn a_string_set_wildcard_is_one_variable() {
        let all = spans("1 of ($a*)");
        assert!(all.contains(&(6, 9, "variable")), "{all:?}");
    }

    #[test]
    fn identifiers_are_coloured_by_their_place() {
        let source = "rule r : t { condition: pe.is_dll() and uint8(0) == 1 and r1 and pe.sections[0].name }";
        let at = |word: &str, nth: usize| {
            let start = source
                .match_indices(word)
                .nth(nth)
                .map(|(i, _)| i)
                .expect("word");
            spans(source)
                .into_iter()
                .find(|s| s.0 == start)
                .map(|s| s.2)
        };
        assert_eq!(at("r :", 0), Some("type"));
        assert_eq!(at("t {", 0), Some("constant"));
        assert_eq!(at("pe.is", 0), Some("type"));
        assert_eq!(at("is_dll", 0), Some("function"));
        assert_eq!(at("uint8", 0), Some("function.builtin"));
        assert_eq!(at("r1", 0), Some("variable"));
        assert_eq!(at("sections", 0), Some("property"));
        assert_eq!(at("name", 0), Some("property"));
    }

    /// Highlighting, parenthesis pairs and folding of one text share a
    /// parse; another text parses again, and replaces the memo.
    #[test]
    fn one_text_is_parsed_once() {
        let a = "rule a {\n  condition: (true)\n}";
        let b = "rule b { condition: false }";
        let before = PARSES.get();
        let spans = highlight_spans(a);
        assert_eq!(paren_pairs(a), [(22, 27)]);
        assert_eq!(folding(a), [(0, a.len())]);
        assert_eq!(PARSES.get() - before, 1);
        assert_ne!(highlight_spans(b), spans);
        assert_eq!(PARSES.get() - before, 2);
        assert_eq!(highlight_spans(a), spans, "a after b: the same result");
        assert_eq!(PARSES.get() - before, 3);
    }

    #[test]
    fn a_broken_text_still_gets_spans_in_order() {
        for source in [
            "rule",
            "rule a { condition: (",
            "$a = \"unterminated",
            "/* open",
            "{ ~",
            "1..",
            "$",
        ] {
            let all = highlight_spans(source);
            assert!(
                all.windows(2).all(|w| w[0].0.end <= w[1].0.start),
                "{source}: {all:?}"
            );
            assert!(all.iter().all(|(s, _)| s.end <= source.len()), "{source}");
            let _ = (paren_pairs(source), folding(source));
        }
    }
}
