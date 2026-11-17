//! The parsed query the analysis reads: the lossless rowan tree, the
//! parser's problems, and the names the analysis gives the tree's kinds.
//!
//! The analysis was written against a tree-sitter tree, and the names stay
//! its own: a node's production name (`from_command`; `JoinQualifier` reads
//! as `identifier`), a token's text (`from`, `|`). A one-token production
//! (an identifier, a string) has no parts the analysis reads, the hidden
//! `WITH {map}` is no node of its own, and a comment is a named leaf
//! wherever it stands (`gates::children_of`).

use crate::gates::SyntaxElement;
use crate::parser;
use crate::syntax::{Lang, SyntaxKind as K};
use opentide_core::ByteSpan;
use rowan::{NodeOrToken, SyntaxNode};
use std::rc::Rc;
use std::sync::OnceLock;

/// What the parser reported: where, and what it said.
#[derive(Clone, Debug)]
pub(crate) struct Problem {
    /// The start of the token it sits before (the end of the source past the last).
    pub(crate) at: usize,
    pub(crate) message: String,
    /// At the end of the input: `at` is right after the last token, and what
    /// follows it is blanks or comments, never the token to quote.
    pub(crate) at_end: bool,
}

/// A parsed query.
pub(crate) struct Tree {
    pub(crate) problems: Vec<Problem>,
    /// Where the problems are, sorted: [`Tree::problem_in`] searches it.
    error_at: Vec<usize>,
    /// The lossless tree's root.
    pub(crate) syntax: SyntaxNode<Lang>,
}

impl Tree {
    /// Whether the parser reported a problem inside `span`: at or after its
    /// start and before its end (a problem at the token right after it,
    /// `foo)`, is not in it, as `foo )` is not); an empty span holds a
    /// problem at its place. A binary search: a name check per node over
    /// every problem made completions quadratic on broken input.
    pub(crate) fn problem_in(&self, span: ByteSpan) -> bool {
        let end = span.end.max(span.start + 1);
        let first = self.error_at.partition_point(|&at| at < span.start);
        self.error_at.get(first).is_some_and(|&at| at < end)
    }

    /// Whether the parser reported a problem inside the whole query.
    pub(crate) fn has_error(&self) -> bool {
        self.problem_in(crate::gates::span_of(&self.syntax))
    }
}

/// Lower-case names of the node kinds, once.
fn names() -> &'static Vec<&'static str> {
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    NAMES.get_or_init(|| {
        (0..=K::PARAMETER as u16)
            .map(|raw| {
                let kind = <Lang as rowan::Language>::kind_from_raw(rowan::SyntaxKind(raw));
                let name = format!("{kind:?}").to_ascii_lowercase();
                &*Box::leak(name.into_boxed_str())
            })
            .collect()
    })
}

pub(crate) fn node_name(kind: K) -> &'static str {
    match kind {
        K::JOIN_QUALIFIER => "identifier",
        K::ERROR => "ERROR",
        _ => names().get(kind as usize).copied().unwrap_or("ERROR"),
    }
}

/// Productions that are one token in tree-sitter: the analysis reads no
/// parts of them.
pub(crate) fn is_leaf(kind: K) -> bool {
    matches!(
        kind,
        K::IDENTIFIER
            | K::QUOTED_IDENTIFIER
            | K::PARAMETER
            | K::STRING
            | K::NUMBER
            | K::BOOLEAN
            | K::NULL
            | K::STAR
            | K::ID_PATTERN
            | K::INDEX_NAME
            | K::CLUSTER
            | K::SELECTOR
            | K::METADATA_FIELD
            | K::PROMQL_TEXT
            | K::COMMAND_NAME
            | K::UNKNOWN_TEXT
            | K::ENRICH_MODE
            | K::POLICY_NAME
            | K::TIME_UNIT
            | K::JOIN_QUALIFIER
    )
}

/// The name of an anonymous token: a keyword's lower-case text, a symbol.
pub(crate) fn token_name(kind: K, text: &str) -> &'static str {
    if let Some(word) = kind.keyword_text() {
        return word;
    }
    match kind {
        K::PIPE => "|",
        K::COMMA => ",",
        K::SEMI => ";",
        K::DOT => ".",
        K::COLON => ":",
        K::COLON_COLON => "::",
        K::EQ => "=",
        K::EQ_EQ => "==",
        K::NOT_EQ => "!=",
        K::LT => "<",
        K::LT_EQ => "<=",
        K::GT => ">",
        K::GT_EQ => ">=",
        K::PLUS => "+",
        K::MINUS => "-",
        K::STAR_TOKEN => "*",
        K::SLASH => "/",
        K::PERCENT => "%",
        K::L_PAREN => "(",
        K::R_PAREN => ")",
        K::L_BRACK => "[",
        K::R_BRACK => "]",
        K::L_BRACE => "{",
        K::R_BRACE => "}",
        _ => {
            if text.is_empty() {
                "ERROR"
            } else {
                "word"
            }
        }
    }
}

thread_local! {
    /// The parses on this thread: [`parses`].
    static PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many queries this thread has parsed.
pub(crate) fn parses() -> usize {
    PARSES.get()
}

/// Parses `source`.
pub(crate) fn parse(source: &str) -> Tree {
    PARSES.set(PARSES.get() + 1);
    let parse = parser::parse(source);
    let problems: Vec<Problem> = parse
        .errors
        .iter()
        .map(|e| Problem {
            at: usize::from(e.anchor(source.len())),
            message: e.message.clone(),
            at_end: usize::from(e.gap.end()) >= source.len(),
        })
        .collect();
    let mut error_at: Vec<usize> = problems.iter().map(|p| p.at).collect();
    error_at.sort_unstable();
    Tree {
        problems,
        error_at,
        syntax: SyntaxNode::new_root(parse.green),
    }
}

/// The highlight capture of a leaf, by the patterns of `highlights.scm` in
/// their order (first wins): what `capture(token, parent)` becomes on the rowan tree.
/// The capture of each keyword and symbol of the highlight table, by text:
/// built once (a scan of the table per token was a tenth of a long query's
/// analysis).
fn keyword_captures() -> &'static std::collections::HashMap<&'static str, &'static str> {
    static CAPTURES: OnceLock<std::collections::HashMap<&'static str, &'static str>> =
        OnceLock::new();
    CAPTURES.get_or_init(|| {
        let mut captures = std::collections::HashMap::new();
        for (token, capture) in
            opentide_highlight::keywords(opentide_core::LanguageId::Esql).unwrap_or_default()
        {
            // The table's first row for a text wins, as the scan's did.
            captures.entry(*token).or_insert(capture.name());
        }
        captures
    })
}

/// The element's parent as the arena had it: `WITH {…}` (`NamedParameters`)
/// is no node of its own.
pub(crate) fn arena_parent(element: &SyntaxElement) -> Option<SyntaxNode<Lang>> {
    let parent = element.parent()?;
    if parent.kind() == K::NAMED_PARAMETERS {
        parent.parent()
    } else {
        Some(parent)
    }
}

/// The highlight capture of a leaf of the arena (a token, a comment, a
/// one-token node), by the patterns of `highlights.scm` in their order
/// (first wins).
pub(crate) fn capture(element: &SyntaxElement) -> Option<&'static str> {
    let node = match element {
        NodeOrToken::Token(t) if t.kind() == K::COMMENT => return Some("comment"),
        NodeOrToken::Token(t) => {
            return keyword_captures()
                .get(token_name(t.kind(), t.text()))
                .copied();
        }
        NodeOrToken::Node(n) => n,
    };
    let kind = node_name(node.kind());
    let parent_node = arena_parent(element);
    let parent = parent_node.as_ref().map(|p| node_name(p.kind()));
    // The first node of the parent: a call's or an option's name.
    let first = || {
        parent_node
            .as_ref()
            .and_then(|p| p.children().next())
            .as_ref()
            == Some(node)
    };
    // FUSE's method: its first node, before `KEY`, `GROUP` or `SCORE`.
    let method = || {
        parent_node.as_ref().is_some_and(|p| {
            let parts = crate::gates::parts(p);
            let at = parts.iter().position(|e| e.as_node().is_some());
            at.is_some_and(|at| {
                parts[at].as_node() == Some(node)
                    && !parts[..at]
                        .iter()
                        .any(|e| matches!(e.kind(), K::KEY_KW | K::GROUP_KW | K::SCORE_KW))
            })
        })
    };
    let capture = match kind {
        "command_name" if parent == Some("unknown_command") => "error",
        "identifier" | "parameter" if parent == Some("function_call") && first() => "function",
        "identifier" if parent == Some("type_name") => "type",
        "time_unit" if parent == Some("qualified_interval") => "constant",
        "index_name" | "cluster" => "type",
        "selector" | "metadata_field" => "constant",
        "policy_name" if parent == Some("enrich_policy") => "type",
        "enrich_mode" if parent == Some("enrich_policy") => "constant",
        "identifier" if parent == Some("command_option") && first() => "keyword",
        "identifier" if parent == Some("fuse_command") && method() => "constant",
        "star" => "operator",
        "promql_text" | "unknown_text" => "string",
        "identifier" | "quoted_identifier" if parent == Some("qualified_name") => "property",
        "id_pattern" | "quoted_identifier" if parent == Some("name_pattern") => "property",
        "identifier" | "quoted_identifier" => "variable",
        "string" => "string",
        "number" => "number",
        "boolean" => "boolean",
        "null" | "parameter" => "constant",
        _ => return None,
    };
    Some(capture)
}

/// The parse of `source`, as the analysis asks for it.
/// The tree of `source`, parsed once per text: an editor asks for the
/// analysis, hover and completions of one text in a row, and every entry
/// point read its own parse (a tenth of a second per megabyte in a release
/// build, a second and a half in a debug one). A tree is a function of its
/// text, so the last one is kept per thread and reused while the text is
/// the same.
pub(crate) fn parse_tree(source: &str) -> Option<Rc<Tree>> {
    LAST.with(|last| {
        let mut last = last.borrow_mut();
        if let Some((text, tree)) = last.as_ref()
            && text.as_str() == source
        {
            return Some(Rc::clone(tree));
        }
        let tree = Rc::new(parse(source));
        *last = Some((source.to_string(), Rc::clone(&tree)));
        Some(tree)
    })
}

thread_local! {
    /// The last text [`parse_tree`] parsed on this thread, and its tree.
    static LAST: std::cell::RefCell<Option<(String, Rc<Tree>)>> =
        const { std::cell::RefCell::new(None) };
}

/// The production names of the tree's named nodes (`from_command`): the
/// names the corpus's `prod:` tags use. `NAMED_PARAMETERS` is hidden and
/// `JOIN_QUALIFIER` reads as an `identifier`, as in [`named_kinds`].
pub(crate) fn production_names() -> Vec<&'static str> {
    (K::SOURCE_FILE as u16..=K::PARAMETER as u16)
        .map(|raw| <Lang as rowan::Language>::kind_from_raw(rowan::SyntaxKind(raw)))
        .filter(|kind| !matches!(kind, K::NAMED_PARAMETERS | K::JOIN_QUALIFIER))
        .map(node_name)
        .collect()
}

/// For each syntax error of `source`, the production names of the nodes it was recorded in,
/// root first (`opentide_parse::SyntaxError::within`).
pub(crate) fn error_kinds(source: &str) -> Vec<Vec<&'static str>> {
    parser::parse(source)
        .errors
        .iter()
        .map(|e| {
            e.within
                .iter()
                .map(|&raw| <Lang as rowan::Language>::kind_from_raw(raw))
                .filter(|kind| !matches!(kind, K::NAMED_PARAMETERS | K::ERROR))
                .map(node_name)
                .collect()
        })
        .collect()
}

/// Whether the parser reported a problem in `source`, and the names of the
/// named nodes of its tree in preorder.
pub(crate) fn named_kinds(source: &str) -> (bool, Vec<&'static str>) {
    let tree = parse(source);
    let mut kinds = Vec::new();
    let mut stack = vec![NodeOrToken::Node(tree.syntax.clone())];
    while let Some(element) = stack.pop() {
        match &element {
            NodeOrToken::Node(node) => {
                kinds.push(node_name(node.kind()));
                stack.extend(crate::gates::children_of(node).into_iter().rev());
            }
            NodeOrToken::Token(token) if token.kind() == K::COMMENT => kinds.push("comment"),
            NodeOrToken::Token(_) => {}
        }
    }
    (!tree.problems.is_empty(), kinds)
}
