//! The parsed tree as the analysis reads it: a [`Node`] is a node of the
//! rowan tree or one of its leaf tokens that the grammar names (a term, a
//! phrase, a boost, ...), with its range trimmed to its first and last
//! token that is not whitespace, and accessors for the grammar's fields
//! (`field:query`, a term query's term, a range's bounds).

use crate::parser;
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_core::ByteSpan;
use opentide_parse::SyntaxError;
use rowan::{NodeOrToken, TextRange, TextSize};

type Element = rowan::SyntaxElement<crate::syntax::Lucene>;

/// A named node or token of the tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Node(Element);

/// Leaf tokens the grammar names; the rest (`:`, brackets, whitespace,
/// keyword tokens inside their `And`/`Or`/`Not` nodes) are anonymous.
const NAMED_TOKENS: [K; 9] = [
    K::Term,
    K::WildcardTerm,
    K::Star,
    K::Phrase,
    K::Regexp,
    K::RangeTerm,
    K::Boost,
    K::Fuzzy,
    K::BareOperator,
];

fn is_named(e: &Element) -> bool {
    match e {
        NodeOrToken::Node(_) => true,
        NodeOrToken::Token(t) => NAMED_TOKENS.contains(&t.kind()),
    }
}

/// The range of `e` without the whitespace at its ends.
fn trimmed(e: &Element) -> TextRange {
    let NodeOrToken::Node(n) = e else {
        return e.text_range();
    };
    let tokens = || {
        n.descendants_with_tokens()
            .filter_map(NodeOrToken::into_token)
            .filter(|t| t.kind() != K::Whitespace)
    };
    let start = tokens().next().map(|t| t.text_range().start());
    // The last token: walk back from the node's last token.
    let mut last = n.last_token();
    while let Some(t) = &last {
        if t.kind() != K::Whitespace || !n.text_range().contains_range(t.text_range()) {
            break;
        }
        last = t.prev_token();
    }
    let end = last
        .filter(|t| n.text_range().contains_range(t.text_range()))
        .map(|t| t.text_range().end());
    // tree-sitter's root runs from its first token to the end of the text.
    let end = if n.kind() == K::SourceFile {
        Some(n.text_range().end())
    } else {
        end
    };
    match (start, end) {
        (Some(s), Some(e)) if s <= e => TextRange::new(s, e),
        _ => TextRange::empty(n.text_range().start()),
    }
}

impl Node {
    /// The tree's root.
    pub(crate) fn root(root: &SyntaxNode) -> Self {
        Self(NodeOrToken::Node(root.clone()))
    }

    pub(crate) fn kind(&self) -> K {
        self.0.kind()
    }

    pub(crate) fn range(&self) -> TextRange {
        trimmed(&self.0)
    }

    pub(crate) fn start(&self) -> usize {
        usize::from(self.range().start())
    }

    pub(crate) fn end(&self) -> usize {
        usize::from(self.range().end())
    }

    /// The span a diagnostic on the node covers: at least one byte. The
    /// range is trimmed once (ADR 0014 §5a).
    pub(crate) fn span(&self) -> ByteSpan {
        let range = self.range();
        let (start, end) = (usize::from(range.start()), usize::from(range.end()));
        ByteSpan::new(start, end.max(start + 1))
    }

    pub(crate) fn text<'s>(&self, source: &'s str) -> &'s str {
        let range = self.range();
        source
            .get(usize::from(range.start())..usize::from(range.end()))
            .unwrap_or("")
    }

    /// The named children, in order.
    pub(crate) fn children(&self) -> Vec<Node> {
        self.named_children().collect()
    }

    /// The named children, in order, read as they are needed: a search for
    /// one stops there, and collects none (ADR 0014 §5a).
    fn named_children(&self) -> impl Iterator<Item = Node> + use<> {
        let node = match &self.0 {
            NodeOrToken::Node(n) => Some(n.clone()),
            NodeOrToken::Token(_) => None,
        };
        node.into_iter()
            .flat_map(|n| n.children_with_tokens())
            .filter(is_named)
            .map(Node)
    }

    /// The first named child of kind `kind`.
    fn child(&self, kinds: &[K]) -> Option<Node> {
        self.named_children().find(|c| kinds.contains(&c.kind()))
    }

    pub(crate) fn first_child(&self) -> Option<Node> {
        self.named_children().next()
    }

    pub(crate) fn parent(&self) -> Option<Node> {
        self.0.parent().map(|p| Node(NodeOrToken::Node(p)))
    }

    /// The next named sibling.
    pub(crate) fn next_sibling(&self) -> Option<Node> {
        let mut next = self.0.next_sibling_or_token();
        while let Some(e) = next {
            if is_named(&e) {
                return Some(Node(e));
            }
            next = e.next_sibling_or_token();
        }
        None
    }

    /// A field query's field name (`field_name`).
    pub(crate) fn field(&self) -> Option<Node> {
        (self.kind() == K::FieldQuery)
            .then(|| self.child(&[K::FieldName]))
            .flatten()
    }

    /// A field query's body (`query`): the node after the field name.
    pub(crate) fn query(&self) -> Option<Node> {
        if self.kind() != K::FieldQuery {
            return None;
        }
        self.named_children()
            .find(|c| c.kind() != K::FieldName && c.kind() != K::Error)
    }

    /// A term query's term.
    pub(crate) fn term(&self) -> Option<Node> {
        (self.kind() == K::TermQuery)
            .then(|| self.child(&[K::Term, K::WildcardTerm, K::Star, K::BareOperator]))
            .flatten()
    }

    /// A phrase query's phrase.
    pub(crate) fn phrase(&self) -> Option<Node> {
        (self.kind() == K::PhraseQuery)
            .then(|| self.child(&[K::Phrase]))
            .flatten()
    }

    /// A range's lower (`upper == false`) or upper bound.
    pub(crate) fn bound(&self, upper: bool) -> Option<Node> {
        if self.kind() != K::RangeQuery {
            return None;
        }
        let NodeOrToken::Node(n) = &self.0 else {
            return None;
        };
        // The bounds sit either side of `TO`.
        let mut seen_to = false;
        for e in n.children_with_tokens() {
            match e.kind() {
                K::ToKw => seen_to = true,
                K::RangeTerm | K::Phrase if seen_to == upper => return Some(Node(e)),
                _ => {}
            }
        }
        None
    }

    /// The first token child, named or not, of one of `kinds` (a range's
    /// brackets).
    pub(crate) fn token(&self, kinds: &[K]) -> Option<Node> {
        match &self.0 {
            NodeOrToken::Node(n) => n
                .children_with_tokens()
                .find(|e| kinds.contains(&e.kind()))
                .map(Node),
            NodeOrToken::Token(_) => None,
        }
    }

    /// A boolean query's operators (`And` and `Or` nodes).
    pub(crate) fn operators(&self) -> Vec<Node> {
        self.children()
            .into_iter()
            .filter(|c| matches!(c.kind(), K::And | K::Or))
            .collect()
    }

    /// The deepest named node or token whose range holds `offset`: the
    /// token starting there at a boundary between two, else the smallest
    /// node around it (tree-sitter's `descendant_for_byte_range`).
    pub(crate) fn at_offset(&self, offset: usize) -> Option<Node> {
        let at = TextSize::from(u32::try_from(offset).ok()?);
        let mut node = self.clone();
        loop {
            let NodeOrToken::Node(n) = &node.0 else {
                return Some(node);
            };
            // Children are in order: the first that ends past `at` is the
            // only one that can hold it.
            let inner = n
                .children_with_tokens()
                .filter(|e| e.kind() != K::Whitespace)
                .find(|e| at < e.text_range().end())
                .filter(|e| {
                    let r = trimmed(e);
                    r.start() <= at && at < r.end()
                });
            match inner {
                Some(e) => node = Node(e),
                None => return Some(node),
            }
        }
    }
}

/// A parse of a Lucene query, for the analysis.
pub(crate) struct Tree {
    pub(crate) root: SyntaxNode,
    pub(crate) errors: Vec<SyntaxError>,
}

impl Tree {
    pub(crate) fn parse(source: &str) -> Self {
        let (root, parse) = parser::parse(source);
        Self {
            root,
            errors: parse.errors,
        }
    }

    pub(crate) fn root(&self) -> Node {
        Node::root(&self.root)
    }

    pub(crate) fn has_error(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// Pre-order walk of the named nodes and tokens under `root` (`root`
/// included), each with its ancestors, root first. Iterative, so a deeply
/// nested query cannot exhaust the stack.
pub(crate) fn walk_with_ancestors(root: &Node, mut f: impl FnMut(&Node, &[Node])) {
    let mut stack: Vec<(Node, usize)> = vec![(root.clone(), 0)];
    let mut ancestors: Vec<Node> = Vec::new();
    while let Some((node, depth)) = stack.pop() {
        count_visit();
        ancestors.truncate(depth);
        f(&node, &ancestors);
        let children = node.children();
        if !children.is_empty() {
            ancestors.push(node);
            for child in children.into_iter().rev() {
                stack.push((child, depth + 1));
            }
        }
    }
}

/// [`walk_with_ancestors`] and a visit of every token, in one pass: `f` gets
/// each named node and token with its ancestors, in the same order, and
/// `token` gets every token in document order. A walk allocates a cursor for
/// each element it visits, and the highlight walked the tree a second time
/// (ADR 0014 §5a).
pub(crate) fn walk_once(
    root: &Node,
    mut f: impl FnMut(&Node, &[Node]),
    mut token: impl FnMut(&rowan::SyntaxToken<crate::syntax::Lucene>),
) {
    let mut stack: Vec<(Element, usize)> = vec![(root.0.clone(), 0)];
    let mut ancestors: Vec<Node> = Vec::new();
    let mut children: Vec<Element> = Vec::new();
    while let Some((element, depth)) = stack.pop() {
        count_visit();
        match element {
            NodeOrToken::Token(t) => {
                token(&t);
                if NAMED_TOKENS.contains(&t.kind()) {
                    ancestors.truncate(depth);
                    f(&Node(NodeOrToken::Token(t)), &ancestors);
                }
            }
            NodeOrToken::Node(n) => {
                ancestors.truncate(depth);
                children.extend(n.children_with_tokens());
                let node = Node(NodeOrToken::Node(n));
                f(&node, &ancestors);
                if !children.is_empty() {
                    stack.extend(children.drain(..).rev().map(|c| (c, depth + 1)));
                    ancestors.push(node);
                }
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// The elements the walks visited on this thread: [`visits`].
    static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Counts one element a walk visited, in tests (ADR 0014 §7).
#[inline]
pub(crate) fn count_visit() {
    #[cfg(test)]
    VISITS.set(VISITS.get() + 1);
}

/// How many elements the walks visited on this thread.
#[cfg(test)]
pub(crate) fn visits() -> usize {
    VISITS.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Corpus and external queries, and every prefix of each short one.
    fn texts() -> Vec<String> {
        let testdata = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
        let mut out = Vec::new();
        for dir in [
            "corpus/lucene",
            "conformance/external/lucene",
            "conformance/external/lucene-queryparser",
        ] {
            let mut dirs = vec![testdata.join(dir)];
            while let Some(dir) = dirs.pop() {
                for path in std::fs::read_dir(&dir)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path())
                {
                    if path.is_dir() {
                        dirs.push(path);
                    } else if let Ok(text) = std::fs::read_to_string(&path) {
                        out.extend(text.lines().map(str::to_owned).take(400));
                        out.push(text);
                    }
                }
            }
        }
        let cut: Vec<String> = out
            .iter()
            .filter(|t| t.len() < 300)
            .flat_map(|t| {
                t.char_indices()
                    .map(|(i, _)| t[..i].to_owned())
                    .collect::<Vec<_>>()
            })
            .collect();
        out.extend(cut);
        out.push(format!("{}a{}", "(".repeat(900), ")".repeat(900)));
        out
    }

    type Visit = (K, TextRange, Vec<(K, TextRange)>);

    fn visit(node: &Node, ancestors: &[Node]) -> Visit {
        let path = ancestors
            .iter()
            .map(|a| (a.kind(), a.0.text_range()))
            .collect();
        (node.kind(), node.0.text_range(), path)
    }

    /// The one walk calls the checks as [`walk_with_ancestors`] does, and
    /// meets the tokens as the highlight's scan did (ADR 0014 §5a).
    #[test]
    fn walk_once_is_the_walk_and_the_token_scan() {
        let mut named = 0;
        for source in texts() {
            let tree = Tree::parse(&source);
            let mut old = Vec::new();
            walk_with_ancestors(&tree.root(), |n, a| old.push(visit(n, a)));
            let old_tokens: Vec<_> = tree
                .root
                .descendants_with_tokens()
                .filter_map(NodeOrToken::into_token)
                .collect();
            let (mut new, mut new_tokens) = (Vec::new(), Vec::new());
            walk_once(
                &tree.root(),
                |n, a| new.push(visit(n, a)),
                |t| new_tokens.push(t.clone()),
            );
            assert_eq!(new, old, "{source:?}");
            assert_eq!(new_tokens, old_tokens, "{source:?}");
            named += old.len();
        }
        assert!(named > 10_000, "{named}");
    }

    /// An analysis visits each element of the tree once (ADR 0014 §7): the
    /// checks' walk and the highlight's walked it twice.
    #[test]
    fn an_analysis_visits_each_element_once() {
        let source = "title:(quick OR brown) AND -status:[200 TO 299} && body:\"fox jumps\"~2 OR /joh?n(ath[oa]n)/ NOT x^2";
        let elements = Tree::parse(source).root.descendants_with_tokens().count();
        let before = visits();
        crate::analyze(source);
        assert_eq!(visits() - before, elements);
    }
}
