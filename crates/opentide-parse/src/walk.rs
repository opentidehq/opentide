//! One walk over a tree for every check of an analysis and its highlight
//! (ADR 0014 §5a). rowan allocates a cursor for each node and token a walk
//! visits; an analysis whose checks walk the tree and whose highlight walks
//! it again pays for every element twice. [`walk_once`] visits each element
//! once, in preorder (tokens in document order), from one stack and one
//! scratch vector, and hands each to the caller with its depth, so the
//! caller can run its checks on the nodes and gather its highlight from the
//! tokens in the same pass.

use rowan::{Language, NodeOrToken, SyntaxElement, SyntaxNode};

/// Visits every element of `root`, `root` first, in preorder: a node before
/// its children, the children in order, so the tokens come in document
/// order. `root` can be any node of a tree, not only its root: the walk
/// stays below it. `visit` gets each element and its depth, the number of
/// nodes above it (`root` is at 0). A caller that needs the ancestors keeps them
/// in an [`Ancestors`], cut to the depth at each element.
pub fn walk_once<L: Language>(
    root: &SyntaxNode<L>,
    mut visit: impl FnMut(SyntaxElement<L>, usize),
) {
    let mut stack: Vec<(SyntaxElement<L>, usize)> = vec![(NodeOrToken::Node(root.clone()), 0)];
    let mut children: Vec<SyntaxElement<L>> = Vec::new();
    while let Some((element, depth)) = stack.pop() {
        if let NodeOrToken::Node(node) = &element {
            children.extend(node.children_with_tokens());
            stack.extend(children.drain(..).rev().map(|c| (c, depth + 1)));
        }
        visit(element, depth);
    }
}

/// The nodes above the element a [`walk_once`] visits, in a caller's own
/// type: [`Ancestors::at`] cuts the stack to the element's depth and gives
/// it, root first; [`Ancestors::push`] adds a node the walk enters. The
/// caller pushes every node it meets, after reading its ancestors: a node
/// left out would shift the depths, and an element below it would get too
/// few ancestors.
#[derive(Debug)]
pub struct Ancestors<T>(Vec<T>);

impl<T> Default for Ancestors<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> Ancestors<T> {
    /// The ancestors of an element at `depth`, root first.
    ///
    /// Debug builds panic when fewer than `depth` nodes were pushed: the
    /// caller skipped a node the walk entered.
    pub fn at(&mut self, depth: usize) -> &[T] {
        debug_assert!(
            depth <= self.0.len(),
            "Ancestors::at({depth}) with {} pushed: push every node the walk enters",
            self.0.len()
        );
        self.0.truncate(depth);
        &self.0
    }

    /// Enters a node: the elements below it have it as their last ancestor.
    pub fn push(&mut self, node: T) {
        self.0.push(node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rowan::{GreenNodeBuilder, SyntaxKind};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum Lang {}

    impl Language for Lang {
        type Kind = SyntaxKind;
        fn kind_from_raw(raw: SyntaxKind) -> SyntaxKind {
            raw
        }
        fn kind_to_raw(kind: SyntaxKind) -> SyntaxKind {
            kind
        }
    }

    /// A tree with empty nodes, a node of tokens only, nesting and a token
    /// at every level.
    fn tree() -> SyntaxNode<Lang> {
        let mut b = GreenNodeBuilder::new();
        b.start_node(SyntaxKind(1));
        b.token(SyntaxKind(10), "a");
        b.start_node(SyntaxKind(2));
        b.start_node(SyntaxKind(3));
        b.finish_node();
        b.token(SyntaxKind(11), " ");
        b.start_node(SyntaxKind(4));
        b.token(SyntaxKind(12), "b");
        b.token(SyntaxKind(13), "c");
        b.finish_node();
        b.finish_node();
        b.token(SyntaxKind(14), "d");
        b.finish_node();
        SyntaxNode::new_root(b.finish())
    }

    /// The walk meets the elements as rowan's preorder enters them, each at
    /// its depth, with its ancestors.
    #[test]
    fn the_walk_is_rowans_preorder() {
        let root = tree();
        let mut walked = Vec::new();
        let mut ancestors = Ancestors::default();
        walk_once(&root, |element, depth| {
            let above: Vec<SyntaxNode<Lang>> = ancestors.at(depth).to_vec();
            if let NodeOrToken::Node(node) = &element {
                ancestors.push(node.clone());
            }
            walked.push((element, depth, above));
        });
        let mut entered = Vec::new();
        let mut open: Vec<SyntaxNode<Lang>> = Vec::new();
        for event in root.preorder_with_tokens() {
            match event {
                rowan::WalkEvent::Enter(element) => {
                    entered.push((element.clone(), open.len(), open.clone()));
                    if let NodeOrToken::Node(node) = element {
                        open.push(node);
                    }
                }
                rowan::WalkEvent::Leave(NodeOrToken::Node(_)) => {
                    open.pop();
                }
                rowan::WalkEvent::Leave(NodeOrToken::Token(_)) => {}
            }
        }
        assert_eq!(walked, entered);
        assert_eq!(walked.len(), root.descendants_with_tokens().count());
    }

    /// A caller that skips a node it enters is caught in debug builds.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "push every node the walk enters")]
    fn skipping_a_node_is_caught() {
        let mut ancestors: Ancestors<SyntaxNode<Lang>> = Ancestors::default();
        walk_once(&tree(), |_, depth| {
            ancestors.at(depth);
        });
    }
}
