//! The green tree builder [`build`](crate::build) uses in place of rowan's
//! `GreenNodeBuilder` (#1616).
//!
//! rowan 0.17's builder interns every token and every small node in its
//! `NodeCache`, a hashbrown table hashed with FxHash. Fx is a fixed function,
//! so names whose hashes share their low bits can be worked out offline, and
//! each one inserted walks the probe sequence past all the earlier ones: a
//! 1 MB KQL `project` list of 70,000 such names parsed about 24 times slower
//! than ordinary names. rowan offers no way to choose its hasher, or to add a
//! token without interning it, so this builder makes the green tree itself
//! from rowan's public constructors ([`GreenToken::new`], [`GreenNode::new`])
//! and keeps its own caches, one per builder:
//!
//! - **Seeded.** Both tables hash with foldhash's per-map seed (ADR 0014
//!   §5b), so collisions prepared ahead of time do not carry over.
//! - **Capped.** Each table holds at most [`MAX_INTERNED`] entries. Once it
//!   is full it is no longer consulted: every later token or node is built
//!   without interning, as it would be without a cache. A full table is where
//!   an attacker who can predict the seed (the browser's WebAssembly module,
//!   where foldhash's seed is close to fixed) would make each lookup walk
//!   thousands of colliding entries; with no lookups past the cap, a build
//!   costs at most the cap's square in probes, then linear time.
//! - **Sized up front.** Each table is made for the input's lexemes, up to
//!   the cap, so it never grows and rehashes: on the many short queries of
//!   the parse benchmarks this builder runs fewer instructions and
//!   allocations than rowan's.
//!
//! Below the cap the tree is shared exactly as rowan's builder shares it: a
//! token is interned on its kind and text; a node of at most three children,
//! all of them interned, is interned on its kind and the identity of its
//! children. The tree's shape and text never depend on the cache.

use foldhash::fast::RandomState;
use rowan::{GreenNode, GreenToken, NodeOrToken, SyntaxKind};
use std::collections::hash_map::Entry;

/// The most distinct tokens, and separately the most distinct nodes, one
/// builder interns. An ordinary query, even a large one, repeats a few
/// hundred names, keywords and punctuation; past this the cache would save
/// little memory and only grow.
pub(crate) const MAX_INTERNED: usize = 4_096;

/// The most children a node may have to be interned, as in rowan: larger
/// nodes rarely repeat.
const MAX_INTERNED_CHILDREN: usize = 3;

/// A child of an open node, and whether it is interned (a node is interned
/// only when all of its children are).
type Child = (NodeOrToken<GreenNode, GreenToken>, bool);

/// An interned node's key: its kind, how many children it has and their
/// addresses. The cache owns the children, so an address is never reused
/// while the key is in it.
type NodeKey = (SyntaxKind, usize, [usize; MAX_INTERNED_CHILDREN]);

/// Builds one green tree.
pub(crate) struct Builder<'a> {
    /// Each open node's kind and its first child in `children`.
    parents: Vec<(SyntaxKind, usize)>,
    children: Vec<Child>,
    tokens: foldhash::HashMap<(SyntaxKind, &'a str), GreenToken>,
    nodes: foldhash::HashMap<NodeKey, GreenNode>,
}

impl<'a> Builder<'a> {
    /// A builder for a tree of about `tokens` tokens: each cache is sized
    /// for that many entries, up to [`MAX_INTERNED`], so it never grows.
    pub(crate) fn new(tokens: usize) -> Self {
        let capacity = tokens.min(MAX_INTERNED);
        Self {
            parents: Vec::new(),
            children: Vec::new(),
            tokens: foldhash::HashMap::with_capacity_and_hasher(capacity, RandomState::default()),
            nodes: foldhash::HashMap::with_capacity_and_hasher(capacity, RandomState::default()),
        }
    }

    /// Adds a token to the open node.
    pub(crate) fn token(&mut self, kind: SyntaxKind, text: &'a str) {
        let child = if self.tokens.len() >= MAX_INTERNED {
            (GreenToken::new(kind, text), false)
        } else {
            match self.tokens.entry((kind, text)) {
                Entry::Occupied(entry) => (entry.get().clone(), true),
                Entry::Vacant(entry) => (entry.insert(GreenToken::new(kind, text)).clone(), true),
            }
        };
        self.children.push((NodeOrToken::Token(child.0), child.1));
    }

    /// Opens a node.
    pub(crate) fn start_node(&mut self, kind: SyntaxKind) {
        self.parents.push((kind, self.children.len()));
    }

    /// Closes the open node.
    ///
    /// # Panics
    ///
    /// When no node is open (a bug of the caller's: `replay` pairs them).
    pub(crate) fn finish_node(&mut self) {
        #[expect(
            clippy::expect_used,
            reason = "the replay opens and closes nodes in pairs; an unpaired close is the builder's caller's bug"
        )]
        let (kind, first) = self.parents.pop().expect("finish_node without start_node");
        let child = self.node(kind, first);
        self.children.push(child);
    }

    /// Builds the node of `kind` from the children from `first` on,
    /// interning it when it may be.
    fn node(&mut self, kind: SyntaxKind, first: usize) -> Child {
        let children = &self.children[first..];
        let internable = self.nodes.len() < MAX_INTERNED
            && children.len() <= MAX_INTERNED_CHILDREN
            && children.iter().all(|c| c.1);
        let key = internable.then(|| {
            let mut ids = [0; MAX_INTERNED_CHILDREN];
            for (id, (child, _)) in ids.iter_mut().zip(children) {
                *id = address(child);
            }
            (kind, children.len(), ids)
        });
        let mut build = || GreenNode::new(kind, self.children.drain(first..).map(|(c, _)| c));
        match key.map(|key| self.nodes.entry(key)) {
            Some(Entry::Occupied(entry)) => {
                self.children.truncate(first);
                (NodeOrToken::Node(entry.get().clone()), true)
            }
            Some(Entry::Vacant(entry)) => (NodeOrToken::Node(entry.insert(build()).clone()), true),
            None => (NodeOrToken::Node(build()), false),
        }
    }

    /// The finished tree: its one root node, or `None` when the starts and
    /// finishes did not leave exactly one node.
    pub(crate) fn finish(mut self) -> Option<GreenNode> {
        if !self.parents.is_empty() || self.children.len() != 1 {
            return None;
        }
        match self.children.pop() {
            Some((NodeOrToken::Node(node), _)) => Some(node),
            _ => None,
        }
    }

    /// How many tokens and nodes are interned.
    #[cfg(test)]
    fn interned(&self) -> (usize, usize) {
        (self.tokens.len(), self.nodes.len())
    }
}

/// A child's identity: the address of its data, which the cache keeps alive.
fn address(child: &NodeOrToken<GreenNode, GreenToken>) -> usize {
    match child {
        NodeOrToken::Node(node) => std::ptr::from_ref::<rowan::GreenNodeData>(node) as usize,
        NodeOrToken::Token(token) => std::ptr::from_ref::<rowan::GreenTokenData>(token) as usize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORD: SyntaxKind = SyntaxKind(1);
    const NAME: SyntaxKind = SyntaxKind(2);
    const ROOT: SyntaxKind = SyntaxKind(3);

    fn ptr(node: &GreenNode, i: usize) -> usize {
        address(
            &node
                .children()
                .nth(i)
                .unwrap_or_else(|| panic!("child {i}"))
                .to_owned(),
        )
    }

    #[test]
    fn repeated_tokens_and_small_nodes_are_shared() {
        let mut b = Builder::new(0);
        b.start_node(ROOT);
        for _ in 0..3 {
            b.start_node(NAME);
            b.token(WORD, "a");
            b.finish_node();
        }
        b.finish_node();
        let root = b.finish().unwrap_or_else(|| panic!("one root"));
        assert_eq!(root.to_string(), "aaa");
        assert_eq!(ptr(&root, 0), ptr(&root, 1));
        assert_eq!(ptr(&root, 1), ptr(&root, 2));
    }

    #[test]
    fn past_the_cap_nothing_is_looked_up_or_interned() {
        let names: Vec<String> = (0..MAX_INTERNED + 100).map(|i| format!("n{i}")).collect();
        let mut b = Builder::new(0);
        b.start_node(ROOT);
        for name in &names {
            b.start_node(NAME);
            b.token(WORD, name);
            b.finish_node();
        }
        // Once a table is full it is not consulted: a name interned before
        // the cap is built anew too, so no lookup walks a full table.
        for name in [&names[0], &names[MAX_INTERNED + 50]] {
            b.start_node(NAME);
            b.token(WORD, name);
            b.finish_node();
        }
        assert_eq!(b.interned(), (MAX_INTERNED, MAX_INTERNED));
        b.finish_node();
        let root = b.finish().unwrap_or_else(|| panic!("one root"));
        assert_eq!(
            root.to_string(),
            names.concat() + &names[0] + &names[MAX_INTERNED + 50]
        );
        let n = names.len();
        assert_ne!(ptr(&root, 0), ptr(&root, n));
        assert_ne!(ptr(&root, MAX_INTERNED + 50), ptr(&root, n + 1));
        // Below the cap, a repeated name and its node are shared.
        let mut b = Builder::new(0);
        b.start_node(ROOT);
        for name in [&names[0], &names[1], &names[0]] {
            b.start_node(NAME);
            b.token(WORD, name);
            b.finish_node();
        }
        b.finish_node();
        let root = b.finish().unwrap_or_else(|| panic!("one root"));
        assert_eq!(ptr(&root, 0), ptr(&root, 2));
    }

    #[test]
    fn unbalanced_builds_have_no_root() {
        let mut b = Builder::new(0);
        b.start_node(ROOT);
        assert!(b.finish().is_none());
        let mut b = Builder::new(0);
        b.token(WORD, "a");
        assert!(b.finish().is_none());
        assert!(Builder::new(0).finish().is_none());
    }
}
