//! The runtime of the typed AST `cargo xtask codegen` generates from a
//! language's `.ungram`: the [`AstNode`] trait its wrappers implement and the
//! [`support`] functions their accessors call, generic over a [`Language`].
//!
//! A wrapper is a view of a [`SyntaxNode`] of one kind (or, for an enum, of
//! one of several): it owns nothing the tree does not, and `cast` never
//! fails on a tree that conforms to the grammar ([`crate::conformance`]).

use std::marker::PhantomData;

use rowan::{Language, SyntaxNode, SyntaxToken};

/// A typed view of a syntax node: a struct for one node kind, an enum for a
/// choice between kinds.
pub trait AstNode: Sized {
    /// The language whose trees this node views.
    type Language: Language;

    /// Whether a node of `kind` is one of this type.
    fn can_cast(kind: <Self::Language as Language>::Kind) -> bool;

    /// The typed view of `syntax`, or `None` when it is not one of this type.
    fn cast(syntax: SyntaxNode<Self::Language>) -> Option<Self>;

    /// The node viewed.
    fn syntax(&self) -> &SyntaxNode<Self::Language>;
}

/// The children of a node that are of one [`AstNode`] type, in source order.
#[derive(Debug, Clone)]
pub struct AstChildren<N: AstNode> {
    inner: rowan::SyntaxNodeChildren<N::Language>,
    ty: PhantomData<fn() -> N>,
}

impl<N: AstNode> AstChildren<N> {
    fn new(parent: &SyntaxNode<N::Language>) -> Self {
        Self {
            inner: parent.children(),
            ty: PhantomData,
        }
    }
}

impl<N: AstNode> Iterator for AstChildren<N> {
    type Item = N;

    fn next(&mut self) -> Option<N> {
        self.inner.find_map(N::cast)
    }
}

/// The child accessors of generated wrappers.
pub mod support {
    use super::{AstChildren, AstNode, Language, SyntaxNode, SyntaxToken};

    /// The first child of `parent` that is an `N`.
    pub fn child<N: AstNode>(parent: &SyntaxNode<N::Language>) -> Option<N> {
        parent.children().find_map(N::cast)
    }

    /// The `n`th (from 0) child of `parent` that is an `N`.
    pub fn nth_child<N: AstNode>(parent: &SyntaxNode<N::Language>, n: usize) -> Option<N> {
        parent.children().filter_map(N::cast).nth(n)
    }

    /// Every child of `parent` that is an `N`.
    pub fn children<N: AstNode>(parent: &SyntaxNode<N::Language>) -> AstChildren<N> {
        AstChildren::new(parent)
    }

    /// The first token directly under `parent` whose kind is `kind`.
    pub fn token<L: Language>(parent: &SyntaxNode<L>, kind: L::Kind) -> Option<SyntaxToken<L>> {
        token_in(parent, &[kind])
    }

    /// Every token directly under `parent` whose kind is one of `kinds`, in
    /// order: a choice of tokens under `*` (`(op:('+' | '-') Expr)*`).
    pub fn tokens_in<L: Language>(
        parent: &SyntaxNode<L>,
        kinds: &[L::Kind],
    ) -> Vec<SyntaxToken<L>> {
        parent
            .children_with_tokens()
            .filter_map(rowan::NodeOrToken::into_token)
            .filter(|token| kinds.contains(&token.kind()))
            .collect()
    }

    /// The first token directly under `parent` whose kind is one of `kinds`.
    pub fn token_in<L: Language>(
        parent: &SyntaxNode<L>,
        kinds: &[L::Kind],
    ) -> Option<SyntaxToken<L>> {
        parent
            .children_with_tokens()
            .filter_map(rowan::NodeOrToken::into_token)
            .find(|token| kinds.contains(&token.kind()))
    }
}
