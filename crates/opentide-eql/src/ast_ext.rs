//! Accessors on the typed AST that `cargo xtask codegen` cannot write: in a `sequence` or a
//! `join`, the `until` term is a term like the others, told apart only by the `until` before
//! it, so the generated `sequence_terms()` and `join_terms()` return it too.

use crate::SyntaxKind;
use crate::ast::{Join, JoinTerm, Sequence, SequenceTerm};
use opentide_parse::ast::AstNode;
use rowan::NodeOrToken;

/// The terms of `node` before `until`, and the one after it.
fn split<T: AstNode<Language = crate::Lang>>(node: &crate::SyntaxNode) -> (Vec<T>, Option<T>) {
    let mut terms = Vec::new();
    let mut after_until = false;
    for child in node.children_with_tokens() {
        match child {
            NodeOrToken::Token(token) if token.kind() == SyntaxKind::UNTIL_KW => after_until = true,
            NodeOrToken::Node(child) => {
                if let Some(term) = T::cast(child) {
                    if after_until {
                        return (terms, Some(term));
                    }
                    terms.push(term);
                }
            }
            NodeOrToken::Token(_) => {}
        }
    }
    (terms, None)
}

impl Sequence {
    /// The terms before `until`.
    pub fn terms(&self) -> Vec<SequenceTerm> {
        split(self.syntax()).0
    }

    /// The term after `until`.
    pub fn until(&self) -> Option<SequenceTerm> {
        split(self.syntax()).1
    }
}

impl Join {
    /// The terms before `until`.
    pub fn terms(&self) -> Vec<JoinTerm> {
        split(self.syntax()).0
    }

    /// The term after `until`.
    pub fn until(&self) -> Option<JoinTerm> {
        split(self.syntax()).1
    }
}
