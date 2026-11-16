//! Checks a syntax tree against its language's `.ungram`: the test helper
//! that keeps a parser and its documented grammar from drifting apart.
//!
//! `cargo xtask codegen` writes, beside the typed AST, a `RULES` table of
//! [`NodeRule`]s: for each node kind, the ungrammar rule its children must
//! match, as data, so this crate depends on no grammar reader. [`check`]
//! walks a tree and reports every node whose children (trivia aside) do not
//! match, each with its range.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use rowan::{Language, NodeOrToken, SyntaxNode, TextRange};

use crate::Grammar;

/// An ungrammar rule over raw syntax kinds (labels erased, enum nodes
/// expanded into the alternatives they stand for).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// One child, node or token, of this raw kind.
    Kind(u16),
    /// The rules one after the other.
    Seq(&'static [Rule]),
    /// Any one of the rules.
    Alt(&'static [Rule]),
    /// The rule or nothing.
    Opt(&'static Rule),
    /// The rule any number of times.
    Rep(&'static Rule),
}

/// What the children of one node kind must match.
#[derive(Debug, Clone, Copy)]
pub struct NodeRule {
    /// The raw kind of the nodes this rule is for.
    pub kind: u16,
    /// The node's name in the grammar.
    pub name: &'static str,
    /// The rule as written in the `.ungram`, for messages.
    pub text: &'static str,
    /// The rule.
    pub rule: Rule,
}

/// A node whose children do not match its rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// The node's range in the source.
    pub range: TextRange,
    /// The node's kind, as the language names it.
    pub kind: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {:?}: {}", self.kind, self.range, self.message)
    }
}

/// Every node of the tree under `root` (itself included) whose children do
/// not match its rule in `rules`, in source order. `grammar.trivia` kinds are
/// ignored; a node of `grammar.error`, or of a kind with no rule, is a
/// mismatch.
pub fn check<L: Language>(
    root: &SyntaxNode<L>,
    rules: &[NodeRule],
    grammar: Grammar,
) -> Vec<Mismatch> {
    let by_kind: HashMap<u16, &NodeRule> = rules.iter().map(|r| (r.kind, r)).collect();
    let mut found = Vec::new();
    for node in root.descendants() {
        let raw = L::kind_to_raw(node.kind()).0;
        let mut mismatch = |message: String| {
            found.push(Mismatch {
                range: node.text_range(),
                kind: format!("{:?}", node.kind()),
                message,
            });
        };
        if raw == grammar.error.0 {
            mismatch("a syntax error node".to_owned());
            continue;
        }
        let Some(rule) = by_kind.get(&raw) else {
            mismatch("the grammar has no rule for this node kind".to_owned());
            continue;
        };
        let children: Vec<u16> = node
            .children_with_tokens()
            .map(|child| match child {
                NodeOrToken::Node(n) => L::kind_to_raw(n.kind()).0,
                NodeOrToken::Token(t) => L::kind_to_raw(t.kind()).0,
            })
            .filter(|&kind| !grammar.trivia.contains(rowan::SyntaxKind(kind)))
            .collect();
        let mut reached = 0;
        let ends = advance(&rule.rule, &children, &BTreeSet::from([0]), &mut reached);
        if ends.contains(&children.len()) {
            continue;
        }
        let name =
            |index: usize| format!("{:?}", L::kind_from_raw(rowan::SyntaxKind(children[index])));
        let problem = if reached < children.len() {
            format!("child {reached} ({}) is not allowed here", name(reached))
        } else {
            "the children end before the rule does".to_owned()
        };
        mismatch(format!("{problem}; `{} = {}`", rule.name, rule.text));
    }
    found
}

/// Panics, listing every mismatch, unless the tree conforms to `rules`.
///
/// # Panics
///
/// When [`check`] finds a mismatch.
#[track_caller]
pub fn assert_conforms<L: Language>(root: &SyntaxNode<L>, rules: &[NodeRule], grammar: Grammar) {
    let found = check(root, rules, grammar);
    assert!(
        found.is_empty(),
        "the tree does not conform to its grammar:\n{}",
        found
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The positions in `input` a match of `rule` can end at, from each of the
/// positions in `from`; `reached` is raised to the furthest position any
/// partial match got to.
fn advance(
    rule: &Rule,
    input: &[u16],
    from: &BTreeSet<usize>,
    reached: &mut usize,
) -> BTreeSet<usize> {
    if let Some(&last) = from.last() {
        *reached = (*reached).max(last);
    }
    match rule {
        Rule::Kind(kind) => from
            .iter()
            .filter(|&&at| input.get(at) == Some(kind))
            .map(|at| at + 1)
            .inspect(|&at| *reached = (*reached).max(at))
            .collect(),
        Rule::Seq(rules) => rules
            .iter()
            .fold(from.clone(), |at, rule| advance(rule, input, &at, reached)),
        Rule::Alt(rules) => rules
            .iter()
            .flat_map(|rule| advance(rule, input, from, reached))
            .collect(),
        Rule::Opt(rule) => {
            let mut ends = advance(rule, input, from, reached);
            ends.extend(from);
            ends
        }
        Rule::Rep(rule) => {
            let mut ends = from.clone();
            let mut frontier = from.clone();
            while !frontier.is_empty() {
                let next = advance(rule, input, &frontier, reached);
                frontier = next.difference(&ends).copied().collect();
                ends.extend(&frontier);
            }
            ends
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ends(rule: &Rule, input: &[u16]) -> (Vec<usize>, usize) {
        let mut reached = 0;
        let ends = advance(rule, input, &BTreeSet::from([0]), &mut reached);
        (ends.into_iter().collect(), reached)
    }

    #[test]
    fn a_repeated_rule_that_can_match_nothing_terminates() {
        let (ends, _) = ends(&Rule::Rep(&Rule::Opt(&Rule::Kind(1))), &[1, 1, 2]);
        assert_eq!(ends, [0, 1, 2]);
    }

    #[test]
    fn the_furthest_partial_match_is_reported() {
        let rule = Rule::Seq(&[Rule::Kind(1), Rule::Kind(2), Rule::Kind(3)]);
        assert_eq!(ends(&rule, &[1, 2, 9]), (vec![], 2));
        assert_eq!(ends(&rule, &[1, 2]), (vec![], 2));
        assert_eq!(ends(&rule, &[1, 2, 3]), (vec![3], 3));
        let choice = Rule::Alt(&[Rule::Seq(&[Rule::Kind(1), Rule::Kind(2)]), Rule::Kind(1)]);
        assert_eq!(ends(&choice, &[1, 2]), (vec![1, 2], 2));
    }
}
