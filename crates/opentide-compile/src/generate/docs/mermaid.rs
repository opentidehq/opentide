//! Mermaid flowcharts: their nodes, edges and groups as data the
//! `mermaid.md.j2` template writes (`documentation/diagram/`). Identifiers
//! and labels are made safe for Mermaid here; labels wrap at word boundaries
//! (textwrap) with `<br>`.

use serde::Serialize;
use textwrap::{Options, WordSeparator, WordSplitter};

/// A node's shape, by object type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Shape {
    /// `id["…"]`: a rule, or anything else.
    Rect,
    /// `id{{"…"}}`: a threat.
    Hex,
    /// `id(["…"])`: an objective.
    Stadium,
    /// `id(("…"))`: a signal.
    Circle,
}

impl Shape {
    /// The shape of an object type.
    pub fn of(object_type: Option<&str>) -> Self {
        match object_type {
            Some("threat") => Self::Hex,
            Some("objective") => Self::Stadium,
            Some("signal") => Self::Circle,
            _ => Self::Rect,
        }
    }
}

/// A node, ready to write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Node {
    /// The identifier written (`[A-Za-z0-9_]`).
    pub id: String,
    /// The label written, wrapped.
    pub label: String,
    /// Its shape.
    pub shape: Shape,
    /// The object it stands for.
    #[serde(skip)]
    pub uuid: String,
}

impl Node {
    /// The node of the object `uuid`.
    pub fn new(uuid: &str, label: &str, shape: Shape) -> Self {
        Self {
            id: identifier(uuid),
            label: wrap(label, 24),
            shape,
            uuid: uuid.to_owned(),
        }
    }
}

/// An edge, ready to write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Edge {
    /// The source's identifier.
    pub source: String,
    /// The target's identifier.
    pub target: String,
    /// The label written, wrapped, if any.
    pub label: Option<String>,
    /// `<-->` instead of `-->`.
    pub both_ways: bool,
}

impl Edge {
    /// From `source` to `target`.
    pub fn new(source: &str, target: &str, label: Option<&str>, both_ways: bool) -> Self {
        Self {
            source: identifier(source),
            target: identifier(target),
            label: label
                .filter(|label| !label.is_empty())
                .map(|label| wrap(label, 18)),
            both_ways,
        }
    }
}

/// A titled group of nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Subgraph {
    /// The title written.
    pub title: String,
    /// Its nodes.
    pub nodes: Vec<Node>,
}

/// A flowchart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flowchart {
    /// `flowchart` or `graph`.
    pub kind: &'static str,
    /// `TB`, `LR`.
    pub direction: &'static str,
    /// The groups, in order.
    pub subgraphs: Vec<Subgraph>,
    /// The nodes in no group.
    pub nodes: Vec<Node>,
    /// The edges.
    pub edges: Vec<Edge>,
}

impl Flowchart {
    /// The flowchart of `nodes` (each once, the last of an identifier
    /// winning, at its first place) and `edges`, the nodes of each of
    /// `groups` (title, uuids) gathered under its title.
    pub fn new(
        kind: &'static str,
        direction: &'static str,
        nodes: Vec<Node>,
        edges: Vec<Edge>,
        groups: Option<Vec<(String, Vec<String>)>>,
    ) -> Self {
        let mut unique: indexmap::IndexMap<String, Node> = indexmap::IndexMap::new();
        for node in nodes {
            unique.insert(node.uuid.clone(), node);
        }
        let mut grouped: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut subgraphs = Vec::new();
        for (title, uuids) in groups.unwrap_or_default() {
            let members: Vec<Node> = uuids
                .iter()
                .filter_map(|uuid| unique.get(uuid).cloned())
                .collect();
            if members.is_empty() {
                continue;
            }
            for member in &members {
                grouped.insert(member.uuid.clone());
            }
            subgraphs.push(Subgraph {
                title: label(&title),
                nodes: members,
            });
        }
        let nodes = unique
            .into_values()
            .filter(|node| !grouped.contains(&node.uuid))
            .collect();
        Self {
            kind,
            direction,
            subgraphs,
            nodes,
            edges,
        }
    }
}

/// An identifier Mermaid accepts: `[A-Za-z0-9_]`, each other character `_`,
/// without leading or trailing `_`; `node` when nothing is left.
pub fn identifier(value: &str) -> String {
    let replaced: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = replaced.trim_matches('_');
    if trimmed.is_empty() {
        "node".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// A label Mermaid reads inside quotes: no brackets, braces or `|`, `'`
/// for `"`, one line; `node` when nothing is left.
pub fn label(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| !matches!(c, '(' | ')' | '[' | ']' | '{' | '}' | '|'))
        .map(|c| match c {
            '"' => '\'',
            '\n' => ' ',
            other => other,
        })
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "node".to_owned()
    } else {
        cleaned.to_owned()
    }
}

/// [`label`], wrapped at `width` characters with `<br>`; a word longer than
/// the width stays whole.
pub fn wrap(value: &str, width: usize) -> String {
    let cleaned = label(value);
    let words: Vec<&str> = cleaned.split_whitespace().collect();
    if words.is_empty() {
        return cleaned;
    }
    let text = words.join(" ");
    let options = Options::new(width)
        .break_words(false)
        .word_separator(WordSeparator::AsciiSpace)
        .word_splitter(WordSplitter::NoHyphenation);
    textwrap::wrap(&text, options).join("<br>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_labels() {
        assert_eq!(
            identifier("00000000-0000-4000-8002-000000000001"),
            "00000000_0000_4000_8002_000000000001"
        );
        assert_eq!(identifier("--"), "node");
        assert_eq!(label(" a (b) \"c\" [d]|{e}\nf "), "a b 'c' de f");
        assert_eq!(label("()"), "node");
    }

    #[test]
    fn labels_wrap_at_words() {
        assert_eq!(
            wrap("Credential Access Objective", 24),
            "Credential Access<br>Objective"
        );
        assert_eq!(wrap("Sentinel KQL Rule", 24), "Sentinel KQL Rule");
        assert_eq!(
            wrap("averyveryveryverylongwordindeed x", 24),
            "averyveryveryverylongwordindeed<br>x"
        );
        assert_eq!(wrap("a  b", 24), "a b");
    }

    #[test]
    fn groups_take_their_nodes_out_of_the_rest() {
        let chart = Flowchart::new(
            "flowchart",
            "TB",
            vec![
                Node::new("a", "A", Shape::Rect),
                Node::new("b", "B", Shape::Hex),
                Node::new("a", "A2", Shape::Rect),
            ],
            vec![],
            Some(vec![
                ("Bs".into(), vec!["b".into(), "z".into()]),
                ("None".into(), vec!["z".into()]),
            ]),
        );
        assert_eq!(chart.subgraphs.len(), 1);
        assert_eq!(chart.subgraphs[0].nodes[0].id, "b");
        assert_eq!(chart.nodes.len(), 1);
        assert_eq!(chart.nodes[0].label, "A2");
    }
}
