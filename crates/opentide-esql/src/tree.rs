//! The analysis's view of the rowan tree: an arena of nodes shaped like the
//! tree-sitter tree the analysis was written against, so the analysis ports
//! with its navigation calls unchanged (`kind`, `child_by_field_name`, ...).
//!
//! Named nodes are the grammar's named productions; keywords and punctuation
//! are anonymous children named by their text; a leaf production (an
//! identifier, a string) has no children; the hidden `WITH {map}` is not a
//! node, its map is the `options` of the command; comments are named leaves
//! wherever they stand. Fields come from the ungram's labels (`assign`).
//! `Node` is `Copy`, as tree-sitter's is.

use crate::parser;
use crate::syntax::{Lang, SyntaxKind as K};
use opentide_core::ByteSpan;
use rowan::{NodeOrToken, SyntaxNode, WalkEvent};
use std::rc::Rc;
use std::sync::OnceLock;

/// What the parser reported: where, and what it said.
#[derive(Clone, Debug)]
pub(crate) struct Problem {
    /// The start of the token it sits before (the end of the source past the last).
    pub(crate) at: usize,
    pub(crate) message: String,
}

struct Data {
    kind: &'static str,
    named: bool,
    start: usize,
    end: usize,
    parent: Option<u32>,
    children: Vec<u32>,
    field: Option<&'static str>,
    /// The rowan node of a named node (a token's arena node has none): the
    /// checks being moved to the typed AST read it (#1415).
    syntax: Option<SyntaxNode<Lang>>,
}

/// A parsed query.
pub(crate) struct Tree {
    data: Vec<Data>,
    pub(crate) problems: Vec<Problem>,
    /// Where the problems are, sorted: [`Node::has_error`] searches it.
    error_at: Vec<usize>,
}

/// Stands where tree-sitter's cursor stood: iteration needs none.
pub(crate) struct Cursor;

#[derive(Clone, Copy)]
pub(crate) struct Node<'t> {
    tree: &'t Tree,
    id: u32,
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

fn node_name(kind: K) -> &'static str {
    match kind {
        K::JOIN_QUALIFIER => "identifier",
        K::ERROR => "ERROR",
        _ => names().get(kind as usize).copied().unwrap_or("ERROR"),
    }
}

/// Productions that are one token in tree-sitter: no children.
fn is_leaf(kind: K) -> bool {
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
fn token_name(kind: K, text: &str) -> &'static str {
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

/// Parses `source` into the arena.
pub(crate) fn parse(source: &str) -> Tree {
    PARSES.set(PARSES.get() + 1);
    let parse = parser::parse(source);
    let problems: Vec<Problem> = parse
        .errors
        .iter()
        .map(|e| Problem {
            at: usize::from(e.gap.end()),
            message: e.message.clone(),
        })
        .collect();
    let root = SyntaxNode::<Lang>::new_root(parse.green);
    let mut data: Vec<Data> = Vec::new();
    // The open real nodes; `None` entries are hidden nodes (`WITH {…}`).
    let mut open: Vec<Option<u32>> = Vec::new();
    let mut skip = 0usize;
    let mut options = false;
    for event in root.preorder_with_tokens() {
        match event {
            WalkEvent::Enter(NodeOrToken::Node(node)) => {
                if skip > 0 {
                    skip += 1;
                    continue;
                }
                let kind = node.kind();
                if kind == K::NAMED_PARAMETERS {
                    options = true;
                    open.push(None);
                    continue;
                }
                let r = node.text_range();
                let id = push(
                    &mut data,
                    &open,
                    node_name(kind),
                    true,
                    usize::from(r.start()),
                    usize::from(r.end()),
                );
                data[id as usize].syntax = Some(node.clone());
                if options && kind == K::MAP_EXPRESSION {
                    data[id as usize].field = Some("options");
                }
                options = false;
                if is_leaf(kind) {
                    skip = 1;
                }
                open.push(Some(id));
            }
            WalkEvent::Leave(NodeOrToken::Node(_)) => {
                if skip > 0 {
                    skip -= 1;
                    if skip > 0 {
                        continue;
                    }
                }
                if let Some(Some(id)) = open.pop() {
                    assign(&mut data, id);
                }
            }
            WalkEvent::Enter(NodeOrToken::Token(token)) => {
                if skip > 0 {
                    continue;
                }
                let kind = token.kind();
                if kind == K::WHITESPACE {
                    continue;
                }
                let r = token.text_range();
                let (name, named) = if kind == K::COMMENT {
                    ("comment", true)
                } else {
                    (token_name(kind, token.text()), false)
                };
                push(
                    &mut data,
                    &open,
                    name,
                    named,
                    usize::from(r.start()),
                    usize::from(r.end()),
                );
            }
            WalkEvent::Leave(NodeOrToken::Token(_)) => {}
        }
    }
    let mut error_at: Vec<usize> = problems.iter().map(|p| p.at).collect();
    error_at.sort_unstable();
    Tree {
        data,
        problems,
        error_at,
    }
}

fn push(
    data: &mut Vec<Data>,
    open: &[Option<u32>],
    kind: &'static str,
    named: bool,
    start: usize,
    end: usize,
) -> u32 {
    let id = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let parent = open.iter().rev().find_map(|o| *o);
    data.push(Data {
        kind,
        named,
        start,
        end,
        parent,
        children: Vec::new(),
        field: None,
        syntax: None,
    });
    if let Some(p) = parent {
        data[p as usize].children.push(id);
    }
    id
}

/// The text of the tokens a child list names, by position: fields of `node`'s
/// children, from the labels of `esql.ungram`.
fn assign(data: &mut [Data], id: u32) {
    let kids: Vec<u32> = data[id as usize].children.clone();
    let kind = data[id as usize].kind;
    let k = |i: usize| data[kids[i] as usize].kind;
    let named = |i: usize| data[kids[i] as usize].named && k(i) != "comment";
    let n = kids.len();
    let mut set: Vec<(usize, &'static str)> = Vec::new();
    // The `i`th kid is `field`.
    let mut put = |i: usize, field: &'static str| set.push((i, field));
    // Indices of the named kids, and the index of the first anonymous `tok`.
    let named_ix: Vec<usize> = (0..n).filter(|&i| named(i)).collect();
    let pos = |tok: &str| (0..n).find(|&i| k(i) == tok);
    let named_after = |tok: &str| -> Vec<usize> {
        pos(tok)
            .map(|p| named_ix.iter().copied().filter(|&i| i > p).collect())
            .unwrap_or_default()
    };
    match kind {
        "query" => {
            for (j, &i) in named_ix.iter().enumerate() {
                put(i, if j == 0 { "source" } else { "command" });
            }
        }
        "source_subquery" => {
            for (j, &i) in named_ix.iter().enumerate() {
                put(i, if j == 0 { "source" } else { "command" });
            }
        }
        "from_command" | "ts_command" => {
            for &i in &named_ix {
                put(
                    i,
                    if k(i) == "metadata" {
                        "metadata"
                    } else {
                        "index"
                    },
                );
            }
        }
        "index_pattern" => {
            for &i in &named_ix {
                match k(i) {
                    "cluster" => put(i, "cluster"),
                    "index_name" => put(i, "name"),
                    "selector" => put(i, "selector"),
                    _ => {}
                }
            }
        }
        "metadata" => {
            for i in 0..n {
                if k(i) == "metadata_field" {
                    put(i, "field");
                } else if k(i) == "[" {
                    put(i, "bracket");
                }
            }
        }
        "set_command" => {
            if let Some(&i) = named_ix.first() {
                put(i, "name");
            }
            for i in named_after("=") {
                put(i, "value");
            }
        }
        "explain_command" => {
            for &i in &named_ix {
                put(i, "query");
            }
        }
        "where_command" => {
            for &i in &named_ix {
                put(i, "condition");
            }
        }
        "order_expression" => {
            if let Some(&i) = named_ix.first() {
                put(i, "key");
            }
            for i in 0..n {
                match k(i) {
                    "asc" | "desc" => put(i, "direction"),
                    "first" | "last" => put(i, "nulls"),
                    _ => {}
                }
            }
        }
        "limit_command" => {
            let by = pos("by").unwrap_or(n);
            for &i in &named_ix {
                put(i, if i < by { "count" } else { "by" });
            }
        }
        "stats_command" | "inline_stats_command" => {
            let by = pos("by").unwrap_or(n);
            for &i in &named_ix {
                put(i, if i < by { "aggregate" } else { "by" });
            }
        }
        "aggregate_field" | "field_assignment_or_expression" => {
            let eq = pos("=");
            let filter = pos("where");
            for &i in &named_ix {
                let f = if filter.is_some_and(|w| i > w) {
                    "filter"
                } else if eq.is_some_and(|e| i < e) {
                    "name"
                } else {
                    "value"
                };
                put(i, f);
            }
        }
        "dissect_command" => {
            for (j, &i) in named_ix.iter().enumerate() {
                put(
                    i,
                    match (j, k(i)) {
                        (0, _) => "input",
                        (_, "command_option") => "option",
                        _ => "pattern",
                    },
                );
            }
        }
        "grok_command" => {
            for (j, &i) in named_ix.iter().enumerate() {
                put(i, if j == 0 { "input" } else { "pattern" });
            }
        }
        "command_option" => {
            for (j, &i) in named_ix.iter().enumerate() {
                put(i, if j == 0 { "name" } else { "value" });
            }
        }
        "enrich_command" => {
            let on = pos("on");
            let with = pos("with");
            for &i in &named_ix {
                let f = if k(i) == "enrich_policy" {
                    "policy"
                } else if with.is_some_and(|w| i > w) {
                    "with"
                } else if on.is_some_and(|o| i > o) {
                    "match_field"
                } else {
                    continue;
                };
                put(i, f);
            }
        }
        "enrich_policy" => {
            for &i in &named_ix {
                match k(i) {
                    "enrich_mode" => put(i, "mode"),
                    "policy_name" => put(i, "name"),
                    _ => {}
                }
            }
        }
        "enrich_with_clause" => {
            let eq = pos("=");
            for &i in &named_ix {
                put(
                    i,
                    if eq.is_some_and(|e| i < e) {
                        "new"
                    } else {
                        "field"
                    },
                );
            }
        }
        "mv_expand_command" => {
            for &i in &named_ix {
                put(i, "field");
            }
        }
        "join_command" => {
            if n > 0 && !named(0) {
                put(0, "kind");
            }
            let on = pos("on").unwrap_or(n);
            for &i in &named_ix {
                match (k(i), i > on) {
                    ("index_pattern", _) => put(i, "target"),
                    ("identifier", false) => put(i, "qualifier"),
                    (_, true) => put(i, "condition"),
                    _ => {}
                }
            }
        }
        "rename_clause" => {
            let as_first = pos("as").is_some();
            for (j, &i) in named_ix.iter().enumerate() {
                let old_first = as_first;
                put(i, if (j == 0) == old_first { "old" } else { "new" });
            }
        }
        "change_point_command" => {
            let on = pos("on");
            let as_ = pos("as");
            let by = pos("by");
            let mut after_as = 0;
            for (j, &i) in named_ix.iter().enumerate() {
                let f = if by.is_some_and(|b| i > b) {
                    "by"
                } else if as_.is_some_and(|a| i > a) {
                    after_as += 1;
                    if after_as == 1 {
                        "type_name"
                    } else {
                        "pvalue_name"
                    }
                } else if on.is_some_and(|o| i > o) {
                    "key"
                } else if j == 0 {
                    "value"
                } else {
                    continue;
                };
                put(i, f);
            }
        }
        "completion_command" => {
            let eq = pos("=");
            let with = pos("with");
            for &i in &named_ix {
                let f = if k(i) == "map_expression" {
                    continue;
                } else if eq.is_some_and(|e| i < e) {
                    "target"
                } else if with.is_some_and(|w| i > w) {
                    "inference_id"
                } else {
                    "prompt"
                };
                put(i, f);
            }
        }
        "rerank_command" => {
            let eq = pos("=");
            let on = pos("on").unwrap_or(n);
            for &i in &named_ix {
                if k(i) == "map_expression" {
                    continue;
                }
                let f = if eq.is_some_and(|e| i < e) {
                    "target"
                } else if i < on {
                    "query"
                } else {
                    continue;
                };
                put(i, f);
            }
        }
        "sample_command" => {
            for &i in &named_ix {
                put(i, "probability");
            }
        }
        "fuse_command" => {
            let (score, key, group) = (pos("score"), pos("key"), pos("group"));
            for (j, &i) in named_ix.iter().enumerate() {
                if k(i) == "map_expression" {
                    continue;
                }
                let before = |p: Option<usize>| p.is_some_and(|p| p < i);
                let f = if before(key)
                    && (!before(group) || group < key)
                    && (!before(score) || score < key)
                {
                    "key"
                } else if before(group) && (!before(score) || score < group) {
                    "group"
                } else if before(score) {
                    "score"
                } else if j == 0 {
                    "method"
                } else {
                    continue;
                };
                put(i, f);
            }
        }
        "uri_parts_command"
        | "registered_domain_command"
        | "user_agent_command"
        | "ip_location_command" => {
            for (j, &i) in named_ix.iter().enumerate() {
                if k(i) == "map_expression" {
                    continue;
                }
                put(i, if j == 0 { "target" } else { "input" });
            }
        }
        "mmr_command" => {
            let on = pos("on").unwrap_or(n);
            let limit = pos("limit").unwrap_or(n);
            for &i in &named_ix {
                if k(i) == "map_expression" {
                    continue;
                }
                put(
                    i,
                    if i < on {
                        "query_vector"
                    } else if i < limit {
                        "field"
                    } else {
                        "limit"
                    },
                );
            }
        }
        "highlight_command" => {
            let on = pos("on");
            for &i in &named_ix {
                if k(i) == "map_expression" || on.is_some() && i > on.unwrap_or(0) {
                    continue;
                }
                put(i, "query");
            }
        }
        "dense_vector_command" => {
            let eq = pos("=");
            for &i in &named_ix {
                if k(i) == "map_expression" {
                    continue;
                }
                put(
                    i,
                    if eq.is_some_and(|e| i < e) {
                        "target"
                    } else {
                        "field"
                    },
                );
            }
        }
        "fill_null_command" => {
            if let Some(&i) = named_ix.first() {
                put(i, "value");
            }
        }
        "unknown_command" => {
            if let Some(&i) = named_ix.first() {
                put(i, "name");
            }
        }
        "like_expression" => {
            if let Some(&i) = named_ix.first() {
                put(i, "left");
            }
            for i in 0..n {
                match k(i) {
                    "like" | "rlike" => put(i, "operator"),
                    "not" => put(i, "negated"),
                    _ => {}
                }
            }
            let op = (0..n)
                .find(|&i| matches!(k(i), "like" | "rlike"))
                .unwrap_or(n);
            for &i in &named_ix {
                if i > op {
                    put(i, "pattern");
                }
            }
        }
        "in_expression" => {
            if let Some(&i) = named_ix.first() {
                put(i, "left");
            }
            for i in 0..n {
                if k(i) == "not" {
                    put(i, "negated");
                }
            }
            let inn = pos("in").unwrap_or(n);
            for &i in &named_ix {
                if i > inn {
                    put(
                        i,
                        if k(i) == "source_subquery" {
                            "subquery"
                        } else {
                            "value"
                        },
                    );
                }
            }
        }
        "is_null_expression" => {
            if let Some(&i) = named_ix.first() {
                put(i, "operand");
            }
            for i in 0..n {
                if k(i) == "not" {
                    put(i, "negated");
                }
            }
        }
        "match_expression" => {
            for (j, &i) in named_ix.iter().enumerate() {
                put(i, if j == 0 { "field" } else { "query" });
            }
        }
        "comparison" => {
            let (first, last) = (named_ix.first().copied(), named_ix.last().copied());
            if let Some(i) = first {
                put(i, "left");
            }
            if let (Some(i), true) = (last, named_ix.len() > 1) {
                put(i, "right");
            }
            for i in 0..n {
                if !named(i) {
                    put(i, "operator");
                }
            }
        }
        "unary_expression" => {
            for i in 0..n {
                put(i, if named(i) { "operand" } else { "operator" });
            }
        }
        "not_expression" => {
            for &i in &named_ix {
                put(i, "operand");
            }
        }
        "inline_cast" => {
            for &i in &named_ix {
                put(i, if k(i) == "type_name" { "type" } else { "value" });
            }
        }
        "function_call" => {
            for (j, &i) in named_ix.iter().enumerate() {
                put(
                    i,
                    if j == 0 {
                        "name"
                    } else if k(i) == "map_expression" {
                        "options"
                    } else {
                        "arguments"
                    },
                );
            }
        }
        "qualified_interval" => {
            for &i in &named_ix {
                put(i, if k(i) == "number" { "value" } else { "unit" });
            }
        }
        "map_entry" => {
            for (j, &i) in named_ix.iter().enumerate() {
                put(i, if j == 0 { "key" } else { "value" });
            }
        }
        _ => {}
    }
    for (i, field) in set {
        if data[kids[i] as usize].field.is_none() {
            data[kids[i] as usize].field = Some(field);
        }
    }
}

impl Tree {
    pub(crate) fn root_node(&self) -> Node<'_> {
        Node { tree: self, id: 0 }
    }
}

impl<'t> Node<'t> {
    fn d(&self) -> &'t Data {
        &self.tree.data[self.id as usize]
    }

    fn at(&self, id: u32) -> Node<'t> {
        Node {
            tree: self.tree,
            id,
        }
    }

    /// The rowan node of a named node; `None` for a token or a comment.
    pub(crate) fn syntax(&self) -> Option<&'t SyntaxNode<Lang>> {
        self.d().syntax.as_ref()
    }

    pub(crate) fn kind(&self) -> &'static str {
        self.d().kind
    }

    pub(crate) fn is_named(&self) -> bool {
        self.d().named
    }

    pub(crate) fn field_name(&self) -> Option<&'static str> {
        self.d().field
    }

    pub(crate) fn id(&self) -> usize {
        self.id as usize
    }

    pub(crate) fn start_byte(&self) -> usize {
        self.d().start
    }

    pub(crate) fn end_byte(&self) -> usize {
        self.d().end
    }

    /// Whether the parser reported a problem inside this node: at or after
    /// its start and before its end (a problem at the token right after it,
    /// `foo)`, is not in it, as `foo )` is not); a node recovery left empty
    /// holds a problem at its place. A binary search: a name check per node
    /// over every problem made completions quadratic on broken input.
    pub(crate) fn has_error(&self) -> bool {
        let d = self.d();
        let end = d.end.max(d.start + 1);
        let errors = &self.tree.error_at;
        let first = errors.partition_point(|&at| at < d.start);
        errors.get(first).is_some_and(|&at| at < end)
    }

    pub(crate) fn parent(&self) -> Option<Node<'t>> {
        self.d().parent.map(|p| self.at(p))
    }

    pub(crate) fn child_count(&self) -> usize {
        self.d().children.len()
    }

    pub(crate) fn child(&self, i: usize) -> Option<Node<'t>> {
        self.d().children.get(i).map(|&c| self.at(c))
    }

    pub(crate) fn next_sibling(&self) -> Option<Node<'t>> {
        let parent = self.parent()?;
        let siblings = &parent.d().children;
        let at = siblings.iter().position(|&c| c == self.id)?;
        siblings.get(at + 1).map(|&c| self.at(c))
    }

    pub(crate) fn walk(&self) -> Cursor {
        Cursor
    }

    pub(crate) fn children(&self, _: &mut Cursor) -> std::vec::IntoIter<Node<'t>> {
        self.d()
            .children
            .iter()
            .map(|&c| self.at(c))
            .collect::<Vec<_>>()
            .into_iter()
    }

    pub(crate) fn named_children(&self, _: &mut Cursor) -> std::vec::IntoIter<Node<'t>> {
        self.d()
            .children
            .iter()
            .map(|&c| self.at(c))
            .filter(Node::is_named)
            .collect::<Vec<_>>()
            .into_iter()
    }

    pub(crate) fn child_by_field_name(&self, field: &str) -> Option<Node<'t>> {
        self.d()
            .children
            .iter()
            .map(|&c| self.at(c))
            .find(|c| c.d().field == Some(field))
    }

    pub(crate) fn children_by_field_name(
        &self,
        field: &str,
        _: &mut Cursor,
    ) -> std::vec::IntoIter<Node<'t>> {
        self.d()
            .children
            .iter()
            .map(|&c| self.at(c))
            .filter(|c| c.d().field == Some(field))
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// The smallest node that spans `start..end`, as tree-sitter finds it.
    pub(crate) fn descendant_for_byte_range(&self, start: usize, end: usize) -> Option<Node<'t>> {
        let mut node = *self;
        'down: loop {
            for &c in &node.d().children {
                let child = self.at(c);
                let (cs, ce) = (child.start_byte(), child.end_byte());
                if ce < end || ce <= start {
                    continue;
                }
                if start < cs {
                    break;
                }
                node = child;
                continue 'down;
            }
            return Some(node);
        }
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

pub(crate) fn capture(node: Node<'_>) -> Option<&'static str> {
    let kind = node.kind();
    if !node.is_named() {
        return keyword_captures().get(kind).copied();
    }
    let parent = node.parent().map(|p| p.kind());
    let field = node.field_name();
    let under = |p: &str, f: &str| parent == Some(p) && field == Some(f);
    let capture = match kind {
        "command_name" if parent == Some("unknown_command") => "error",
        "identifier" | "parameter" if under("function_call", "name") => "function",
        "identifier" if parent == Some("type_name") => "type",
        "time_unit" if under("qualified_interval", "unit") => "constant",
        "index_name" | "cluster" => "type",
        "selector" | "metadata_field" => "constant",
        "policy_name" if under("enrich_policy", "name") => "type",
        "enrich_mode" if under("enrich_policy", "mode") => "constant",
        "identifier" if under("command_option", "name") => "keyword",
        "identifier" if under("fuse_command", "method") => "constant",
        "star" => "operator",
        "promql_text" | "unknown_text" => "string",
        "identifier" | "quoted_identifier" if parent == Some("qualified_name") => "property",
        "id_pattern" | "quoted_identifier" if parent == Some("name_pattern") => "property",
        "identifier" | "quoted_identifier" => "variable",
        "string" => "string",
        "number" => "number",
        "boolean" => "boolean",
        "null" | "parameter" => "constant",
        "comment" => "comment",
        _ => return None,
    };
    Some(capture)
}

/// The byte span of a node.
pub(crate) fn node_span(node: Node<'_>) -> ByteSpan {
    ByteSpan::new(node.start_byte(), node.end_byte())
}

/// Calls `f` on `root` and everything below it, in document order.
pub(crate) fn walk<'t>(root: Node<'t>, mut f: impl FnMut(Node<'t>)) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        f(node);
        let mut cursor = node.walk();
        let mut kids: Vec<_> = node.children(&mut cursor).collect();
        kids.reverse();
        stack.extend(kids);
    }
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
/// `JOIN_QUALIFIER` reads as an `identifier`, as in [`parse`].
pub(crate) fn production_names() -> Vec<&'static str> {
    (K::SOURCE_FILE as u16..=K::PARAMETER as u16)
        .map(|raw| <Lang as rowan::Language>::kind_from_raw(rowan::SyntaxKind(raw)))
        .filter(|kind| !matches!(kind, K::NAMED_PARAMETERS | K::JOIN_QUALIFIER))
        .map(node_name)
        .collect()
}

/// Whether the parser reported a problem in `source`, and the names of the
/// named nodes of its tree in preorder.
pub(crate) fn named_kinds(source: &str) -> (bool, Vec<&'static str>) {
    let tree = parse(source);
    let mut kinds = Vec::new();
    walk(tree.root_node(), |node| {
        if node.is_named() {
            kinds.push(node.kind());
        }
    });
    (!tree.problems.is_empty(), kinds)
}
