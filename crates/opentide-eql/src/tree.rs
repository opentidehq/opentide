//! The analysis's view of the rowan tree: an arena of nodes shaped like the tree-sitter tree
//! the analysis was written against, so it keeps its navigation (`kind`, `child_by_field_name`,
//! `named_children`, ...) unchanged.
//!
//! Named nodes are `eql.ungram`'s nodes under tree-sitter's names; keywords and punctuation are
//! anonymous children named by their text; a node tree-sitter made of one token (`identifier`,
//! `string`, `any`, ...) is a leaf; comments are named leaves in the deepest node they stand
//! strictly inside, as tree-sitter places extras. The flat runs of `or`, `and` and the
//! arithmetic operators are nested to the left, as tree-sitter nested them; the arena is built
//! and walked without recursion, so a 20,000-term chain costs no stack. Fields are the
//! grammar's, given by position. `Node` is `Copy`, as tree-sitter's is.

use crate::parser;
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use opentide_core::ByteSpan;
use rowan::{NodeOrToken, WalkEvent};

/// What the parser reported.
#[derive(Clone, Debug)]
pub(crate) struct Problem {
    /// Where: the gap before the token it sits at.
    pub(crate) span: ByteSpan,
    /// The token it sits at (empty at the end of the source).
    pub(crate) token: ByteSpan,
    /// What the parser said.
    pub(crate) message: String,
    /// What it expected there, as words (`"`where`, or `(`"`).
    pub(crate) expected: Option<String>,
    /// Whether the toolkit's depth guard said it.
    pub(crate) too_deep: bool,
}

struct Data {
    kind: &'static str,
    named: bool,
    start: usize,
    end: usize,
    parent: Option<u32>,
    children: Vec<u32>,
    field: Option<&'static str>,
}

/// A parsed query.
pub(crate) struct Tree {
    data: Vec<Data>,
    pub(crate) problems: Vec<Problem>,
    /// A small value an analysis pass computed for a node, kept so that a pass over a long
    /// left-nested run reads each node once (`semantics`' operand types).
    memo: std::cell::RefCell<std::collections::HashMap<u32, u8>>,
}

/// Stands where tree-sitter's cursor stood: iteration needs none.
pub(crate) struct Cursor;

/// A node of a [`Tree`].
#[derive(Clone, Copy)]
pub(crate) struct Node<'t> {
    tree: &'t Tree,
    id: u32,
}

/// Tree-sitter's name of a node kind.
fn node_name(kind: K) -> &'static str {
    match kind {
        K::SOURCE_FILE => "source_file",
        K::EVENT_QUERY => "event_query",
        K::ANY => "any",
        K::EVENT_CATEGORY => "event_category",
        K::SEQUENCE => "sequence",
        K::SEQUENCE_PARAMS => "sequence_params",
        K::TIME_UNIT => "time_unit",
        K::SAMPLE => "sample",
        K::JOIN => "join",
        K::JOIN_KEYS => "join_keys",
        K::JOIN_TERM => "join_term",
        K::SEQUENCE_TERM => "sequence_term",
        K::TERM_OPTION => "term_option",
        K::SUBQUERY => "subquery",
        K::MISSING_EVENT_OPEN => "missing_event_open",
        K::PIPE_STAGE => "pipe",
        K::OR_EXPRESSION => "or_expression",
        K::AND_EXPRESSION => "and_expression",
        K::NOT_EXPRESSION => "not_expression",
        K::RELATIONSHIP => "relationship",
        K::COMPARISON => "comparison",
        K::UNARY_EXPRESSION => "unary_expression",
        K::BINARY_EXPRESSION => "binary_expression",
        K::PREDICATE_EXPRESSION => "predicate_expression",
        K::PARENTHESIZED_EXPRESSION => "parenthesized_expression",
        K::FUNCTION_CALL => "function_call",
        K::CASE_INSENSITIVE_NAME => "case_insensitive_name",
        K::FIELD => "field",
        K::OPTIONAL_MARKER => "optional_marker",
        K::INDEX => "index",
        K::IDENTIFIER => "identifier",
        K::QUOTED_IDENTIFIER => "quoted_identifier",
        K::NULL => "null",
        K::BOOLEAN => "boolean",
        K::NUMBER => "number",
        K::STRING => "string",
        _ => "ERROR",
    }
}

/// Nodes that are one token in tree-sitter: no children. (`boolean` is not one: tree-sitter
/// keeps its `true` or `false` as an anonymous child.)
fn is_leaf(kind: K) -> bool {
    matches!(
        kind,
        K::ANY
            | K::MISSING_EVENT_OPEN
            | K::CASE_INSENSITIVE_NAME
            | K::OPTIONAL_MARKER
            | K::INDEX
            | K::IDENTIFIER
            | K::QUOTED_IDENTIFIER
            | K::NULL
            | K::NUMBER
            | K::STRING
    )
}

/// The flat runs tree-sitter nested to the left, as `(left, right)` children of one node each.
fn is_run(kind: K) -> bool {
    matches!(
        kind,
        K::OR_EXPRESSION | K::AND_EXPRESSION | K::BINARY_EXPRESSION
    )
}

/// The parser's errors, each with the token it stops at.
fn problems(root: &SyntaxNode, errors: &[opentide_parse::SyntaxError]) -> Vec<Problem> {
    errors
        .iter()
        .map(|e| {
            let at = usize::from(e.gap.end());
            let end = root
                .token_at_offset(e.gap.end())
                .right_biased()
                .filter(|t| usize::from(t.text_range().start()) == at)
                .map_or(at, |t| usize::from(t.text_range().end()));
            Problem {
                span: ByteSpan::new(usize::from(e.gap.start()), at),
                token: ByteSpan::new(at, end),
                message: e.message.clone(),
                expected: opentide_parse::describe_expected(e.expected, |k| {
                    K::from_raw(k).describe()
                }),
                too_deep: matches!(
                    e.kind,
                    opentide_parse::ErrorKind::TooDeep { .. }
                        | opentide_parse::ErrorKind::TreeTooDeep { .. }
                ),
            }
        })
        .collect()
}

/// Parses `source` into the analysis's tree.
pub(crate) fn parse(source: &str) -> Tree {
    let parse = parser::parse(source);
    let root = SyntaxNode::new_root(parse.green);
    let problems = problems(&root, &parse.errors);
    let mut tree = Tree {
        data: Vec::new(),
        problems,
        memo: std::cell::RefCell::default(),
    };
    let mut open: Vec<u32> = Vec::new();
    let mut skip = 0usize;
    let mut comments = Vec::new();
    for event in root.preorder_with_tokens() {
        match event {
            WalkEvent::Enter(NodeOrToken::Node(node)) => {
                if skip > 0 {
                    skip += 1;
                    continue;
                }
                let kind = node.kind();
                // A leaf spans its token; any other node is trimmed to its children on leaving.
                let r = node
                    .children_with_tokens()
                    .filter_map(NodeOrToken::into_token)
                    .find(|t| !t.kind().is_trivia())
                    .map_or_else(|| node.text_range(), |t| t.text_range());
                let id = tree.push(
                    open.last().copied(),
                    node_name(kind),
                    true,
                    usize::from(r.start()),
                    usize::from(r.end()),
                );
                if is_leaf(kind) {
                    skip = 1;
                }
                open.push(id);
            }
            WalkEvent::Leave(NodeOrToken::Node(node)) => {
                if skip > 0 {
                    skip -= 1;
                    if skip > 0 {
                        continue;
                    }
                }
                if let Some(id) = open.pop() {
                    if is_run(node.kind()) {
                        tree.nest(id);
                    }
                    tree.trim(id);
                }
            }
            WalkEvent::Enter(NodeOrToken::Token(token)) => {
                if skip > 0 {
                    continue;
                }
                let r = token.text_range();
                let span = (usize::from(r.start()), usize::from(r.end()));
                match token.kind() {
                    K::WHITESPACE => {}
                    K::LINE_COMMENT | K::BLOCK_COMMENT => comments.push(span),
                    _ => {
                        let name = token_name(token.kind(), token.text());
                        tree.push(open.last().copied(), name, false, span.0, span.1);
                    }
                }
            }
            WalkEvent::Leave(NodeOrToken::Token(_)) => {}
        }
    }
    if let Some(root) = tree.data.first_mut() {
        // The root spans the source, as tree-sitter's does.
        root.start = 0;
        root.end = source.len();
    }
    tree.place_comments(&comments);
    for id in 0..tree.data.len() {
        assign_fields(&mut tree.data, u32::try_from(id).unwrap_or(u32::MAX));
    }
    tree
}

/// The name of an anonymous token: its text (a keyword, an operator, a bracket).
fn token_name(kind: K, text: &str) -> &'static str {
    match kind {
        K::IN_TILDE => "in~",
        K::LIKE_TILDE => "like~",
        K::REGEX_TILDE => "regex~",
        K::PIPE => "|",
        K::EQ => "=",
        K::EQ_EQ => "==",
        K::NOT_EQ => "!=",
        K::LT => "<",
        K::LT_EQ => "<=",
        K::GT => ">",
        K::GT_EQ => ">=",
        K::PLUS => "+",
        K::MINUS => "-",
        K::STAR => "*",
        K::SLASH => "/",
        K::PERCENT => "%",
        K::L_PAREN => "(",
        K::R_PAREN => ")",
        K::L_BRACK => "[",
        K::R_BRACK => "]",
        K::COMMA => ",",
        K::DOT => ".",
        K::COLON => ":",
        K::QUESTION => "?",
        K::BANG_L_BRACK => "![",
        // A keyword is lower case: its text is its name.
        _ if let Some(keyword) = crate::KEYWORD_WORDS.iter().find(|k| **k == text) => keyword,
        // A name or a literal with no node of its own stands in an error region; it is named by
        // what it is, so that highlighting still reads it.
        K::WORD => ERROR_WORD,
        K::TILDE_WORD => ERROR_TILDE_WORD,
        K::QUOTED_IDENT_TOKEN => ERROR_QUOTED,
        K::STRING_TOKEN => ERROR_STRING,
        K::NUMBER_TOKEN => ERROR_NUMBER,
        _ => "ERROR",
    }
}

/// Anonymous tokens in an error region, by what the lexer cut.
const ERROR_WORD: &str = "ERROR word";
const ERROR_TILDE_WORD: &str = "ERROR tilde_word";
const ERROR_QUOTED: &str = "ERROR quoted_identifier";
const ERROR_STRING: &str = "ERROR string";
const ERROR_NUMBER: &str = "ERROR number";

impl Tree {
    fn push(
        &mut self,
        parent: Option<u32>,
        kind: &'static str,
        named: bool,
        start: usize,
        end: usize,
    ) -> u32 {
        let id = u32::try_from(self.data.len()).unwrap_or(u32::MAX);
        self.data.push(Data {
            kind,
            named,
            start,
            end,
            parent,
            children: Vec::new(),
            field: None,
        });
        if let Some(p) = parent {
            self.data[p as usize].children.push(id);
        }
        id
    }

    /// A node's span is its children's, as tree-sitter's is (rowan's takes in trivia).
    fn trim(&mut self, id: u32) {
        let d = &self.data[id as usize];
        if let (Some(&first), Some(&last)) = (d.children.first(), d.children.last()) {
            let (start, end) = (
                self.data[first as usize].start,
                self.data[last as usize].end,
            );
            let d = &mut self.data[id as usize];
            d.start = start;
            d.end = end;
        }
    }

    /// Re-nests a flat run `a op b op c` as `((a op b) op c)`: `id` keeps the outermost pair.
    fn nest(&mut self, id: u32) {
        let kids = self.data[id as usize].children.clone();
        if kids.len() <= 3 {
            return;
        }
        let kind = self.data[id as usize].kind;
        let mut left = kids[0];
        let mut i = 1;
        // Every pair but the last becomes a new node holding the previous one.
        while i + 2 < kids.len() {
            let start = self.data[left as usize].start;
            let end = self.data[kids[i + 1] as usize].end;
            let inner = self.push(None, kind, true, start, end);
            for &child in &[left, kids[i], kids[i + 1]] {
                self.data[child as usize].parent = Some(inner);
                self.data[inner as usize].children.push(child);
            }
            self.data[inner as usize].parent = Some(id);
            left = inner;
            i += 2;
        }
        let rest = &kids[kids.len() - 2..];
        let mut children = vec![left];
        children.extend_from_slice(rest);
        self.data[id as usize].children = children;
    }

    /// Puts each comment (in document order) in the deepest node it stands strictly inside (a
    /// child before it and one after it), else in the root. A node's children are in order and
    /// do not overlap, so each level is a binary search, and each node's comments are merged
    /// into its children once: linear in the comments, where an insert per comment was not.
    fn place_comments(&mut self, comments: &[(usize, usize)]) {
        if self.data.is_empty() {
            return;
        }
        let mut placed: Vec<(u32, u32)> = Vec::with_capacity(comments.len());
        for &(start, end) in comments {
            let node = self.comment_parent(start, end);
            let id = self.push(None, "comment", true, start, end);
            self.data[id as usize].parent = Some(node);
            placed.push((node, id));
        }
        // Stable: a node's comments stay in document order.
        placed.sort_by_key(|&(node, _)| node);
        for group in placed.chunk_by(|a, b| a.0 == b.0) {
            let node = group[0].0 as usize;
            let kids = std::mem::take(&mut self.data[node].children);
            let mut merged = Vec::with_capacity(kids.len() + group.len());
            let mut pending = group.iter().map(|&(_, id)| id).peekable();
            for kid in kids {
                let kid_start = self.data[kid as usize].start;
                while let Some(&c) = pending.peek() {
                    if self.data[c as usize].end > kid_start {
                        break;
                    }
                    merged.push(c);
                    pending.next();
                }
                merged.push(kid);
            }
            merged.extend(pending);
            self.data[node].children = merged;
        }
    }

    /// The deepest node a comment at `start..end` stands strictly inside.
    fn comment_parent(&self, start: usize, end: usize) -> u32 {
        let mut node = 0u32;
        loop {
            let kids = &self.data[node as usize].children;
            // The only child that can hold the comment: the last one starting before it.
            let i = kids.partition_point(|&k| self.data[k as usize].start < start);
            let Some(&c) = i.checked_sub(1).and_then(|i| kids.get(i)) else {
                return node;
            };
            let child = &self.data[c as usize];
            let (Some(&first), Some(&last)) = (child.children.first(), child.children.last())
            else {
                return node;
            };
            let inside = child.named
                && child.start < start
                && end < child.end
                && self.data[first as usize].end <= start
                && self.data[last as usize].start >= end;
            if !inside {
                return node;
            }
            node = c;
        }
    }

    pub(crate) fn root_node(&self) -> Node<'_> {
        Node { tree: self, id: 0 }
    }
}

/// The fields of `id`'s children, by the grammar's positions.
#[expect(clippy::too_many_lines, reason = "one arm per node kind with fields")]
fn assign_fields(data: &mut [Data], id: u32) {
    let kids = data[id as usize].children.clone();
    let kind = data[id as usize].kind;
    let k = |i: usize| data[kids[i] as usize].kind;
    let named = |i: usize| data[kids[i] as usize].named && k(i) != "comment";
    let n = kids.len();
    let named_ix: Vec<usize> = (0..n).filter(|&i| named(i)).collect();
    let pos = |tok: &str| (0..n).find(|&i| k(i) == tok);
    let mut set: Vec<(usize, &'static str)> = Vec::new();
    match kind {
        "source_file" => {
            for &i in &named_ix {
                set.push((i, if k(i) == "pipe" { "pipe" } else { "query" }));
            }
        }
        "event_query" | "subquery" => {
            if let Some(i) = pos("[").or_else(|| pos("missing_event_open")) {
                set.push((i, "open"));
            }
            for &i in &named_ix {
                match k(i) {
                    "any" | "event_category" => set.push((i, "category")),
                    "missing_event_open" => {}
                    _ => set.push((i, "condition")),
                }
            }
        }
        "sequence" | "sample" | "join" => {
            let until = pos("until");
            for &i in &named_ix {
                match k(i) {
                    "join_keys" => set.push((i, "by")),
                    "sequence_term" | "join_term" if until.is_some_and(|u| i > u) => {
                        set.push((i, "until"));
                    }
                    "sequence_term" | "join_term" => set.push((i, "term")),
                    _ => {}
                }
            }
        }
        "sequence_params" => named_ix.iter().for_each(|&i| set.push((i, "maxspan"))),
        "time_unit" => {
            for &i in &named_ix {
                set.push((i, if k(i) == "number" { "value" } else { "unit" }));
            }
        }
        "join_term" | "sequence_term" => {
            for &i in &named_ix {
                if k(i) == "join_keys" {
                    set.push((i, "by"));
                }
            }
        }
        "term_option" => {
            for &i in &named_ix {
                set.push((i, if k(i) == "number" { "value" } else { "key" }));
            }
        }
        "pipe" => {
            for (j, &i) in named_ix.iter().enumerate() {
                set.push((i, if j == 0 { "name" } else { "arguments" }));
            }
            // The field spans the comma list, commas included.
            if let Some(&first) = named_ix.get(1) {
                (first..n)
                    .filter(|&i| k(i) == ",")
                    .for_each(|i| set.push((i, "arguments")));
            }
        }
        "function_call" => {
            if let Some(&i) = named_ix.first() {
                set.push((i, "name"));
            }
            for &i in named_ix.iter().skip(1) {
                set.push((i, "arguments"));
            }
            if let Some(open) = pos("(") {
                (open + 1..n)
                    .filter(|&i| k(i) == ",")
                    .for_each(|i| set.push((i, "arguments")));
            }
        }
        "or_expression" | "and_expression" | "comparison" | "binary_expression" => {
            if let Some(&i) = named_ix.first() {
                set.push((i, "left"));
            }
            if let Some(&i) = named_ix.get(1) {
                set.push((i, "right"));
            }
            if kind != "or_expression"
                && kind != "and_expression"
                && let Some(i) = (0..n).find(|&i| !named(i) && k(i) != "comment")
            {
                set.push((i, "operator"));
            }
        }
        "not_expression" | "unary_expression" => {
            if let Some(&i) = named_ix.first() {
                set.push((i, "operand"));
            }
            if kind == "unary_expression" && n > 0 && !named(0) {
                set.push((0, "operator"));
            }
        }
        "relationship" => {
            for &i in &named_ix {
                set.push((
                    i,
                    if k(i) == "subquery" {
                        "subquery"
                    } else {
                        "relation"
                    },
                ));
            }
        }
        "predicate_expression" => {
            if let Some(&i) = named_ix.first() {
                set.push((i, "subject"));
            }
            for i in 0..n {
                match k(i) {
                    "not" => set.push((i, "negated")),
                    "in" | "in~" | ":" | "like" | "like~" | "regex" | "regex~" => {
                        set.push((i, "operator"));
                    }
                    "," => set.push((i, "values")),
                    _ => {}
                }
            }
            for &i in named_ix.iter().skip(1) {
                set.push((i, "values"));
            }
        }
        "field" => {
            if let Some(i) = pos("optional_marker") {
                set.push((i, "optional"));
            }
        }
        _ => {}
    }
    for (i, field) in set {
        let child = &mut data[kids[i] as usize];
        if child.field.is_none() {
            child.field = Some(field);
        }
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

    /// The value [`Node::remember`] kept for this node.
    pub(crate) fn remembered(&self) -> Option<u8> {
        self.tree.memo.borrow().get(&self.id).copied()
    }

    /// Keeps `value` for this node.
    pub(crate) fn remember(&self, value: u8) {
        self.tree.memo.borrow_mut().insert(self.id, value);
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

    /// Whether the parser reported a problem inside this node, or it holds an error node.
    pub(crate) fn has_error(&self) -> bool {
        let d = self.d();
        self.kind() == "ERROR"
            || self.tree.problems.iter().any(|p| {
                (p.token.start >= d.start && p.token.start < d.end)
                    || (p.span.start > d.start && p.span.start <= d.end)
            })
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

    pub(crate) fn named_child(&self, i: usize) -> Option<Node<'t>> {
        self.named_children(&mut Cursor).nth(i)
    }

    pub(crate) fn named_child_count(&self) -> usize {
        self.named_children(&mut Cursor).count()
    }

    pub(crate) fn walk(&self) -> Cursor {
        Cursor
    }

    pub(crate) fn children(&self, _: &mut Cursor) -> std::vec::IntoIter<Node<'t>> {
        let kids: Vec<_> = self.d().children.iter().map(|&c| self.at(c)).collect();
        kids.into_iter()
    }

    pub(crate) fn named_children(&self, cursor: &mut Cursor) -> std::vec::IntoIter<Node<'t>> {
        let kids: Vec<_> = self.children(cursor).filter(Node::is_named).collect();
        kids.into_iter()
    }

    pub(crate) fn child_by_field_name(&self, field: &str) -> Option<Node<'t>> {
        self.children(&mut Cursor)
            .find(|c| c.d().field == Some(field))
    }

    pub(crate) fn children_by_field_name(
        &self,
        field: &str,
        cursor: &mut Cursor,
    ) -> std::vec::IntoIter<Node<'t>> {
        let kids: Vec<_> = self
            .children(cursor)
            .filter(|c| c.d().field == Some(field))
            .collect();
        kids.into_iter()
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

/// The byte span of a node.
pub(crate) fn node_span(node: Node<'_>) -> ByteSpan {
    ByteSpan::new(node.start_byte(), node.end_byte())
}

/// Calls `f` on `root` and everything below it, in document order.
pub(crate) fn walk<'t>(root: Node<'t>, mut f: impl FnMut(Node<'t>)) {
    walk_with_ancestors(root, |node, _| f(node));
}

/// Calls `f` on `root` and everything below it, in document order, with the node's ancestors
/// (the outermost first), without recursing.
pub(crate) fn walk_with_ancestors<'t>(root: Node<'t>, mut f: impl FnMut(Node<'t>, &[Node<'t>])) {
    let mut ancestors: Vec<Node<'t>> = Vec::new();
    // Each entry: a node, and how many ancestors it has.
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        ancestors.truncate(depth);
        f(node, &ancestors);
        ancestors.push(node);
        let kids = &node.d().children;
        stack.extend(kids.iter().rev().map(|&c| (node.at(c), depth + 1)));
    }
}

/// The highlight capture of a leaf, by the patterns of `highlights.scm` in their order (the
/// first that matches wins): what `capture(token, parent)` becomes on this tree.
pub(crate) fn capture(node: Node<'_>) -> Option<&'static str> {
    let kind = node.kind();
    // A name or a literal in an error region reads as it would in a query that parses.
    match kind {
        ERROR_WORD | ERROR_QUOTED => return Some("variable"),
        ERROR_TILDE_WORD => return Some("function"),
        ERROR_STRING => return Some("string"),
        ERROR_NUMBER => return Some("number"),
        _ => {}
    }
    // `(boolean) @boolean`: the node is not a leaf here, its `true` or `false` is.
    if !node.is_named() && node.parent().is_some_and(|p| p.kind() == "boolean") {
        return Some("boolean");
    }
    if !node.is_named() {
        return opentide_highlight::keywords(opentide_core::LanguageId::Eql)?
            .iter()
            .find(|(token, _)| *token == kind)
            .map(|(_, capture)| capture.name());
    }
    let parent = node.parent().map(|p| p.kind());
    let field = node.field_name();
    let under = |p: &str, f: &str| parent == Some(p) && field == Some(f);
    Some(match kind {
        "identifier" if under("relationship", "relation") => "error",
        "identifier" if under("pipe", "name") || under("term_option", "key") => "keyword",
        "identifier" if under("time_unit", "unit") => "constant",
        "identifier" | "string" if parent == Some("event_category") => "type",
        "any" => "type",
        "identifier" | "case_insensitive_name" if under("function_call", "name") => "function",
        "identifier" | "quoted_identifier" if parent == Some("field") => "property",
        "index" | "number" => "number",
        "optional_marker" | "missing_event_open" => "operator",
        "identifier" | "quoted_identifier" => "variable",
        "string" => "string",
        "boolean" => "boolean",
        "null" => "constant",
        "comment" => "comment",
        _ => return None,
    })
}
