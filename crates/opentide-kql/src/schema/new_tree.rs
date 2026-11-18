//! The column pass of [`super`] on the new tree (#1230): the same schemas,
//! references, definitions and diagnostics as the tree-sitter pass, from the
//! nodes of `kql.ungram`. The schema logic that reads no tree (sources,
//! unions, aggregate names, types, the column checks) is the parent's.

use super::{
    AggArg, Analysis, Column, Ctx, Definition, Item, Known, LITERAL_FUNCTIONS, MadeBy, Pipeline,
    Primary, Reference, Schema, Source, Stage, aggregate_columns_for, asim_schema, glob_matches,
    merge_union, mismatch_message, primary_type, reshaped, resolve_column, source_schema,
    type_mismatch, unknown_column,
};
use crate::Catalog;
use crate::syntax::{SyntaxKind as K, SyntaxNode, SyntaxToken};
use crate::syntax_util::{
    child as child_of, ident, legacy_kind, literal_kind, name, simple_call, simple_ident,
    simple_primary, span, text, token_span, tokens,
};
use opentide_core::{ByteSpan, Diagnostic, LineIndex, codes};
use rowan::TextRange;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Runs the pass over a parsed query; diagnostics only when it parsed
/// without an error (`clean`).
pub(crate) fn analyze(root: &SyntaxNode, source: &str, catalog: &Catalog, clean: bool) -> Analysis {
    run(root, source, catalog, clean).out
}

fn run<'a>(root: &SyntaxNode, source: &'a str, catalog: &'a Catalog, clean: bool) -> Pass<'a> {
    let mut pass = Pass {
        source,
        catalog,
        lines: LineIndex::new(source),
        out: Analysis::default(),
        diagnose: clean,
        depth: 0,
        function_schemas: HashMap::new(),
        bodies_read: 0,
    };
    let mut scope = Scope::default();
    for child in root.children() {
        match child.kind() {
            K::LET_STATEMENT => pass.let_statement(&child, &mut scope),
            K::QUERY => {
                if let Some(body) = child_of(&child, K::TABULAR_EXPRESSION) {
                    pass.tabular(&body, &scope);
                }
            }
            _ => {}
        }
    }
    pass
}

/// Names a scope binds: they are never columns. A function body's scope is
/// a layer over the scope it is defined in ([`Scope::inner`]), not a copy of
/// it: copying made a chain of `n` functions quadratic (#1424). A name is
/// looked up in each layer, innermost first, map by map, as in a copy that
/// the body's bindings were inserted into.
#[derive(Default)]
struct Scope<'p> {
    outer: Option<&'p Scope<'p>>,
    tabular: HashMap<String, Schema>,
    functions: HashMap<String, SyntaxNode>,
    scalars: BTreeSet<String>,
}

impl<'p> Scope<'p> {
    /// An empty layer over `outer`.
    fn inner(outer: &'p Scope<'p>) -> Self {
        Scope {
            outer: Some(outer),
            ..Scope::default()
        }
    }

    /// This layer and the ones it is over, innermost first.
    fn layers(&self) -> impl Iterator<Item = &Scope<'p>> {
        std::iter::successors(Some(self), |s| s.outer)
    }

    fn tabular(&self, name: &str) -> Option<&Schema> {
        self.layers().find_map(|s| s.tabular.get(name))
    }

    fn function(&self, name: &str) -> Option<&SyntaxNode> {
        self.layers().find_map(|s| s.functions.get(name))
    }

    fn binds(&self, name: &str) -> bool {
        self.layers().any(|s| {
            s.scalars.contains(name)
                || s.tabular.contains_key(name)
                || s.functions.contains_key(name)
        })
    }
}

struct Pass<'a> {
    source: &'a str,
    catalog: &'a Catalog,
    /// One line index for every range of the analysis.
    lines: LineIndex<'a>,
    out: Analysis,
    diagnose: bool,
    /// What the walk down the tree has spent of [`BUDGET`].
    depth: u32,
    /// What each `let` function's body returns, read once where the
    /// function is defined (with the names in scope there, as Kusto binds
    /// them) and keyed by the definition's range: a call reuses it. Reading
    /// the body again at each call made a chain of functions that call the
    /// one before quadratic, and exponential when each calls it twice (#1424).
    function_schemas: HashMap<TextRange, Option<Schema>>,
    /// How many function bodies the pass has read: the work counter the
    /// tests hold to one per definition.
    bodies_read: usize,
}

/// How deep the pass walks, so that it never overflows a 1 MB stack (the
/// browser's): a level of an expression costs 1, a level of a pipeline (a
/// tabular expression, a subquery, a function body) costs [`PIPELINE`],
/// which has about twelve times its stack (a debug build: about 1.2 KB a
/// level of expression, 15 KB a level of nested `join`). Past it the pass
/// reads nothing deeper: a pipeline's schema is open. The parser's nesting
/// limit bounds the expressions and pipelines a query nests, but not a chain
/// of members (`a.b.c`) or indexes, which the pass reads as nested nodes.
const BUDGET: u32 = 480;
/// What a level of a pipeline costs of [`BUDGET`]: 40 nested pipelines, more
/// than the 35 levels the tree-sitter engine took.
const PIPELINE: u32 = 12;

/// Matches a quirk of the tree-sitter pass: it read the items of `project`,
/// `extend` and either list of `summarize` by a field that also holds the
/// commas between them, and took each comma for an item it cannot name, so
/// a list of two or more items leaves the schema open (no column
/// diagnostic after it). Kept for parity with the engine this one replaces
/// (epic #1219); #1386 removes it after the port, behind a measurement of
/// every new `kql_unknown_column` over the corpora.
fn comma_quirk(out: &mut Schema, items: usize) {
    if items >= 2 {
        out.make_open();
    }
}

/// The child nodes of an operator that are not one of `skip`.
fn nodes_but(node: &SyntaxNode, skip: &[K]) -> Vec<SyntaxNode> {
    node.children()
        .filter(|c| !skip.contains(&c.kind()))
        .collect()
}

/// The child node right after the token `kind` (`limit` of `mv-expand`).
fn node_after(node: &SyntaxNode, kind: K) -> Option<SyntaxNode> {
    let at = tokens(node).find(|t| t.kind() == kind)?.text_range().end();
    node.children().find(|c| c.text_range().start() >= at)
}

/// The value of an assignment (`A = value`, `(A, B) = value`) or a named
/// argument: its last child node.
fn value_of(node: &SyntaxNode) -> Option<SyntaxNode> {
    node.children().last()
}

fn is_assignment(node: &SyntaxNode) -> bool {
    matches!(node.kind(), K::ASSIGNMENT | K::TUPLE_ASSIGNMENT)
}

impl<'a> Pass<'a> {
    fn text(&self, node: &SyntaxNode) -> &'a str {
        if node.kind() == K::NAME_REF {
            name(self.source, node)
        } else {
            text(self.source, node)
        }
    }

    /// A token's text, borrowed from the source.
    fn token(&self, token: &SyntaxToken) -> &'a str {
        let r = token.text_range();
        &self.source[usize::from(r.start())..usize::from(r.end())]
    }

    fn token_text(token: &SyntaxToken) -> String {
        token.text().to_owned()
    }

    fn named_source(&self, word: &str, scope: &Scope) -> Option<Schema> {
        if let Some(schema) = scope.tabular(word) {
            return Some(schema.clone());
        }
        source_schema(self.catalog, word, &HashMap::new(), scope.binds(word))
    }

    // --- bindings ---------------------------------------------------------

    fn let_statement(&mut self, node: &SyntaxNode, scope: &mut Scope) {
        let Some(name) = ident(node).map(|t| Self::token_text(&t)) else {
            return;
        };
        let Some(value) = node.first_child() else {
            return;
        };
        match value.kind() {
            K::TABULAR_EXPRESSION => {
                let mut schema = self.tabular(&value, scope);
                schema.source = Source::Let(name.clone());
                scope.tabular.insert(name, schema);
            }
            K::FUNCTION_DEFINITION => {
                let schema = self.function_schema(&value, scope);
                self.function_schemas.insert(value.text_range(), schema);
                scope.functions.insert(name, value);
            }
            _ => {
                if let Some(ident) = simple_ident(&value) {
                    let word = self.text(&ident);
                    if let Some(mut schema) = self.named_source(word, scope) {
                        schema.source = Source::Let(name.clone());
                        scope.tabular.insert(name, schema);
                        return;
                    }
                }
                self.expression(&value, Ctx::One(&Schema::open()), scope, span(node), &[]);
                scope.scalars.insert(name);
            }
        }
    }

    /// Runs `walk` one level deeper, or gives `None` past the budget.
    fn deeper<T>(&mut self, cost: u32, walk: impl FnOnce(&mut Self) -> T) -> Option<T> {
        if self.depth + cost > BUDGET {
            return None;
        }
        self.depth += cost;
        let out = walk(self);
        self.depth -= cost;
        Some(out)
    }

    fn function_schema(&mut self, def: &SyntaxNode, outer: &Scope) -> Option<Schema> {
        self.deeper(PIPELINE, |pass| pass.function_schema_at(def, outer))
            .flatten()
    }

    fn function_schema_at(&mut self, def: &SyntaxNode, outer: &Scope) -> Option<Schema> {
        self.bodies_read += 1;
        let mut scope = Scope::inner(outer);
        let mut body = None;
        for child in def.children() {
            match child.kind() {
                K::PARAMETER => {
                    let Some(name) = ident(&child).map(|t| Self::token_text(&t)) else {
                        continue;
                    };
                    let tabular = child_of(&child, K::TYPE)
                        .is_some_and(|t| self.text(&t).trim_start().starts_with('('));
                    if tabular {
                        let mut schema = Schema::open();
                        schema.source = Source::Let(name.clone());
                        scope.tabular.insert(name, schema);
                    } else {
                        scope.scalars.insert(name);
                    }
                }
                K::LET_STATEMENT => self.let_statement(&child, &mut scope),
                K::ERROR => {}
                _ => body = Some(child),
            }
        }
        let body = body?;
        if body.kind() == K::TABULAR_EXPRESSION {
            return Some(self.tabular(&body, &scope));
        }
        if let Some(ident) = simple_ident(&body)
            && let Some(schema) = self.named_source(self.text(&ident), &scope)
        {
            return Some(schema);
        }
        self.expression(&body, Ctx::One(&Schema::open()), &scope, span(&body), &[]);
        None
    }

    // --- tabular expressions ---------------------------------------------

    fn tabular(&mut self, expr: &SyntaxNode, scope: &Scope) -> Schema {
        self.deeper(PIPELINE, |pass| pass.tabular_at(expr, scope))
            .unwrap_or_else(Schema::open)
    }

    fn tabular_at(&mut self, expr: &SyntaxNode, scope: &Scope) -> Schema {
        let expr_span = span(expr);
        let Some(source) = child_of(expr, K::TABULAR_SOURCE) else {
            return Schema::open();
        };
        let mut schema = self.primary(&source, scope);
        let start = schema.clone();
        let mut stages = Vec::new();
        for op in nodes_but(expr, &[K::TABULAR_SOURCE, K::ERROR]) {
            let input = schema;
            let output = self.operator(&op, input.clone(), scope);
            stages.push(Stage {
                operator: legacy_kind(op.kind()),
                span: span(&op),
                input,
                output: output.clone(),
            });
            schema = output;
        }
        self.out.pipelines.push(Pipeline {
            span: expr_span,
            source: start,
            stages,
        });
        schema
    }

    fn subquery(&mut self, node: &SyntaxNode, input: Schema, scope: &Scope) -> Schema {
        self.deeper(PIPELINE, |pass| pass.subquery_at(node, input, scope))
            .unwrap_or_else(Schema::open)
    }

    fn subquery_at(&mut self, node: &SyntaxNode, input: Schema, scope: &Scope) -> Schema {
        let mut schema = input;
        for op in nodes_but(node, &[K::ERROR]) {
            schema = self.operator(&op, schema, scope);
        }
        schema
    }

    /// The schema of a pipeline's source (`TABULAR_SOURCE`, or what it holds).
    fn primary(&mut self, node: &SyntaxNode, scope: &Scope) -> Schema {
        let inner = if node.kind() == K::TABULAR_SOURCE {
            match node.first_child() {
                Some(inner) => inner,
                None => return Schema::open(),
            }
        } else {
            node.clone()
        };
        match inner.kind() {
            K::TABLE_REF => {
                let word = ident(&inner)
                    .map(|t| Self::token_text(&t))
                    .unwrap_or_default();
                self.named_source(&word, scope).unwrap_or_else(|| {
                    let mut schema = Schema::open();
                    if !scope.binds(&word) {
                        schema.source = Source::Named(word.clone());
                    }
                    schema
                })
            }
            K::PAREN_TABULAR | K::MATERIALIZE_EXPRESSION => child_of(&inner, K::TABULAR_EXPRESSION)
                .map(|b| self.tabular(&b, scope))
                .unwrap_or_else(Schema::open),
            K::DATATABLE_EXPRESSION | K::EXTERNALDATA_EXPRESSION => self.datatable(&inner),
            K::RANGE_OPERATOR => {
                let column = ident(&inner)
                    .map(|t| Self::token_text(&t))
                    .unwrap_or_default();
                Schema::closed(vec![Column::new(column, None)], Source::Literal)
            }
            K::PRINT_OPERATOR => self.print(&inner, scope),
            K::UNION_OPERATOR => self.union(&inner, None, scope),
            K::FUNCTION_CALL => self.call_source(&inner, scope),
            _ => Schema::open(),
        }
    }

    fn call_source(&mut self, call: &SyntaxNode, scope: &Scope) -> Schema {
        let name = ident(call)
            .map(|t| Self::token_text(&t))
            .unwrap_or_default();
        let call_span = span(call);
        let args: Vec<SyntaxNode> = call.children().collect();
        for arg in &args {
            let value = if arg.kind() == K::NAMED_ARGUMENT {
                value_of(arg)
            } else {
                Some(arg.clone())
            };
            if let Some(value) = value {
                self.expression(&value, Ctx::One(&Schema::open()), scope, call_span, &[]);
            }
        }
        if name == "table" {
            // `table("SigninLogs")`
            if let Some(arg) = args.first().and_then(simple_primary)
                && literal_kind(&arg) == Some(K::STRING)
            {
                let text = self.text(&arg);
                let table = text.trim_matches(|c| c == '"' || c == '\'' || c == '@');
                return self.named_source(table, scope).unwrap_or_else(Schema::open);
            }
            return Schema::open();
        }
        if let Some(def) = scope.function(&name) {
            // Its body was read where it was defined. A function cannot call
            // itself: its name is bound after its body is read.
            return self
                .function_schemas
                .get(&def.text_range())
                .cloned()
                .flatten()
                .map(|mut s| {
                    s.source = Source::Let(name.clone());
                    s
                })
                .unwrap_or_else(Schema::open);
        }
        if !scope.binds(&name)
            && let Some(schema) = asim_schema(self.catalog, &name)
        {
            return schema;
        }
        Schema::open()
    }

    fn datatable(&self, node: &SyntaxNode) -> Schema {
        let columns = node
            .children()
            .filter(|c| c.kind() == K::DATATABLE_COLUMN)
            .filter_map(|c| {
                let name = ident(&c)?;
                let ty = child_of(&c, K::TYPE)?;
                Some(Column::new(
                    name.text(),
                    Some(self.text(&ty).trim().to_string()),
                ))
            })
            .collect();
        Schema::closed(columns, Source::Literal)
    }

    fn print(&mut self, node: &SyntaxNode, scope: &Scope) -> Schema {
        let mut schema = Schema::closed(Vec::new(), Source::Print);
        let node_span = span(node);
        for (index, item) in node.children().enumerate() {
            match self.column_item(&item, &Schema::open(), scope, node_span, &[]) {
                Item::Named(names, type_name) => {
                    for name in names {
                        schema.set(Column::new(name, type_name.clone()));
                    }
                }
                Item::Unnamed(_) => {
                    schema.set(Column::new(format!("print_{index}"), None));
                }
            }
        }
        schema
    }

    fn union(&mut self, node: &SyntaxNode, input: Option<Schema>, scope: &Scope) -> Schema {
        let mut legs: Vec<Schema> = input.into_iter().collect();
        let mut withsource = None;
        for child in node.children() {
            match child.kind() {
                K::OPERATOR_OPTION => {
                    let option = tokens(&child).next().map(|t| t.text().to_ascii_lowercase());
                    if matches!(option.as_deref(), Some("withsource" | "source")) {
                        withsource =
                            child_of(&child, K::OPTION_VALUE).map(|v| self.text(&v).to_string());
                    }
                }
                K::TABLE_REF => {
                    let word = ident(&child)
                        .map(|t| Self::token_text(&t))
                        .unwrap_or_default();
                    legs.push(self.named_source(&word, scope).unwrap_or_else(Schema::open));
                }
                K::PAREN_TABULAR => {
                    if let Some(body) = child_of(&child, K::TABULAR_EXPRESSION) {
                        legs.push(self.tabular(&body, scope));
                    }
                }
                K::FUNCTION_CALL => legs.push(self.call_source(&child, scope)),
                _ => {}
            }
        }
        merge_union(&legs, withsource)
    }

    // --- operators --------------------------------------------------------

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per operator, as the tree-sitter pass has them"
    )]
    fn operator(&mut self, op: &SyntaxNode, input: Schema, scope: &Scope) -> Schema {
        let op_span = span(op);
        let kind = legacy_kind(op.kind());
        let made_by = MadeBy {
            operator: kind,
            span: op_span,
        };
        let ctx_input = input.clone();
        let ctx = Ctx::One(&ctx_input);
        match op.kind() {
            K::WHERE_OPERATOR | K::FILTER_OPERATOR => {
                if let Some(p) = op.first_child() {
                    self.expression(&p, ctx, scope, op_span, &[]);
                }
                input
            }
            K::TAKE_OPERATOR | K::LIMIT_OPERATOR | K::RENDER_OPERATOR => input,
            K::COUNT_OPERATOR => {
                let mut out = Schema::closed(
                    vec![Column {
                        made_by: Some(made_by),
                        ..Column::new("Count", Some("long".into()))
                    }],
                    input.source.clone(),
                );
                out.known = reshaped(input.known);
                out.narrowed = true;
                out.reshaped_by = Some(kind);
                out
            }
            K::SORT_OPERATOR | K::TOP_OPERATOR => {
                for key in op.children() {
                    self.expression(&key, ctx, scope, op_span, &[]);
                }
                input
            }
            K::PROJECT_OPERATOR => self.project(op, input, scope, made_by),
            K::PROJECT_AWAY_OPERATOR => {
                let mut out = input.clone();
                out.reshaped_by = Some(kind);
                let (names, patterns) = self.column_refs(op);
                for ident in names {
                    let name = self.text(&ident).to_string();
                    self.reference(&ident, ctx, scope, op_span);
                    out.remove(&name, kind);
                }
                let dropped: Vec<String> = out
                    .columns
                    .iter()
                    .filter(|c| patterns.iter().any(|p| glob_matches(p, &c.name)))
                    .map(|c| c.name.clone())
                    .collect();
                for name in dropped {
                    out.remove(&name, kind);
                }
                out
            }
            K::PROJECT_KEEP_OPERATOR | K::PROJECT_REORDER_OPERATOR => {
                let keep = op.kind() == K::PROJECT_KEEP_OPERATOR;
                let (names, patterns) = self.column_refs(op);
                let mut kept = Vec::new();
                for ident in names {
                    self.reference(&ident, ctx, scope, op_span);
                    kept.push(self.text(&ident).to_string());
                }
                let mut out = input.clone();
                if keep {
                    let dropped: Vec<String> = out
                        .columns
                        .iter()
                        .filter(|c| {
                            !kept.contains(&c.name)
                                && !patterns.iter().any(|p| glob_matches(p, &c.name))
                        })
                        .map(|c| c.name.clone())
                        .collect();
                    for name in dropped {
                        out.remove(&name, kind);
                    }
                    out.narrowed = true;
                    out.reshaped_by = Some(kind);
                    if patterns.is_empty() {
                        out.known = reshaped(input.known);
                        out.custom_columns = false;
                    }
                }
                out
            }
            K::PROJECT_RENAME_OPERATOR => {
                let mut out = input.clone();
                out.reshaped_by = Some(kind);
                for item in op.children().filter(|c| c.kind() == K::RENAME_ITEM) {
                    let names: Vec<SyntaxNode> = item
                        .children()
                        .filter(|c| c.kind() == K::NAME_REF)
                        .collect();
                    let [new, old] = names.as_slice() else {
                        continue;
                    };
                    let old_name = self.text(old).to_string();
                    let new_name = self.text(new).to_string();
                    self.reference(old, ctx, scope, op_span);
                    let type_name = input.column(&old_name).and_then(|c| c.type_name.clone());
                    out.remove(&old_name, kind);
                    let column = Column {
                        made_by: Some(made_by),
                        renamed_from: Some(old_name),
                        ..Column::new(new_name, type_name)
                    };
                    self.define(span(new), &column);
                    out.set(column);
                }
                out
            }
            K::EXTEND_OPERATOR => {
                let mut out = input.clone();
                let mut defined: Vec<String> = Vec::new();
                comma_quirk(&mut out, op.children().count());
                for item in op.children() {
                    let extra: Vec<&str> = defined.iter().map(String::as_str).collect();
                    match self.column_item(&item, &input, scope, op_span, &extra) {
                        Item::Named(names, type_name) => {
                            for (name, node) in names.into_iter().zip(assigned_names(&item)) {
                                let column = Column {
                                    made_by: Some(made_by),
                                    ..Column::new(name.clone(), type_name.clone())
                                };
                                self.define(span(&node), &column);
                                defined.push(name);
                                out.set(column);
                            }
                        }
                        Item::Unnamed(Some(_)) => {}
                        Item::Unnamed(None) => out.make_open(),
                    }
                }
                out
            }
            K::SUMMARIZE_OPERATOR => self.summarize(op, input, scope, made_by),
            K::DISTINCT_OPERATOR => self.distinct(op, input, scope, made_by),
            K::JOIN_OPERATOR => self.join(op, input, scope, made_by),
            K::LOOKUP_OPERATOR => self.lookup(op, input, scope, made_by),
            K::UNION_OPERATOR => self.union(op, Some(input), scope),
            K::MV_EXPAND_OPERATOR => self.mv_expand(op, input, scope, made_by),
            K::MV_APPLY_OPERATOR => {
                let mut out = self.mv_expand(op, input, scope, made_by);
                if let Some(sub) = child_of(op, K::SUBQUERY) {
                    let mut inner = out.clone();
                    inner.make_open();
                    let result = self.subquery(&sub, inner, scope);
                    for column in Arc::unwrap_or_clone(result.columns) {
                        if !out.has(&column.name) {
                            Arc::make_mut(&mut out.columns).push(column);
                        }
                    }
                }
                out.make_open();
                out
            }
            K::PARSE_OPERATOR | K::PARSE_WHERE_OPERATOR => {
                let mut out = input.clone();
                if let Some(column) = nodes_but(
                    op,
                    &[
                        K::OPERATOR_OPTION,
                        K::PARSE_PIECE,
                        K::PARSE_COLUMN,
                        K::ERROR,
                    ],
                )
                .first()
                {
                    self.expression(column, ctx, scope, op_span, &[]);
                }
                for part in op.children().filter(|c| c.kind() == K::PARSE_COLUMN) {
                    let Some(name) = ident(&part) else {
                        continue;
                    };
                    let type_name = child_of(&part, K::TYPE)
                        .map_or_else(|| "string".into(), |t| self.text(&t).trim().to_string());
                    let column = Column {
                        made_by: Some(made_by),
                        ..Column::new(name.text(), Some(type_name))
                    };
                    self.define(token_span(&name), &column);
                    out.set(column);
                }
                out
            }
            K::MAKE_SERIES_OPERATOR => {
                // Not the `range(...)` of `on T in range(...)`, as before.
                let range = node_after(op, K::IN_KW);
                for child in nodes_but(op, &[K::MV_OPTION]) {
                    if Some(&child) != range.as_ref() {
                        self.expression(&child, ctx, scope, op_span, &[]);
                    }
                }
                let mut out = input;
                out.make_open();
                out.narrowed = true;
                out.reshaped_by = Some(kind);
                out
            }
            K::EVALUATE_OPERATOR => {
                let plugin = child_of(op, K::FUNCTION_CALL)
                    .and_then(|p| ident(&p))
                    .map(|n| n.text().to_ascii_lowercase())
                    .unwrap_or_default();
                let mut out = input;
                if !matches!(
                    plugin.as_str(),
                    "bag_unpack" | "ipv4_lookup" | "ipv6_lookup" | "geoip_lookup"
                ) {
                    Arc::make_mut(&mut out.columns).clear();
                    out.narrowed = true;
                }
                out.make_open();
                out
            }
            K::KEYWORD_OPERATOR => {
                let keyword = tokens(op)
                    .next()
                    .map(|k| k.text().to_ascii_lowercase())
                    .unwrap_or_default();
                let bare = op.first_child().is_none();
                match keyword.as_str() {
                    "as" | "sample" => input,
                    "serialize" if bare => input,
                    _ => {
                        let mut out = input;
                        out.make_open();
                        out
                    }
                }
            }
            _ => {
                let mut out = input;
                out.make_open();
                out
            }
        }
    }

    /// The names and the patterns an operator's column list holds
    /// (`project-away a, User*`, `project-reorder b desc`).
    fn column_refs(&self, op: &SyntaxNode) -> (Vec<SyntaxNode>, Vec<&'a str>) {
        let mut names = Vec::new();
        let mut patterns = Vec::new();
        for child in op.children() {
            let item = if child.kind() == K::REORDER_ITEM {
                match child.first_child() {
                    Some(item) => item,
                    None => continue,
                }
            } else {
                child
            };
            match item.kind() {
                K::NAME_REF => names.push(item),
                K::COLUMN_PATTERN => patterns.push(self.text(&item)),
                _ => {}
            }
        }
        (names, patterns)
    }

    fn distinct(
        &mut self,
        op: &SyntaxNode,
        input: Schema,
        scope: &Scope,
        made_by: MadeBy,
    ) -> Schema {
        let op_span = made_by.span;
        let items = nodes_but(op, &[K::HINT_OPTION]);
        if items.is_empty() || items.iter().any(|n| n.kind() == K::STAR_ARG) {
            return input;
        }
        let mut out = Schema {
            columns: Arc::default(),
            known: reshaped(input.known),
            narrowed: true,
            custom_columns: false,
            reshaped_by: Some(made_by.operator),
            removed: HashMap::new(),
            ..input.clone()
        };
        for item in items {
            match self.column_item(&item, &input, scope, op_span, &[]) {
                Item::Named(names, type_name) => {
                    for (name, node) in names.into_iter().zip(assigned_names(&item)) {
                        let column = Column {
                            made_by: Some(made_by),
                            ..Column::new(name, type_name.clone())
                        };
                        self.define(span(&node), &column);
                        out.set(column);
                    }
                }
                Item::Unnamed(Some(column)) => out.set(column),
                Item::Unnamed(None) => out.make_open(),
            }
        }
        out
    }

    fn project(
        &mut self,
        op: &SyntaxNode,
        input: Schema,
        scope: &Scope,
        made_by: MadeBy,
    ) -> Schema {
        let op_span = made_by.span;
        let mut out = Schema {
            columns: Arc::default(),
            known: reshaped(input.known),
            narrowed: true,
            custom_columns: false,
            reshaped_by: Some(made_by.operator),
            removed: HashMap::new(),
            ..input.clone()
        };
        let mut defined: Vec<String> = Vec::new();
        comma_quirk(&mut out, op.children().count());
        for item in op.children() {
            let extra: Vec<&str> = defined.iter().map(String::as_str).collect();
            match self.column_item(&item, &input, scope, op_span, &extra) {
                Item::Named(names, type_name) => {
                    let from = value_of(&item)
                        .filter(|_| is_assignment(&item))
                        .as_ref()
                        .and_then(simple_ident)
                        .map(|n| self.text(&n).to_string());
                    for (name, node) in names.into_iter().zip(assigned_names(&item)) {
                        let column = Column {
                            made_by: Some(made_by),
                            renamed_from: from.clone().filter(|f| *f != name),
                            ..Column::new(name.clone(), type_name.clone())
                        };
                        self.define(span(&node), &column);
                        defined.push(name);
                        out.set(column);
                    }
                }
                Item::Unnamed(Some(column)) => out.set(column),
                Item::Unnamed(None) => out.make_open(),
            }
        }
        out
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the aggregate naming rules, as the tree-sitter pass has them"
    )]
    fn summarize(
        &mut self,
        op: &SyntaxNode,
        input: Schema,
        scope: &Scope,
        made_by: MadeBy,
    ) -> Schema {
        let op_span = made_by.span;
        let ctx_input = input.clone();
        let mut out = Schema {
            columns: Arc::default(),
            known: reshaped(input.known),
            narrowed: true,
            custom_columns: false,
            reshaped_by: Some(made_by.operator),
            removed: HashMap::new(),
            ..input.clone()
        };
        let by_at = tokens(op)
            .find(|t| t.kind() == K::BY_KW)
            .map(|t| t.text_range().end());
        let items = nodes_but(op, &[K::HINT_OPTION, K::ERROR]);
        let (by_items, aggregates): (Vec<SyntaxNode>, Vec<SyntaxNode>) = items
            .into_iter()
            .partition(|n| by_at.is_some_and(|at| n.text_range().start() >= at));
        comma_quirk(&mut out, by_items.len());
        comma_quirk(&mut out, aggregates.len());
        let mut by_columns = Vec::new();
        for item in &by_items {
            match self.column_item(item, &ctx_input, scope, op_span, &[]) {
                Item::Named(names, type_name) => {
                    for name in names {
                        by_columns.push(Column {
                            made_by: Some(made_by),
                            ..Column::new(name, type_name.clone())
                        });
                    }
                }
                Item::Unnamed(Some(column)) => by_columns.push(column),
                Item::Unnamed(None) => {
                    let kept = simple_call(item).and_then(|c| {
                        let name = ident(&c)?;
                        if !matches!(
                            name.text(),
                            "bin" | "floor" | "bin_at" | "startofday" | "startofhour"
                        ) {
                            return None;
                        }
                        let first = c.first_child()?;
                        simple_ident(&first).map(|n| self.text(&n).to_string())
                    });
                    match kept {
                        Some(name) => {
                            let type_name =
                                ctx_input.column(&name).and_then(|c| c.type_name.clone());
                            by_columns.push(Column {
                                made_by: Some(made_by),
                                ..Column::new(name, type_name)
                            });
                        }
                        None => out.make_open(),
                    }
                }
            }
        }
        // Every column the operator makes, in order, named in one batch at
        // the end: a batch per item rebuilt the set of names taken each time,
        // quadratic in the items (#1424). The items read the input, not `out`.
        let mut made = by_columns;
        for item in &aggregates {
            match self.column_item(item, &ctx_input, scope, op_span, &[]) {
                Item::Named(names, _) if names.len() == 1 && self.is_arg_extreme(item) => {
                    let Some(mut columns) = self.aggregate_columns(item, &ctx_input) else {
                        out.make_open();
                        continue;
                    };
                    if let Some(first) = columns.first_mut() {
                        first.name.clone_from(&names[0]);
                    }
                    if let Some(node) = assigned_names(item).first() {
                        self.define(span(node), &columns[0]);
                    }
                    made.extend(columns.into_iter().map(|column| Column {
                        made_by: Some(made_by),
                        ..column
                    }));
                }
                Item::Named(_, _)
                    if aggregate_call(item)
                        .and_then(|c| ident(&c))
                        .is_some_and(|n| {
                            matches!(
                                n.text(),
                                "argmax" | "argmin" | "percentiles" | "percentilesw"
                            )
                        }) =>
                {
                    out.make_open();
                }
                Item::Named(names, type_name) => {
                    for (name, node) in names.into_iter().zip(assigned_names(item)) {
                        let column = Column {
                            made_by: Some(made_by),
                            ..Column::new(name, type_name.clone())
                        };
                        self.define(span(&node), &column);
                        made.push(column);
                    }
                }
                Item::Unnamed(_) => match self.aggregate_columns(item, &ctx_input) {
                    Some(columns) => {
                        made.extend(columns.into_iter().map(|column| Column {
                            made_by: Some(made_by),
                            ..column
                        }));
                    }
                    None => out.make_open(),
                },
            }
        }
        out.push_all_unique(made);
        out
    }

    fn is_arg_extreme(&self, item: &SyntaxNode) -> bool {
        aggregate_call(item)
            .and_then(|c| ident(&c))
            .is_some_and(|n| matches!(n.text(), "arg_max" | "arg_min"))
    }

    fn aggregate_columns(&self, item: &SyntaxNode, input: &Schema) -> Option<Vec<Column>> {
        let call = aggregate_call(item)?;
        let name = ident(&call)?.text().to_ascii_lowercase();
        let args: Vec<AggArg> = call
            .children()
            .map(|arg| {
                if arg.kind() == K::STAR_ARG {
                    AggArg::Star
                } else {
                    simple_ident(&arg)
                        .map_or(AggArg::Other, |n| AggArg::Name(self.text(&n).to_string()))
                }
            })
            .collect();
        aggregate_columns_for(&name, &args, input)
    }

    fn join(&mut self, op: &SyntaxNode, left: Schema, scope: &Scope, made_by: MadeBy) -> Schema {
        let kind = self
            .option(op, "kind")
            .unwrap_or_else(|| "innerunique".into());
        let right = child_of(op, K::TABULAR_SOURCE)
            .map(|r| self.primary(&r, scope))
            .unwrap_or_else(Schema::open);
        for condition in nodes_but(op, &[K::OPERATOR_OPTION, K::TABULAR_SOURCE, K::ERROR]) {
            self.expression(
                &condition,
                Ctx::Join(&left, &right),
                scope,
                made_by.span,
                &[],
            );
        }
        let mut out = match kind.as_str() {
            "leftsemi" | "leftanti" | "leftantisemi" => left.clone(),
            "rightsemi" | "rightanti" | "rightantisemi" => right.clone(),
            _ => {
                let mut out = left.clone();
                out.push_all_unique(right.columns.iter().cloned());
                out.weaken(right.known);
                out.custom_columns |= right.custom_columns;
                out
            }
        };
        out.weaken(left.known.min(right.known));
        out.narrowed = left.narrowed && right.narrowed;
        out.reshaped_by = Some(made_by.operator);
        out
    }

    fn lookup(&mut self, op: &SyntaxNode, left: Schema, scope: &Scope, made_by: MadeBy) -> Schema {
        let right = child_of(op, K::TABULAR_SOURCE)
            .map(|r| self.primary(&r, scope))
            .unwrap_or_else(Schema::open);
        let mut keys = BTreeSet::new();
        for condition in nodes_but(op, &[K::OPERATOR_OPTION, K::TABULAR_SOURCE, K::ERROR]) {
            self.expression(
                &condition,
                Ctx::Join(&left, &right),
                scope,
                made_by.span,
                &[],
            );
            if let Some(ident) = simple_ident(&condition) {
                keys.insert(self.text(&ident).to_string());
            } else {
                // `$left.A == $right.B`: B is the right side's key.
                for node in condition
                    .descendants()
                    .filter(|n| n.kind() == K::MEMBER_EXPR)
                {
                    let object = node.first_child().map(|o| self.text(&o).trim().to_string());
                    let member = tokens(&node).filter(|t| t.kind() == K::IDENT).last();
                    if object.as_deref() == Some("$right")
                        && let Some(member) = member
                    {
                        keys.insert(member.text().to_string());
                    }
                }
            }
        }
        let mut out = left.clone();
        out.push_all_unique(
            right
                .columns
                .iter()
                .filter(|c| !keys.contains(&c.name))
                .cloned(),
        );
        out.weaken(right.known);
        out.custom_columns |= right.custom_columns;
        out.reshaped_by = Some(made_by.operator);
        out
    }

    fn mv_expand(
        &mut self,
        op: &SyntaxNode,
        input: Schema,
        scope: &Scope,
        made_by: MadeBy,
    ) -> Schema {
        let op_span = made_by.span;
        let mut out = input.clone();
        for child in op.children() {
            match child.kind() {
                K::MV_OPTION => {
                    let name = tokens(&child).next().map(|t| t.text().to_owned());
                    if name.as_deref() == Some("with_itemindex")
                        && let Some(value) = child_of(&child, K::OPTION_VALUE)
                    {
                        let column = Column {
                            made_by: Some(made_by),
                            ..Column::new(self.text(&value), Some("long".into()))
                        };
                        self.define(span(&value), &column);
                        out.set(column);
                    }
                }
                K::MV_EXPAND_ITEM => {
                    let to_type = child_of(&child, K::TYPE)
                        .map_or_else(|| "dynamic".into(), |t| self.text(&t).trim().to_string());
                    let Some(first) = child.children().find(|c| c.kind() != K::TYPE) else {
                        continue;
                    };
                    if is_assignment(&first) {
                        if let Some(value) = value_of(&first) {
                            self.expression(&value, Ctx::One(&input), scope, op_span, &[]);
                        }
                        for name in assigned_names(&first) {
                            let column = Column {
                                made_by: Some(made_by),
                                ..Column::new(self.text(&name), Some(to_type.clone()))
                            };
                            self.define(span(&name), &column);
                            out.set(column);
                        }
                    } else {
                        self.expression(&first, Ctx::One(&input), scope, op_span, &[]);
                        match simple_ident(&first) {
                            Some(ident) => {
                                let name = self.text(&ident);
                                if let Some(column) = Arc::make_mut(&mut out.columns)
                                    .iter_mut()
                                    .find(|c| c.name == name)
                                {
                                    column.type_name = Some(to_type.clone());
                                    column.made_by = Some(made_by);
                                }
                            }
                            None => out.make_open(),
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(limit) = node_after(op, K::LIMIT_KW) {
            self.expression(&limit, Ctx::One(&input), scope, op_span, &[]);
        }
        out
    }

    fn option(&self, op: &SyntaxNode, name: &str) -> Option<String> {
        op.children()
            .filter(|c| c.kind() == K::OPERATOR_OPTION)
            .find(|c| {
                tokens(c)
                    .next()
                    .is_some_and(|n| n.text().eq_ignore_ascii_case(name))
            })
            .and_then(|c| child_of(&c, K::OPTION_VALUE))
            .map(|v| self.text(&v).to_ascii_lowercase())
    }

    // --- items and expressions ---------------------------------------------

    /// An item of `extend`, `project`, `summarize`, `print`: check what it
    /// reads, and say what it names.
    fn column_item(
        &mut self,
        item: &SyntaxNode,
        input: &Schema,
        scope: &Scope,
        op: ByteSpan,
        extra: &[&str],
    ) -> Item {
        if is_assignment(item) {
            let value = value_of(item);
            if let Some(value) = &value {
                self.expression(value, Ctx::One(input), scope, op, extra);
            }
            let names: Vec<String> = assigned_names(item)
                .iter()
                .map(|n| self.text(n).to_string())
                .collect();
            let type_name = if names.len() == 1 {
                value.and_then(|v| self.type_of(&v, input))
            } else {
                None
            };
            return Item::Named(names, type_name);
        }
        self.expression(item, Ctx::One(input), scope, op, extra);
        if let Some(ident) = simple_ident(item) {
            let name = self.text(&ident);
            let column = input
                .column(name)
                .cloned()
                .unwrap_or_else(|| Column::new(name, None));
            return Item::Unnamed(Some(column));
        }
        Item::Unnamed(None)
    }

    fn type_of(&self, expr: &SyntaxNode, input: &Schema) -> Option<String> {
        let node = simple_primary(expr)?;
        let text = self.text(&node);
        let primary = match node.kind() {
            K::NAME_REF => Primary::Name(text),
            K::LITERAL => match literal_kind(&node)? {
                K::STRING => Primary::String,
                K::BOOLEAN => Primary::Boolean,
                K::TIMESPAN => Primary::Timespan,
                K::TYPED_LITERAL => Primary::Typed(text),
                K::NUMBER => Primary::Number(text),
                _ => return None,
            },
            K::DYNAMIC_LITERAL => Primary::Dynamic,
            K::FUNCTION_CALL => Primary::Call(self.token(&ident(&node)?)),
            _ => return None,
        };
        primary_type(&primary, input)
    }

    fn expression(
        &mut self,
        node: &SyntaxNode,
        ctx: Ctx,
        scope: &Scope,
        op: ByteSpan,
        extra: &[&str],
    ) {
        self.deeper(1, |pass| pass.expression_at(node, ctx, scope, op, extra));
    }

    fn expression_at(
        &mut self,
        node: &SyntaxNode,
        ctx: Ctx,
        scope: &Scope,
        op: ByteSpan,
        extra: &[&str],
    ) {
        match node.kind() {
            K::NAME_REF => {
                let name = self.text(node).to_string();
                self.reference_in(&name, span(node), ctx, scope, op, extra);
            }
            K::FUNCTION_CALL => {
                let name = ident(node)
                    .map(|n| n.text().to_ascii_lowercase())
                    .unwrap_or_default();
                if LITERAL_FUNCTIONS.contains(&name.as_str()) {
                    return;
                }
                for arg in node.children() {
                    let value = if arg.kind() == K::NAMED_ARGUMENT {
                        value_of(&arg)
                    } else {
                        Some(arg)
                    };
                    if let Some(value) = value {
                        self.expression(&value, ctx, scope, op, extra);
                    }
                }
            }
            K::MEMBER_EXPR => {
                let Some(object) = node.first_child() else {
                    return;
                };
                let side = self.text(&object).trim();
                if side == "$left" || side == "$right" {
                    let member = tokens(node).filter(|t| t.kind() == K::IDENT).last();
                    if let (Ctx::Join(left, right), Some(member)) = (ctx, member) {
                        let schema = if side == "$left" { left } else { right };
                        self.reference_in(
                            member.text(),
                            token_span(&member),
                            Ctx::One(schema),
                            scope,
                            op,
                            extra,
                        );
                    }
                    return;
                }
                self.expression(&object, ctx, scope, op, extra);
            }
            K::TOSCALAR_EXPR | K::MATERIALIZE_EXPRESSION => {
                if let Some(body) = child_of(node, K::TABULAR_EXPRESSION) {
                    self.tabular(&body, scope);
                }
            }
            K::TABULAR_EXPRESSION => {
                self.tabular(node, scope);
            }
            K::COMPARISON_EXPR | K::IN_EXPR | K::BETWEEN_EXPR => {
                for child in node.children() {
                    self.expression(&child, ctx, scope, op, extra);
                }
                if let Ctx::One(schema) = ctx {
                    self.check_types(node, schema, scope);
                }
            }
            // The names an assignment writes, or an argument's, are not read.
            K::ASSIGNMENT | K::TUPLE_ASSIGNMENT | K::NAMED_ARGUMENT => {
                if let Some(value) = value_of(node) {
                    self.expression(&value, ctx, scope, op, extra);
                }
            }
            K::LITERAL | K::DYNAMIC_LITERAL | K::TYPE | K::STAR_ARG | K::NAME_TUPLE => {}
            _ => {
                for child in node.children() {
                    self.expression(&child, ctx, scope, op, extra);
                }
            }
        }
    }

    fn reference(&mut self, ident: &SyntaxNode, ctx: Ctx, scope: &Scope, op: ByteSpan) {
        let name = self.text(ident).to_string();
        self.reference_in(&name, span(ident), ctx, scope, op, &[]);
    }

    /// A name read where a column is expected.
    fn reference_in(
        &mut self,
        name: &str,
        name_span: ByteSpan,
        ctx: Ctx,
        scope: &Scope,
        op: ByteSpan,
        extra: &[&str],
    ) {
        if name.starts_with('$') || scope.binds(name) || extra.contains(&name) {
            return;
        }
        if self.catalog.table(name).is_some() || self.catalog.asim_parser(name).is_some() {
            return;
        }
        let schemas: Vec<&Schema> = match ctx {
            Ctx::One(s) => vec![s],
            Ctx::Join(l, r) => vec![l, r],
        };
        let found = resolve_column(name, &schemas);
        self.out.references.push(Reference {
            name: name.to_string(),
            span: name_span,
            column: found.clone(),
            operator: op,
        });
        if found.is_some() || !self.diagnose {
            return;
        }
        if let Some(d) = unknown_column(name, &schemas, self.lines.range(name_span)) {
            self.out.diagnostics.push(d);
        }
    }

    fn define(&mut self, at: ByteSpan, column: &Column) {
        self.out.definitions.push(Definition {
            column: column.clone(),
            span: at,
        });
    }

    // --- types --------------------------------------------------------------

    fn check_types(&mut self, node: &SyntaxNode, schema: &Schema, scope: &Scope) {
        if !self.diagnose || schema.known == Known::Open {
            return;
        }
        let elements: Vec<rowan::SyntaxElement<crate::syntax::Lang>> = node
            .children_with_tokens()
            .filter(|e| {
                e.as_token()
                    .is_none_or(|t| !crate::syntax_util::is_trivia(t))
            })
            .collect();
        let Some(left) = elements.first().and_then(|e| e.as_node()).cloned() else {
            return;
        };
        let operator_tokens: Vec<SyntaxToken> = elements
            .iter()
            .skip(1)
            .map_while(|e| e.as_token().cloned())
            .collect();
        let (Some(first), Some(last)) = (operator_tokens.first(), operator_tokens.last()) else {
            return;
        };
        let operator: String = operator_tokens
            .iter()
            .map(SyntaxToken::text)
            .collect::<Vec<_>>()
            .join(" ");
        let right = elements
            .iter()
            .skip(1 + operator_tokens.len())
            .find_map(|e| e.as_node().cloned());
        let op_span = ByteSpan::new(token_span(first).start, token_span(last).end);
        let column_of = |pass: &Self, n: &SyntaxNode| -> Option<(String, String)> {
            let ident = simple_ident(n)?;
            let name = pass.text(&ident);
            if scope.binds(name) {
                return None;
            }
            let column = schema.column(name)?;
            Some((column.name.clone(), column.type_name.clone()?))
        };
        let literal = |pass: &Self, n: &SyntaxNode| -> Option<&'static str> {
            let node = simple_primary(n)?;
            match literal_kind(&node)? {
                K::STRING => Some("string"),
                K::NUMBER => Some(if pass.text(&node).contains('.') {
                    "real"
                } else {
                    "long"
                }),
                _ => None,
            }
        };
        let op = operator.as_str();
        let found = type_mismatch(
            op,
            column_of(self, &left),
            right.as_ref().and_then(|r| column_of(self, r)),
            literal(self, &left),
            right.as_ref().and_then(|r| literal(self, r)),
        );
        let Some((column, kind)) = found else {
            return;
        };
        self.out.diagnostics.push(Diagnostic::error(
            codes::KQL_TYPE_MISMATCH,
            mismatch_message(op, &column, &kind),
            self.lines.range(op_span),
        ));
    }
}

/// The `NAME_REF`s an item writes (`A = ...`, `(A, B) = ...`).
fn assigned_names(item: &SyntaxNode) -> Vec<SyntaxNode> {
    match item.kind() {
        K::ASSIGNMENT => item
            .first_child()
            .filter(|n| n.kind() == K::NAME_REF)
            .into_iter()
            .collect(),
        K::TUPLE_ASSIGNMENT => child_of(item, K::NAME_TUPLE)
            .map(|t| t.children().filter(|n| n.kind() == K::NAME_REF).collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The aggregate call of a summarize item, named or not.
fn aggregate_call(item: &SyntaxNode) -> Option<SyntaxNode> {
    if is_assignment(item) {
        return value_of(item).as_ref().and_then(simple_call);
    }
    simple_call(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Profile;

    /// The pass over `source`, against the Sentinel catalog.
    fn pass_over(source: &str, check: impl FnOnce(&Pass<'_>)) {
        let parsed = crate::parser::parse(source);
        let root = SyntaxNode::new_root(parsed.green);
        let catalog = Catalog::for_workspace(Profile::Sentinel, source);
        check(&run(&root, source, &catalog, parsed.errors.is_empty()));
    }

    /// `n` functions, each calling the one before `calls` times.
    fn chain(n: usize, calls: usize) -> String {
        let mut out = String::from("let f0 = () { SigninLogs | project UserPrincipalName };\n");
        for i in 1..n {
            let call = format!("f{}()", i - 1);
            let body = if calls == 1 {
                call
            } else {
                format!("union {}", vec![call; calls].join(", "))
            };
            out.push_str(&format!("let f{i} = () {{ {body} }};\n"));
        }
        out.push_str(&format!("f{}() | where Nope == 1", n - 1));
        out
    }

    /// Each body is read once, where it is defined, however often it is
    /// called (#1424): re-reading it at each call was quadratic on a chain
    /// and exponential when each function calls the one before twice.
    #[test]
    fn each_function_body_is_read_once() {
        for (n, calls) in [(1, 1), (200, 1), (40, 2), (40, 3)] {
            pass_over(&chain(n, calls), |pass| {
                assert_eq!(pass.bodies_read, n, "{n} functions, {calls} calls each");
                // The first body's schema reaches the last call: `Nope` is
                // not a column after its `project`.
                assert!(
                    pass.out
                        .diagnostics
                        .iter()
                        .any(|d| d.message.contains("'Nope'")),
                    "{n}, {calls}: {:?}",
                    pass.out.diagnostics
                );
            });
        }
    }

    /// A chain longer than the depth budget allowed when each call re-read
    /// the body (about 20 functions) still carries its columns to the last
    /// call: before #1424 the schema went open there and `Nope` passed.
    #[test]
    fn a_long_chain_keeps_its_columns() {
        for n in [19, 40, 200] {
            pass_over(&chain(n, 1), |pass| {
                assert!(
                    pass.out
                        .diagnostics
                        .iter()
                        .any(|d| d.message.contains("'Nope'")),
                    "{n}: {:?}",
                    pass.out.diagnostics
                );
            });
        }
    }

    /// Functions defined inside function bodies, `n` deep, each calling the
    /// one it defines: each body is still read once (it was exponential).
    #[test]
    fn nested_definitions_are_read_once() {
        let n = 30;
        let mut source = String::new();
        for i in 0..n {
            source.push_str(&format!("let f{i} = () {{ "));
        }
        source.push_str("SigninLogs | project AppId");
        for i in (0..n).rev() {
            if i + 1 < n {
                source.push_str(&format!(" }}; f{}() | extend c{i} = 1", i + 1));
            }
        }
        source.push_str(" };\nf0() | where Nope == 1");
        pass_over(&source, |pass| {
            assert_eq!(pass.bodies_read, n, "{source}");
            assert!(
                pass.out
                    .diagnostics
                    .iter()
                    .any(|d| d.message.contains("'Nope'")),
                "{:?}",
                pass.out.diagnostics
            );
        });
    }

    /// A body binds the names in scope where it is defined, as Kusto does:
    /// a name rebound after the definition does not change what it returns.
    #[test]
    fn a_body_binds_the_names_of_its_definition() {
        let source = "let X = SigninLogs | project q = 1;\n\
                      let f = () { X | extend z = 2 };\n\
                      let X = SecurityEvent;\n\
                      f() | where z == 1 | where q == 2 | where w == 3";
        pass_over(source, |pass| {
            let unknown: Vec<&str> = pass
                .out
                .diagnostics
                .iter()
                .map(|d| d.message.as_str())
                .collect();
            assert!(
                unknown.len() == 1 && unknown[0].contains("'w'"),
                "{unknown:?}"
            );
        });
    }

    /// A layer shadows the scope under it map by map, exactly as the copy
    /// it replaces did: a scalar parameter `T` does not hide an outer table
    /// `T` from a tabular lookup. That is a quirk the copy already had
    /// (Kusto's parameter would win), kept so this change alters no result;
    /// fixing it is a change of its own.
    #[test]
    fn a_layer_shadows_map_by_map() {
        let mut outer = Scope::default();
        outer.tabular.insert("T".into(), Schema::open());
        outer.scalars.insert("s".into());
        let mut inner = Scope::inner(&outer);
        inner.scalars.insert("T".into());
        assert!(inner.tabular("T").is_some());
        assert!(inner.binds("T") && inner.binds("s"));
        assert!(!inner.binds("u"));
        assert!(outer.function("T").is_none());
    }
}
