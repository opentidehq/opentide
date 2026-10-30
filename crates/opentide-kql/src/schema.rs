//! Columns through a KQL query (#112).
//!
//! A pass over each tabular expression that knows, at every operator, which
//! columns the rows hold, their types, and which operator made each one. It
//! follows `let` bindings (tabular values and tabular functions), `datatable`,
//! `print`, `union`, `join`, `lookup`, `summarize`, the `project` family,
//! `extend`, `mv-expand`, `mv-apply`, `parse` and `distinct`.
//!
//! How much the pass knows about a pipeline's columns is [`Known`]:
//!
//! - `Closed`: the query itself says which columns exist (after `project`,
//!   `summarize`, `distinct`, `count`; a `datatable`, `print`), so a name
//!   that is not one of them is not a column: `kql_unknown_column`.
//! - `Typos`: a documented source (an Azure Monitor Logs or advanced hunting
//!   table, an ASIM parser). Its documented columns are known, but a table
//!   gains columns before the reference lists them and ASIM source parsers
//!   can add their own, so only a near miss of a documented column is
//!   reported, with the column it misspells.
//! - `Open`: an unknown source, an `evaluate` plugin, `bag_unpack`, an
//!   operator whose output naming the pass does not model. Nothing below it
//!   gets a column diagnostic.
//!
//! The pass never reports on a query that does not parse.

use crate::{Catalog, Profile, strsim_distance, tables};
use opentide_core::{ByteSpan, Diagnostic, codes, span_to_range};
use std::collections::{BTreeSet, HashMap};
use tree_sitter::Node;

/// The operator that made a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MadeBy {
    /// The operator's node kind (`extend_operator`, `summarize_operator`, ...).
    pub operator: &'static str,
    /// The operator's span in the query.
    pub span: ByteSpan,
}

impl MadeBy {
    /// The operator as written in a query (`extend`, `project-rename`).
    pub fn keyword(&self) -> &'static str {
        operator_keyword(self.operator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    /// The Kusto scalar type, when known.
    pub type_name: Option<String>,
    /// The operator that made it; `None` for a column of the source.
    pub made_by: Option<MadeBy>,
    /// The column it renames (`project-rename New = Old`, `project New = Old`).
    pub renamed_from: Option<String>,
}

impl Column {
    fn new(name: impl Into<String>, type_name: Option<String>) -> Self {
        Self {
            name: name.into(),
            type_name,
            made_by: None,
            renamed_from: None,
        }
    }
}

/// How completely the pass knows a pipeline's columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Known {
    /// Columns may exist that the pass does not know: no column diagnostic.
    Open,
    /// The documented columns are known, others may exist: only near misses.
    Typos,
    /// The columns are exactly these.
    Closed,
}

/// Where a pipeline's rows come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A catalog table.
    Table(String),
    /// An ASIM parser and the schema it returns.
    Asim { parser: String, schema: String },
    /// A `let`-bound tabular value or function.
    Let(String),
    /// A name the catalog does not know and no `let` binds (a custom `_CL`
    /// table, a workspace function).
    Named(String),
    /// `datatable`, `externaldata`, `range`.
    Literal,
    /// `print`.
    Print,
    /// A `union` of several sources.
    Union,
    /// Anything else: an unknown name, `search`, `externaldata`.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Schema {
    pub columns: Vec<Column>,
    pub known: Known,
    pub source: Source,
    /// `project`, `summarize` or `distinct` narrowed the columns (in this
    /// pipeline or in the `let` it starts from).
    pub narrowed: bool,
    /// `_CF` custom columns may exist: a data collection rule can add them to
    /// a Log Analytics table.
    custom_columns: bool,
    /// The last operator that replaced the set of columns, for messages.
    reshaped_by: Option<&'static str>,
    /// Columns `project-away`, `project-rename` or `project-keep` removed,
    /// with the operator: certainly not columns, whatever the source.
    removed: HashMap<String, &'static str>,
    pub citation: Option<String>,
}

impl Schema {
    fn open() -> Self {
        Self {
            columns: Vec::new(),
            known: Known::Open,
            source: Source::Unknown,
            narrowed: false,
            custom_columns: false,
            reshaped_by: None,
            removed: HashMap::new(),
            citation: None,
        }
    }

    fn closed(columns: Vec<Column>, source: Source) -> Self {
        Self {
            columns,
            known: Known::Closed,
            source,
            ..Self::open()
        }
    }

    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }

    fn has(&self, name: &str) -> bool {
        self.column(name).is_some()
    }

    /// Add `column`, replacing one of the same name (as `extend` does).
    fn set(&mut self, column: Column) {
        self.removed.remove(&column.name);
        if let Some(existing) = self.columns.iter_mut().find(|c| c.name == column.name) {
            *existing = column;
        } else {
            self.columns.push(column);
        }
    }

    /// Add `column` under a name not yet taken: `Name`, `Name1`, `Name2`, ...
    /// as Kusto names the columns `join`, `lookup` and `summarize` repeat.
    fn push_unique(&mut self, mut column: Column) {
        if self.has(&column.name) {
            let base = column.name.clone();
            let mut n = 1;
            while self.has(&format!("{base}{n}")) {
                n += 1;
            }
            column.name = format!("{base}{n}");
        }
        self.removed.remove(&column.name);
        self.columns.push(column);
    }

    fn remove(&mut self, name: &str, by: &'static str) {
        self.columns.retain(|c| c.name != name);
        self.removed.insert(name.to_string(), by);
    }

    fn weaken(&mut self, known: Known) {
        self.known = self.known.min(known);
    }

    fn make_open(&mut self) {
        self.known = Known::Open;
    }

    /// What the pipeline reads, for messages.
    pub fn describe_source(&self) -> String {
        match &self.source {
            Source::Table(t) => t.clone(),
            Source::Asim { parser, schema } => format!("{parser} (ASIM {schema} schema)"),
            Source::Let(name) | Source::Named(name) => name.clone(),
            Source::Literal => "the datatable".into(),
            Source::Print => "the print".into(),
            Source::Union => "the union".into(),
            Source::Unknown => "the source".into(),
        }
    }
}

/// One column reference in the query.
#[derive(Debug, Clone)]
pub struct Reference {
    pub name: String,
    pub span: ByteSpan,
    /// The column it resolves to, if the pass knows it.
    pub column: Option<Column>,
    /// The tabular operator (or source) it is part of.
    pub operator: ByteSpan,
}

/// A column an operator defines (`extend New = ...`, `project-rename New = Old`).
#[derive(Debug, Clone)]
pub struct Definition {
    pub column: Column,
    pub span: ByteSpan,
}

/// One operator of a pipeline with the columns it reads and writes.
#[derive(Debug, Clone)]
pub struct Stage {
    pub operator: &'static str,
    pub span: ByteSpan,
    pub input: Schema,
    pub output: Schema,
}

/// One tabular expression: the schema its source gives, then each operator.
#[derive(Debug, Clone)]
pub struct Pipeline {
    pub span: ByteSpan,
    pub source: Schema,
    pub stages: Vec<Stage>,
}

impl Pipeline {
    /// The rows come straight from a table or an ASIM parser (a name no `let`
    /// binds), not a `let`, a `union` or a literal.
    pub fn reads_dataset(&self) -> bool {
        matches!(
            self.source.source,
            Source::Table(_) | Source::Asim { .. } | Source::Named(_)
        )
    }
}

/// What the pass learned about one query.
#[derive(Debug, Clone, Default)]
pub struct Analysis {
    pub pipelines: Vec<Pipeline>,
    pub references: Vec<Reference>,
    pub definitions: Vec<Definition>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Analysis {
    /// The pipeline of the `tabular_expression` at `span`.
    pub fn pipeline(&self, span: ByteSpan) -> Option<&Pipeline> {
        self.pipelines.iter().find(|p| p.span == span)
    }

    /// The column references inside `span` (a predicate, an operator): which
    /// columns it reads, and for each the operator that made it.
    pub fn reads(&self, span: ByteSpan) -> impl Iterator<Item = &Reference> {
        self.references
            .iter()
            .filter(move |r| r.span.start >= span.start && r.span.end <= span.end)
    }

    /// The column reference or definition at a byte offset, for hover.
    pub fn column_at(&self, offset: usize) -> Option<&Column> {
        self.references
            .iter()
            .filter(|r| r.span.start <= offset && offset <= r.span.end)
            .find_map(|r| r.column.as_ref())
            .or_else(|| {
                self.definitions
                    .iter()
                    .find(|d| d.span.start <= offset && offset <= d.span.end)
                    .map(|d| &d.column)
            })
    }
}

/// Run the pass over a parsed query. Diagnostics are only collected when the
/// tree has no syntax error.
pub fn analyze(root: Node, source: &str, catalog: &Catalog) -> Analysis {
    let mut pass = Pass {
        source,
        catalog,
        out: Analysis::default(),
        quiet: 0,
        diagnose: !root.has_error(),
    };
    let mut scope = Scope::default();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        match child.kind() {
            "let_statement" => pass.let_statement(child, &mut scope),
            "query" => {
                if let Some(body) = child.child_by_field_name("body") {
                    pass.tabular(body, &scope);
                }
            }
            _ => {}
        }
    }
    pass.out
}

/// Names a scope binds: they are never columns.
#[derive(Clone, Default)]
struct Scope<'t> {
    tabular: HashMap<String, Schema>,
    functions: HashMap<String, Node<'t>>,
    scalars: BTreeSet<String>,
}

impl Scope<'_> {
    fn binds(&self, name: &str) -> bool {
        self.scalars.contains(name)
            || self.tabular.contains_key(name)
            || self.functions.contains_key(name)
    }
}

struct Pass<'a> {
    source: &'a str,
    catalog: &'a Catalog,
    out: Analysis,
    /// Above zero while re-reading a function body for its schema: nothing is
    /// recorded twice.
    quiet: u32,
    diagnose: bool,
}

/// Where a column reference is resolved.
#[derive(Clone, Copy)]
enum Ctx<'s> {
    One(&'s Schema),
    /// A join or lookup condition: `$left.X`, `$right.X`, or `X` on both sides.
    Join(&'s Schema, &'s Schema),
}

// Functions whose arguments are literals of their type, not expressions over
// columns: `datetime(2024-01-01T10:00:00Z)`, `real(nan)`, `typeof(long)`.
const LITERAL_FUNCTIONS: &[&str] = &[
    "datetime", "date", "time", "timespan", "int", "long", "real", "double", "decimal", "bool",
    "boolean", "guid", "uniqueid", "dynamic", "string", "typeof",
];

const STRING_OPERATORS: &[&str] = &[
    "has",
    "!has",
    "has_cs",
    "!has_cs",
    "contains",
    "!contains",
    "contains_cs",
    "!contains_cs",
    "startswith",
    "!startswith",
    "startswith_cs",
    "!startswith_cs",
    "endswith",
    "!endswith",
    "endswith_cs",
    "!endswith_cs",
    "hasprefix",
    "!hasprefix",
    "hasprefix_cs",
    "!hasprefix_cs",
    "hassuffix",
    "!hassuffix",
    "hassuffix_cs",
    "!hassuffix_cs",
    "=~",
    "!~",
    "matches regex",
];
const STRING_SET_OPERATORS: &[&str] = &["has_any", "has_all", "in~", "!in~"];
const ORDERING: &[&str] = &["<", ">", "<=", ">="];
const NUMERIC: &[&str] = &["int", "long", "real", "decimal"];

impl<'a> Pass<'a> {
    fn text(&self, node: Node) -> &'a str {
        &self.source[node.byte_range()]
    }

    fn span(node: Node) -> ByteSpan {
        ByteSpan::new(node.start_byte(), node.end_byte())
    }

    // --- bindings ---------------------------------------------------------

    fn let_statement<'t>(&mut self, node: Node<'t>, scope: &mut Scope<'t>) {
        let Some(name) = node
            .child_by_field_name("name")
            .map(|n| self.text(n).to_string())
        else {
            return;
        };
        let Some(value) = node.child_by_field_name("value") else {
            return;
        };
        match value.kind() {
            "tabular_expression" => {
                let mut schema = self.tabular(value, scope);
                schema.source = Source::Let(name.clone());
                scope.tabular.insert(name, schema);
            }
            "function_definition" => {
                // Check the body once, with its parameters bound.
                self.function_schema(value, scope);
                scope.functions.insert(name, value);
            }
            _ => {
                // `let T = SigninLogs;` parses as an expression.
                if let Some(ident) = simple_ident(value) {
                    let word = self.text(ident);
                    if let Some(mut schema) = self.named_source(word, scope) {
                        schema.source = Source::Let(name.clone());
                        scope.tabular.insert(name, schema);
                        return;
                    }
                }
                self.expression(
                    value,
                    Ctx::One(&Schema::open()),
                    scope,
                    Self::span(node),
                    &[],
                );
                scope.scalars.insert(name);
            }
        }
    }

    /// The schema a function body returns, its parameters bound. `None` for a
    /// scalar function.
    fn function_schema<'t>(&mut self, def: Node<'t>, outer: &Scope<'t>) -> Option<Schema> {
        let mut scope = outer.clone();
        let mut cursor = def.walk();
        for child in def.named_children(&mut cursor) {
            match child.kind() {
                "parameter" => {
                    let Some(name) = child.child_by_field_name("name") else {
                        continue;
                    };
                    let name = self.text(name).to_string();
                    let tabular = child
                        .child_by_field_name("type")
                        .is_some_and(|t| self.text(t).trim_start().starts_with('('));
                    if tabular {
                        let mut schema = Schema::open();
                        schema.source = Source::Let(name.clone());
                        scope.tabular.insert(name, schema);
                    } else {
                        scope.scalars.insert(name);
                    }
                }
                "let_statement" => self.let_statement(child, &mut scope),
                _ => {}
            }
        }
        let body = def.child_by_field_name("body")?;
        if body.kind() == "tabular_expression" {
            return Some(self.tabular(body, &scope));
        }
        if let Some(ident) = simple_ident(body) {
            if let Some(schema) = self.named_source(self.text(ident), &scope) {
                return Some(schema);
            }
        }
        self.expression(
            body,
            Ctx::One(&Schema::open()),
            &scope,
            Self::span(body),
            &[],
        );
        None
    }

    /// A table, `let`-bound tabular value or ASIM parser named by `word`.
    fn named_source(&self, word: &str, scope: &Scope) -> Option<Schema> {
        if let Some(schema) = scope.tabular.get(word) {
            return Some(schema.clone());
        }
        if scope.binds(word) {
            return None;
        }
        self.table_schema(word).or_else(|| self.asim_schema(word))
    }

    fn table_schema(&self, name: &str) -> Option<Schema> {
        let table = self.catalog.table(name)?;
        let columns: Vec<Column> = self
            .catalog
            .columns_for_table(name)
            .into_iter()
            .filter(|c| c.table == name)
            .map(|c| Column::new(c.name.clone(), c.type_name.clone()))
            .collect();
        // The documented columns are reliable but not complete: tables gain
        // columns before the reference lists them. A near miss of one is a
        // typo; any other name is left alone.
        let known = if table.documented {
            Known::Typos
        } else {
            Known::Open
        };
        let mut schema = Schema {
            columns,
            known,
            source: Source::Table(name.to_string()),
            custom_columns: true,
            citation: table.citation.clone(),
            ..Schema::open()
        };
        // Every Log Analytics table has the standard columns.
        if self.catalog.profile == Profile::Sentinel && table.documented {
            for (column, type_name) in tables::STANDARD_COLUMNS {
                if !schema.has(column) {
                    schema
                        .columns
                        .push(Column::new(*column, Some((*type_name).to_string())));
                }
            }
        }
        Some(schema)
    }

    fn asim_schema(&self, name: &str) -> Option<Schema> {
        let parser = self.catalog.asim_parser(name)?;
        let asim = tables::asim();
        let schema = asim.schemas.get(&parser.schema)?;
        Some(Schema {
            columns: schema
                .columns
                .iter()
                .map(|c| Column::new(c.0.clone(), Some(c.1.clone())))
                .collect(),
            known: Known::Typos,
            source: Source::Asim {
                parser: parser.name.clone(),
                schema: parser.schema.clone(),
            },
            citation: schema.citation.clone(),
            ..Schema::open()
        })
    }

    // --- tabular expressions ---------------------------------------------

    fn tabular(&mut self, expr: Node, scope: &Scope) -> Schema {
        let span = Self::span(expr);
        let Some(source) = expr.child_by_field_name("source") else {
            return Schema::open();
        };
        let mut schema = self.primary(source, scope);
        let start = schema.clone();
        let mut stages = Vec::new();
        let mut cursor = expr.walk();
        for op in expr.children_by_field_name("operator", &mut cursor) {
            let Some(inner) = op.named_child(0) else {
                continue;
            };
            let input = schema;
            let output = self.operator(inner, input.clone(), scope);
            if self.quiet == 0 {
                stages.push(Stage {
                    operator: inner.kind(),
                    span: Self::span(inner),
                    input,
                    output: output.clone(),
                });
            }
            schema = output;
        }
        if self.quiet == 0 {
            self.out.pipelines.push(Pipeline {
                span,
                source: start,
                stages,
            });
        }
        schema
    }

    /// A `subquery` (the operators after `mv-apply ... on (`) over `input`.
    fn subquery(&mut self, node: Node, input: Schema, scope: &Scope) -> Schema {
        let mut schema = input;
        let mut cursor = node.walk();
        for op in node.children_by_field_name("operator", &mut cursor) {
            if let Some(inner) = op.named_child(0) {
                schema = self.operator(inner, schema, scope);
            }
        }
        schema
    }

    fn primary(&mut self, node: Node, scope: &Scope) -> Schema {
        if let Some(table) = node.child_by_field_name("table") {
            let word = self.text(table);
            return self.named_source(word, scope).unwrap_or_else(|| {
                let mut schema = Schema::open();
                if !scope.binds(word) {
                    schema.source = Source::Named(word.to_string());
                }
                schema
            });
        }
        let Some(inner) = node.named_child(0) else {
            return Schema::open();
        };
        match inner.kind() {
            "tabular_expression" => self.tabular(inner, scope),
            "materialize_expression" => inner
                .child_by_field_name("body")
                .map(|b| self.tabular(b, scope))
                .unwrap_or_else(Schema::open),
            // `datatable` and `externaldata` declare their columns.
            "datatable_expression" | "externaldata_expression" => self.datatable(inner),
            // `range x from 1 to 10 step 1`: one column.
            "range_operator" => {
                let column = inner
                    .child_by_field_name("column")
                    .map(|c| self.text(c).to_string())
                    .unwrap_or_default();
                Schema::closed(vec![Column::new(column, None)], Source::Literal)
            }
            "print_operator" => self.print(inner, scope),
            "union_operator" => self.union(inner, None, scope),
            "function_call" => self.call_source(inner, scope),
            "identifier" => {
                let word = self.text(inner);
                self.named_source(word, scope).unwrap_or_else(Schema::open)
            }
            // `search`, `find`: every table, or those `in (...)` names.
            _ => Schema::open(),
        }
    }

    fn call_source(&mut self, call: Node, scope: &Scope) -> Schema {
        let name = call
            .child_by_field_name("name")
            .map(|n| self.text(n))
            .unwrap_or_default();
        let span = Self::span(call);
        // Arguments are scalar: check the columns they read (none) and bind nothing.
        let mut cursor = call.walk();
        for arg in call.children_by_field_name("arguments", &mut cursor) {
            let value = if arg.kind() == "named_argument" {
                arg.child_by_field_name("value")
            } else {
                Some(arg)
            };
            if let Some(value) = value {
                self.expression(value, Ctx::One(&Schema::open()), scope, span, &[]);
            }
        }
        if name == "table" {
            // `table("SigninLogs")`
            let mut cursor = call.walk();
            let arg = call
                .children_by_field_name("arguments", &mut cursor)
                .find(|n| n.is_named());
            if let Some(arg) = arg.and_then(simple_primary) {
                if arg.kind() == "string" {
                    let text = self.text(arg);
                    let table = text.trim_matches(|c| c == '"' || c == '\'' || c == '@');
                    return self.named_source(table, scope).unwrap_or_else(Schema::open);
                }
            }
            return Schema::open();
        }
        if let Some(def) = scope.functions.get(name).copied() {
            self.quiet += 1;
            let schema = self.function_schema(def, scope);
            self.quiet -= 1;
            return schema
                .map(|mut s| {
                    s.source = Source::Let(name.to_string());
                    s
                })
                .unwrap_or_else(Schema::open);
        }
        if !scope.binds(name) {
            if let Some(schema) = self.asim_schema(name) {
                return schema;
            }
        }
        Schema::open()
    }

    fn datatable(&mut self, node: Node) -> Schema {
        let mut columns = Vec::new();
        let mut pending: Option<String> = None;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "identifier" => pending = Some(self.text(child).to_string()),
                "type" => {
                    if let Some(name) = pending.take() {
                        columns.push(Column::new(name, Some(self.text(child).trim().to_string())));
                    }
                }
                _ => {}
            }
        }
        Schema::closed(columns, Source::Literal)
    }

    fn print(&mut self, node: Node, scope: &Scope) -> Schema {
        let mut schema = Schema::closed(Vec::new(), Source::Print);
        let span = Self::span(node);
        let mut cursor = node.walk();
        for (index, item) in node.named_children(&mut cursor).enumerate() {
            match self.column_item(item, &Schema::open(), scope, span, &[]) {
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

    fn union(&mut self, node: Node, input: Option<Schema>, scope: &Scope) -> Schema {
        let mut legs: Vec<Schema> = input.into_iter().collect();
        let mut withsource = None;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "operator_option" => {
                    let option = child
                        .child_by_field_name("name")
                        .map(|n| self.text(n).to_ascii_lowercase());
                    if matches!(option.as_deref(), Some("withsource" | "source")) {
                        withsource = child
                            .child_by_field_name("value")
                            .map(|v| self.text(v).to_string());
                    }
                }
                "identifier" => {
                    let word = self.text(child);
                    legs.push(self.named_source(word, scope).unwrap_or_else(Schema::open));
                }
                "tabular_expression" => legs.push(self.tabular(child, scope)),
                // `union g("a"), g("b")`: a tabular function's rows.
                "function_call" => legs.push(self.call_source(child, scope)),
                _ => {}
            }
        }
        let mut out = Schema::closed(Vec::new(), Source::Union);
        let mut types: HashMap<String, Option<String>> = HashMap::new();
        let mut conflicts = BTreeSet::new();
        for leg in &legs {
            out.weaken(leg.known);
            out.custom_columns |= leg.custom_columns;
            for column in &leg.columns {
                match types.get(&column.name) {
                    None => {
                        types.insert(column.name.clone(), column.type_name.clone());
                        out.columns.push(column.clone());
                    }
                    Some(t) if *t != column.type_name => {
                        conflicts.insert(column.name.clone());
                    }
                    Some(_) => {}
                }
            }
        }
        // A name with two types becomes one column per type (`A_string`,
        // `A_long`); with a type the pass does not know, it cannot name them.
        for name in conflicts {
            let mut kinds: Vec<Option<String>> = legs
                .iter()
                .filter_map(|leg| leg.column(&name).map(|c| c.type_name.clone()))
                .collect();
            kinds.dedup();
            out.columns.retain(|c| c.name != name);
            if kinds.iter().any(Option::is_none) {
                out.make_open();
                continue;
            }
            for kind in kinds.into_iter().flatten() {
                let renamed = format!("{name}_{kind}");
                if !out.has(&renamed) {
                    out.columns.push(Column::new(renamed, Some(kind)));
                }
            }
        }
        if let Some(name) = withsource {
            out.set(Column::new(name, Some("string".into())));
        }
        if legs.is_empty() {
            out.make_open();
        }
        out
    }

    // --- operators --------------------------------------------------------

    fn operator(&mut self, op: Node, input: Schema, scope: &Scope) -> Schema {
        let span = Self::span(op);
        let made_by = MadeBy {
            operator: op.kind(),
            span,
        };
        let ctx_input = input.clone();
        let ctx = Ctx::One(&ctx_input);
        match op.kind() {
            "where_operator" | "filter_operator" => {
                if let Some(p) = op.child_by_field_name("predicate") {
                    self.expression(p, ctx, scope, span, &[]);
                }
                input
            }
            "take_operator" | "limit_operator" | "render_operator" => input,
            "count_operator" => {
                let mut out = Schema::closed(
                    vec![Column {
                        made_by: Some(made_by),
                        ..Column::new("Count", Some("long".into()))
                    }],
                    input.source.clone(),
                );
                out.known = reshaped(input.known);
                out.narrowed = true;
                out.reshaped_by = Some(op.kind());
                out
            }
            "sort_operator" | "top_operator" => {
                let mut cursor = op.walk();
                for key in op.children_by_field_name("keys", &mut cursor) {
                    self.expression(key, ctx, scope, span, &[]);
                }
                input
            }
            "project_operator" => self.project(op, input, scope, made_by),
            "project_away_operator" => {
                let mut out = input.clone();
                out.reshaped_by = Some(op.kind());
                for ident in self.identifiers(op, "columns") {
                    let name = self.text(ident).to_string();
                    self.reference(ident, ctx, scope, span);
                    out.remove(&name, op.kind());
                }
                out
            }
            "project_keep_operator" | "project_reorder_operator" => {
                let keep = op.kind() == "project_keep_operator";
                let mut kept = Vec::new();
                for ident in self.identifiers(op, "columns") {
                    self.reference(ident, ctx, scope, span);
                    kept.push(self.text(ident).to_string());
                }
                let mut out = input.clone();
                if keep {
                    let dropped: Vec<String> = out
                        .columns
                        .iter()
                        .filter(|c| !kept.contains(&c.name))
                        .map(|c| c.name.clone())
                        .collect();
                    for name in dropped {
                        out.remove(&name, op.kind());
                    }
                    out.known = reshaped(input.known);
                    out.narrowed = true;
                    out.custom_columns = false;
                    out.reshaped_by = Some(op.kind());
                }
                out
            }
            "project_rename_operator" => {
                let mut out = input.clone();
                out.reshaped_by = Some(op.kind());
                let mut cursor = op.walk();
                for item in op.children_by_field_name("renames", &mut cursor) {
                    let (Some(new), Some(old)) = (
                        item.child_by_field_name("new"),
                        item.child_by_field_name("old"),
                    ) else {
                        continue;
                    };
                    let old_name = self.text(old).to_string();
                    let new_name = self.text(new).to_string();
                    self.reference(old, ctx, scope, span);
                    let type_name = input.column(&old_name).and_then(|c| c.type_name.clone());
                    out.remove(&old_name, op.kind());
                    let column = Column {
                        made_by: Some(made_by),
                        renamed_from: Some(old_name),
                        ..Column::new(new_name, type_name)
                    };
                    self.define(new, &column);
                    out.set(column);
                }
                out
            }
            "extend_operator" => {
                let mut out = input.clone();
                let mut defined: Vec<String> = Vec::new();
                let mut cursor = op.walk();
                for item in op.children_by_field_name("assignments", &mut cursor) {
                    // A column made earlier in the same `extend` is in reach.
                    let extra: Vec<&str> = defined.iter().map(String::as_str).collect();
                    match self.column_item(item, &input, scope, span, &extra) {
                        Item::Named(names, type_name) => {
                            for (name, node) in names.into_iter().zip(self.assigned_names(item)) {
                                let column = Column {
                                    made_by: Some(made_by),
                                    ..Column::new(name.clone(), type_name.clone())
                                };
                                self.define(node, &column);
                                defined.push(name);
                                out.set(column);
                            }
                        }
                        Item::Unnamed(Some(_)) => {}
                        // `extend tolower(X)` names its column `Column1`.
                        Item::Unnamed(None) => out.make_open(),
                    }
                }
                out
            }
            "summarize_operator" => self.summarize(op, input, scope, made_by),
            "distinct_operator" => {
                let idents = self.identifiers(op, "columns");
                if idents.is_empty() {
                    return input;
                }
                let mut out = Schema {
                    columns: Vec::new(),
                    known: reshaped(input.known),
                    narrowed: true,
                    custom_columns: false,
                    reshaped_by: Some(op.kind()),
                    removed: HashMap::new(),
                    ..input.clone()
                };
                for ident in idents {
                    self.reference(ident, ctx, scope, span);
                    let name = self.text(ident);
                    let column = input
                        .column(name)
                        .cloned()
                        .unwrap_or_else(|| Column::new(name, None));
                    out.set(column);
                }
                out
            }
            "join_operator" => self.join(op, input, scope, made_by),
            "lookup_operator" => self.lookup(op, input, scope, made_by),
            "union_operator" => self.union(op, Some(input), scope),
            "mv_expand_operator" => self.mv_expand(op, input, scope, made_by),
            "mv_apply_operator" => {
                let mut out = self.mv_expand(op, input, scope, made_by);
                if let Some(sub) = op.child_by_field_name("subquery") {
                    let mut inner = out.clone();
                    inner.make_open();
                    let result = self.subquery(sub, inner, scope);
                    for column in result.columns {
                        if !out.has(&column.name) {
                            out.columns.push(column);
                        }
                    }
                }
                out.make_open();
                out
            }
            "parse_operator" => {
                let mut out = input.clone();
                if let Some(column) = op.child_by_field_name("column") {
                    self.expression(column, ctx, scope, span, &[]);
                }
                let mut cursor = op.walk();
                for part in op.children_by_field_name("pattern", &mut cursor) {
                    if part.kind() != "parse_column" {
                        continue;
                    }
                    let Some(name) = part.named_child(0) else {
                        continue;
                    };
                    let type_name = part
                        .named_child(1)
                        .map(|t| self.text(t).trim().to_string())
                        .unwrap_or_else(|| "string".into());
                    let column = Column {
                        made_by: Some(made_by),
                        ..Column::new(self.text(name), Some(type_name))
                    };
                    self.define(name, &column);
                    out.set(column);
                }
                out
            }
            "make_series_operator" => {
                for field in ["aggregates", "axis", "from", "to", "step", "by"] {
                    let mut cursor = op.walk();
                    for child in op.children_by_field_name(field, &mut cursor) {
                        self.expression(child, ctx, scope, span, &[]);
                    }
                }
                let mut out = input;
                out.make_open();
                out.narrowed = true;
                out.reshaped_by = Some(op.kind());
                out
            }
            "evaluate_operator" => {
                let plugin = op
                    .child_by_field_name("plugin")
                    .and_then(|p| p.child_by_field_name("name"))
                    .map(|n| self.text(n).to_ascii_lowercase())
                    .unwrap_or_default();
                let mut out = input;
                // bag_unpack and the lookup plugins add columns to the rows;
                // the others return a table of their own.
                if !matches!(
                    plugin.as_str(),
                    "bag_unpack" | "ipv4_lookup" | "ipv6_lookup" | "geoip_lookup"
                ) {
                    out.columns.clear();
                    out.narrowed = true;
                }
                out.make_open();
                out
            }
            "keyword_operator" => {
                let keyword = op
                    .child(0)
                    .map(|k| self.text(k).to_ascii_lowercase())
                    .unwrap_or_default();
                let bare = op.child_by_field_name("args").is_none();
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
            // parse-where, parse-kv, unknown operators: their columns are
            // not modelled.
            _ => {
                let mut out = input;
                out.make_open();
                out
            }
        }
    }

    fn identifiers<'t>(&self, op: Node<'t>, field: &str) -> Vec<Node<'t>> {
        let mut cursor = op.walk();
        op.children_by_field_name(field, &mut cursor)
            .filter(|n| n.kind() == "identifier")
            .collect()
    }

    /// The name nodes an assignment item writes (`A = ...`, `(A, B) = ...`).
    fn assigned_names<'t>(&self, item: Node<'t>) -> Vec<Node<'t>> {
        let assignment = if item.kind() == "assignment" {
            Some(item)
        } else {
            item.named_child(0).filter(|n| n.kind() == "assignment")
        };
        let Some(assignment) = assignment else {
            return Vec::new();
        };
        let mut cursor = assignment.walk();
        assignment
            .children_by_field_name("name", &mut cursor)
            .filter(|n| n.kind() == "identifier")
            .collect()
    }

    fn project(&mut self, op: Node, input: Schema, scope: &Scope, made_by: MadeBy) -> Schema {
        let span = made_by.span;
        let mut out = Schema {
            columns: Vec::new(),
            known: reshaped(input.known),
            narrowed: true,
            custom_columns: false,
            reshaped_by: Some(op.kind()),
            removed: HashMap::new(),
            ..input.clone()
        };
        let mut defined: Vec<String> = Vec::new();
        let mut cursor = op.walk();
        for item in op.children_by_field_name("columns", &mut cursor) {
            let extra: Vec<&str> = defined.iter().map(String::as_str).collect();
            match self.column_item(item, &input, scope, span, &extra) {
                Item::Named(names, type_name) => {
                    let from = item
                        .named_child(0)
                        .filter(|n| n.kind() == "assignment")
                        .and_then(|a| a.child_by_field_name("value"))
                        .and_then(simple_ident)
                        .map(|n| self.text(n).to_string());
                    for (name, node) in names.into_iter().zip(self.assigned_names(item)) {
                        let column = Column {
                            made_by: Some(made_by),
                            renamed_from: from.clone().filter(|f| *f != name),
                            ..Column::new(name.clone(), type_name.clone())
                        };
                        self.define(node, &column);
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

    fn summarize(&mut self, op: Node, input: Schema, scope: &Scope, made_by: MadeBy) -> Schema {
        let span = made_by.span;
        let ctx_input = input.clone();
        let mut out = Schema {
            columns: Vec::new(),
            known: reshaped(input.known),
            narrowed: true,
            custom_columns: false,
            reshaped_by: Some(op.kind()),
            removed: HashMap::new(),
            ..input.clone()
        };
        let mut by_columns = Vec::new();
        let mut cursor = op.walk();
        for item in op.children_by_field_name("by", &mut cursor) {
            match self.column_item(item, &ctx_input, scope, span, &[]) {
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
                    // `by bin(T, 1h)`, `floor(X, 10)`, `bin_at(...)`,
                    // `startofday(T)` keep the column's name.
                    let call = item.named_child(0).and_then(simple_call);
                    let kept = call.and_then(|c| {
                        let name = c.child_by_field_name("name").map(|n| self.text(n))?;
                        if !matches!(
                            name,
                            "bin" | "floor" | "bin_at" | "startofday" | "startofhour"
                        ) {
                            return None;
                        }
                        let mut args = c.walk();
                        let first = c
                            .children_by_field_name("arguments", &mut args)
                            .find(|n| n.is_named())?;
                        simple_ident(first).map(|n| self.text(n).to_string())
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
        for column in by_columns {
            out.push_unique(column);
        }
        let mut cursor = op.walk();
        for item in op.children_by_field_name("aggregates", &mut cursor) {
            match self.column_item(item, &ctx_input, scope, span, &[]) {
                // `L = arg_max(T, *)` names T's column `L` and keeps the rest.
                Item::Named(names, _) if names.len() == 1 && self.is_arg_extreme(item) => {
                    let Some(mut columns) = self.aggregate_columns(item, &ctx_input) else {
                        out.make_open();
                        continue;
                    };
                    if let Some(first) = columns.first_mut() {
                        first.name = names[0].clone();
                    }
                    if let Some(node) = self.assigned_names(item).first() {
                        self.define(*node, &columns[0]);
                    }
                    for column in columns {
                        out.push_unique(Column {
                            made_by: Some(made_by),
                            ..column
                        });
                    }
                }
                // The deprecated `argmax`/`argmin` name their columns
                // `max_T_Col`, and `percentiles` makes one column per
                // percentile: a single name does not say what they make.
                Item::Named(_, _)
                    if self
                        .aggregate_call(item)
                        .and_then(|c| c.child_by_field_name("name"))
                        .is_some_and(|n| {
                            matches!(
                                self.text(n),
                                "argmax" | "argmin" | "percentiles" | "percentilesw"
                            )
                        }) =>
                {
                    out.make_open();
                }
                Item::Named(names, type_name) => {
                    for (name, node) in names.into_iter().zip(self.assigned_names(item)) {
                        let column = Column {
                            made_by: Some(made_by),
                            ..Column::new(name, type_name.clone())
                        };
                        self.define(node, &column);
                        out.push_unique(column);
                    }
                }
                Item::Unnamed(_) => match self.aggregate_columns(item, &ctx_input) {
                    Some(columns) => {
                        for column in columns {
                            out.push_unique(Column {
                                made_by: Some(made_by),
                                ..column
                            });
                        }
                    }
                    None => out.make_open(),
                },
            }
        }
        out
    }

    /// `arg_max(...)` or `arg_min(...)`, named or not.
    fn is_arg_extreme(&self, item: Node) -> bool {
        self.aggregate_call(item)
            .and_then(|c| c.child_by_field_name("name"))
            .is_some_and(|n| matches!(self.text(n), "arg_max" | "arg_min"))
    }

    /// The aggregate call of a summarize item, named or not.
    fn aggregate_call<'t>(&self, item: Node<'t>) -> Option<Node<'t>> {
        let inner = item.named_child(0)?;
        if inner.kind() == "assignment" {
            return inner.child_by_field_name("value").and_then(simple_call);
        }
        simple_call(inner)
    }

    /// The columns an unnamed aggregate makes, as Kusto names them
    /// (`count()` is `count_`, `dcount(User)` is `dcount_User`,
    /// `arg_max(T, *)` keeps every column). `None` when the naming is not
    /// modelled.
    fn aggregate_columns(&self, item: Node, input: &Schema) -> Option<Vec<Column>> {
        let call = self.aggregate_call(item)?;
        let name = self
            .text(call.child_by_field_name("name")?)
            .to_ascii_lowercase();
        let mut cursor = call.walk();
        let args: Vec<Node> = call
            .children_by_field_name("arguments", &mut cursor)
            .filter(|n| n.is_named())
            .collect();
        let first = || {
            args.first()
                .copied()
                .and_then(simple_ident)
                .map(|n| self.text(n).to_string())
        };
        let typed = |column: &str| input.column(column).and_then(|c| c.type_name.clone());
        let one =
            |name: String, type_name: Option<String>| Some(vec![Column::new(name, type_name)]);
        match name.as_str() {
            "count" => one("count_".into(), Some("long".into())),
            "countif" => one("countif_".into(), Some("long".into())),
            "make_bag" | "make_bag_if" => one("bag_".into(), Some("dynamic".into())),
            "dcount" | "dcountif" => one(format!("{name}_{}", first()?), Some("long".into())),
            "sum" | "sumif" | "min" | "max" | "minif" | "maxif" => {
                let column = first()?;
                let type_name = typed(&column);
                one(format!("{name}_{column}"), type_name)
            }
            "avg" | "avgif" | "stdev" | "stdevif" | "variance" | "varianceif" => {
                one(format!("{name}_{}", first()?), Some("real".into()))
            }
            "make_set" | "make_set_if" => one(format!("set_{}", first()?), Some("dynamic".into())),
            "make_list" | "make_list_if" => {
                one(format!("list_{}", first()?), Some("dynamic".into()))
            }
            "take_any" => {
                let column = first()?;
                let type_name = typed(&column);
                one(column, type_name)
            }
            "arg_max" | "arg_min" => {
                let mut out = Vec::new();
                for arg in &args {
                    if arg.kind() == "star" {
                        for column in &input.columns {
                            if !out.iter().any(|c: &Column| c.name == column.name) {
                                out.push(Column::new(
                                    column.name.clone(),
                                    column.type_name.clone(),
                                ));
                            }
                        }
                        continue;
                    }
                    let column = simple_ident(*arg).map(|n| self.text(n).to_string())?;
                    let type_name = typed(&column);
                    out.push(Column::new(column, type_name));
                }
                Some(out)
            }
            _ => None,
        }
    }

    fn join(&mut self, op: Node, left: Schema, scope: &Scope, made_by: MadeBy) -> Schema {
        let kind = self
            .option(op, "kind")
            .unwrap_or_else(|| "innerunique".into());
        let right = op
            .child_by_field_name("right")
            .map(|r| self.primary(r, scope))
            .unwrap_or_else(Schema::open);
        let mut cursor = op.walk();
        for condition in op.children_by_field_name("condition", &mut cursor) {
            self.expression(
                condition,
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
                for column in &right.columns {
                    out.push_unique(column.clone());
                }
                out.weaken(right.known);
                out.custom_columns |= right.custom_columns;
                out
            }
        };
        out.weaken(left.known.min(right.known));
        out.narrowed = left.narrowed && right.narrowed;
        out.reshaped_by = Some(op.kind());
        out
    }

    fn lookup(&mut self, op: Node, left: Schema, scope: &Scope, made_by: MadeBy) -> Schema {
        let right = op
            .child_by_field_name("table")
            .map(|r| self.primary(r, scope))
            .unwrap_or_else(Schema::open);
        let mut keys = BTreeSet::new();
        let mut cursor = op.walk();
        for condition in op.children_by_field_name("condition", &mut cursor) {
            self.expression(
                condition,
                Ctx::Join(&left, &right),
                scope,
                made_by.span,
                &[],
            );
            if let Some(ident) = simple_ident(condition) {
                keys.insert(self.text(ident).to_string());
            } else {
                // `$left.A == $right.B`: B is the right side's key.
                let mut stack = vec![condition];
                while let Some(node) = stack.pop() {
                    if node.kind() == "member_expression" {
                        let object = node
                            .child_by_field_name("object")
                            .map(|o| self.text(o).trim().to_string());
                        if object.as_deref() == Some("$right") {
                            if let Some(member) = node.child_by_field_name("member") {
                                keys.insert(self.text(member).to_string());
                            }
                        }
                        continue;
                    }
                    let mut c = node.walk();
                    stack.extend(node.named_children(&mut c));
                }
            }
        }
        let mut out = left.clone();
        for column in &right.columns {
            if !keys.contains(&column.name) {
                out.push_unique(column.clone());
            }
        }
        out.weaken(right.known);
        out.custom_columns |= right.custom_columns;
        out.reshaped_by = Some(op.kind());
        out
    }

    fn mv_expand(&mut self, op: Node, input: Schema, scope: &Scope, made_by: MadeBy) -> Schema {
        let span = made_by.span;
        let mut out = input.clone();
        let mut cursor = op.walk();
        for child in op.named_children(&mut cursor) {
            match child.kind() {
                "mv_option" => {
                    let name = child.child(0).map(|n| self.text(n)).unwrap_or_default();
                    if name == "with_itemindex" {
                        if let Some(value) = child.child_by_field_name("value") {
                            let column = Column {
                                made_by: Some(made_by),
                                ..Column::new(self.text(value), Some("long".into()))
                            };
                            self.define(value, &column);
                            out.set(column);
                        }
                    }
                }
                "mv_expand_item" => {
                    let to_type = child
                        .named_children(&mut child.walk())
                        .find(|n| n.kind() == "type")
                        .map(|t| self.text(t).trim().to_string())
                        .unwrap_or_else(|| "dynamic".into());
                    let Some(first) = child.named_child(0) else {
                        continue;
                    };
                    if first.kind() == "assignment" {
                        if let Some(value) = first.child_by_field_name("value") {
                            self.expression(value, Ctx::One(&input), scope, span, &[]);
                        }
                        for name in self.assigned_names(first) {
                            let column = Column {
                                made_by: Some(made_by),
                                ..Column::new(self.text(name), Some(to_type.clone()))
                            };
                            self.define(name, &column);
                            out.set(column);
                        }
                    } else {
                        self.expression(first, Ctx::One(&input), scope, span, &[]);
                        match simple_ident(first) {
                            Some(ident) => {
                                let name = self.text(ident);
                                if let Some(column) =
                                    out.columns.iter_mut().find(|c| c.name == name)
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
        if let Some(limit) = op.child_by_field_name("limit") {
            self.expression(limit, Ctx::One(&input), scope, span, &[]);
        }
        out
    }

    fn option(&self, op: Node, name: &str) -> Option<String> {
        let mut cursor = op.walk();
        op.named_children(&mut cursor)
            .filter(|c| c.kind() == "operator_option")
            .find(|c| {
                c.child_by_field_name("name")
                    .is_some_and(|n| self.text(n).eq_ignore_ascii_case(name))
            })
            .and_then(|c| c.child_by_field_name("value"))
            .map(|v| self.text(v).to_ascii_lowercase())
    }

    // --- items and expressions ---------------------------------------------

    /// A `column_item` / `project_item`: check what it reads, and say what it
    /// names.
    fn column_item(
        &mut self,
        item: Node,
        input: &Schema,
        scope: &Scope,
        span: ByteSpan,
        extra: &[&str],
    ) -> Item {
        let Some(inner) = item.named_child(0) else {
            return Item::Unnamed(None);
        };
        if inner.kind() == "assignment" {
            let value = inner.child_by_field_name("value");
            if let Some(value) = value {
                self.expression(value, Ctx::One(input), scope, span, extra);
            }
            let names: Vec<String> = self
                .assigned_names(inner)
                .into_iter()
                .map(|n| self.text(n).to_string())
                .collect();
            let type_name = if names.len() == 1 {
                value.and_then(|v| self.type_of(v, input))
            } else {
                None
            };
            return Item::Named(names, type_name);
        }
        self.expression(inner, Ctx::One(input), scope, span, extra);
        // A bare column keeps its name and type.
        if let Some(ident) = simple_ident(inner) {
            let name = self.text(ident);
            let column = input
                .column(name)
                .cloned()
                .unwrap_or_else(|| Column::new(name, None));
            return Item::Unnamed(Some(column));
        }
        Item::Unnamed(None)
    }

    /// The type of a simple expression, when it is plain.
    fn type_of(&self, expr: Node, input: &Schema) -> Option<String> {
        let node = simple_primary(expr)?;
        match node.kind() {
            "identifier" => input.column(self.text(node))?.type_name.clone(),
            "string" => Some("string".into()),
            "boolean" => Some("bool".into()),
            "timespan" => Some("timespan".into()),
            "dynamic_literal" => Some("dynamic".into()),
            // `datetime(2024-01-01)`, `long(null)`: the literal's type.
            "typed_literal" => {
                let text = self.text(node);
                let name = text[..text.find('(')?].trim().to_ascii_lowercase();
                Some(match name.as_str() {
                    "date" => "datetime".into(),
                    "time" => "timespan".into(),
                    "double" => "real".into(),
                    "boolean" => "bool".into(),
                    "uniqueid" => "guid".into(),
                    other => other.to_string(),
                })
            }
            "number" => Some(if self.text(node).contains(['.', 'e', 'E']) {
                "real".into()
            } else {
                "long".into()
            }),
            "function_call" => {
                let name = self
                    .text(node.child_by_field_name("name")?)
                    .to_ascii_lowercase();
                let t = match name.as_str() {
                    "tostring" | "tolower" | "toupper" | "strcat" | "trim" | "substring"
                    | "replace_string" | "extract" | "strcat_delim" | "format_datetime" => "string",
                    "toint" => "int",
                    "tolong" | "strlen" | "array_length" => "long",
                    "todouble" | "toreal" => "real",
                    "tobool" | "toboolean" | "isempty" | "isnotempty" | "isnull" | "isnotnull" => {
                        "bool"
                    }
                    "todatetime" | "now" | "ago" | "datetime" => "datetime",
                    "count" | "countif" | "dcount" | "dcountif" => "long",
                    "make_set" | "make_list" | "make_bag" | "make_set_if" | "make_list_if" => {
                        "dynamic"
                    }
                    "avg" | "avgif" | "stdev" | "variance" => "real",
                    "totimespan" => "timespan",
                    "todynamic" | "parse_json" | "pack" | "bag_pack" | "pack_array" | "split" => {
                        "dynamic"
                    }
                    _ => return None,
                };
                Some(t.into())
            }
            _ => None,
        }
    }

    fn expression(&mut self, node: Node, ctx: Ctx, scope: &Scope, op: ByteSpan, extra: &[&str]) {
        match node.kind() {
            "identifier" => {
                if node
                    .parent()
                    .is_some_and(|p| p.kind() == "primary_expression")
                {
                    self.reference_in(node, ctx, scope, op, extra);
                }
            }
            "function_call" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n).to_ascii_lowercase())
                    .unwrap_or_default();
                if LITERAL_FUNCTIONS.contains(&name.as_str()) {
                    return;
                }
                let mut cursor = node.walk();
                for arg in node.children_by_field_name("arguments", &mut cursor) {
                    let value = if arg.kind() == "named_argument" {
                        arg.child_by_field_name("value")
                    } else {
                        Some(arg)
                    };
                    if let Some(value) = value {
                        self.expression(value, ctx, scope, op, extra);
                    }
                }
            }
            "member_expression" => {
                let Some(object) = node.child_by_field_name("object") else {
                    return;
                };
                let side = self.text(object).trim();
                if side == "$left" || side == "$right" {
                    if let (Ctx::Join(left, right), Some(member)) =
                        (ctx, node.child_by_field_name("member"))
                    {
                        let schema = if side == "$left" { left } else { right };
                        self.reference_in(member, Ctx::One(schema), scope, op, extra);
                    }
                    return;
                }
                // `Bag.key`: only the column is checked, not the property.
                self.expression(object, ctx, scope, op, extra);
            }
            "toscalar_expression" | "materialize_expression" => {
                if let Some(body) = node.child_by_field_name("body") {
                    self.tabular(body, scope);
                }
            }
            "tabular_expression" => {
                self.tabular(node, scope);
            }
            "comparison_expression" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    self.expression(child, ctx, scope, op, extra);
                }
                if let Ctx::One(schema) = ctx {
                    self.check_types(node, schema, scope);
                }
            }
            "string" | "number" | "timespan" | "boolean" | "null" | "dynamic_literal"
            | "typed_literal" | "comment" | "type" | "star" => {}
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    self.expression(child, ctx, scope, op, extra);
                }
            }
        }
    }

    fn reference(&mut self, ident: Node, ctx: Ctx, scope: &Scope, op: ByteSpan) {
        self.reference_in(ident, ctx, scope, op, &[]);
    }

    /// A name read where a column is expected.
    fn reference_in(&mut self, ident: Node, ctx: Ctx, scope: &Scope, op: ByteSpan, extra: &[&str]) {
        let name = self.text(ident);
        if name.starts_with('$') || scope.binds(name) || extra.contains(&name) {
            return;
        }
        // `in (SigninLogs)`, `in (_Im_Dns)`: a single-column table.
        if self.catalog.table(name).is_some() || self.catalog.asim_parser(name).is_some() {
            return;
        }
        let span = Self::span(ident);
        let schemas: Vec<&Schema> = match ctx {
            Ctx::One(s) => vec![s],
            Ctx::Join(l, r) => vec![l, r],
        };
        // A join key (`on Key`) must be on both sides.
        let found = if schemas
            .iter()
            .all(|s| s.has(name) || s.known == Known::Open)
        {
            schemas.iter().find_map(|s| s.column(name)).cloned()
        } else {
            None
        };
        if self.quiet == 0 {
            self.out.references.push(Reference {
                name: name.to_string(),
                span,
                column: found.clone(),
                operator: op,
            });
        }
        if found.is_some() || self.quiet > 0 || !self.diagnose {
            return;
        }
        // A join key must be on both sides; report against the first that lacks it.
        let Some(schema) = schemas
            .into_iter()
            .find(|s| !s.has(name) && s.known != Known::Open)
        else {
            return;
        };
        if schema.custom_columns && tables::is_custom_column(name) {
            return;
        }
        // A column an operator removed is gone, whatever the source documents.
        if let Some(op) = schema.removed.get(name) {
            self.out.diagnostics.push(Diagnostic::error(
                codes::KQL_UNKNOWN_COLUMN,
                format!("'{name}' is not a column after `{}`", operator_keyword(op)),
                span_to_range(self.source, span),
            ));
            return;
        }
        let suggestion = schema
            .columns
            .iter()
            .map(|c| {
                (
                    c,
                    strsim_distance(&c.name.to_ascii_lowercase(), &name.to_ascii_lowercase()),
                )
            })
            .filter(|(_, d)| *d <= 2 && *d * 2 < name.len())
            .min_by_key(|(_, d)| *d)
            .map(|(c, _)| c.name.clone());
        let report = match schema.known {
            Known::Closed => true,
            Known::Typos => suggestion.is_some(),
            Known::Open => false,
        };
        if !report {
            return;
        }
        let message = match schema.reshaped_by {
            Some(op) => format!("'{name}' is not a column after `{}`", operator_keyword(op)),
            None => format!("'{name}' is not a column of {}", schema.describe_source()),
        };
        let mut d = Diagnostic::error(
            codes::KQL_UNKNOWN_COLUMN,
            message,
            span_to_range(self.source, span),
        );
        if let Some(s) = suggestion {
            d = d.with_suggestion(s);
        }
        self.out.diagnostics.push(d);
    }

    fn define(&mut self, node: Node, column: &Column) {
        if self.quiet == 0 {
            self.out.definitions.push(Definition {
                column: column.clone(),
                span: Self::span(node),
            });
        }
    }

    // --- types --------------------------------------------------------------

    /// `kql_type_mismatch`: an operator Kusto does not define for a column's
    /// documented type (`EventID has "46"`, `TimeGenerated > "2024-01-01"`,
    /// `Account between ("a" .. "b")`). Only on a column the pass resolved.
    fn check_types(&mut self, node: Node, schema: &Schema, scope: &Scope) {
        if self.quiet > 0 || !self.diagnose || schema.known == Known::Open {
            return;
        }
        let mut cursor = node.walk();
        let children: Vec<Node> = node.children(&mut cursor).collect();
        let Some(left) = children.first().copied().filter(|n| n.is_named()) else {
            return;
        };
        let tokens: Vec<Node> = children
            .iter()
            .skip(1)
            .take_while(|n| !n.is_named())
            .copied()
            .collect();
        if tokens.is_empty() {
            return;
        }
        let operator: String = tokens
            .iter()
            .map(|t| self.text(*t))
            .collect::<Vec<_>>()
            .join(" ");
        let right = children
            .iter()
            .skip(1 + tokens.len())
            .copied()
            .find(|n| n.is_named());
        let op_span = ByteSpan::new(tokens[0].start_byte(), tokens[tokens.len() - 1].end_byte());
        let column_of = |pass: &Self, n: Node| -> Option<(String, String)> {
            let ident = simple_ident(n)?;
            let name = pass.text(ident);
            if scope.binds(name) {
                return None;
            }
            let column = schema.column(name)?;
            Some((column.name.clone(), column.type_name.clone()?))
        };
        let literal = |pass: &Self, n: Node| -> Option<&'static str> {
            let node = simple_primary(n)?;
            match node.kind() {
                "string" => Some("string"),
                "number" => Some(if pass.text(node).contains('.') {
                    "real"
                } else {
                    "long"
                }),
                _ => None,
            }
        };
        let op = operator.as_str();
        let mut found: Option<(String, String)> = None;
        if STRING_OPERATORS.contains(&op) || STRING_SET_OPERATORS.contains(&op) {
            if let Some((column, kind)) = column_of(self, left) {
                if NUMERIC.contains(&kind.as_str())
                    || matches!(kind.as_str(), "datetime" | "timespan" | "bool")
                {
                    found = Some((column, kind));
                }
            }
        } else if op == "between" || op == "!between" {
            if let Some((column, kind)) = column_of(self, left) {
                if matches!(kind.as_str(), "string" | "bool" | "guid") {
                    found = Some((column, kind));
                }
            }
        } else if ORDERING.contains(&op) {
            if let Some(right) = right {
                let pairs = [(left, right), (right, left)];
                for (c, l) in pairs {
                    let (Some((column, kind)), Some(lit)) = (column_of(self, c), literal(self, l))
                    else {
                        continue;
                    };
                    let bad = match kind.as_str() {
                        "string" | "guid" | "datetime" | "timespan" => true,
                        k if NUMERIC.contains(&k) => lit == "string",
                        _ => false,
                    };
                    if bad {
                        found = Some((column, kind));
                        break;
                    }
                }
            }
        }
        let Some((column, kind)) = found else {
            return;
        };
        self.out.diagnostics.push(Diagnostic::error(
            codes::KQL_TYPE_MISMATCH,
            format!(
                "`{op}` is not defined for `{column}`, {} {kind} column; Kusto rejects the query",
                if kind.starts_with(['a', 'e', 'i', 'o', 'u']) {
                    "an"
                } else {
                    "a"
                }
            ),
            span_to_range(self.source, op_span),
        ));
    }
}

enum Item {
    /// `A = ...` or `(A, B) = ...`, with the type when it is plain.
    Named(Vec<String>, Option<String>),
    /// An expression without a name: a bare column keeps its own; anything
    /// else gets a generated name (`Column1`), which is `None`.
    Unnamed(Option<Column>),
}

/// The columns an operator such as `project` leaves are exactly those it
/// names, unless the pass already lost track of the rows' columns.
fn reshaped(input: Known) -> Known {
    if input == Known::Open {
        Known::Open
    } else {
        Known::Closed
    }
}

/// The keyword an operator node is written with.
fn operator_keyword(kind: &str) -> &'static str {
    match kind {
        "where_operator" => "where",
        "filter_operator" => "filter",
        "project_operator" => "project",
        "project_away_operator" => "project-away",
        "project_keep_operator" => "project-keep",
        "project_rename_operator" => "project-rename",
        "project_reorder_operator" => "project-reorder",
        "extend_operator" => "extend",
        "summarize_operator" => "summarize",
        "distinct_operator" => "distinct",
        "join_operator" => "join",
        "lookup_operator" => "lookup",
        "union_operator" => "union",
        "mv_expand_operator" => "mv-expand",
        "mv_apply_operator" => "mv-apply",
        "parse_operator" => "parse",
        "count_operator" => "count",
        "make_series_operator" => "make-series",
        "evaluate_operator" => "evaluate",
        _ => "the operator",
    }
}

/// The single node a chain of one-child expression wrappers holds
/// (`expression` → ... → `primary_expression` → X), or `None` when the
/// expression has an operator.
pub(crate) fn simple_primary(node: Node) -> Option<Node> {
    let mut node = node;
    loop {
        match node.kind() {
            "expression"
            | "or_expression"
            | "and_expression"
            | "not_expression"
            | "comparison_expression"
            | "additive_expression"
            | "multiplicative_expression"
            | "unary_expression"
            | "primary_expression"
            | "column_item"
            | "project_item"
            | "sort_item" => {
                if node.child_count() != 1 {
                    return None;
                }
                node = node.named_child(0)?;
            }
            _ => return Some(node),
        }
    }
}

/// The identifier an expression is, if it is a bare name.
pub(crate) fn simple_ident(node: Node) -> Option<Node> {
    simple_primary(node).filter(|n| n.kind() == "identifier")
}

/// The call an expression is, if it is a bare call.
pub(crate) fn simple_call(node: Node) -> Option<Node> {
    simple_primary(node).filter(|n| n.kind() == "function_call")
}
