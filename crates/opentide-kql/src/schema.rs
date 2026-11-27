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

use crate::{Catalog, Dialect, tables};
use foldhash::{HashMap, HashMapExt, HashSet};
use opentide_core::{ByteSpan, Diagnostic, codes};
use std::collections::BTreeSet;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

pub(crate) mod new_tree;

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
    /// The catalog table or ASIM schema it comes from; `None` for a column
    /// the query makes or a source the catalog does not know.
    pub origin: Option<Origin>,
}

impl Column {
    fn new(name: impl Into<String>, type_name: Option<String>) -> Self {
        Self {
            name: name.into(),
            type_name,
            made_by: None,
            renamed_from: None,
            origin: None,
        }
    }

    fn with_origin(mut self, origin: Origin) -> Self {
        self.origin = Some(origin);
        self
    }
}

/// Where a column of a source comes from: what hover describes it with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A catalog table (`SigninLogs`): its catalog row has the column's docs.
    /// Shared: every column of a table names it, and copying a pipeline's
    /// columns copied it once per column.
    Table(Arc<str>),
    /// An ASIM schema, with the column's class (`Mandatory`, `Optional`, ...).
    Asim { schema: Arc<str>, class: Arc<str> },
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

/// A schema's columns, in order, with an index from name to position once
/// the schema is changed often enough to need one.
///
/// An operator looks up each column it sets: a scan per lookup made a
/// `project` of n columns compare n²/2 names (150k columns took 48 s,
/// #1628), and the references to such a schema m·n. The index holds
/// positions, not names. The changes that look a name up (`set`, `get_mut`)
/// count the columns they scan and build it once that passes
/// `SCANNED_BEFORE_INDEX` times the schema's length. A schema that gained
/// `PUSHED_BEFORE_INDEX` columns (`summarize`, `join`, `union`, `mv-apply`
/// push theirs) counts its lookups' scans too, and builds it the same way:
/// built on the push, it cost the corpus analysis 1.2%, as a join or a union
/// pushes a whole table its query reads a few times. Then every change keeps
/// it in step, a copy keeps it, and every lookup uses it. A schema
/// that is only read (a catalog table's, shared between analyses, as long
/// as the catalog says) is scanned: a lookup that counted or built cost
/// every reference of every query 0.5% of the analysis.
#[derive(Default)]
pub struct Columns {
    list: Vec<Arc<Column>>,
    /// The position of the first column of each name.
    index: OnceLock<Index>,
    /// The columns scanned toward building the index: by the changes, and by
    /// the lookups once [`Self::pushed`] says the schema is wide.
    scanned: AtomicUsize,
    /// The columns added while the schema had no index.
    pushed: usize,
}

/// Schemas up to this long are always scanned: hashing costs about as much.
const SCAN_ONLY: usize = 8;
/// How many times its length the changes scan before a schema's index is
/// built: hashing every name and inserting it costs about as much as
/// comparing that many names, and an `extend` of a few columns to a long
/// table costs less than building it.
const SCANNED_BEFORE_INDEX: usize = 8;
/// How many columns added make a schema count its lookups toward the index:
/// below it, the counting costs more than the scans it would save.
const PUSHED_BEFORE_INDEX: usize = 64;

/// A schema's name index: positions in its list, hashed with a seed of its
/// own. Column names come from the query, so a fixed seed would let a query
/// pick names that collide and bring the n² back (ADR 0014 §5b).
#[derive(Clone)]
struct Index {
    table: hashbrown::HashTable<usize>,
    hasher: foldhash::fast::RandomState,
}

impl Index {
    fn hash(&self, name: &str) -> u64 {
        self.hasher.hash_one(name)
    }

    fn find(&self, list: &[Arc<Column>], name: &str) -> Option<usize> {
        #[cfg(test)]
        tests::count_name_compared();
        self.table
            .find(self.hash(name), |&i| list[i].name == name)
            .copied()
    }

    /// Record position `i` for `name` unless an earlier column has the name;
    /// `list` may not hold the column yet (`i == list.len()`).
    fn insert(&mut self, list: &[Arc<Column>], i: usize, name: &str) {
        let hash = self.hash(name);
        if self.table.find(hash, |&j| list[j].name == name).is_none() {
            let hasher = &self.hasher;
            self.table.insert_unique(hash, i, |&j| {
                hasher.hash_one(list.get(j).map_or(name, |c| c.name.as_str()))
            });
        }
    }
}

impl Columns {
    /// The column named `name`.
    #[must_use]
    #[inline]
    pub fn get(&self, name: &str) -> Option<&Arc<Column>> {
        self.position(name).map(|i| &self.list[i])
    }

    /// The position of the first column named `name`.
    #[must_use]
    #[inline]
    pub fn position(&self, name: &str) -> Option<usize> {
        if let Some(index) = self.index.get() {
            return index.find(&self.list, name);
        }
        let found = self.list.iter().position(|c| {
            #[cfg(test)]
            tests::count_name_compared();
            c.name == name
        });
        if self.pushed >= PUSHED_BEFORE_INDEX {
            self.count_scanned(found);
        }
        found
    }

    /// Count a scan that found `found`, and build the index once the scans
    /// pass [`SCANNED_BEFORE_INDEX`] times the schema's length. A load and a
    /// store, not an atomic add: a count lost to a race only builds it later.
    #[cold]
    fn count_scanned(&self, found: Option<usize>) {
        let len = self.list.len();
        let scanned = self.scanned.load(Ordering::Relaxed) + found.map_or(len, |i| i + 1);
        self.scanned.store(scanned, Ordering::Relaxed);
        if scanned >= SCANNED_BEFORE_INDEX * len {
            self.index.get_or_init(|| self.build_index());
        }
    }

    /// [`Self::position`] for a change: counts what it scans, and builds the
    /// index once that is enough.
    fn position_to_change(&mut self, name: &str) -> Option<usize> {
        let found = self.position(name);
        let len = self.list.len();
        if self.index.get().is_none() && len > SCAN_ONLY && self.pushed < PUSHED_BEFORE_INDEX {
            let scanned = self.scanned.get_mut();
            *scanned += found.map_or(len, |i| i + 1);
            if *scanned >= SCANNED_BEFORE_INDEX * len {
                let index = self.build_index();
                self.index = OnceLock::from(index);
            }
        }
        found
    }

    fn build_index(&self) -> Index {
        let mut index = Index {
            table: hashbrown::HashTable::with_capacity(self.list.len()),
            hasher: foldhash::fast::RandomState::default(),
        };
        for (i, column) in self.list.iter().enumerate() {
            #[cfg(test)]
            tests::count_name_compared();
            index.insert(&self.list, i, &column.name);
        }
        index
    }

    /// Add `column` at the end.
    pub(crate) fn push(&mut self, column: impl Into<Arc<Column>>) {
        let column = column.into();
        if let Some(index) = self.index.get_mut() {
            // Before the push: `list` does not hold the column yet.
            index.insert(&self.list, self.list.len(), &column.name);
        } else {
            self.pushed += 1;
        }
        self.list.push(column);
    }

    /// Add `column`, replacing the first one of the same name.
    pub(crate) fn set(&mut self, column: Column) {
        match self.position_to_change(&column.name) {
            Some(i) => self.list[i] = Arc::new(column),
            None => self.push(column),
        }
    }

    /// The column named `name`, to change it. Not its name: the index would
    /// no longer find it.
    pub(crate) fn get_mut(&mut self, name: &str) -> Option<&mut Column> {
        let i = self.position_to_change(name)?;
        Some(Arc::make_mut(&mut self.list[i]))
    }

    /// Keep the columns `keep` accepts.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&Arc<Column>) -> bool) {
        let before = self.list.len();
        self.list.retain(|c| {
            #[cfg(test)]
            tests::count_name_compared();
            keep(c)
        });
        if self.list.len() != before {
            self.forget_index();
        }
    }

    /// Remove every column.
    pub(crate) fn clear(&mut self) {
        self.list.clear();
        self.forget_index();
    }

    fn forget_index(&mut self) {
        self.index = OnceLock::new();
        *self.scanned.get_mut() = 0;
        self.pushed = 0;
    }
}

impl From<Vec<Arc<Column>>> for Columns {
    fn from(list: Vec<Arc<Column>>) -> Self {
        Self {
            list,
            index: OnceLock::new(),
            scanned: AtomicUsize::new(0),
            pushed: 0,
        }
    }
}

impl Clone for Columns {
    fn clone(&self) -> Self {
        Self {
            list: self.list.clone(),
            index: self.index.clone(),
            scanned: AtomicUsize::new(self.scanned.load(Ordering::Relaxed)),
            pushed: self.pushed,
        }
    }
}

impl FromIterator<Arc<Column>> for Columns {
    fn from_iter<I: IntoIterator<Item = Arc<Column>>>(columns: I) -> Self {
        Self::from(columns.into_iter().collect::<Vec<_>>())
    }
}

impl std::fmt::Debug for Columns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.list.fmt(f)
    }
}

impl std::ops::Deref for Columns {
    type Target = [Arc<Column>];
    fn deref(&self) -> &Self::Target {
        &self.list
    }
}

impl IntoIterator for Columns {
    type Item = Arc<Column>;
    type IntoIter = std::vec::IntoIter<Arc<Column>>;
    fn into_iter(self) -> Self::IntoIter {
        self.list.into_iter()
    }
}

impl<'a> IntoIterator for &'a Columns {
    type Item = &'a Arc<Column>;
    type IntoIter = std::slice::Iter<'a, Arc<Column>>;
    fn into_iter(self) -> Self::IntoIter {
        self.list.iter()
    }
}

#[derive(Debug, Clone)]
pub struct Schema {
    /// Shared between the copies of a schema each stage of a pipeline
    /// records, until one of them changes its columns (`Arc::make_mut`):
    /// a deep copy per stage was a third of a short query's analysis.
    pub columns: Arc<Columns>,
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
            columns: Arc::default(),
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
            columns: Arc::new(Columns::from(
                columns.into_iter().map(Arc::new).collect::<Vec<_>>(),
            )),
            known: Known::Closed,
            source,
            ..Self::open()
        }
    }

    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.get(name).map(|c| &**c)
    }

    fn has(&self, name: &str) -> bool {
        self.column(name).is_some()
    }

    /// Add `column`, replacing one of the same name (as `extend` does).
    fn set(&mut self, column: Column) {
        self.removed.remove(&column.name);
        Arc::make_mut(&mut self.columns).set(column);
    }

    /// Add `columns`, in order, each under a name not yet taken: `Name`,
    /// `Name1`, `Name2`, ... as Kusto names the columns `join`, `lookup` and
    /// `summarize` repeat, the columns added before it counting as taken.
    /// One set of the names taken and, per name, the next suffix to try: a
    /// scan of the schema per column (and per suffix tried) made nested
    /// joins cubic in their depth (#1424). An operator adds all its columns
    /// in one call: a call per item rebuilt the set each time. The smallest free suffix of a name only grows as columns are
    /// added, so resuming from the last one gives the same names.
    fn push_all_unique(&mut self, columns: impl IntoIterator<Item = impl Into<Arc<Column>>>) {
        let mut taken: HashSet<String> = self.columns.iter().map(|c| c.name.clone()).collect();
        let mut next: HashMap<String, usize> = HashMap::new();
        for column in columns {
            let mut column: Arc<Column> = column.into();
            #[cfg(test)]
            tests::count_name_compared();
            if taken.contains(&column.name) {
                let column = Arc::make_mut(&mut column);
                let base = std::mem::take(&mut column.name);
                let n = next.entry(base.clone()).or_insert(1);
                while taken.contains(&format!("{base}{n}")) {
                    #[cfg(test)]
                    tests::count_name_compared();
                    *n += 1;
                }
                column.name = format!("{base}{n}");
            }
            taken.insert(column.name.clone());
            self.removed.remove(&column.name);
            Arc::make_mut(&mut self.columns).push(column);
        }
    }

    fn remove(&mut self, name: &str, by: &'static str) {
        // Copied on write only when there is a column to remove.
        if self.has(name) {
            Arc::make_mut(&mut self.columns).retain(|c| c.name != name);
        }
        self.removed.insert(name.to_string(), by);
    }

    /// [`Self::remove`] each of `names`, in one pass over the columns: a pass
    /// per name made `project-away` or `project-keep` of k names over n
    /// columns O(k·n) (#1628's follow-up).
    pub(crate) fn remove_all(&mut self, names: Vec<String>, by: &'static str) {
        // A few names are removed one at a time, as hashing costs more.
        if names.len() <= SCAN_ONLY {
            for name in names {
                self.remove(&name, by);
            }
            return;
        }
        let gone: HashSet<&str> = names.iter().map(String::as_str).collect();
        // Copied on write only when there is a column to remove.
        if self.columns.iter().any(|c| gone.contains(c.name.as_str())) {
            Arc::make_mut(&mut self.columns).retain(|c| !gone.contains(c.name.as_str()));
        }
        drop(gone);
        for name in names {
            self.removed.insert(name, by);
        }
    }

    /// `project-rename`'s renames, `(new, old)` in order, as many
    /// [`Self::remove`] of `old` then [`Self::set`] of the renamed column
    /// would leave the schema, in one pass: a pass per rename made k renames
    /// over n columns O(k·n). A few are applied one at a time, as hashing
    /// every column costs more.
    pub(crate) fn rename_all(&mut self, renames: Vec<Column>, by: &'static str) {
        if renames.len() <= SCAN_ONLY {
            for column in renames {
                if let Some(old) = &column.renamed_from {
                    self.remove(old, by);
                }
                self.set(column);
            }
            return;
        }
        // The columns, with a hole where one was removed, and where each
        // name's live columns are, first to last.
        let mut slots: Vec<Option<Arc<Column>>> = self.columns.iter().cloned().map(Some).collect();
        let mut at: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, column) in self.columns.iter().enumerate() {
            at.entry(column.name.clone()).or_default().push(i);
        }
        for column in renames {
            if let Some(old) = &column.renamed_from {
                #[cfg(test)]
                tests::count_name_compared();
                if let Some(positions) = at.remove(old) {
                    for i in positions {
                        slots[i] = None;
                    }
                }
                self.removed.insert(old.clone(), by);
            }
            self.removed.remove(&column.name);
            #[cfg(test)]
            tests::count_name_compared();
            match at.get(&column.name).and_then(|p| p.first()) {
                Some(&i) => slots[i] = Some(Arc::new(column)),
                None => {
                    at.insert(column.name.clone(), vec![slots.len()]);
                    slots.push(Some(Arc::new(column)));
                }
            }
        }
        self.columns = Arc::new(slots.into_iter().flatten().collect());
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
        self.pipelines.iter().find(|p| {
            #[cfg(test)]
            tests::PIPELINES_SCANNED.with(|n| n.set(n.get() + 1));
            p.span == span
        })
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

/// Whether `name` matches a column pattern: `*` stands for any run of
/// characters, everything else matches itself (case-sensitive, as Kusto
/// column names are).
fn glob_matches(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        // No `*` at all: the pattern is a plain name.
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
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

/// The name a quoted identifier holds: `['a b']` and `["a b"]` are `a b`.
pub(crate) fn unquote_name(text: &str) -> &str {
    let inner = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(text)
        .trim();
    inner
        .strip_prefix(['\'', '"'])
        .and_then(|t| t.strip_suffix(['\'', '"']))
        .unwrap_or(inner)
}

/// A table, `let`-bound tabular value or ASIM parser named by `word`; `binds`
/// when a scope binds the word to something else.
pub(crate) fn source_schema(
    catalog: &Catalog,
    word: &str,
    tabular: &HashMap<String, Schema>,
    binds: bool,
) -> Option<Schema> {
    if let Some(schema) = tabular.get(word) {
        return Some(schema.clone());
    }
    if binds {
        return None;
    }
    table_schema(catalog, word).or_else(|| asim_schema(catalog, word))
}

/// [`build_table_schema`], built once per table and catalog, and kept on
/// the catalog for every thread: a query names a few tables, and building
/// one copies its hundred-odd columns from the catalog (a fifth of a short
/// query's analysis). A workspace's catalog with declared columns keeps its
/// own, built from its columns. A copy of the built schema shares its
/// columns ([`Schema::columns`] is copied on write). Only tables are kept,
/// so the memo is bounded by the catalog: a name that is not a table (each
/// prefix typed in an editor) is looked up each time.
fn table_schema(catalog: &Catalog, name: &str) -> Option<Schema> {
    memoised(catalog, name, 0, build_table_schema)
}

/// The schema an ASIM parser (`imAuthentication`, `_Im_Dns`) returns, kept
/// as [`table_schema`] keeps a table's.
pub(crate) fn asim_schema(catalog: &Catalog, name: &str) -> Option<Schema> {
    memoised(catalog, name, 1, build_asim_schema)
}

/// `build(catalog, name)`, kept in `catalog`'s memo when it is a schema, by
/// `kind` (0: tables, 1: ASIM parsers) and name. Two threads that build the
/// same one at once keep the first.
fn memoised(
    catalog: &Catalog,
    name: &str,
    kind: usize,
    build: fn(&Catalog, &str) -> Option<Schema>,
) -> Option<Schema> {
    let Some(memo) = catalog.memo.schemas.get(kind) else {
        return build(catalog, name);
    };
    let read = memo
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(hit) = read.get(name) {
        return Some(hit.clone());
    }
    drop(read);
    let schema = build(catalog, name)?;
    memo.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(name.to_string())
        .or_insert_with(|| schema.clone());
    Some(schema)
}

fn build_table_schema(catalog: &Catalog, name: &str) -> Option<Schema> {
    let table = catalog.table(name)?;
    let origin: Arc<str> = Arc::from(name);
    let columns: Vec<Column> = catalog
        .columns_for_table(name)
        .into_iter()
        .filter(|c| &*c.table == name)
        .map(|c| {
            Column::new(
                c.name.to_string(),
                c.type_name.as_deref().map(str::to_owned),
            )
            .with_origin(Origin::Table(Arc::clone(&origin)))
        })
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
        columns: Arc::new(columns.into_iter().map(Arc::new).collect()),
        known,
        source: Source::Table(name.to_string()),
        custom_columns: true,
        citation: table.citation.clone(),
        ..Schema::open()
    };
    // Every Log Analytics table has the standard columns.
    if catalog.profile == Dialect::Sentinel && table.documented {
        for (column, type_name) in tables::STANDARD_COLUMNS {
            if !schema.has(column) {
                Arc::make_mut(&mut schema.columns).push(Arc::new(
                    Column::new(*column, Some((*type_name).to_string()))
                        .with_origin(Origin::Table(Arc::clone(&origin))),
                ));
            }
        }
    }
    Some(schema)
}

fn build_asim_schema(catalog: &Catalog, name: &str) -> Option<Schema> {
    let parser = catalog.asim_parser(name)?;
    let asim = tables::asim();
    let schema = asim.schemas.get(&parser.schema)?;
    let schema_name: Arc<str> = Arc::from(parser.schema.as_str());
    Some(Schema {
        columns: schema
            .columns
            .iter()
            .map(|c| {
                Column::new(c.name.clone(), Some(c.type_name.to_string())).with_origin(
                    Origin::Asim {
                        schema: Arc::clone(&schema_name),
                        class: Arc::from(c.class.as_str()),
                    },
                )
            })
            .map(Arc::new)
            .collect::<Columns>()
            .into(),
        known: Known::Typos,
        source: Source::Asim {
            parser: parser.name.clone(),
            schema: parser.schema.clone(),
        },
        citation: schema.citation.clone(),
        ..Schema::open()
    })
}

/// The schema of a `union` of `legs`, with the `withsource` column.
pub(crate) fn merge_union(legs: &[Schema], withsource: Option<String>) -> Schema {
    let mut out = Schema::closed(Vec::new(), Source::Union);
    let mut types: HashMap<String, Option<String>> = HashMap::new();
    let mut conflicts = BTreeSet::new();
    for leg in legs {
        out.weaken(leg.known);
        out.custom_columns |= leg.custom_columns;
        for column in leg.columns.iter() {
            match types.get(&column.name) {
                None => {
                    types.insert(column.name.clone(), column.type_name.clone());
                    Arc::make_mut(&mut out.columns).push(column.clone());
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
    if conflicts.len() <= SCAN_ONLY {
        // A few: a pass per conflict, as hashing every column costs more.
        for name in conflicts {
            let mut kinds: Vec<Option<String>> = legs
                .iter()
                .filter_map(|leg| leg.column(&name).map(|c| c.type_name.clone()))
                .collect();
            kinds.dedup();
            Arc::make_mut(&mut out.columns).retain(|c| c.name != name);
            if kinds.iter().any(Option::is_none) {
                out.make_open();
                continue;
            }
            for kind in kinds.into_iter().flatten() {
                let renamed = format!("{name}_{kind}");
                if !out.has(&renamed) {
                    Arc::make_mut(&mut out.columns)
                        .push(Arc::new(Column::new(renamed, Some(kind))));
                }
            }
        }
    } else {
        // Many: one pass over the legs and one over the columns for them
        // all, as a pass per conflict made n conflicts O(n²).
        // Each conflict's type in each leg that has it, in leg order: the
        // first column of that name in the leg, as `Schema::column` finds.
        let mut kinds: HashMap<&str, Vec<Option<String>>> = HashMap::new();
        for leg in legs {
            let mut seen: HashSet<&str> = HashSet::default();
            for column in leg.columns.iter() {
                #[cfg(test)]
                tests::count_name_compared();
                if let Some(name) = conflicts.get(column.name.as_str())
                    && seen.insert(name.as_str())
                {
                    kinds
                        .entry(name.as_str())
                        .or_default()
                        .push(column.type_name.clone());
                }
            }
        }
        Arc::make_mut(&mut out.columns).retain(|c| !conflicts.contains(&c.name));
        for name in &conflicts {
            let mut kinds = kinds.remove(name.as_str()).unwrap_or_default();
            kinds.dedup();
            if kinds.iter().any(Option::is_none) {
                out.make_open();
                continue;
            }
            for kind in kinds.into_iter().flatten() {
                let renamed = format!("{name}_{kind}");
                // A renamed column that is a later conflict's name: the pass
                // per conflict found that conflict's column still there and
                // added none (and then removed the conflict's).
                if !conflicts.contains(&renamed) && !out.has(&renamed) {
                    Arc::make_mut(&mut out.columns)
                        .push(Arc::new(Column::new(renamed, Some(kind))));
                }
            }
        }
    }
    if let Some(name) = withsource {
        out.set(Column::new(name, Some("string".into())));
    }
    // A union of narrowed legs (`let`s that end in project or summarize) is narrow.
    out.narrowed = !legs.is_empty() && legs.iter().all(|leg| leg.narrowed);
    if legs.is_empty() {
        out.make_open();
    }
    out
}

/// An argument of an aggregate call, as its naming reads it.
pub(crate) enum AggArg {
    /// `*`
    Star,
    /// A bare column.
    Name(String),
    /// Anything else.
    Other,
}

/// The columns an unnamed aggregate `name(args)` makes (lower-case `name`), as
/// Kusto names them; `None` when the naming is not modelled.
pub(crate) fn aggregate_columns_for(
    name: &str,
    args: &[AggArg],
    input: &Schema,
) -> Option<Vec<Column>> {
    let first = || match args.first() {
        Some(AggArg::Name(name)) => Some(name.clone()),
        _ => None,
    };
    let typed = |column: &str| input.column(column).and_then(|c| c.type_name.clone());
    let one = |name: String, type_name: Option<String>| Some(vec![Column::new(name, type_name)]);
    match name {
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
        "make_list" | "make_list_if" => one(format!("list_{}", first()?), Some("dynamic".into())),
        "take_any" => {
            let column = first()?;
            let type_name = typed(&column);
            one(column, type_name)
        }
        "arg_max" | "arg_min" => {
            let mut out = Vec::new();
            for arg in args {
                let column = match arg {
                    AggArg::Star => {
                        for column in input.columns.iter() {
                            if !out.iter().any(|c: &Column| c.name == column.name) {
                                out.push(Column::new(
                                    column.name.clone(),
                                    column.type_name.clone(),
                                ));
                            }
                        }
                        continue;
                    }
                    AggArg::Name(name) => name.clone(),
                    AggArg::Other => return None,
                };
                let type_name = typed(&column);
                out.push(Column::new(column, type_name));
            }
            Some(out)
        }
        _ => None,
    }
}

/// A plain expression, as [`primary_type`] reads it.
pub(crate) enum Primary<'s> {
    /// A column (unquoted).
    Name(&'s str),
    String,
    Boolean,
    Timespan,
    Dynamic,
    /// `datetime(2024-01-01)`: the literal's text.
    Typed(&'s str),
    /// The number's text.
    Number(&'s str),
    /// A call: the function's name.
    Call(&'s str),
}

/// The type of a plain expression, when the pass knows it.
pub(crate) fn primary_type(primary: &Primary<'_>, input: &Schema) -> Option<String> {
    match primary {
        Primary::Name(name) => input.column(name)?.type_name.clone(),
        Primary::String => Some("string".into()),
        Primary::Boolean => Some("bool".into()),
        Primary::Timespan => Some("timespan".into()),
        Primary::Dynamic => Some("dynamic".into()),
        // `datetime(2024-01-01)`, `long(null)`: the literal's type.
        Primary::Typed(text) => {
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
        // A hexadecimal integer (`0x1E`) is a long, whatever digits it has.
        Primary::Number(text) => Some(
            if !text.starts_with("0x") && !text.starts_with("0X") && text.contains(['.', 'e', 'E'])
            {
                "real".into()
            } else {
                "long".into()
            },
        ),
        Primary::Call(name) => {
            let name = name.to_ascii_lowercase();
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
                "make_set" | "make_list" | "make_bag" | "make_set_if" | "make_list_if" => "dynamic",
                "avg" | "avgif" | "stdev" | "variance" => "real",
                "totimespan" => "timespan",
                "todynamic" | "parse_json" | "pack" | "bag_pack" | "pack_array" | "split" => {
                    "dynamic"
                }
                _ => return None,
            };
            Some(t.into())
        }
    }
}

/// The column and type a comparison `left op right` uses wrongly
/// (`kql_type_mismatch`), from the column each side is and the literal each
/// side is.
pub(crate) fn type_mismatch(
    op: &str,
    left_column: Option<(String, String)>,
    right_column: Option<(String, String)>,
    left_literal: Option<&'static str>,
    right_literal: Option<&'static str>,
) -> Option<(String, String)> {
    if STRING_OPERATORS.contains(&op) || STRING_SET_OPERATORS.contains(&op) {
        let (column, kind) = left_column?;
        return (NUMERIC.contains(&kind.as_str())
            || matches!(kind.as_str(), "datetime" | "timespan" | "bool"))
        .then_some((column, kind));
    }
    if op == "between" || op == "!between" {
        let (column, kind) = left_column?;
        return matches!(kind.as_str(), "string" | "bool" | "guid").then_some((column, kind));
    }
    if !ORDERING.contains(&op) {
        return None;
    }
    for (column, literal) in [(left_column, right_literal), (right_column, left_literal)] {
        let (Some((column, kind)), Some(lit)) = (column, literal) else {
            continue;
        };
        let bad = match kind.as_str() {
            "string" | "guid" | "datetime" | "timespan" => true,
            k if NUMERIC.contains(&k) => lit == "string",
            _ => false,
        };
        if bad {
            return Some((column, kind));
        }
    }
    None
}

/// The message of `kql_type_mismatch`.
pub(crate) fn mismatch_message(op: &str, column: &str, kind: &str) -> String {
    format!(
        "`{op}` is not defined for `{column}`, {} {kind} column; Kusto rejects the query",
        if kind.starts_with(['a', 'e', 'i', 'o', 'u']) {
            "an"
        } else {
            "a"
        }
    )
}

/// The column `name` is in `schemas` (one, or both sides of a join), when the
/// pass knows it: a join key (`on Key`) must be on both sides.
pub(crate) fn resolve_column(name: &str, schemas: &[&Schema]) -> Option<Column> {
    if schemas
        .iter()
        .all(|s| s.has(name) || s.known == Known::Open)
    {
        schemas.iter().find_map(|s| s.column(name)).cloned()
    } else {
        None
    }
}

/// `kql_unknown_column` at `range` for a name [`resolve_column`] did not find;
/// `None` where the pass cannot say it is not a column.
pub(crate) fn unknown_column(
    name: &str,
    schemas: &[&Schema],
    range: opentide_core::Range,
) -> Option<Diagnostic> {
    // A join key must be on both sides; report against the first that lacks it.
    let schema = schemas
        .iter()
        .copied()
        .find(|s| !s.has(name) && s.known != Known::Open)?;
    if schema.custom_columns && tables::is_custom_column(name) {
        return None;
    }
    // A column an operator removed is gone, whatever the source documents.
    if let Some(op) = schema.removed.get(name) {
        return Some(Diagnostic::error(
            codes::KQL_UNKNOWN_COLUMN,
            format!("'{name}' is not a column after `{}`", operator_keyword(op)),
            range,
        ));
    }
    // A near miss is within two edits (strsim's Levenshtein distance,
    // ignoring case) and less than half the name: the threshold decides
    // whether a documented table reports the column at all
    // (`Known::Typos`). Among the columns within it, the shared rule
    // chooses ([`opentide_core::suggest::best`]).
    // The distance is at least the difference in length: a candidate more
    // than two characters longer or shorter is never measured (a name of a
    // million characters was measured against every column, quadratically).
    let lower = name.to_ascii_lowercase();
    let chars = lower.chars().count();
    let suggestion = opentide_core::suggest::best(
        name,
        schema.columns.iter().map(|c| c.name.as_str()).filter(|c| {
            c.chars().count().abs_diff(chars) <= 2 && {
                crate::inspect::count_column_measured();
                let d = strsim::levenshtein(&c.to_ascii_lowercase(), &lower);
                d <= 2 && d * 2 < name.len()
            }
        }),
    )
    .map(str::to_string);
    let report = match schema.known {
        Known::Closed => true,
        Known::Typos => suggestion.is_some(),
        Known::Open => false,
    };
    if !report {
        return None;
    }
    let message = match schema.reshaped_by {
        Some(op) => format!("'{name}' is not a column after `{}`", operator_keyword(op)),
        None => format!("'{name}' is not a column of {}", schema.describe_source()),
    };
    let mut d = Diagnostic::error(codes::KQL_UNKNOWN_COLUMN, message, range);
    if let Some(s) = suggestion {
        d = d.with_suggestion(s);
    }
    Some(d)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::glob_matches;
    use super::{Column, Columns, Schema, Source, merge_union};
    use std::sync::Arc;

    /// A workspace's catalog with declared columns keeps the schemas it
    /// builds, as a bundled catalog does: the second lookup of a table shares
    /// the first's columns, where it was built again on every call. Its
    /// schemas are its own (a declared column is in its table's, not in the
    /// bundled catalog's), and a copy of it builds its own again.
    #[test]
    fn a_declared_catalog_keeps_its_own_schemas() {
        use crate::{Catalog, Dialect};
        use std::sync::Arc;
        let declared = opentide_core::datasets::DeclaredDatasets::from_visibility(
            "[[logsources]]\nname = \"SecurityEvent\"\ndescription = \"x\"\n\
             system = \"sentinel\"\n\n[logsources.columns]\nContoso_s = { type = \"string\" }\n",
        )
        .expect("visibility.toml");
        let sources: Vec<_> = declared.sources_with_columns("sentinel").cloned().collect();
        let bundled = Catalog::cached(Dialect::Sentinel);
        let catalog = bundled.with_declared_columns(&sources, &[]);
        let has = |schema: &Schema, name: &str| schema.columns.iter().any(|c| c.name == name);

        let first = super::table_schema(&catalog, "SecurityEvent").expect("a table");
        let again = super::table_schema(&catalog, "SecurityEvent").expect("a table");
        assert!(Arc::ptr_eq(&first.columns, &again.columns), "kept");
        assert!(has(&first, "Contoso_s"), "the declared column");

        let plain = super::table_schema(bundled, "SecurityEvent").expect("a table");
        assert!(!has(&plain, "Contoso_s"), "the bundled catalog's own");
        assert!(!Arc::ptr_eq(&plain.columns, &first.columns));

        let copy = catalog.clone();
        let copied = super::table_schema(&copy, "SecurityEvent").expect("a table");
        assert!(
            !Arc::ptr_eq(&copied.columns, &first.columns),
            "a copy builds its own"
        );
        assert!(has(&copied, "Contoso_s"));
    }

    /// The names the scan per column gave, before #1424.
    fn naive(start: &[&str], added: &[&str]) -> Vec<String> {
        let mut names: Vec<String> = start.iter().map(ToString::to_string).collect();
        for name in added {
            let mut chosen = (*name).to_string();
            if names.contains(&chosen) {
                let mut n = 1;
                while names.contains(&format!("{name}{n}")) {
                    n += 1;
                }
                chosen = format!("{name}{n}");
            }
            names.push(chosen);
        }
        names
    }

    fn pushed(start: &[&str], added: &[&str]) -> Vec<String> {
        let mut schema = Schema::open();
        schema.push_all_unique(start.iter().map(|n| Column::new((*n).to_string(), None)));
        schema.push_all_unique(added.iter().map(|n| Column::new((*n).to_string(), None)));
        std::sync::Arc::unwrap_or_clone(schema.columns)
            .into_iter()
            .map(|c| c.name.clone())
            .collect()
    }

    /// One pass gives each column the name a scan per column gave: the
    /// smallest free suffix, with names added earlier in the batch taken.
    #[test]
    fn a_batch_names_columns_as_one_at_a_time() {
        for (start, added) in [
            (&["a", "b"][..], &["a", "a", "a1", "a", "b", "c"][..]),
            (&["a", "a1", "a3"][..], &["a", "a", "a", "a2"][..]),
            (&["x1"][..], &["x", "x", "x", "x1", "x11"][..]),
            (&[][..], &["k", "k", "k1", "k11", "k1", "k"][..]),
        ] {
            assert_eq!(
                pushed(start, added),
                naive(start, added),
                "{start:?} + {added:?}"
            );
        }
    }

    thread_local! {
        /// The column names compared or looked up on this thread.
        static NAMES_COMPARED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    pub(crate) fn count_name_compared() {
        NAMES_COMPARED.with(|n| n.set(n.get() + 1));
    }

    /// Through the column pass: nested `join`s, a `summarize` of many
    /// `arg_max(*)` and one of many same-named aggregates compare or look up
    /// at most about three names per column their stages make. Each call
    /// site adding its columns one at a time, or one batch per item, probed
    /// the suffixes again from 1 for each and grew with the square (#1424).
    #[test]
    fn operators_compare_about_one_name_per_column_they_make() {
        let mut joins = String::from("SecurityEvent");
        for _ in 0..30 {
            joins = format!("SecurityEvent | join ({joins}) on Account");
        }
        let items = |item: &str, n: usize| {
            format!(
                "SecurityEvent | summarize {} by Account",
                vec![item; n].join(", ")
            )
        };
        for (name, q) in [
            ("30 nested joins", joins),
            ("100 arg_max(*)", items("arg_max(TimeGenerated, *)", 100)),
            ("1000 `x = count()`", items("x = count()", 1000)),
            ("1000 `count()`", items("count()", 1000)),
        ] {
            NAMES_COMPARED.with(|c| c.set(0));
            let analysis = crate::columns(&q, crate::Dialect::Sentinel);
            let compared = NAMES_COMPARED.with(std::cell::Cell::get);
            let made: usize = analysis
                .pipelines
                .iter()
                .flat_map(|p| &p.stages)
                .map(|s| s.output.columns.len())
                .sum();
            assert!(made > 1000, "{name}: {made}");
            assert!(
                compared <= 3 * made,
                "{name}: {compared} names compared for {made} columns"
            );
        }
    }

    /// A `project`, `extend` or `summarize` of n columns, an `extend` whose
    /// items read the ones before, and n references to an n-column schema
    /// compare or look up a number of names that grows with n, not n²:
    /// `Schema::set` and `Schema::column` scanned the columns per lookup, and
    /// an operator's names defined so far were a slice scanned per reference;
    /// a 150k-column `project` took 48 s (#1628). A work count, not a clock
    /// (the rule of #1459).
    #[test]
    fn many_columns_compare_names_in_proportion() {
        let list = |n: usize, item: &dyn Fn(usize) -> String| {
            (0..n).map(item).collect::<Vec<_>>().join(", ")
        };
        let queries: [(&str, &dyn Fn(usize) -> String); 11] = [
            ("project", &|n| {
                format!("T | project {}", list(n, &|i| format!("x{i}=1")))
            }),
            ("extend", &|n| {
                format!("print a=1 | extend {}", list(n, &|i| format!("x{i}=1")))
            }),
            ("print", &|n| {
                format!("print {}", list(n, &|i| format!("x{i}=1")))
            }),
            ("summarize", &|n| {
                format!(
                    "T | summarize {} by k",
                    list(n, &|i| format!("x{i}=count()"))
                )
            }),
            ("an extend reading its earlier items", &|n| {
                format!(
                    "print x0=1 | extend {}",
                    list(n, &|i| format!("x{}=x{i}", i + 1))
                )
            }),
            ("references after a summarize", &|n| {
                format!(
                    "T | summarize {} by k | where {}",
                    list(n, &|i| format!("x{i}=count()")),
                    list(n, &|i| format!("isnotnull(x{i})")).replace(", ", " and ")
                )
            }),
            ("project-away", &|n| {
                format!(
                    "print {} | project-away {}",
                    list(n, &|i| format!("x{i}=1")),
                    list(n / 2, &|i| format!("x{}", 2 * i))
                )
            }),
            ("project-keep", &|n| {
                format!(
                    "print {} | project-keep {}",
                    list(n, &|i| format!("x{i}=1")),
                    list(n / 2, &|i| format!("x{}", 2 * i))
                )
            }),
            ("project-rename", &|n| {
                format!(
                    "print {} | project-rename {}",
                    list(n, &|i| format!("x{i}=1")),
                    list(n, &|i| format!("y{i}=x{i}"))
                )
            }),
            ("a union's conflicting columns", &|n| {
                format!(
                    "union (print {}), (print {})",
                    list(n, &|i| format!("a{i}=1")),
                    list(n, &|i| format!("a{i}='s'"))
                )
            }),
            ("references", &|n| {
                format!(
                    "T | project {} | where {}",
                    list(n, &|i| format!("x{i}=1")),
                    list(n, &|i| format!("isnotnull(x{i})")).replace(", ", " and ")
                )
            }),
        ];
        for (name, query) in queries {
            let compared = |n: usize| {
                let q = query(n);
                NAMES_COMPARED.with(|c| c.set(0));
                let _ = crate::columns(&q, crate::Dialect::Core);
                NAMES_COMPARED.with(std::cell::Cell::get)
            };
            let (small, large) = (compared(1_000), compared(2_000));
            assert!(
                small >= 1_000,
                "{name}: {small} names compared for 1,000 columns"
            );
            // Twice the columns, at most 2.1 times the work: a scan per lookup
            // makes it 4 times.
            assert!(
                large * 10 <= small * 21,
                "{name}: {small} names compared for 1,000 columns, {large} for 2,000"
            );
        }
    }

    /// `remove_all` and `rename_all` leave a schema as `remove` and `remove`
    /// then `set`, one at a time, do: chains (`b=a, c=b`), a name renamed
    /// to itself, onto a column that exists, twice, and names removed twice
    /// or not there.
    #[test]
    fn batched_removals_and_renames_match_one_at_a_time() {
        let start = || {
            let mut s = Schema::open();
            for name in ["a", "b", "c", "a", "d", "e", "f", "g", "h", "i", "j"] {
                Arc::make_mut(&mut s.columns).push(Column::new(name, Some("long".into())));
            }
            s
        };
        let names = |s: &Schema| {
            let mut removed: Vec<_> = s.removed.iter().map(|(k, v)| (k.clone(), *v)).collect();
            removed.sort();
            (
                s.columns
                    .iter()
                    .map(|c| (c.name.clone(), c.renamed_from.clone()))
                    .collect::<Vec<_>>(),
                removed,
            )
        };
        let column_for = |new: &str, old: &str| Column {
            renamed_from: Some(old.into()),
            ..Column::new(new, Some("string".into()))
        };
        let renames: Vec<(&str, &str)> = vec![
            ("b", "a"),
            ("x", "b"),
            ("c", "c"),
            ("d", "e"),
            ("y", "zz"),
            ("y", "f"),
            ("g", "x"),
            ("h", "h"),
            ("k", "i"),
            ("a", "k"),
            ("j", "d"),
        ];
        let mut one = start();
        for (new, old) in &renames {
            one.remove(old, "r");
            one.set(column_for(new, old));
        }
        let mut batch = start();
        batch.rename_all(renames.iter().map(|(n, o)| column_for(n, o)).collect(), "r");
        assert_eq!(names(&batch), names(&one));

        // Past the threshold too, with names twice and names not there.
        for gone in [
            &["a", "zz", "d", "a", "j"][..],
            &["a", "zz", "d", "a", "j", "b", "yy", "e", "f", "e", "i"][..],
        ] {
            let mut one = start();
            for name in gone {
                one.remove(name, "r");
            }
            let mut batch = start();
            batch.remove_all(gone.iter().map(ToString::to_string).collect(), "r");
            assert_eq!(names(&batch), names(&one), "{gone:?}");
        }

        // A rename onto a name two columns have: the first is replaced.
        let renames: Vec<(&str, &str)> = vec![
            ("a", "f"),
            ("a", "g"),
            ("q", "a"),
            ("a", "h"),
            ("b", "c"),
            ("b", "i"),
            ("j", "b"),
            ("d", "d"),
            ("e", "zz"),
        ];
        let mut one = start();
        for (new, old) in &renames {
            one.remove(old, "r");
            one.set(column_for(new, old));
        }
        let mut batch = start();
        batch.rename_all(renames.iter().map(|(n, o)| column_for(n, o)).collect(), "r");
        assert_eq!(names(&batch), names(&one));
    }

    /// A union's conflicts name their columns as one pass per conflict did
    /// (`one_at_a_time`, the code before), a renamed column that is a later
    /// conflict's name, a leg with a name twice and an untyped leg included.
    #[test]
    fn union_conflicts_as_one_at_a_time() {
        use foldhash::HashMap;
        use std::collections::BTreeSet;
        fn one_at_a_time(legs: &[Schema]) -> Schema {
            let mut out = Schema::closed(Vec::new(), Source::Union);
            let mut types: HashMap<String, Option<String>> = HashMap::default();
            let mut conflicts = BTreeSet::new();
            for leg in legs {
                for column in leg.columns.iter() {
                    match types.get(&column.name) {
                        None => {
                            types.insert(column.name.clone(), column.type_name.clone());
                            Arc::make_mut(&mut out.columns).push(column.clone());
                        }
                        Some(t) if *t != column.type_name => {
                            conflicts.insert(column.name.clone());
                        }
                        Some(_) => {}
                    }
                }
            }
            for name in conflicts {
                let mut kinds: Vec<Option<String>> = legs
                    .iter()
                    .filter_map(|leg| leg.column(&name).map(|c| c.type_name.clone()))
                    .collect();
                kinds.dedup();
                Arc::make_mut(&mut out.columns).retain(|c| c.name != name);
                if kinds.iter().any(Option::is_none) {
                    out.make_open();
                    continue;
                }
                for kind in kinds.into_iter().flatten() {
                    let renamed = format!("{name}_{kind}");
                    if !out.has(&renamed) {
                        Arc::make_mut(&mut out.columns)
                            .push(Arc::new(Column::new(renamed, Some(kind))));
                    }
                }
            }
            out
        }
        let leg = |cols: &[(&str, Option<&str>)]| {
            Schema::closed(
                cols.iter()
                    .map(|(n, t)| Column::new(*n, t.map(ToString::to_string)))
                    .collect(),
                Source::Literal,
            )
        };
        let shape = |s: &Schema| {
            let columns: Vec<_> = s
                .columns
                .iter()
                .map(|c| (c.name.clone(), c.type_name.clone()))
                .collect();
            (columns, s.known)
        };
        for legs in [
            vec![
                leg(&[
                    ("A", Some("long")),
                    ("A_string", Some("long")),
                    ("B", Some("int")),
                ]),
                leg(&[
                    ("A", Some("string")),
                    ("A_string", Some("real")),
                    ("B", Some("int")),
                ]),
                leg(&[("A", Some("long")), ("C", Some("bool")), ("C", Some("int"))]),
            ],
            vec![
                leg(&[("A", Some("long")), ("D", None)]),
                leg(&[
                    ("A_long", Some("int")),
                    ("A", Some("real")),
                    ("D", Some("int")),
                ]),
                leg(&[("A", Some("real")), ("A", Some("long"))]),
            ],
        ] {
            assert_eq!(
                shape(&merge_union(&legs, None)),
                shape(&one_at_a_time(&legs))
            );
            // The same legs past the threshold, with nine more conflicts
            // after them, so the batched path meets the same edge cases.
            let padded: Vec<Schema> = legs
                .iter()
                .enumerate()
                .map(|(i, leg)| {
                    let mut leg = leg.clone();
                    for p in 0..9 {
                        let ty = if i % 2 == 0 { "long" } else { "string" };
                        Arc::make_mut(&mut leg.columns)
                            .push(Column::new(format!("P{p}"), Some(ty.into())));
                    }
                    leg
                })
                .collect();
            assert_eq!(
                shape(&merge_union(&padded, None)),
                shape(&one_at_a_time(&padded))
            );
        }
        // Past the few a pass each handles: many conflicts, with the same
        // edge cases (a renamed column that is a later conflict's name, an
        // untyped leg, a leg with a name twice).
        let mut names: Vec<String> = (0..12).map(|i| format!("N{i}")).collect();
        names.extend(["A", "A_string", "C", "D", "N3_long"].map(String::from));
        let many = |types: &[Option<&str>], extra: &[(&str, Option<&str>)]| {
            let mut columns: Vec<Column> = names
                .iter()
                .zip(types.iter().cycle())
                .map(|(n, t)| Column::new(n.clone(), t.map(ToString::to_string)))
                .collect();
            columns.extend(
                extra
                    .iter()
                    .map(|(n, t)| Column::new(*n, t.map(ToString::to_string))),
            );
            Schema::closed(columns, Source::Literal)
        };
        let legs = [
            many(&[Some("long")], &[]),
            many(&[Some("string"), Some("real"), None], &[]),
            many(&[Some("long"), Some("int")], &[("C", Some("bool"))]),
        ];
        assert_eq!(
            shape(&merge_union(&legs, None)),
            shape(&one_at_a_time(&legs))
        );
    }

    /// The index answers as a scan would, with repeated names (the first
    /// wins), after columns are replaced, removed, cleared and pushed again,
    /// and on a copy.
    #[test]
    fn the_index_answers_as_a_scan() {
        fn scan<'a>(columns: &'a Columns, name: &str) -> Option<&'a Arc<Column>> {
            columns.iter().find(|c| c.name == name)
        }
        fn check(columns: &Columns, names: &[String]) {
            for name in names {
                assert_eq!(
                    columns.position(name),
                    columns.iter().position(|c| c.name == *name),
                    "{name}"
                );
                assert!(
                    columns.get(name).map(Arc::as_ptr) == scan(columns, name).map(Arc::as_ptr),
                    "{name}"
                );
            }
        }
        let column = |name: &str, ty: &str| Column::new(name, Some(ty.to_string()));
        let names: Vec<String> = (0..40)
            .map(|i| format!("c{i}"))
            .chain(["zz".into()])
            .collect();
        let mut columns: Columns = (0..30)
            .map(|i| Arc::new(column(&format!("c{}", i % 20), "long")))
            .collect();
        // Changes that miss, past the scans that build the index.
        let build = |columns: &mut Columns| {
            check(columns, &names);
            while columns.index.get().is_none() {
                assert!(columns.get_mut("zz").is_none());
            }
            check(columns, &names);
        };
        build(&mut columns);
        columns.set(column("c3", "string"));
        columns.set(column("c35", "string"));
        columns.push(column("c35", "real"));
        columns.push(column("c36", "real"));
        check(&columns, &names);
        assert_eq!(
            columns.get("c3").and_then(|c| c.type_name.as_deref()),
            Some("string")
        );
        assert_eq!(
            columns.get("c35").and_then(|c| c.type_name.as_deref()),
            Some("string")
        );
        if let Some(c) = columns.get_mut("c4") {
            c.type_name = Some("bool".into());
        }
        assert_eq!(
            scan(&columns, "c4").and_then(|c| c.type_name.as_deref()),
            Some("bool")
        );
        let copy = columns.clone();
        assert!(copy.index.get().is_some(), "a copy keeps the index");
        // Each index has a seed of its own (ADR 0014 §5b): names a query
        // picks cannot be made to collide in every analysis.
        let mut other = columns.iter().cloned().collect::<Columns>();
        build(&mut other);
        let seed = |c: &Columns| c.index.get().map(|i| i.hash("c1"));
        assert_ne!(seed(&columns), seed(&other), "seeded per index");
        check(&copy, &names);
        columns.retain(|c| c.name != "c5" && c.name != "c0");
        assert!(columns.index.get().is_none(), "a removal forgets the index");
        build(&mut columns);
        columns.clear();
        check(&columns, &names);
        for i in (0..40).rev() {
            columns.push(column(&format!("c{}", i % 25), "long"));
        }
        build(&mut columns);
        check(&copy, &names);
    }

    /// Adding `n` columns to a schema of `n` compares or looks up about one
    /// name per column, whose names collide or not: a scan of the schema per
    /// column, the way a join added its right side, made a 30-deep nested
    /// `join` take 100 s in a debug build (#1424). A work count, not a clock
    /// (the rule of #1459).
    #[test]
    fn a_batch_of_columns_compares_about_one_name_each() {
        let schema = |n: usize, prefix: &str| {
            let mut s = Schema::open();
            s.push_all_unique((0..n).map(|i| Column::new(format!("{prefix}{i}x"), None)));
            s
        };
        for n in [1_000, 4_000] {
            for prefix in ["c", "d"] {
                let mut left = schema(n, "c");
                let right = schema(n, prefix);
                NAMES_COMPARED.with(|c| c.set(0));
                left.push_all_unique(std::sync::Arc::unwrap_or_clone(right.columns));
                let compared = NAMES_COMPARED.with(std::cell::Cell::get);
                assert_eq!(left.columns.len(), 2 * n);
                // One lookup per column, and one more per suffix tried when
                // its name is taken (`c0x` → `c0x1`).
                assert!(
                    compared <= 3 * n,
                    "{n} `{prefix}` columns: {compared} names compared"
                );
            }
        }
    }

    thread_local! {
        /// The pipelines [`super::Analysis::pipeline`] scanned on this thread.
        pub(crate) static PIPELINES_SCANNED: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
    }

    #[test]
    fn column_patterns_glob_over_names() {
        assert!(glob_matches("*", "Anything"));
        assert!(glob_matches("User*", "UserPrincipalName"));
        assert!(glob_matches("User*", "User"));
        assert!(glob_matches("*Id", "TenantId"));
        assert!(glob_matches("Device*Name", "DeviceName"));
        assert!(glob_matches("Device*Name", "DeviceHostName"));
        assert!(glob_matches("a*b*c", "aXbYc"));
        assert!(!glob_matches("User*", "user"));
        assert!(!glob_matches("User*", "AppUser"));
        assert!(!glob_matches("*Id", "Identity"));
        assert!(!glob_matches("a*a", "a"));
        assert!(!glob_matches("a*b*c", "acb"));
    }
}
