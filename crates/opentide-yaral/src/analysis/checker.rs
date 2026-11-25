//! The yara-l-1.0 checks of a rule or a search on the typed tree: sections,
//! scope, `match`, `outcome`, `condition`, `options`. The checks that read
//! one node at a time are in `nodes.rs`.
//!
//! The same checks as the tree-sitter engine's `check.rs`, on trees whose
//! chains are flat (`a or b or c` is one node) and whose literals are a node
//! over one token.

use super::nav::{
    At, accessor_segments, at, at_token, dollar_name, is_literal, literal_kind, root_variable,
    unparen,
};
use super::support::{
    DAY, MAX_OUTCOMES, duration, format_minutes, in_profile, reference_limits, section_rank,
};
use crate::ast::{Comparison, MatchWindow, UnaryExpr};
use crate::catalog::{Functions, Segment, is_keyword};
use crate::syntax::{SyntaxKind as K, SyntaxNode};
use crate::{Finding, Profile};
use opentide_core::{Severity, codes};
use opentide_parse::ast::AstNode;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub(super) struct Section {
    pub(super) name: &'static str,
    pub(super) node: SyntaxNode,
    pub(super) label: At,
}

pub(super) fn section_name(kind: K) -> Option<&'static str> {
    Some(match kind {
        K::META_SECTION => "meta",
        K::SETUP_SECTION => "setup",
        K::EVENTS_SECTION | K::SEARCH_EVENTS => "events",
        K::MATCH_SECTION => "match",
        K::OUTCOME_SECTION => "outcome",
        K::CONDITION_SECTION => "condition",
        K::OPTIONS_SECTION => "options",
        K::EXPORT_SECTION => "export",
        K::DEDUP_SECTION => "dedup",
        K::ORDER_SECTION => "order",
        K::LIMIT_SECTION => "limit",
        K::SELECT_SECTION => "select",
        K::UNSELECT_SECTION => "unselect",
        _ => return None,
    })
}

/// A match window's length in minutes, when it has one.
pub(super) struct Window {
    minutes: Option<u64>,
}

/// The names a rule or stage defines.
#[derive(Default)]
pub(super) struct Scope {
    pub(super) events: BTreeMap<String, At>,
    pub(super) placeholders: BTreeMap<String, At>,
    pub(super) outcomes: BTreeSet<String>,
    /// Placeholder: the event variables a statement of `events` assigns it from.
    assigned: BTreeMap<String, BTreeSet<String>>,
    /// Outcome variable: the event variables its value reads, directly or
    /// through placeholders and earlier outcomes.
    outcome_events: BTreeMap<String, BTreeSet<String>>,
}

/// What a condition term says about an event variable or placeholder.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bound {
    Bounded,
    Unbounded,
}

pub(crate) struct Checker<'s> {
    pub(super) source: &'s str,
    pub(super) profile: Profile,
    meta_required: bool,
    pub findings: Vec<Finding>,
    pub(super) stages: BTreeSet<String>,
    /// The highlight's spans, gathered by the walk over every element when
    /// the caller wants them (ADR 0014 §5a).
    pub(super) spans: Option<Vec<(opentide_core::ByteSpan, &'static str)>>,
    /// Every node of the tree in preorder, read once by [`Checker::run`]:
    /// the checks read a node's descendants from it, not from a walk of
    /// their own (ADR 0014 §5).
    nodes: Option<Descendants>,
}

/// The nodes of a tree in preorder, each with the end of its subtree: a
/// node's descendants, itself first, are one slice, in the order rowan's
/// `descendants` gives them.
struct Descendants {
    nodes: std::rc::Rc<Vec<SyntaxNode>>,
    ends: Vec<usize>,
}

impl Descendants {
    fn new(root: &SyntaxNode) -> Self {
        let mut nodes = Vec::new();
        let mut ends = Vec::new();
        let mut open: Vec<usize> = Vec::new();
        for event in root.preorder() {
            match event {
                rowan::WalkEvent::Enter(node) => {
                    open.push(nodes.len());
                    nodes.push(node);
                    ends.push(0);
                }
                rowan::WalkEvent::Leave(_) => {
                    if let Some(i) = open.pop() {
                        ends[i] = nodes.len();
                    }
                }
            }
        }
        Self {
            nodes: std::rc::Rc::new(nodes),
            ends,
        }
    }

    /// Where `node` is: preorder sorts the nodes by where they start, so a
    /// binary search finds the nodes starting where it does (a node and its
    /// first descendants), and `node` is one of them.
    fn place(&self, node: &SyntaxNode) -> Option<usize> {
        let start = node.text_range().start();
        let first = self
            .nodes
            .partition_point(|n| n.text_range().start() < start);
        self.nodes[first..]
            .iter()
            .take_while(|n| n.text_range().start() == start)
            .position(|n| n == node)
            .map(|i| first + i)
    }
}

/// A node's descendants from [`Descendants`], or from rowan for a node it
/// does not hold.
pub(super) enum Under {
    Indexed {
        nodes: std::rc::Rc<Vec<SyntaxNode>>,
        next: usize,
        end: usize,
    },
    Walked(Box<dyn Iterator<Item = SyntaxNode>>),
}

impl Iterator for Under {
    type Item = SyntaxNode;

    fn next(&mut self) -> Option<SyntaxNode> {
        match self {
            Under::Indexed { nodes, next, end } => {
                let node = (*next < *end).then(|| nodes[*next].clone())?;
                *next += 1;
                #[cfg(test)]
                INDEXED.set(INDEXED.get() + 1);
                Some(node)
            }
            Under::Walked(walk) => {
                let node = walk.next()?;
                #[cfg(test)]
                WALKED.set(WALKED.get() + 1);
                Some(node)
            }
        }
    }
}

impl<'s> Checker<'s> {
    pub(crate) fn new(source: &'s str, profile: Profile, meta_required: bool) -> Self {
        Self {
            source,
            profile,
            meta_required,
            findings: Vec::new(),
            stages: BTreeSet::new(),
            spans: None,
            nodes: None,
        }
    }

    pub(super) fn text(&self, node: &SyntaxNode) -> &'s str {
        let r = node.text_range();
        self.source
            .get(usize::from(r.start())..usize::from(r.end()))
            .unwrap_or("")
    }

    pub(super) fn push(&mut self, code: &'static str, severity: Severity, message: String, at: At) {
        self.findings
            .push(Finding::new(code, severity, message, at.0, at.1));
    }

    pub(super) fn error(&mut self, code: &'static str, message: String, at: At) {
        self.push(code, Severity::Error, message, at);
    }

    pub(super) fn warning(&mut self, code: &'static str, message: String, at: At) {
        self.push(code, Severity::Warning, message, at);
    }

    /// `node` and the nodes below it, in preorder: rowan's `descendants`,
    /// read from the index [`Checker::run`] builds.
    pub(super) fn under(&self, node: &SyntaxNode) -> Under {
        match &self.nodes {
            Some(index) => match index.place(node) {
                Some(i) => Under::Indexed {
                    nodes: std::rc::Rc::clone(&index.nodes),
                    next: i,
                    end: index.ends[i],
                },
                None => Under::Walked(Box::new(node.descendants())),
            },
            None => Under::Walked(Box::new(node.descendants())),
        }
    }

    /// Every check on a tree that parsed.
    pub(crate) fn run(&mut self, root: &SyntaxNode) {
        self.nodes = Some(Descendants::new(root));
        let rules: Vec<SyntaxNode> = root
            .children()
            .filter(|n| n.kind() == K::RULE_DECLARATION)
            .collect();
        if let Some(second) = rules.get(1) {
            self.error(
                codes::YARAL_PARSE_ERROR,
                "a YARA-L text holds one rule: Google stores and verifies one rule at a time"
                    .into(),
                at(second),
            );
        }
        if let Some(rule) = rules.first() {
            self.rule(rule);
        } else if let Some(search) = root.children().find(|n| n.kind() == K::SEARCH_QUERY) {
            self.search(&search);
        }
        self.walk_all(root);
    }

    fn rule(&mut self, rule: &SyntaxNode) {
        let name = rule.children().find(|n| n.kind() == K::RULE_NAME);
        if let Some(name) = &name {
            let text = self.text(name);
            if is_keyword(text) {
                self.error(
                    codes::YARAL_RESERVED_IDENTIFIER,
                    format!("`{text}` is a YARA-L keyword, not a rule name"),
                    at(name),
                );
            }
        }
        let sections = self.sections_of(rule);
        let anchor = at(name.as_ref().unwrap_or(rule));
        self.body(&sections, anchor);
    }

    fn search(&mut self, search: &SyntaxNode) {
        let stages: Vec<SyntaxNode> = search.children().filter(|n| n.kind() == K::STAGE).collect();
        for stage in &stages {
            if let Some(name) = stage.children().find(|n| n.kind() == K::STAGE_NAME) {
                self.stages.insert(format!("${}", self.text(&name)));
            }
        }
        for stage in &stages {
            let sections = self.sections_of(stage);
            let name = stage.children().find(|n| n.kind() == K::STAGE_NAME);
            let anchor = at(name.as_ref().unwrap_or(stage));
            self.body(&sections, anchor);
        }
        let sections = self.sections_of(search);
        self.body(&sections, at(search));
    }

    fn sections_of(&self, node: &SyntaxNode) -> Vec<Section> {
        node.children()
            .filter_map(|n| {
                let name = section_name(n.kind())?;
                // Unlabelled search events: the section itself stands for its label.
                let label = if n.kind() == K::SEARCH_EVENTS {
                    at(&n)
                } else {
                    at_token(&n.first_token()?)
                };
                Some(Section {
                    name,
                    node: n,
                    label,
                })
            })
            .collect()
    }

    /// The checks of one rule, or one search stage.
    fn body(&mut self, sections: &[Section], anchor: At) {
        let profile = self.profile;
        // Order, repeats, profile.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut last = 0u8;
        let mut last_name = "";
        for s in sections {
            if !in_profile(s.name, profile) {
                let message = match profile {
                    Profile::Rule => format!(
                        "`{}` is a search section: a rule has meta, setup, events, match, outcome, condition, options and export",
                        s.name
                    ),
                    Profile::Search => format!(
                        "`{}` is not part of a search: setup and options are rule sections",
                        s.name
                    ),
                };
                self.error(codes::YARAL_SECTION_UNAVAILABLE, message, s.label);
                continue;
            }
            let rank = section_rank(s.name);
            if !seen.insert(s.name) {
                self.error(
                    codes::YARAL_SECTION_ORDER,
                    format!("`{}` appears twice: each section appears once", s.name),
                    s.label,
                );
            } else if rank < last {
                let hint = if s.name == "options" && last_name == "export" {
                    "; `export` is the last section"
                } else {
                    ""
                };
                self.error(
                    codes::YARAL_SECTION_ORDER,
                    format!(
                        "`{}` comes after `{last_name}`: write it before{hint}",
                        s.name
                    ),
                    s.label,
                );
            }
            if rank >= last {
                last = rank;
                last_name = s.name;
            }
        }
        let has = |name: &str| sections.iter().any(|s| s.name == name);
        let mut required: Vec<&str> = Vec::new();
        if profile == Profile::Rule {
            if self.meta_required {
                required.push("meta");
            }
            required.extend(["events", "condition"]);
        } else if !self.reads_stages(sections) {
            // A stage or root query that reads only earlier stages
            // (`$stage.field`) has no `events` of its own.
            required.push("events");
        }
        for name in required {
            if !has(name) {
                self.error(
                    codes::YARAL_SECTION_MISSING,
                    format!("a {} needs a `{name}` section", profile.noun()),
                    anchor,
                );
            }
        }

        let find = |name: &str| sections.iter().find(|s| s.name == name).cloned();
        // Meta: a search's is ignored.
        if let Some(meta) = find("meta")
            && profile == Profile::Rule
        {
            self.meta(&meta.node);
        }
        // Scope: events and setup define event variables and placeholders.
        let mut scope = Scope::default();
        for s in sections
            .iter()
            .filter(|s| matches!(s.name, "events" | "setup"))
        {
            self.collect_events(&s.node, &mut scope);
        }
        let events = find("events");
        // Match.
        let joined = self.joined(sections, &scope);
        let match_section = find("match");
        let window = match_section
            .as_ref()
            .and_then(|m| self.match_section(&m.node, &scope, joined));
        let has_match = match_section
            .as_ref()
            .is_some_and(|m| m.node.children().next().is_some());
        if profile == Profile::Rule && scope.events.len() >= 2 && !has_match {
            let names: Vec<&str> = scope.events.keys().map(String::as_str).collect();
            let at = events.as_ref().map_or(anchor, |e| e.label);
            self.error(
                codes::YARAL_MULTI_EVENT_MATCH,
                format!(
                    "{} event variables ({}) need a `match` section that joins them over a window",
                    names.len(),
                    names.join(", ")
                ),
                at,
            );
        }
        let matched = match_section
            .as_ref()
            .map(|m| self.match_names(&m.node))
            .unwrap_or_default();
        // Outcome.
        if let Some(outcome) = find("outcome") {
            self.outcome(&outcome.node, &mut scope, has_match.then_some(&matched));
        }
        // Window bounds: never in `events`, and only with a `match` window.
        self.window_bounds(sections, window.is_some());
        // Condition.
        let condition = find("condition");
        if let Some(condition) = &condition {
            self.condition(&condition.node, &scope, window.as_ref());
        }
        if profile == Profile::Rule
            && let Some(condition) = &condition
        {
            let used = self.condition_names(&condition.node);
            // Google's condition-syntax: an event variable appears in
            // `condition`, or a placeholder assigned from it does; Google's
            // own examples also condition on an outcome read from it
            // (`$daily_failed_login_count > 5`).
            let through_placeholder = |event: &str| {
                used.iter().any(|u| {
                    scope
                        .assigned
                        .get(u)
                        .or_else(|| scope.outcome_events.get(u))
                        .is_some_and(|events| events.contains(event))
                })
            };
            let mut missing = Vec::new();
            for (name, at) in &scope.events {
                if !used.contains(name) && !through_placeholder(name) {
                    missing.push((name.clone(), *at));
                }
            }
            for (name, at) in missing {
                self.error(
                    codes::YARAL_UNDEFINED_VARIABLE,
                    format!("event variable `{name}` of `events` does not appear in `condition`, nor does a placeholder or outcome read from it"),
                    at,
                );
            }
        }
        // Options.
        if let Some(options) = find("options") {
            self.options(&options.node, window.as_ref());
        }
        // Export: outcome variables only.
        if let Some(export) = find("export") {
            self.references(&export.node, &scope, "export");
            self.export_values(&export.node, &scope, &matched);
        }
        // Order and dedup read outcomes and placeholders.
        for name in ["order", "dedup"] {
            if let Some(s) = find(name) {
                self.references(&s.node, &scope, name);
            }
        }
        // `in` statements.
        self.reference_lists(sections);
        // Unfiltered event variables.
        if profile == Profile::Rule
            && let Some(events) = &events
        {
            self.unfiltered(&events.node, &scope);
        }
        // `cross join` joins the stages of a multi-stage search: a rule has none.
        if profile == Profile::Rule {
            let mut joins = Vec::new();
            for s in sections {
                joins.extend(self.under(&s.node).filter(|n| n.kind() == K::CROSS_JOIN));
            }
            for join in joins {
                self.error(
                    codes::YARAL_PARSE_ERROR,
                    "`cross join` belongs to a multi-stage search; a rule joins events through placeholders".to_string(),
                    at(&join),
                );
            }
        }
    }

    /// Whether a variable path starts at a stage of a multi-stage search.
    pub(super) fn stage_field(&self, field: &SyntaxNode) -> bool {
        root_variable(field).is_some_and(|v| self.stages.contains(self.text(&v)))
    }

    /// Whether a search body reads an earlier stage (`$stage.field`, `cross join`).
    fn reads_stages(&self, sections: &[Section]) -> bool {
        let mut reads = false;
        for s in sections {
            for n in self.under(&s.node) {
                match n.kind() {
                    K::CROSS_JOIN => reads = true,
                    K::UDM_FIELD => reads |= self.stage_field(&n),
                    _ => {}
                }
            }
        }
        reads
    }

    /// Whether a body joins: `cross join`, two event variables, or events
    /// read with an earlier stage (multi-stage "Window size limits").
    fn joined(&self, sections: &[Section], scope: &Scope) -> bool {
        let mut cross = false;
        let mut events = false;
        for s in sections {
            for n in self.under(&s.node) {
                match n.kind() {
                    K::CROSS_JOIN => cross = true,
                    K::BARE_FIELD => events = true,
                    K::UDM_FIELD => events |= !self.stage_field(&n),
                    _ => {}
                }
            }
        }
        cross || scope.events.len() >= 2 || (events && self.reads_stages(sections))
    }

    /// The names a `match` groups by.
    fn match_names(&self, node: &SyntaxNode) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for clause in node.children().filter(|n| n.kind() == K::MATCH_CLAUSE) {
            for key in clause.children().filter(|n| n.kind() != K::MATCH_WINDOW) {
                // `$user`, or a search's field key (`principal.hostname`).
                out.insert(self.text(&key).to_string());
            }
        }
        out
    }

    /// `yaral_window_bound`: `window_start` or `window_end` in `events` or
    /// `setup`, or in a body with no `match` window (windowing-logic,
    /// "Troubleshooting").
    fn window_bounds(&mut self, sections: &[Section], windowed: bool) {
        let mut found: Vec<(SyntaxNode, bool)> = Vec::new();
        for s in sections {
            let predicates = matches!(s.name, "events" | "setup");
            for n in self.under(&s.node).filter(|n| n.kind() == K::WINDOW_BOUND) {
                found.push((n, predicates));
            }
        }
        for (n, predicates) in found {
            let name = self.text(&n).to_ascii_lowercase();
            if predicates {
                self.error(
                    codes::YARAL_WINDOW_BOUND,
                    format!("`{name}` is the match window's bound: use it in outcome, condition or order, not in events"),
                    at(&n),
                );
            } else if !windowed {
                self.error(
                    codes::YARAL_WINDOW_BOUND,
                    format!("`{name}` needs a `match` window (`over` or `by` a duration)"),
                    at(&n),
                );
            }
        }
    }

    /// `yaral_export_value`: a `write_row` value that is not an outcome
    /// variable (data-tables: "You can only export outcome variables").
    fn export_values(&mut self, node: &SyntaxNode, scope: &Scope, matched: &BTreeSet<String>) {
        let mut values: Vec<SyntaxNode> = Vec::new();
        for n in self.under(node) {
            if n.kind() == K::NAMED_ARGUMENT
                && n.ancestors().any(|a| a.kind() == K::TABLE_CALL)
                && let Some(value) = crate::ast::NamedArgument::cast(n.clone())
                    .and_then(|a| a.value())
                    .map(|v| v.syntax().clone())
            {
                values.push(value);
            }
        }
        for value in values {
            let value = unparen(value);
            if self.profile == Profile::Search {
                // A search writes scalar values too (data-tables: "the support
                // offered in Search for writing scalar values to data tables",
                // `write_row(col_name: $e.metadata.product_name)`); only a
                // `match` key is refused ("You can't include a match variable
                // in the export section of a statistics query").
                let name = self.text(&value);
                if matched.contains(name) {
                    self.error(
                        codes::YARAL_EXPORT_VALUE,
                        format!(
                            "`{name}` is a `match` variable: a search does not export match variables"
                        ),
                        at(&value),
                    );
                }
                continue;
            }
            if value.kind() == K::VARIABLE {
                let name = self.text(&value);
                let defined = scope.events.contains_key(name)
                    || scope.placeholders.contains_key(name)
                    || self.stages.contains(name);
                if scope.outcomes.contains(name) || !defined {
                    // Undefined names are `yaral_undefined_variable`.
                    continue;
                }
            }
            self.error(
                codes::YARAL_EXPORT_VALUE,
                format!(
                    "`{}` is not an outcome variable: `export` writes outcome variables only; assign it in `outcome` first",
                    self.text(&value)
                ),
                at(&value),
            );
        }
    }

    fn meta(&mut self, meta: &SyntaxNode) {
        let mut keys: BTreeSet<&str> = BTreeSet::new();
        for entry in meta.children() {
            let key = entry.children().find(|n| n.kind() == K::META_KEY);
            let value = entry.children().find(|n| n.kind() != K::META_KEY);
            let (Some(key), Some(value)) = (key, value) else {
                continue;
            };
            let name = self.text(&key);
            if is_keyword(name) {
                self.error(
                    codes::YARAL_RESERVED_IDENTIFIER,
                    format!("`{name}` is a YARA-L keyword, not a meta key"),
                    at(&key),
                );
            }
            if !keys.insert(name) {
                self.error(
                    codes::YARAL_META_DUPLICATE,
                    format!("meta key `{name}` appears twice"),
                    at(&key),
                );
            }
            if !is_literal(&value, K::STRING) {
                self.error(
                    codes::YARAL_META_DUPLICATE,
                    format!("meta `{name}` takes a double-quoted string"),
                    at(&value),
                );
            }
        }
    }

    /// Event variables (the root of a field path) and placeholders (a bare
    /// variable) of `events` and `setup`.
    fn collect_events(&self, node: &SyntaxNode, scope: &mut Scope) {
        for n in self.under(node) {
            match n.kind() {
                K::UDM_FIELD => {
                    if let Some(var) = root_variable(&n) {
                        let name = self.text(&var).to_string();
                        if !self.stages.contains(&name) {
                            scope.events.entry(name).or_insert(at(&var));
                        }
                    }
                }
                K::VARIABLE => {
                    let parent = n.parent().map(|p| p.kind());
                    if parent != Some(K::UDM_FIELD) && parent != Some(K::MATCH_WINDOW) {
                        let name = self.text(&n).to_string();
                        if !self.stages.contains(&name) {
                            scope.placeholders.entry(name).or_insert(at(&n));
                        }
                    }
                }
                _ => {}
            }
        }
        // A name used both ways is an event variable.
        scope
            .placeholders
            .retain(|k, _| !scope.events.contains_key(k));
        // Which event variables each placeholder is assigned from: the
        // statements that name both.
        for statement in node.children() {
            let mut events = BTreeSet::new();
            let mut placeholders = BTreeSet::new();
            for n in self.under(&statement).filter(|n| n.kind() == K::VARIABLE) {
                let name = self.text(&n).to_string();
                if n.parent().map(|p| p.kind()) == Some(K::UDM_FIELD) {
                    events.insert(name);
                } else if scope.placeholders.contains_key(&name) {
                    placeholders.insert(name);
                }
            }
            for p in placeholders {
                scope
                    .assigned
                    .entry(p)
                    .or_default()
                    .extend(events.iter().cloned());
            }
        }
    }

    fn match_section(&mut self, node: &SyntaxNode, scope: &Scope, joined: bool) -> Option<Window> {
        let clause = node.children().find(|n| n.kind() == K::MATCH_CLAUSE)?;
        let keys: Vec<SyntaxNode> = clause
            .children()
            .filter(|n| n.kind() != K::MATCH_WINDOW)
            .collect();
        for key in keys {
            if key.kind() == K::VARIABLE {
                let name = self.text(&key);
                if !scope.placeholders.contains_key(name) {
                    let why = if scope.events.contains_key(name) {
                        "is an event variable"
                    } else {
                        "is not bound in `events`"
                    };
                    self.error(
                        codes::YARAL_MATCH_VARIABLE,
                        format!("`{name}` {why}: `match` groups by placeholders bound in `events`"),
                        at(&key),
                    );
                }
            } else if self.profile == Profile::Rule {
                self.error(
                    codes::YARAL_MATCH_VARIABLE,
                    "a rule groups by placeholders: bind the field to a `$placeholder` in `events`"
                        .into(),
                    at(&key),
                );
            }
        }
        let window = clause
            .children()
            .find(|n| n.kind() == K::MATCH_WINDOW)
            .and_then(MatchWindow::cast);
        let Some(window) = window else {
            if self.profile == Profile::Rule {
                self.error(
                    codes::YARAL_MATCH_WINDOW,
                    "a rule's `match` needs a window: `over <duration>` or `by <duration>`".into(),
                    at(&clause),
                );
            }
            return None;
        };
        let kind = window
            .kind()
            .map(|k| k.text().to_ascii_lowercase())
            .unwrap_or_default();
        let sliding = window.direction().is_some();
        if self.profile == Profile::Rule {
            for extra in [window.every_token(), window.first_token()]
                .into_iter()
                .flatten()
            {
                self.error(
                    codes::YARAL_MATCH_WINDOW,
                    format!(
                        "`{}` is a search window: a rule's window is `over` or `by` a duration",
                        extra.text()
                    ),
                    at_token(&extra),
                );
            }
        }
        if let Some(pivot) = window.pivot() {
            let name = self.text(pivot.syntax());
            if !scope.events.contains_key(name) {
                self.error(
                    codes::YARAL_UNDEFINED_VARIABLE,
                    format!("`{name}` is not an event variable of `events`: a sliding window pivots on one"),
                    at(pivot.syntax()),
                );
            }
        }
        let tumbling = kind == "by";
        // yara-l-1.0 1.1 `match`: rule hop and sliding 1m-14d, tumbling
        // 1m-72h; search hop and sliding 1m-48h, tumbling 1m-30d, or 48h
        // with a join.
        let (max, what) = match (self.profile, tumbling) {
            (Profile::Rule, true) => (72 * 60, "a tumbling (`by`) window"),
            (Profile::Rule, false) if sliding => (14 * DAY, "a sliding window"),
            (Profile::Rule, false) => (14 * DAY, "a hop (`over`) window"),
            (Profile::Search, true) if joined => {
                (48 * 60, "a search's tumbling (`by`) window with a join")
            }
            (Profile::Search, true) => (30 * DAY, "a search's tumbling (`by`) window"),
            (Profile::Search, false) if sliding => (48 * 60, "a search's sliding window"),
            (Profile::Search, false) => (48 * 60, "a search's hop (`over`) window"),
        };
        let mut minutes = None;
        // `by 2 week` puts the count and the unit apart: the unit (or a
        // duration) is what is measured.
        let length: Option<(String, At, bool)> = window
            .duration_token()
            .map(|t| (t.text().to_owned(), at_token(&t), true))
            .or_else(|| {
                window
                    .time_unit()
                    .map(|u| (self.text(u.syntax()).to_owned(), at(u.syntax()), false))
            });
        let Some((text, length_at, is_duration)) = length else {
            return Some(Window { minutes });
        };
        let measured = if is_duration {
            let units: &[&str] = match self.profile {
                Profile::Rule => &["m", "h", "d"],
                Profile::Search => &["m", "h", "d", "w", "mo"],
            };
            duration(&text).filter(|(_, unit)| units.contains(unit))
        } else {
            // `by day`, `over every 2 hour`: a search's unit words.
            let count: u64 = window
                .integer_token()
                .and_then(|t| t.text().parse().ok())
                .unwrap_or(1);
            let per = match text.to_ascii_lowercase().as_str() {
                "m" | "minute" | "minutes" => Some(1),
                "h" | "hour" | "hours" => Some(60),
                "d" | "day" | "days" => Some(DAY),
                "w" | "week" | "weeks" => Some(7 * DAY),
                "mo" | "month" | "months" => Some(30 * DAY),
                _ => None,
            };
            per.filter(|_| self.profile == Profile::Search)
                .map(|per| (count.saturating_mul(per), ""))
        };
        match measured {
            Some((value, _)) => {
                minutes = Some(value);
                if value < 1 || value > max {
                    self.error(
                        codes::YARAL_MATCH_WINDOW,
                        format!("{text}: {what} is 1m to {}", format_minutes(max)),
                        length_at,
                    );
                }
            }
            None => {
                let hint = match self.profile {
                    Profile::Rule => "a number of minutes, hours or days (`10m`, `1h`, `2d`)",
                    Profile::Search => {
                        "a number of minutes, hours, days, weeks or months (`10m`, `1h`, `2d`, `1w`, `1mo`), or a unit word (`by day`)"
                    }
                };
                self.error(
                    codes::YARAL_MATCH_WINDOW,
                    format!("`{text}` is not a window length: write {hint}"),
                    length_at,
                );
            }
        }
        Some(Window { minutes })
    }

    /// `matched`: the `match` names, when the body has a `match`.
    fn outcome(
        &mut self,
        node: &SyntaxNode,
        scope: &mut Scope,
        matched: Option<&BTreeSet<String>>,
    ) {
        let mut count = 0;
        for statement in node.children() {
            let comparison = Comparison::cast(statement.clone())
                .filter(|c| c.op().is_some_and(|o| o.text() == "="));
            let left = comparison
                .as_ref()
                .and_then(Comparison::left)
                .map(|l| l.syntax().clone());
            let (Some(comparison), Some(left)) = (comparison, left) else {
                self.references(&statement, scope, "outcome");
                continue;
            };
            if left.kind() != K::VARIABLE {
                self.references(&statement, scope, "outcome");
                continue;
            }
            let name = self.text(&left).to_string();
            if let Some(right) = comparison.right().map(|r| r.syntax().clone()) {
                let mut read: BTreeSet<String> = BTreeSet::new();
                for n in self.under(&right).filter(|n| n.kind() == K::VARIABLE) {
                    let v = self.text(&n).to_string();
                    if n.parent().map(|p| p.kind()) == Some(K::UDM_FIELD) {
                        read.insert(v);
                    } else if let Some(events) = scope.assigned.get(&v) {
                        read.extend(events.iter().cloned());
                    } else if let Some(events) = scope.outcome_events.get(&v) {
                        read.extend(events.iter().cloned());
                    }
                }
                scope
                    .outcome_events
                    .entry(name.clone())
                    .or_default()
                    .extend(read);
                self.references(&right, scope, "outcome");
                if let Some(matched) = matched {
                    self.aggregation(&right, scope, matched, false);
                }
            }
            if !scope.outcomes.contains(&name) {
                count += 1;
                if count == MAX_OUTCOMES + 1 {
                    self.error(
                        codes::YARAL_OUTCOME_LIMIT,
                        format!("`{name}` is outcome variable {count}: a rule or search has at most {MAX_OUTCOMES}"),
                        at(&left),
                    );
                }
            }
            scope.outcomes.insert(name);
        }
    }

    /// `yaral_outcome_aggregation` on an outcome's value, in a rule or search
    /// with `match`: event fields, and placeholders that are not `match`
    /// variables, are read through an aggregation (outcome-syntax,
    /// "Aggregations"). A loop over the value's nodes in source order, with
    /// whether each sits inside an aggregation: never a frame per tree level,
    /// since a run of comparisons nests thousands deep.
    fn aggregation(
        &mut self,
        node: &SyntaxNode,
        scope: &Scope,
        matched: &BTreeSet<String>,
        inside: bool,
    ) {
        let mut stack = vec![(node.clone(), inside)];
        while let Some((node, inside)) = stack.pop() {
            self.aggregation_at(&node, scope, matched, inside, &mut stack);
        }
    }

    /// [`Checker::aggregation`] on one node; what it holds goes on `stack`,
    /// the first child on top.
    fn aggregation_at(
        &mut self,
        node: &SyntaxNode,
        scope: &Scope,
        matched: &BTreeSet<String>,
        inside: bool,
        stack: &mut Vec<(SyntaxNode, bool)>,
    ) {
        match node.kind() {
            K::FUNCTION_CALL => {
                let name = self.function_name(node);
                let aggregate = Functions::cached()
                    .get(&name)
                    .is_some_and(|f| f.aggregation || name.starts_with("window."));
                let arguments: Vec<SyntaxNode> = node
                    .children()
                    .filter(|c| c.kind() == K::ARGUMENTS)
                    .flat_map(|c| c.children())
                    .collect();
                stack.extend(
                    arguments
                        .into_iter()
                        .rev()
                        .map(|a| (a, inside || aggregate)),
                );
            }
            K::UDM_FIELD | K::BARE_FIELD if !inside => {
                let root = root_variable(node).map(|v| self.text(&v).to_string());
                if root.as_ref().is_some_and(|r| scope.outcomes.contains(r)) {
                    return;
                }
                self.error(
                    codes::YARAL_OUTCOME_AGGREGATION,
                    format!(
                        "`{}` reads an event field in a {} with `match`: wrap it in an aggregation (max, min, sum, count, count_distinct, array, array_distinct)",
                        self.text(node),
                        self.profile.noun()
                    ),
                    at(node),
                );
            }
            K::VARIABLE if !inside => {
                let name = self.text(node);
                if scope.placeholders.contains_key(name)
                    && !matched.contains(name)
                    && !scope.outcomes.contains(name)
                {
                    self.error(
                        codes::YARAL_OUTCOME_AGGREGATION,
                        format!(
                            "`{name}` is a placeholder, not a `match` variable: in a {} with `match`, read it through an aggregation (max, min, count_distinct, array_distinct, ...)",
                            self.profile.noun()
                        ),
                        at(node),
                    );
                }
            }
            K::VARIABLE => {
                let name = self.text(node);
                if scope.outcomes.contains(name) {
                    self.error(
                        codes::YARAL_OUTCOME_AGGREGATION,
                        format!("`{name}` is an outcome variable, already aggregated: do not aggregate it again"),
                        at(node),
                    );
                }
            }
            K::NAMED_ARGUMENT => {}
            _ => {
                let children: Vec<SyntaxNode> = node.children().collect();
                stack.extend(children.into_iter().rev().map(|c| (c, inside)));
            }
        }
    }

    /// Variables a section reads that `events` and `outcome` do not define.
    fn references(&mut self, node: &SyntaxNode, scope: &Scope, section: &str) {
        let mut found: Vec<(SyntaxNode, String)> = Vec::new();
        for n in self.under(node) {
            if matches!(n.kind(), K::VARIABLE | K::COUNT_REF) {
                let name = dollar_name(self.text(&n));
                let parent = n.parent().map(|p| p.kind());
                if parent == Some(K::UDM_FIELD) && self.profile == Profile::Search {
                    continue;
                }
                found.push((n, name));
            }
        }
        for (n, name) in found {
            let known = scope.events.contains_key(&name)
                || scope.placeholders.contains_key(&name)
                || scope.outcomes.contains(&name)
                || self.stages.contains(&name);
            if !known {
                self.error(
                    codes::YARAL_UNDEFINED_VARIABLE,
                    format!(
                        "`{}` in `{section}` is not defined by `events` or `outcome`",
                        self.text(&n)
                    ),
                    at(&n),
                );
            }
        }
    }

    /// The `$name`s a condition mentions, as `$name` (counts included).
    fn condition_names(&self, node: &SyntaxNode) -> BTreeSet<String> {
        self.under(node)
            .filter(|n| {
                matches!(n.kind(), K::VARIABLE | K::COUNT_REF)
                    && n.parent().map(|p| p.kind()) != Some(K::UDM_FIELD)
            })
            .map(|n| dollar_name(self.text(&n)))
            .collect()
    }

    /// What a condition term says about an event variable or placeholder,
    /// and its name.
    fn term(&self, node: &SyntaxNode, scope: &Scope) -> Option<(String, Bound)> {
        let node = unparen(node.clone());
        let known =
            |name: &str| scope.events.contains_key(name) || scope.placeholders.contains_key(name);
        match node.kind() {
            K::VARIABLE => {
                let name = self.text(&node).to_string();
                known(&name).then_some((name, Bound::Bounded))
            }
            K::UNARY_EXPR => {
                let unary = UnaryExpr::cast(node)?;
                let op = unary.op()?;
                let operand = unparen(unary.operand()?.syntax().clone());
                if op.text() == "!" && operand.kind() == K::VARIABLE {
                    let name = self.text(&operand).to_string();
                    return known(&name).then_some((name, Bound::Unbounded));
                }
                None
            }
            K::COMPARISON => {
                let comparison = Comparison::cast(node)?;
                let left = unparen(comparison.left()?.syntax().clone());
                let right = unparen(comparison.right()?.syntax().clone());
                let op = comparison.op()?.text().to_owned();
                let (count, number, op) =
                    if left.kind() == K::COUNT_REF && is_literal(&right, K::INTEGER) {
                        (left, right, op)
                    } else if is_literal(&left, K::INTEGER) && right.kind() == K::COUNT_REF {
                        let flipped = match op.as_str() {
                            "<" => ">",
                            "<=" => ">=",
                            ">" => "<",
                            ">=" => "<=",
                            other => other,
                        };
                        (right, left, flipped.to_owned())
                    } else {
                        return None;
                    };
                let name = dollar_name(self.text(&count));
                if !known(&name) {
                    return None;
                }
                let n: u64 = self.text(&number).parse().unwrap_or(0);
                let bound = match op.as_str() {
                    ">" => Bound::Bounded,
                    ">=" if n > 0 => Bound::Bounded,
                    "!=" if n == 0 => Bound::Bounded,
                    "=" if n > 0 => Bound::Bounded,
                    _ => Bound::Unbounded,
                };
                Some((name, bound))
            }
            _ => None,
        }
    }

    /// The operands of an `or` chain, through parentheses that hold an `or`,
    /// in source order; a loop, not a frame per level.
    fn or_operands(node: &SyntaxNode, out: &mut Vec<SyntaxNode>) {
        let mut stack = vec![node.clone()];
        while let Some(node) = stack.pop() {
            let inner = unparen(node.clone());
            if inner.kind() == K::OR_EXPR {
                let children: Vec<SyntaxNode> = inner.children().collect();
                stack.extend(children.into_iter().rev());
            } else {
                out.push(node);
            }
        }
    }

    fn condition(&mut self, node: &SyntaxNode, scope: &Scope, window: Option<&Window>) {
        let statements: Vec<SyntaxNode> = node.children().collect();
        self.references(node, scope, "condition");
        if self.profile == Profile::Rule && statements.len() > 1 {
            // Two juxtaposed terms: Google reads a comma or nothing between them as an error.
            self.error(
                codes::YARAL_CONDITION_SHAPE,
                "`condition` is one boolean expression: join its terms with `and` or `or`".into(),
                at(&statements[1]),
            );
        }
        let mut terms: Vec<(String, Bound)> = Vec::new();
        let mut not_terms: Vec<SyntaxNode> = Vec::new();
        let mut or_groups: Vec<SyntaxNode> = Vec::new();
        for statement in &statements {
            for n in self.under(statement) {
                // `$e` under `!` is the `!$e` term, not a term of its own.
                let negated = n.kind() == K::VARIABLE
                    && n.parent().is_some_and(|p| p.kind() == K::UNARY_EXPR);
                if !negated && let Some(t) = self.term(&n, scope) {
                    terms.push(t);
                }
                if n.kind() == K::NOT_EXPR
                    && n.children()
                        .next()
                        .is_some_and(|o| self.term(&o, scope).is_some())
                {
                    not_terms.push(n.clone());
                }
                if n.kind() == K::OR_EXPR
                    && !n
                        .ancestors()
                        .skip(1)
                        .take_while(|a| matches!(a.kind(), K::PAREN_EXPR | K::OR_EXPR))
                        .any(|a| a.kind() == K::OR_EXPR)
                {
                    or_groups.push(n);
                }
            }
        }
        for n in not_terms {
            self.error(
                codes::YARAL_CONDITION_SHAPE,
                "negate an event or placeholder term with `!`, not `not` (`!$e`, `#e = 0`)".into(),
                at(&n),
            );
        }
        let unbounded = terms.iter().any(|(_, b)| *b == Bound::Unbounded);
        let limit = match self.profile {
            Profile::Rule => 2,
            Profile::Search => 3,
        };
        for group in or_groups {
            let mut operands = Vec::new();
            Self::or_operands(&group, &mut operands);
            let mut events: BTreeSet<String> = BTreeSet::new();
            let mut event_terms = false;
            for operand in &operands {
                if let Some((name, _)) = self.term(operand, scope) {
                    event_terms = true;
                    if scope.events.contains_key(&name) {
                        events.insert(name);
                    }
                }
            }
            let mixed = operands.iter().any(|o| {
                o.kind() == K::AND_EXPR && self.under(o).any(|n| self.term(&n, scope).is_some())
            });
            if !event_terms && !mixed {
                continue;
            }
            if events.len() > limit {
                self.error(
                    codes::YARAL_CONDITION_SHAPE,
                    format!(
                        "`or` joins {} event variables: a {} joins at most {limit}",
                        events.len(),
                        self.profile.noun()
                    ),
                    at(&group),
                );
            } else if unbounded {
                self.error(
                    codes::YARAL_CONDITION_SHAPE,
                    "`or` is refused in a condition with an unbounded term (`!$e`, `#e = 0`)"
                        .into(),
                    at(&group),
                );
            } else if mixed {
                self.error(
                    codes::YARAL_CONDITION_SHAPE,
                    "an `or` among event and placeholder terms needs the group in parentheses: `($a or $b) and ...`".into(),
                    at(&group),
                );
            }
        }
        if unbounded {
            let windowed = window.is_some();
            let bounded_event = terms
                .iter()
                .any(|(name, b)| *b == Bound::Bounded && scope.events.contains_key(name));
            if !windowed || !bounded_event {
                let why = if windowed {
                    "at least one bounded event variable (`$e`, `#e > 0`)"
                } else {
                    "a `match` window"
                };
                let anchor = statements.first().map_or_else(|| at(node), at);
                self.error(
                    codes::YARAL_CONDITION_SHAPE,
                    format!("a non-existence term (`!$e`, `#e = 0`, `#e < n`) needs {why}"),
                    anchor,
                );
            }
        }
    }

    fn options(&mut self, node: &SyntaxNode, window: Option<&Window>) {
        for entry in node.children() {
            let key = entry.children().find(|n| n.kind() == K::OPTION_KEY);
            let value = entry.children().find(|n| n.kind() != K::OPTION_KEY);
            let (Some(key), Some(value)) = (key, value) else {
                continue;
            };
            let name = self.text(&key);
            let text = self.text(&value);
            match name {
                "allow_zero_values" => {
                    if !matches!(literal_kind(&value), Some(K::TRUE_KW | K::FALSE_KW)) {
                        self.error(
                            codes::YARAL_OPTION,
                            format!("allow_zero_values takes true or false, not `{text}`"),
                            at(&value),
                        );
                    }
                }
                "suppression_window" => {
                    let parsed = is_literal(&value, K::DURATION)
                        .then(|| duration(text))
                        .flatten()
                        .filter(|(m, unit)| *m > 0 && matches!(*unit, "m" | "h" | "d"));
                    match parsed {
                        None => self.error(
                            codes::YARAL_OPTION,
                            format!("suppression_window takes a positive duration (`5m`, `1h`, `24h`), not `{text}`"),
                            at(&value),
                        ),
                        Some((minutes, _)) => {
                            if let Some(w) = window.and_then(|w| w.minutes)
                                && self.profile == Profile::Rule
                                && minutes <= w
                            {
                                self.error(
                                    codes::YARAL_OPTION,
                                    format!(
                                        "suppression_window {text} must be longer than the match window ({})",
                                        format_minutes(w)
                                    ),
                                    at(&value),
                                );
                            }
                        }
                    }
                }
                _ => self.error(
                    codes::YARAL_OPTION,
                    format!(
                        "`{name}` is not an option: write allow_zero_values or suppression_window"
                    ),
                    at(&key),
                ),
            }
        }
    }

    fn reference_lists(&mut self, sections: &[Section]) {
        let (max_all, max_regex, max_cidr) = reference_limits(self.profile);
        let mut all = 0;
        let mut regex = 0;
        let mut cidr = 0;
        let mut over: Vec<(SyntaxNode, String)> = Vec::new();
        for s in sections {
            for n in self.under(&s.node).filter(|n| n.kind() == K::IN_EXPR) {
                all += 1;
                let kind = n
                    .children_with_tokens()
                    .filter_map(|e| e.into_token())
                    .find(|t| matches!(t.kind(), K::REGEX_KW | K::CIDR_KW))
                    .map(|t| t.text().to_ascii_lowercase());
                match kind.as_deref() {
                    Some("regex") => regex += 1,
                    Some("cidr") => cidr += 1,
                    _ => {}
                }
                if all == max_all + 1 {
                    over.push((n.clone(), format!("more than {max_all} `in` statements")));
                }
                if kind.as_deref() == Some("regex") && regex == max_regex + 1 {
                    over.push((
                        n.clone(),
                        format!("more than {max_regex} `in regex` statements"),
                    ));
                }
                if kind.as_deref() == Some("cidr") && cidr == max_cidr + 1 {
                    over.push((n, format!("more than {max_cidr} `in cidr` statements")));
                }
            }
        }
        for (n, what) in over {
            self.error(
                codes::YARAL_REFERENCE_LIST_LIMIT,
                format!("{what}: Google's limit for a {}", self.profile.noun()),
                at(&n),
            );
        }
    }

    /// `yaral_unfiltered_event`: an event variable with no equality on its
    /// event type, log type or product name.
    fn unfiltered(&mut self, events: &SyntaxNode, scope: &Scope) {
        let mut filtered: BTreeSet<String> = BTreeSet::new();
        let mut detection: BTreeSet<String> = BTreeSet::new();
        for n in self.under(events) {
            if n.kind() == K::UDM_FIELD {
                let segs = accessor_segments(&n);
                if let (Some(var), Some(Segment::Name(first, _))) =
                    (root_variable(&n), segs.first())
                    && first == "detection"
                {
                    detection.insert(self.text(&var).to_string());
                }
            }
            let (left, right) = match n.kind() {
                K::COMPARISON => {
                    let c = Comparison::cast(n.clone());
                    if c.as_ref()
                        .and_then(Comparison::op)
                        .is_none_or(|o| o.text() != "=")
                    {
                        continue;
                    }
                    (
                        c.as_ref()
                            .and_then(Comparison::left)
                            .map(|e| e.syntax().clone()),
                        c.as_ref()
                            .and_then(Comparison::right)
                            .map(|e| e.syntax().clone()),
                    )
                }
                K::IN_EXPR => (
                    crate::ast::InExpr::cast(n.clone())
                        .and_then(|i| i.left())
                        .map(|e| e.syntax().clone()),
                    None,
                ),
                _ => continue,
            };
            for side in [left, right].into_iter().flatten() {
                let side = unparen(side);
                if side.kind() != K::UDM_FIELD {
                    continue;
                }
                let Some(var) = root_variable(&side) else {
                    continue;
                };
                let names: Vec<String> = accessor_segments(&side)
                    .into_iter()
                    .filter_map(|s| match s {
                        Segment::Name(n, _) => Some(n),
                        _ => None,
                    })
                    .collect();
                let path: Vec<&str> = names
                    .iter()
                    .map(String::as_str)
                    .skip_while(|s| matches!(*s, "udm" | "graph"))
                    .collect();
                if matches!(
                    path.as_slice(),
                    [
                        "metadata",
                        "event_type" | "log_type" | "product_name" | "entity_type"
                    ]
                ) {
                    filtered.insert(self.text(&var).to_string());
                }
            }
        }
        for (name, at) in &scope.events {
            if !filtered.contains(name) && !detection.contains(name) {
                self.push(
                    codes::YARAL_UNFILTERED_EVENT,
                    Severity::Warning,
                    format!(
                        "`{name}` has no equality on metadata.event_type, metadata.log_type or metadata.product_name: the rule scans every event"
                    ),
                    *at,
                );
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// The descendants the checks read from the index on this thread.
    static INDEXED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The descendants the checks walked to with rowan on this thread.
    static WALKED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod index_tests {
    use super::*;
    use crate::parser::parse;

    /// Rules and searches like Google's and the corpus's, written here: an
    /// engine crate reads no file (`check-io-free.sh`).
    const SAMPLES: &[&str] = &[
        r#"rule r {
  meta:
    author = "a"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.principal.hostname = $host
    $f.target.ip IN %allow_list
    not $e.target.user.userid = /admin.*/ nocase
  match:
    $host over 5m
  outcome:
    $n = count_distinct($e.metadata.id)
    $risk_score = max(if($e.principal.ip = "1.2.3.4", 10, 0))
  condition:
    $e and #e > 2 and ($f or !$f)
  options:
    allow_zero_values = true
}"#,
        "metadata.event_type = \"USER_LOGIN\"\nselect:\n  principal.ip, target.user.userid",
        "stage s { metadata.event_type = \"X\" match: principal.hostname } $s.hostname = \"a\" cross join outcome: $n = window_start",
        "rule broken { events: $e.x = ( condition: $e and",
    ];

    fn texts() -> Vec<String> {
        let mut out: Vec<String> = SAMPLES.iter().map(|s| (*s).to_owned()).collect();
        out.extend(
            SAMPLES
                .iter()
                .flat_map(|t| t.char_indices().step_by(2).map(|(i, _)| t[..i].to_owned())),
        );
        out
    }

    /// The index gives every node's descendants as rowan does: the same
    /// nodes in the same order, the node itself first (ADR 0014 §5).
    #[test]
    fn the_index_gives_rowans_descendants() {
        for source in texts() {
            let root = SyntaxNode::new_root(parse(&source).green);
            let mut checker = Checker::new(&source, Profile::Rule, false);
            checker.nodes = Some(Descendants::new(&root));
            for node in root.descendants() {
                let indexed: Vec<SyntaxNode> = checker.under(&node).collect();
                let walked: Vec<SyntaxNode> = node.descendants().collect();
                assert_eq!(indexed, walked, "{source:?}");
            }
        }
    }

    /// The checks read every descendant from the index and walk to none
    /// (ADR 0014 §7): each walked its sections' and statements' subtrees.
    #[test]
    fn the_checks_walk_no_subtree() {
        for source in [SAMPLES[0], SAMPLES[1]] {
            let (indexed, walked) = (INDEXED.get(), WALKED.get());
            crate::analyze(source);
            assert_eq!(WALKED.get() - walked, 0, "{source:?}");
            assert!(INDEXED.get() - indexed > 0, "{source:?}");
        }
    }
}
