//! The yara-l-1.0 checks on a parsed text: sections, scope, `match`,
//! `outcome`, `condition`, `options`, the catalogues, literals and limits.
//! Each finding carries its code from `opentide_core::codes`.

use crate::catalog::{Functions, Segment, TypeKind, Udm, is_keyword};
use crate::{Finding, Profile};
use opentide_core::{Severity, codes};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::{Node, Tree};

/// Section order of yara-l-1.0 "Sections"; `select` and `unselect` share 12.
fn section_rank(name: &str) -> u8 {
    match name {
        "meta" => 1,
        "setup" => 2,
        "events" => 3,
        "match" => 4,
        "outcome" => 5,
        "condition" => 6,
        "options" => 7,
        "export" => 8,
        "dedup" => 9,
        "order" => 10,
        "limit" => 11,
        _ => 12,
    }
}

fn in_profile(name: &str, profile: Profile) -> bool {
    match profile {
        Profile::Rule => matches!(
            name,
            "meta" | "setup" | "events" | "match" | "outcome" | "condition" | "options" | "export"
        ),
        // `meta` is optional in a search and ignored (getting-started).
        Profile::Search => !matches!(name, "setup" | "options"),
    }
}

/// The most `in` statements of each kind (total, regex, cidr).
fn reference_limits(profile: Profile) -> (usize, usize, usize) {
    match profile {
        Profile::Rule => (10, 5, 5),
        Profile::Search => (7, 4, 2),
    }
}

const MAX_OUTCOMES: usize = 20;

/// A search's grouped fields: aliases for groups of UDM fields
/// (search-syntax-reference, "Search grouped fields").
const GROUPED_FIELDS: &[&str] = &[
    "domain",
    "email",
    "file_path",
    "hash",
    "hostname",
    "ip",
    "namespace",
    "process_id",
    "user",
];
const DAY: u64 = 24 * 60;

#[derive(Clone, Copy)]
struct Section<'t> {
    name: &'static str,
    node: Node<'t>,
    label: Node<'t>,
}

fn section_name(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "meta_section" => "meta",
        "setup_section" => "setup",
        "events_section" | "search_events" => "events",
        "match_section" => "match",
        "outcome_section" => "outcome",
        "condition_section" => "condition",
        "options_section" => "options",
        "export_section" => "export",
        "dedup_section" => "dedup",
        "order_section" => "order",
        "limit_section" => "limit",
        "select_section" => "select",
        "unselect_section" => "unselect",
        _ => return None,
    })
}

/// A match window: its kind, length in minutes when it has one, and pivot.
struct Window {
    minutes: Option<u64>,
}

/// The names a rule or stage defines.
#[derive(Default)]
struct Scope {
    events: BTreeMap<String, (usize, usize)>,
    placeholders: BTreeMap<String, (usize, usize)>,
    outcomes: BTreeSet<String>,
    /// Placeholder → the event variables a statement of `events` assigns it
    /// from (`$user = $e.target.user.userid`).
    assigned: BTreeMap<String, BTreeSet<String>>,
    /// Outcome variable → the event variables its value reads, directly or
    /// through placeholders and earlier outcomes.
    outcome_events: BTreeMap<String, BTreeSet<String>>,
}

pub(crate) struct Checker<'s> {
    source: &'s str,
    profile: Profile,
    meta_required: bool,
    pub findings: Vec<Finding>,
    stages: BTreeSet<String>,
}

fn span(node: Node<'_>) -> (usize, usize) {
    (
        node.start_byte(),
        node.end_byte().max(node.start_byte() + 1),
    )
}

/// `node` without the parentheses around it.
fn unparen(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        match node.named_child(0) {
            Some(inner) if inner.kind() != "comment" => node = inner,
            _ => break,
        }
    }
    node
}

fn named_children<'t>(node: Node<'t>) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|c| c.kind() != "comment")
        .collect()
}

/// A duration's minutes, and its unit.
fn duration(text: &str) -> Option<(u64, &str)> {
    let digits = text.chars().take_while(char::is_ascii_digit).count();
    let amount: u64 = text[..digits].parse().ok()?;
    let unit = &text[digits..];
    let per = match unit {
        "s" => return Some((amount / 60, unit)),
        "m" => 1,
        "h" => 60,
        "d" => DAY,
        "w" => 7 * DAY,
        "mo" => 30 * DAY,
        _ => return Some((0, unit)),
    };
    Some((amount.saturating_mul(per), unit))
}

fn format_minutes(minutes: u64) -> String {
    if minutes.is_multiple_of(DAY) && minutes >= 7 * DAY {
        format!("{}d", minutes / DAY)
    } else if minutes.is_multiple_of(60) {
        format!("{}h", minutes / 60)
    } else {
        format!("{minutes}m")
    }
}

/// The closest of `candidates` to `name`, within two edits.
pub(crate) fn closest<'a>(
    name: &str,
    candidates: impl Iterator<Item = &'a str>,
) -> Option<&'a str> {
    candidates
        .map(|c| (edit_distance(name, c), c))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, c)| (*d, *c))
        .map(|(_, c)| c)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut prev = row[0];
        row[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let next = (row[j] + 1).min(row[j - 1] + 1).min(prev + cost);
            prev = row[j];
            row[j] = next;
        }
    }
    row[b.len()]
}

/// The segments of a `udm_field` (after its variable) or a `bare_field`.
pub(crate) fn segments(node: Node<'_>, source: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    for child in named_children(node) {
        match child.kind() {
            "field_name" => out.push(Segment::Name(
                source[child.byte_range()].to_string(),
                (child.start_byte(), child.end_byte()),
            )),
            "index" => {
                let key = child.child_by_field_name("key");
                if key.is_some_and(|k| k.kind() == "integer") {
                    out.push(Segment::Position(span(child)));
                } else {
                    out.push(Segment::Key(span(child)));
                }
            }
            _ => {}
        }
    }
    out
}

/// The text of a string or raw string literal, decoded.
pub(crate) fn literal_text(node: Node<'_>, source: &str) -> Option<String> {
    let raw = &source[node.byte_range()];
    match node.kind() {
        "raw_string" => Some(raw.get(1..raw.len().saturating_sub(1))?.to_string()),
        "string" => {
            let inner = raw.get(1..raw.len().saturating_sub(1))?;
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c != '\\' {
                    out.push(c);
                    continue;
                }
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some(other) => out.push(other),
                    None => out.push('\\'),
                }
            }
            Some(out)
        }
        _ => None,
    }
}

/// An RE2 pattern as Rust's `regex-syntax` reads it: a `{` that does not
/// start a repetition is a literal in RE2 and must be escaped here.
fn as_rust_pattern(pattern: &str) -> String {
    let bytes = pattern.as_bytes();
    let mut out = String::with_capacity(pattern.len() + 4);
    let mut i = 0;
    let mut class = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            // RE2 octal escapes: `\0`, or two or three octal digits (`\12`).
            // A single non-zero digit is a backreference, which RE2 refuses.
            let octal = bytes[i + 1..]
                .iter()
                .take(3)
                .take_while(|b| (b'0'..=b'7').contains(b))
                .count();
            if octal > 0 && (next == b'0' || octal > 1) {
                let digits = &pattern[i + 1..i + 1 + octal];
                let value = u32::from_str_radix(digits, 8).unwrap_or(0);
                out.push_str(&format!("\\x{{{value:x}}}"));
                i += 1 + octal;
                continue;
            }
            // `\/` is a literal slash in a YARA-L regex literal.
            if next == b'/' {
                out.push('/');
            } else {
                out.push_str(&pattern[i..i + 2 + utf8_extra(bytes[i + 1])]);
                i += utf8_extra(bytes[i + 1]);
            }
            i += 2;
            continue;
        }
        if c == b'[' {
            class = true;
        } else if c == b']' {
            class = false;
        } else if c == b'{' && !class {
            let rest = &pattern[i..];
            let repetition = rest[1..].split_once('}').is_some_and(|(inside, _)| {
                let (lo, hi) = inside.split_once(',').unwrap_or((inside, "0"));
                !lo.is_empty()
                    && lo.bytes().all(|b| b.is_ascii_digit())
                    && hi.bytes().all(|b| b.is_ascii_digit())
            });
            if !repetition {
                out.push_str("\\{");
                i += 1;
                continue;
            }
        }
        let len = 1 + utf8_extra(c);
        out.push_str(&pattern[i..i + len]);
        i += len;
    }
    out
}

fn utf8_extra(first: u8) -> usize {
    match first {
        0xF0..=0xFF => 3,
        0xE0..=0xEF => 2,
        0xC0..=0xDF => 1,
        _ => 0,
    }
}

/// Why RE2 refuses `pattern`, if it does.
pub(crate) fn regex_problem(pattern: &str) -> Option<String> {
    let rust = as_rust_pattern(pattern);
    regex_syntax::ParserBuilder::new()
        .build()
        .parse(&rust)
        .err()
        .map(|e| {
            let text = e.to_string();
            text.lines()
                .rev()
                .find(|l| l.starts_with("error:"))
                .map_or(text.clone(), |l| {
                    l.trim_start_matches("error:").trim().to_string()
                })
        })
}

/// A pattern that starts with `.*` and has no anchor.
fn leading_wildcard(pattern: &str) -> bool {
    let mut p = pattern;
    // Inline flags first: `(?i).*x`.
    while let Some(rest) = p.strip_prefix("(?") {
        match rest.find(')') {
            Some(end)
                if rest[..end]
                    .chars()
                    .all(|c| c.is_ascii_alphabetic() || c == '-') =>
            {
                p = &rest[end + 1..]
            }
            _ => break,
        }
    }
    p.starts_with(".*")
}

/// What a condition term says about an event variable or placeholder.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bound {
    Bounded,
    Unbounded,
}

impl<'s> Checker<'s> {
    pub fn new(source: &'s str, profile: Profile, meta_required: bool) -> Self {
        Self {
            source,
            profile,
            meta_required,
            findings: Vec::new(),
            stages: BTreeSet::new(),
        }
    }

    fn text(&self, node: Node<'_>) -> &'s str {
        &self.source[node.byte_range()]
    }

    fn push(
        &mut self,
        code: &'static str,
        severity: Severity,
        message: String,
        at: (usize, usize),
    ) {
        self.findings
            .push(Finding::new(code, severity, message, at.0, at.1));
    }

    fn error(&mut self, code: &'static str, message: String, node: Node<'_>) {
        self.push(code, Severity::Error, message, span(node));
    }

    fn warning(&mut self, code: &'static str, message: String, node: Node<'_>) {
        self.push(code, Severity::Warning, message, span(node));
    }

    /// Every check on a tree that parsed.
    pub fn run(&mut self, tree: &Tree) {
        let root = tree.root_node();
        let top = named_children(root);
        let rules: Vec<Node<'_>> = top
            .iter()
            .copied()
            .filter(|n| n.kind() == "rule_declaration")
            .collect();
        if let Some(second) = rules.get(1) {
            self.error(
                codes::YARAL_PARSE_ERROR,
                "a YARA-L text holds one rule: Google stores and verifies one rule at a time"
                    .into(),
                *second,
            );
        }
        if let Some(rule) = rules.first() {
            self.rule(*rule);
        } else if let Some(search) = top.iter().find(|n| n.kind() == "search_query") {
            self.search(*search);
        }
        self.walk_all(root);
    }

    fn rule(&mut self, rule: Node<'_>) {
        if let Some(name) = rule.child_by_field_name("name") {
            let text = self.text(name);
            if is_keyword(text) {
                self.error(
                    codes::YARAL_RESERVED_IDENTIFIER,
                    format!("`{text}` is a YARA-L keyword, not a rule name"),
                    name,
                );
            }
        }
        let sections: Vec<Section<'_>> = named_children(rule)
            .into_iter()
            .filter_map(|n| {
                let name = section_name(n.kind())?;
                Some(Section {
                    name,
                    node: n,
                    label: n.child(0)?,
                })
            })
            .collect();
        let anchor = rule.child_by_field_name("name").unwrap_or(rule);
        self.body(&sections, anchor);
    }

    fn search(&mut self, search: Node<'_>) {
        let children = named_children(search);
        for stage in children.iter().filter(|n| n.kind() == "stage") {
            if let Some(name) = stage.child_by_field_name("name") {
                self.stages.insert(format!("${}", self.text(name)));
            }
        }
        for stage in children.iter().filter(|n| n.kind() == "stage") {
            let sections = self.sections_of(*stage);
            let anchor = stage.child_by_field_name("name").unwrap_or(*stage);
            self.body(&sections, anchor);
        }
        let sections = self.sections_of(search);
        self.body(&sections, search);
    }

    fn sections_of<'t>(&self, node: Node<'t>) -> Vec<Section<'t>> {
        named_children(node)
            .into_iter()
            .filter_map(|n| {
                let name = section_name(n.kind())?;
                // Unlabelled search events: the section itself stands for its label.
                let label = if n.kind() == "search_events" {
                    n
                } else {
                    n.child(0)?
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
    fn body(&mut self, sections: &[Section<'_>], anchor: Node<'_>) {
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

        let find = |name: &str| sections.iter().find(|s| s.name == name).copied();
        // Meta: a search's is ignored.
        if let Some(meta) = find("meta")
            && profile == Profile::Rule
        {
            self.meta(meta.node);
        }
        // Scope: events and setup define event variables and placeholders.
        let mut scope = Scope::default();
        for s in sections
            .iter()
            .filter(|s| matches!(s.name, "events" | "setup"))
        {
            self.collect_events(s.node, &mut scope);
        }
        let events = find("events");
        // Match.
        let joined = self.joined(sections, &scope);
        let window = find("match").and_then(|m| self.match_section(m.node, &scope, joined));
        let has_match = find("match").is_some_and(|m| m.node.named_child_count() > 0);
        if profile == Profile::Rule && scope.events.len() >= 2 && !has_match {
            let names: Vec<&str> = scope.events.keys().map(String::as_str).collect();
            let at = events.map_or(anchor, |e| e.label);
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
        let matched = find("match")
            .map(|m| self.match_names(m.node))
            .unwrap_or_default();
        // Outcome.
        if let Some(outcome) = find("outcome") {
            self.outcome(outcome.node, &mut scope, has_match.then_some(&matched));
        }
        // Window bounds: never in `events`, and only with a `match` window.
        self.window_bounds(sections, window.is_some());
        // Condition.
        if let Some(condition) = find("condition") {
            self.condition(condition.node, &scope, window.as_ref());
        } else if profile == Profile::Rule {
            // `yaral_section_missing` reported above.
        }
        if profile == Profile::Rule
            && let Some(condition) = find("condition")
        {
            let used = self.condition_names(condition.node);
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
            for (name, at) in &scope.events {
                if !used.contains(name) && !through_placeholder(name) {
                    self.push(
                        codes::YARAL_UNDEFINED_VARIABLE,
                        Severity::Error,
                        format!("event variable `{name}` of `events` does not appear in `condition`, nor does a placeholder or outcome read from it"),
                        *at,
                    );
                }
            }
        }
        // Options.
        if let Some(options) = find("options") {
            self.options(options.node, window.as_ref());
        }
        // Export: outcome variables only.
        if let Some(export) = find("export") {
            self.references(export.node, &scope, "export");
            self.export_values(export.node, &scope, &matched);
        }
        // Order and dedup read outcomes and placeholders.
        for name in ["order", "dedup"] {
            if let Some(s) = find(name) {
                self.references(s.node, &scope, name);
            }
        }
        // `in` statements.
        self.reference_lists(sections);
        // Unfiltered event variables.
        if profile == Profile::Rule
            && let Some(events) = events
        {
            self.unfiltered(events.node, &scope);
        }
    }

    /// Whether a search body reads an earlier stage (`$stage.field`, `cross join`).
    fn reads_stages(&self, sections: &[Section<'_>]) -> bool {
        let mut reads = false;
        for s in sections {
            opentide_syntax::walk_with_ancestors(s.node, |n, _| match n.kind() {
                "cross_join" => reads = true,
                "udm_field" => reads |= self.stage_field(n),
                _ => {}
            });
        }
        reads
    }

    /// Whether a body joins: `cross join`, two event variables, or events
    /// read with an earlier stage (multi-stage "Window size limits").
    fn joined(&self, sections: &[Section<'_>], scope: &Scope) -> bool {
        let mut cross = false;
        let mut events = false;
        for s in sections {
            opentide_syntax::walk_with_ancestors(s.node, |n, _| match n.kind() {
                "cross_join" => cross = true,
                "bare_field" => events = true,
                "udm_field" => events |= !self.stage_field(n),
                _ => {}
            });
        }
        cross || scope.events.len() >= 2 || (events && self.reads_stages(sections))
    }

    /// The `$names` a `match` groups by.
    fn match_names(&self, node: Node<'_>) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for clause in named_children(node)
            .into_iter()
            .filter(|n| n.kind() == "match_clause")
        {
            let mut cursor = clause.walk();
            for key in clause.children_by_field_name("key", &mut cursor) {
                // `$user`, or a search's field key (`principal.hostname`).
                out.insert(self.text(key).to_string());
            }
        }
        out
    }

    /// `yaral_window_bound`: `window_start` or `window_end` in `events` or
    /// `setup`, or in a body with no `match` window (windowing-logic,
    /// "Troubleshooting").
    fn window_bounds(&mut self, sections: &[Section<'_>], windowed: bool) {
        let mut found: Vec<(Node<'_>, bool)> = Vec::new();
        for s in sections {
            let predicates = matches!(s.name, "events" | "setup");
            opentide_syntax::walk_with_ancestors(s.node, |n, _| {
                if n.kind() == "window_bound" {
                    found.push((n, predicates));
                }
            });
        }
        for (n, predicates) in found {
            let name = self.text(n).to_ascii_lowercase();
            if predicates {
                self.error(
                    codes::YARAL_WINDOW_BOUND,
                    format!("`{name}` is the match window's bound: use it in outcome, condition or order, not in events"),
                    n,
                );
            } else if !windowed {
                self.error(
                    codes::YARAL_WINDOW_BOUND,
                    format!("`{name}` needs a `match` window (`over` or `by` a duration)"),
                    n,
                );
            }
        }
    }

    /// `yaral_export_value`: a `write_row` value that is not an outcome
    /// variable (data-tables: "You can only export outcome variables").
    fn export_values(&mut self, node: Node<'_>, scope: &Scope, matched: &BTreeSet<String>) {
        let mut values: Vec<Node<'_>> = Vec::new();
        opentide_syntax::walk_with_ancestors(node, |n, ancestors| {
            if n.kind() == "named_argument"
                && ancestors.iter().any(|a| a.kind() == "table_call")
                && let Some(value) = n.child_by_field_name("value")
            {
                values.push(value);
            }
        });
        for value in values {
            let value = unparen(value);
            // A search writes scalar values too (data-tables: "the support
            // offered in Search for writing scalar values to data tables",
            // `write_row(col_name: $e.metadata.product_name)`).
            // A `match` key is not exported ("You can't include a match
            // variable in the export section of a statistics query").
            if self.profile == Profile::Search
                && matches!(value.kind(), "udm_field" | "bare_field")
                && !self.stage_field(value)
                && !matched.contains(self.text(value))
            {
                continue;
            }
            if value.kind() == "variable" {
                let name = self.text(value);
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
                    self.text(value)
                ),
                value,
            );
        }
    }

    fn meta(&mut self, meta: Node<'_>) {
        let mut keys: BTreeSet<&str> = BTreeSet::new();
        for entry in named_children(meta) {
            let (Some(key), Some(value)) = (
                entry.child_by_field_name("key"),
                entry.child_by_field_name("value"),
            ) else {
                continue;
            };
            let name = self.text(key);
            if is_keyword(name) {
                self.error(
                    codes::YARAL_RESERVED_IDENTIFIER,
                    format!("`{name}` is a YARA-L keyword, not a meta key"),
                    key,
                );
            }
            if !keys.insert(name) {
                self.error(
                    codes::YARAL_META_DUPLICATE,
                    format!("meta key `{name}` appears twice"),
                    key,
                );
            }
            if value.kind() != "string" {
                self.error(
                    codes::YARAL_META_DUPLICATE,
                    format!("meta `{name}` takes a double-quoted string"),
                    value,
                );
            }
        }
    }

    /// Event variables (the root of a field path) and placeholders (a bare
    /// variable) of `events` and `setup`.
    fn collect_events(&self, node: Node<'_>, scope: &mut Scope) {
        opentide_syntax::walk_with_ancestors(node, |n, ancestors| match n.kind() {
            "udm_field" => {
                if let Some(var) = n.child_by_field_name("variable") {
                    let name = self.text(var).to_string();
                    if !self.stages.contains(&name) {
                        scope.events.entry(name).or_insert(span(var));
                    }
                }
            }
            "variable" => {
                let parent = ancestors.last().map(|p| p.kind());
                if parent != Some("udm_field") && parent != Some("match_window") {
                    let name = self.text(n).to_string();
                    if !self.stages.contains(&name) {
                        scope.placeholders.entry(name).or_insert(span(n));
                    }
                }
            }
            _ => {}
        });
        // A name used both ways is an event variable.
        scope
            .placeholders
            .retain(|k, _| !scope.events.contains_key(k));
        // Which event variables each placeholder is assigned from: the
        // statements that name both.
        for statement in named_children(node) {
            let mut events = BTreeSet::new();
            let mut placeholders = BTreeSet::new();
            opentide_syntax::walk_with_ancestors(statement, |n, ancestors| {
                if n.kind() != "variable" {
                    return;
                }
                let name = self.text(n).to_string();
                if ancestors.last().map(|p| p.kind()) == Some("udm_field") {
                    events.insert(name);
                } else if scope.placeholders.contains_key(&name) {
                    placeholders.insert(name);
                }
            });
            for p in placeholders {
                scope
                    .assigned
                    .entry(p)
                    .or_default()
                    .extend(events.iter().cloned());
            }
        }
    }

    fn match_section(&mut self, node: Node<'_>, scope: &Scope, joined: bool) -> Option<Window> {
        let clause = named_children(node)
            .into_iter()
            .find(|n| n.kind() == "match_clause")?;
        let mut cursor = clause.walk();
        let keys: Vec<Node<'_>> = clause.children_by_field_name("key", &mut cursor).collect();
        for key in keys {
            match key.kind() {
                "variable" => {
                    let name = self.text(key);
                    if !scope.placeholders.contains_key(name) {
                        let why = if scope.events.contains_key(name) {
                            "is an event variable"
                        } else {
                            "is not bound in `events`"
                        };
                        self.error(
                            codes::YARAL_MATCH_VARIABLE,
                            format!(
                                "`{name}` {why}: `match` groups by placeholders bound in `events`"
                            ),
                            key,
                        );
                    }
                }
                _ if self.profile == Profile::Rule => {
                    self.error(
                        codes::YARAL_MATCH_VARIABLE,
                        "a rule groups by placeholders: bind the field to a `$placeholder` in `events`"
                            .into(),
                        key,
                    );
                }
                _ => {}
            }
        }
        let window = clause.child_by_field_name("window");
        let Some(window) = window else {
            if self.profile == Profile::Rule {
                self.error(
                    codes::YARAL_MATCH_WINDOW,
                    "a rule's `match` needs a window: `over <duration>` or `by <duration>`".into(),
                    clause,
                );
            }
            return None;
        };
        let kind = window
            .child_by_field_name("kind")
            .map(|k| self.text(k).to_ascii_lowercase())
            .unwrap_or_default();
        let direction = window.child_by_field_name("direction");
        let sliding = direction.is_some();
        let mut extras = Vec::new();
        let mut cursor = window.walk();
        for child in window.children(&mut cursor) {
            if matches!(child.kind(), "every" | "first") {
                extras.push(child);
            }
        }
        if self.profile == Profile::Rule {
            for extra in &extras {
                self.error(
                    codes::YARAL_MATCH_WINDOW,
                    format!(
                        "`{}` is a search window: a rule's window is `over` or `by` a duration",
                        self.text(*extra)
                    ),
                    *extra,
                );
            }
        }
        if let Some(pivot) = window.child_by_field_name("pivot") {
            let name = self.text(pivot);
            if !scope.events.contains_key(name) {
                self.error(
                    codes::YARAL_UNDEFINED_VARIABLE,
                    format!("`{name}` is not an event variable of `events`: a sliding window pivots on one"),
                    pivot,
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
        // `by 2 week` puts the count and the unit under `length`: the unit
        // (or a duration) is what is measured.
        let length = named_children(window)
            .into_iter()
            .find(|n| matches!(n.kind(), "duration" | "time_unit"));
        let Some(length) = length else {
            return Some(Window { minutes });
        };
        let text = self.text(length);
        let measured = match length.kind() {
            "duration" => {
                let units: &[&str] = match self.profile {
                    Profile::Rule => &["m", "h", "d"],
                    Profile::Search => &["m", "h", "d", "w", "mo"],
                };
                duration(text).filter(|(_, unit)| units.contains(unit))
            }
            // `by day`, `over every 2 hour`: a search's unit words.
            _ => {
                let count: u64 = named_children(window)
                    .into_iter()
                    .find(|n| n.kind() == "integer")
                    .and_then(|n| self.text(n).parse().ok())
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
            }
        };
        match measured {
            Some((value, _)) => {
                minutes = Some(value);
                if value < 1 || value > max {
                    self.error(
                        codes::YARAL_MATCH_WINDOW,
                        format!("{text}: {what} is 1m to {}", format_minutes(max)),
                        length,
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
                    length,
                );
            }
        }
        Some(Window { minutes })
    }

    /// `matched`: the `match` names, when the body has a `match`.
    fn outcome(&mut self, node: Node<'_>, scope: &mut Scope, matched: Option<&BTreeSet<String>>) {
        let mut count = 0;
        for statement in named_children(node) {
            let assignment = statement.kind() == "comparison"
                && statement
                    .child_by_field_name("operator")
                    .is_some_and(|o| self.text(o) == "=");
            let left = statement.child_by_field_name("left");
            let (Some(left), true) = (left, assignment) else {
                self.references(statement, scope, "outcome");
                continue;
            };
            if left.kind() != "variable" {
                self.references(statement, scope, "outcome");
                continue;
            }
            let name = self.text(left).to_string();
            if let Some(right) = statement.child_by_field_name("right") {
                let mut read: BTreeSet<String> = BTreeSet::new();
                opentide_syntax::walk_with_ancestors(right, |n, ancestors| {
                    if n.kind() != "variable" {
                        return;
                    }
                    let v = self.text(n).to_string();
                    if ancestors.last().map(|p| p.kind()) == Some("udm_field") {
                        read.insert(v);
                    } else if let Some(events) = scope.assigned.get(&v) {
                        read.extend(events.iter().cloned());
                    } else if let Some(events) = scope.outcome_events.get(&v) {
                        read.extend(events.iter().cloned());
                    }
                });
                scope
                    .outcome_events
                    .entry(name.clone())
                    .or_default()
                    .extend(read);
                self.references(right, scope, "outcome");
                if let Some(matched) = matched {
                    self.aggregation(right, scope, matched, false);
                }
            }
            if !scope.outcomes.contains(&name) {
                count += 1;
                if count == MAX_OUTCOMES + 1 {
                    self.error(
                        codes::YARAL_OUTCOME_LIMIT,
                        format!("`{name}` is outcome variable {count}: a rule or search has at most {MAX_OUTCOMES}"),
                        left,
                    );
                }
            }
            scope.outcomes.insert(name);
        }
    }

    /// `yaral_outcome_aggregation` on an outcome's value, in a rule or search
    /// with `match`: event fields, and placeholders that are not `match`
    /// variables, are read through an aggregation (outcome-syntax,
    /// "Aggregations").
    fn aggregation(
        &mut self,
        node: Node<'_>,
        scope: &Scope,
        matched: &BTreeSet<String>,
        inside: bool,
    ) {
        match node.kind() {
            "function_call" => {
                let name = self.function_name(node);
                let aggregate = Functions::cached()
                    .get(&name)
                    .is_some_and(|f| f.aggregation || name.starts_with("window."));
                for child in named_children(node) {
                    if child.kind() == "arguments" {
                        for argument in named_children(child) {
                            self.aggregation(argument, scope, matched, inside || aggregate);
                        }
                    }
                }
            }
            "udm_field" | "bare_field" if !inside => {
                let root = node
                    .child_by_field_name("variable")
                    .map(|v| self.text(v).to_string());
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
                    node,
                );
            }
            "variable" if !inside => {
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
                        node,
                    );
                }
            }
            "variable" if inside => {
                let name = self.text(node);
                if scope.outcomes.contains(name) {
                    self.error(
                        codes::YARAL_OUTCOME_AGGREGATION,
                        format!("`{name}` is an outcome variable, already aggregated: do not aggregate it again"),
                        node,
                    );
                }
            }
            "named_argument" => {}
            _ => {
                for child in named_children(node) {
                    self.aggregation(child, scope, matched, inside);
                }
            }
        }
    }

    /// Variables a section reads that `events` and `outcome` do not define.
    fn references(&mut self, node: Node<'_>, scope: &Scope, section: &str) {
        let mut found: Vec<(Node<'_>, String)> = Vec::new();
        opentide_syntax::walk_with_ancestors(node, |n, ancestors| match n.kind() {
            "variable" | "count" => {
                let name = format!("${}", &self.text(n)[1..]);
                let parent = ancestors.last().map(|p| p.kind());
                if parent == Some("udm_field") && self.profile == Profile::Search {
                    return;
                }
                found.push((n, name));
            }
            _ => {}
        });
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
                        self.text(n)
                    ),
                    n,
                );
            }
        }
    }

    /// The `$name`s a condition mentions, as `$name` (counts included).
    fn condition_names(&self, node: Node<'_>) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        opentide_syntax::walk_with_ancestors(node, |n, ancestors| {
            if matches!(n.kind(), "variable" | "count")
                && ancestors.last().map(|p| p.kind()) != Some("udm_field")
            {
                out.insert(format!("${}", &self.text(n)[1..]));
            }
        });
        out
    }

    /// What a condition term says about an event variable or placeholder,
    /// and its name.
    fn term(&self, node: Node<'_>, scope: &Scope) -> Option<(String, Bound)> {
        let node = unparen(node);
        let known =
            |name: &str| scope.events.contains_key(name) || scope.placeholders.contains_key(name);
        match node.kind() {
            "variable" => {
                let name = self.text(node).to_string();
                known(&name).then_some((name, Bound::Bounded))
            }
            "unary_expression" => {
                let op = node.child_by_field_name("operator").map(|o| self.text(o));
                let operand = unparen(node.child_by_field_name("operand")?);
                if op == Some("!") && operand.kind() == "variable" {
                    let name = self.text(operand).to_string();
                    return known(&name).then_some((name, Bound::Unbounded));
                }
                None
            }
            "comparison" => {
                let left = unparen(node.child_by_field_name("left")?);
                let right = unparen(node.child_by_field_name("right")?);
                let op = self.text(node.child_by_field_name("operator")?);
                let (count, number, op) = match (left.kind(), right.kind()) {
                    ("count", "integer") => (left, right, op.to_string()),
                    ("integer", "count") => {
                        let flipped = match op {
                            "<" => ">",
                            "<=" => ">=",
                            ">" => "<",
                            ">=" => "<=",
                            other => other,
                        };
                        (right, left, flipped.to_string())
                    }
                    _ => return None,
                };
                let name = format!("${}", &self.text(count)[1..]);
                if !known(&name) {
                    return None;
                }
                let n: u64 = self.text(number).parse().unwrap_or(0);
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

    /// The operands of an `or` chain, through parentheses that hold an `or`.
    fn or_operands<'t>(&self, node: Node<'t>, out: &mut Vec<Node<'t>>) {
        let inner = unparen(node);
        if inner.kind() == "or_expression" {
            for side in ["left", "right"] {
                if let Some(s) = inner.child_by_field_name(side) {
                    self.or_operands(s, out);
                }
            }
        } else {
            out.push(node);
        }
    }

    fn condition(&mut self, node: Node<'_>, scope: &Scope, window: Option<&Window>) {
        let statements = named_children(node);
        self.references(node, scope, "condition");
        if self.profile == Profile::Rule && statements.len() > 1 {
            // Two juxtaposed terms: Google reads a comma or nothing between them as an error.
            self.error(
                codes::YARAL_CONDITION_SHAPE,
                "`condition` is one boolean expression: join its terms with `and` or `or`".into(),
                statements[1],
            );
        }
        let mut terms: Vec<(String, Bound)> = Vec::new();
        let mut not_terms: Vec<Node<'_>> = Vec::new();
        let mut or_groups: Vec<Node<'_>> = Vec::new();
        for statement in &statements {
            opentide_syntax::walk_with_ancestors(*statement, |n, ancestors| {
                // `$e` under `!` is the `!$e` term, not a term of its own.
                let negated = n.kind() == "variable"
                    && ancestors
                        .last()
                        .is_some_and(|p| p.kind() == "unary_expression");
                if !negated && let Some(t) = self.term(n, scope) {
                    terms.push(t);
                }
                if n.kind() == "not_expression"
                    && n.child_by_field_name("operand")
                        .is_some_and(|o| self.term(o, scope).is_some())
                {
                    not_terms.push(n);
                }
                if n.kind() == "or_expression"
                    && !ancestors
                        .iter()
                        .rev()
                        .take_while(|a| {
                            a.kind() == "parenthesized_expression" || a.kind() == "or_expression"
                        })
                        .any(|a| a.kind() == "or_expression")
                {
                    or_groups.push(n);
                }
            });
        }
        for n in not_terms {
            self.error(
                codes::YARAL_CONDITION_SHAPE,
                "negate an event or placeholder term with `!`, not `not` (`!$e`, `#e = 0`)".into(),
                n,
            );
        }
        let unbounded = terms.iter().any(|(_, b)| *b == Bound::Unbounded);
        let limit = match self.profile {
            Profile::Rule => 2,
            Profile::Search => 3,
        };
        for group in or_groups {
            let mut operands = Vec::new();
            self.or_operands(group, &mut operands);
            let mut events: BTreeSet<String> = BTreeSet::new();
            let mut event_terms = false;
            for operand in &operands {
                if let Some((name, _)) = self.term(*operand, scope) {
                    event_terms = true;
                    if scope.events.contains_key(&name) {
                        events.insert(name);
                    }
                }
            }
            let mixed = operands.iter().any(|o| {
                o.kind() == "and_expression" && {
                    let mut any = false;
                    opentide_syntax::walk_with_ancestors(*o, |n, _| {
                        any |= self.term(n, scope).is_some();
                    });
                    any
                }
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
                    group,
                );
            } else if unbounded {
                self.error(
                    codes::YARAL_CONDITION_SHAPE,
                    "`or` is refused in a condition with an unbounded term (`!$e`, `#e = 0`)"
                        .into(),
                    group,
                );
            } else if mixed {
                self.error(
                    codes::YARAL_CONDITION_SHAPE,
                    "an `or` among event and placeholder terms needs the group in parentheses: `($a or $b) and ...`".into(),
                    group,
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
                let at = statements.first().copied().unwrap_or(node);
                self.error(
                    codes::YARAL_CONDITION_SHAPE,
                    format!("a non-existence term (`!$e`, `#e = 0`, `#e < n`) needs {why}"),
                    at,
                );
            }
        }
    }

    fn options(&mut self, node: Node<'_>, window: Option<&Window>) {
        for entry in named_children(node) {
            let (Some(key), Some(value)) = (
                entry.child_by_field_name("key"),
                entry.child_by_field_name("value"),
            ) else {
                continue;
            };
            let name = self.text(key);
            let text = self.text(value);
            match name {
                "allow_zero_values" => {
                    if value.kind() != "boolean" {
                        self.error(
                            codes::YARAL_OPTION,
                            format!("allow_zero_values takes true or false, not `{text}`"),
                            value,
                        );
                    }
                }
                "suppression_window" => {
                    let parsed = (value.kind() == "duration")
                        .then(|| duration(text))
                        .flatten()
                        .filter(|(m, unit)| *m > 0 && matches!(*unit, "m" | "h" | "d"));
                    match parsed {
                        None => self.error(
                            codes::YARAL_OPTION,
                            format!("suppression_window takes a positive duration (`5m`, `1h`, `24h`), not `{text}`"),
                            value,
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
                                    value,
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
                    key,
                ),
            }
        }
    }

    fn reference_lists(&mut self, sections: &[Section<'_>]) {
        let (max_all, max_regex, max_cidr) = reference_limits(self.profile);
        let mut all = 0;
        let mut regex = 0;
        let mut cidr = 0;
        let mut over: Vec<(Node<'_>, String)> = Vec::new();
        for s in sections {
            opentide_syntax::walk_with_ancestors(s.node, |n, _| {
                if n.kind() != "in_expression" {
                    return;
                }
                all += 1;
                let kind = n
                    .child_by_field_name("kind")
                    .map(|k| self.text(k).to_ascii_lowercase());
                match kind.as_deref() {
                    Some("regex") => regex += 1,
                    Some("cidr") => cidr += 1,
                    _ => {}
                }
                if all == max_all + 1 {
                    over.push((n, format!("more than {max_all} `in` statements")));
                }
                if kind.as_deref() == Some("regex") && regex == max_regex + 1 {
                    over.push((n, format!("more than {max_regex} `in regex` statements")));
                }
                if kind.as_deref() == Some("cidr") && cidr == max_cidr + 1 {
                    over.push((n, format!("more than {max_cidr} `in cidr` statements")));
                }
            });
        }
        for (n, what) in over {
            self.error(
                codes::YARAL_REFERENCE_LIST_LIMIT,
                format!("{what}: Google's limit for a {}", self.profile.noun()),
                n,
            );
        }
    }

    /// `yaral_unfiltered_event`: an event variable with no equality on its
    /// event type, log type or product name.
    fn unfiltered(&mut self, events: Node<'_>, scope: &Scope) {
        let mut filtered: BTreeSet<String> = BTreeSet::new();
        let mut detection: BTreeSet<String> = BTreeSet::new();
        opentide_syntax::walk_with_ancestors(events, |n, _| {
            if n.kind() == "udm_field" {
                let segs = segments(n, self.source);
                if let (Some(var), Some(Segment::Name(first, _))) =
                    (n.child_by_field_name("variable"), segs.first())
                    && first == "detection"
                {
                    detection.insert(self.text(var).to_string());
                }
            }
            let (left, right, ok) = match n.kind() {
                "comparison" => (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                    n.child_by_field_name("operator")
                        .is_some_and(|o| self.text(o) == "="),
                ),
                "in_expression" => (n.child_by_field_name("left"), None, true),
                _ => return,
            };
            if !ok {
                return;
            }
            for side in [left, right].into_iter().flatten() {
                let side = unparen(side);
                if side.kind() != "udm_field" {
                    continue;
                }
                let Some(var) = side.child_by_field_name("variable") else {
                    continue;
                };
                let names: Vec<String> = segments(side, self.source)
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
                    filtered.insert(self.text(var).to_string());
                }
            }
        });
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

    pub(crate) fn function_name(&self, call: Node<'_>) -> String {
        call.child_by_field_name("function")
            .map(|f| self.text(f).split_whitespace().collect::<String>())
            .unwrap_or_default()
    }

    /// The checks that read one node at a time, over the whole text.
    fn walk_all(&mut self, root: Node<'_>) {
        // (node, section, inside a named argument's value or a meta/option entry)
        let mut nodes: Vec<(Node<'_>, Option<&'static str>, bool)> = Vec::new();
        opentide_syntax::walk_with_ancestors(root, |n, ancestors| {
            let section = ancestors.iter().rev().find_map(|a| section_name(a.kind()));
            let free = ancestors
                .iter()
                .any(|a| matches!(a.kind(), "named_argument" | "meta_entry" | "option_entry"));
            nodes.push((n, section, free));
        });
        for (n, section, free) in nodes {
            match n.kind() {
                "function_call" => self.call(n),
                "table_call" => self.table_call(n, section),
                "identifier" if !free => self.bare_name(n),
                "udm_field" | "bare_field" => self.field(n),
                "comparison" => self.comparison(n),
                "quantified_field" => self.quantified(n),
                "string" => self.escapes(n),
                "regex" => {
                    let text = self.text(n);
                    let pattern = &text[1..text.len().saturating_sub(1)];
                    self.pattern(pattern, n);
                }
                "variable" => {
                    let text = self.text(n);
                    let bare = &text[1..];
                    if matches!(
                        bare.to_ascii_lowercase().as_str(),
                        "window_start" | "window_end"
                    ) {
                        self.error(
                            codes::YARAL_RESERVED_IDENTIFIER,
                            format!("`{text}` is reserved: window_start and window_end are the match window's bounds"),
                            n,
                        );
                    } else if is_keyword(bare) {
                        self.error(
                            codes::YARAL_RESERVED_IDENTIFIER,
                            format!("`{bare}` is a YARA-L keyword, not a variable name"),
                            n,
                        );
                    }
                }
                "in_expression" => {
                    if let Some(right) = n.child_by_field_name("right")
                        && right.kind() == "reference_list"
                    {
                        self.warning(
                            codes::YARAL_REFERENCE_LIST_DEPRECATED,
                            format!(
                                "`{}` is a reference list: Google deprecates reference lists from May 2027; use a data table (`%table.column`)",
                                self.text(right)
                            ),
                            right,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    /// A bare name as a term: a search's grouped field or `raw`
    /// (search-syntax-reference); a metric field only inside a `metrics.*`
    /// argument, which `walk_all` leaves alone.
    fn bare_name(&mut self, node: Node<'_>) {
        let name = self.text(node);
        if self.profile == Profile::Search && (GROUPED_FIELDS.contains(&name) || name == "raw") {
            return;
        }
        let message = match self.profile {
            Profile::Search => format!(
                "`{name}` is not a UDM field: a search names a full path (`principal.hostname`), a grouped field ({}) or `raw`",
                GROUPED_FIELDS.join(", ")
            ),
            Profile::Rule => format!(
                "`{name}` is not a field: a rule reads fields through an event variable (`$e.principal.hostname`); grouped fields and `raw` are search only"
            ),
        };
        self.error(codes::YARAL_UNKNOWN_UDM_FIELD, message, node);
    }

    fn call(&mut self, call: Node<'_>) {
        let name = self.function_name(call);
        let at = call.child_by_field_name("function").unwrap_or(call);
        let arguments: Vec<Node<'_>> = named_children(call)
            .into_iter()
            .find(|c| c.kind() == "arguments")
            .map(named_children)
            .unwrap_or_default();
        let functions = Functions::cached();
        let Some(function) = functions.get(&name) else {
            let namespace = name.split_once('.').map(|(ns, _)| ns);
            let message = match namespace {
                Some(ns) if functions.is_namespace(ns) => {
                    let short = name.rsplit('.').next().unwrap_or(&name);
                    let suggestion =
                        closest(short, functions.in_namespace(ns).map(|f| f.short_name()));
                    match suggestion {
                        Some(s) => format!(
                            "`{name}` is not a function of `{ns}`; did you mean `{ns}.{s}`?"
                        ),
                        None => format!("`{name}` is not a function of `{ns}`"),
                    }
                }
                Some(ns) => format!("`{ns}` is not a YARA-L function namespace"),
                None => {
                    match closest(
                        &name,
                        functions
                            .all()
                            .filter(|f| f.namespace.is_none())
                            .map(|f| f.name.as_str()),
                    ) {
                        Some(s) => {
                            format!("`{name}` is not a YARA-L function; did you mean `{s}`?")
                        }
                        None => format!("`{name}` is not a YARA-L function"),
                    }
                }
            };
            self.error(codes::YARAL_UNKNOWN_FUNCTION, message, at);
            return;
        };
        let count = arguments.len();
        let too_few = count < function.min_args;
        let too_many = function.max_args.is_some_and(|max| count > max);
        if too_few || too_many {
            let expected = match function.max_args {
                Some(max) if max == function.min_args => format!("{max}"),
                Some(max) => format!("{} to {max}", function.min_args),
                None => format!("at least {}", function.min_args),
            };
            self.error(
                codes::YARAL_UNKNOWN_FUNCTION,
                format!(
                    "`{name}` takes {expected} argument{}, not {count}: {}",
                    if expected == "1" { "" } else { "s" },
                    function.signature
                ),
                at,
            );
        }
        if !function.available_in(self.profile) {
            let instead = match name.as_str() {
                "avg" | "stddev" => format!("; a rule writes `window.{name}`"),
                _ => String::new(),
            };
            self.error(
                codes::YARAL_FUNCTION_UNAVAILABLE,
                format!(
                    "`{name}` is not available in a {}{instead}",
                    self.profile.noun()
                ),
                at,
            );
        }
        // re.* patterns.
        if matches!(
            name.as_str(),
            "re.regex" | "re.capture" | "re.capture_all" | "re.replace"
        ) && let Some(pattern) = arguments.get(1)
            && matches!(pattern.kind(), "string" | "raw_string")
            && let Some(text) = literal_text(*pattern, self.source)
        {
            self.pattern(&text, *pattern);
        }
    }

    fn table_call(&mut self, call: Node<'_>, section: Option<&str>) {
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        let name = self.text(function);
        if name != "write_row" {
            self.error(
                codes::YARAL_UNKNOWN_FUNCTION,
                format!("`{name}` is not a data table function: `export` writes rows with `%table.write_row(column: $value, ...)`"),
                function,
            );
        } else if section != Some("export") {
            self.error(
                codes::YARAL_UNKNOWN_FUNCTION,
                "`write_row` writes a data table row in `export`, the last section".into(),
                function,
            );
        }
    }

    fn pattern(&mut self, pattern: &str, node: Node<'_>) {
        if let Some(problem) = regex_problem(pattern) {
            self.error(
                codes::YARAL_REGEX,
                format!("not a valid RE2 regular expression: {problem}"),
                node,
            );
        } else if leading_wildcard(pattern) {
            self.warning(
                codes::YARAL_LEADING_WILDCARD_REGEX,
                "the regex starts with `.*`: RE2 matches anywhere in the value already, and the prefix only costs time".into(),
                node,
            );
        }
    }

    pub(crate) fn string_escapes(&mut self, node: Node<'_>) {
        self.escapes(node);
    }

    fn escapes(&mut self, node: Node<'_>) {
        let text = self.text(node);
        let bytes = text.as_bytes();
        let mut i = 1;
        while i + 1 < bytes.len() {
            if bytes[i] == b'\\' {
                let next = text[i + 1..].chars().next().unwrap_or(' ');
                if !matches!(next, '\\' | '"' | 'n' | 'r' | 't') {
                    let start = node.start_byte() + i;
                    self.push(
                        codes::YARAL_STRING_ESCAPE,
                        Severity::Warning,
                        format!("`\\{next}` is not an escape: a double-quoted string takes \\\\, \\\", \\n, \\r and \\t; write `\\\\{next}`, or a back-quoted string for a regex"),
                        (start, start + 1 + next.len_utf8()),
                    );
                }
                i += 1 + text[i + 1..].chars().next().map_or(1, char::len_utf8);
                continue;
            }
            i += 1;
        }
    }

    /// Whether a field path's root is a stage of a multi-stage search.
    fn stage_field(&self, field: Node<'_>) -> bool {
        field
            .child_by_field_name("variable")
            .is_some_and(|v| self.stages.contains(self.text(v)))
    }

    fn field_segments(&self, field: Node<'_>) -> Vec<Segment> {
        let mut segs = Vec::new();
        if field.kind() == "bare_field"
            && let Some(root) = field.child_by_field_name("root")
        {
            segs.push(Segment::Name(
                self.text(root).to_string(),
                (root.start_byte(), root.end_byte()),
            ));
        }
        segs.extend(
            segments(field, self.source)
                .into_iter()
                .filter(|s| !matches!(s, Segment::Name(_, at) if field.kind() == "bare_field" && at.0 == field.start_byte())),
        );
        segs
    }

    fn field(&mut self, field: Node<'_>) {
        if self.stage_field(field) {
            return;
        }
        let segs = self.field_segments(field);
        let udm = Udm::cached();
        let resolution = udm.resolve(&segs);
        if self.profile == Profile::Search
            && resolution.unknown.is_some_and(|(index, _)| index == 0)
        {
            // `$zzz.u`: a stage reference the tenant checks (yara-l-1.0
            // 1.1, "Checked by the tenant only"); `labels["k"]`: a search's
            // top-level map.
            let top_map = field.kind() == "bare_field"
                && matches!(segs.as_slice(), [Segment::Name(n, _), Segment::Key(_), ..] if n == "labels");
            if field.kind() == "udm_field" || top_map {
                return;
            }
        }
        if let Some((index, message)) = resolution.unknown
            && let Some(Segment::Name(name, at)) = segs.get(index)
        {
            let candidates = udm
                .message(message)
                .map(|m| m.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            let path: Vec<&str> = segs[..index]
                .iter()
                .filter_map(|s| match s {
                    Segment::Name(n, _) => Some(n.as_str()),
                    _ => None,
                })
                .collect();
            let under = if path.is_empty() {
                "the UDM event".to_string()
            } else {
                format!("`{}` ({message})", path.join("."))
            };
            let mut message = format!("`{name}` is not a field of {under}");
            if let Some(s) = closest(name, candidates.into_iter()) {
                message.push_str(&format!("; did you mean `{s}`?"));
            }
            self.push(
                codes::YARAL_UNKNOWN_UDM_FIELD,
                Severity::Error,
                message,
                *at,
            );
        }
        for (index, f) in resolution.deprecated {
            if let Some(Segment::Name(name, at)) = segs.get(index) {
                let doc = f.doc.as_deref().unwrap_or("");
                self.push(
                    codes::YARAL_DEPRECATED_FIELD,
                    Severity::Warning,
                    format!("`{name}` is deprecated in the UDM. {doc}")
                        .trim_end()
                        .to_string(),
                    *at,
                );
            }
        }
    }

    /// The UDM type of an operand, when it is a field path the catalogue has.
    fn operand_kind(&self, node: Node<'_>) -> Option<(TypeKind<'static>, bool)> {
        let node = unparen(node);
        let field = match node.kind() {
            "udm_field" | "bare_field" => node,
            "quantified_field" => node.child_by_field_name("field")?,
            _ => return None,
        };
        if !matches!(field.kind(), "udm_field" | "bare_field") || self.stage_field(field) {
            return None;
        }
        let r = Udm::cached().resolve(&self.field_segments(field));
        if r.unknown.is_some() || r.free {
            return None;
        }
        Some((r.kind?, r.map_key))
    }

    fn comparison(&mut self, node: Node<'_>) {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        let nocase = node.child_by_field_name("nocase");
        let (left, right) = (unparen(left), unparen(right));
        // #e > "5": a count is a number.
        for (a, b) in [(left, right), (right, left)] {
            if a.kind() == "count" && matches!(b.kind(), "string" | "raw_string" | "regex") {
                self.error(
                    codes::YARAL_TYPE,
                    format!(
                        "`{}` counts events: compare it with a number, not `{}`",
                        self.text(a),
                        self.text(b)
                    ),
                    b,
                );
            }
        }
        for (field, other) in [(left, right), (right, left)] {
            let Some((kind, _)) = self.operand_kind(field) else {
                continue;
            };
            match kind {
                TypeKind::Enum(name, values) => {
                    if let Some(n) = nocase {
                        self.error(
                            codes::YARAL_NOCASE_ON_ENUM,
                            format!("`{}` is an enumerated field ({name}): its values are exact, so `nocase` does not apply", self.text(field)),
                            n,
                        );
                    }
                    if matches!(other.kind(), "string" | "raw_string")
                        && let Some(value) = literal_text(other, self.source)
                        && !values.is_empty()
                        && !values.contains(&value)
                    {
                        let mut message = format!("`{value}` is not a value of {name}");
                        if let Some(s) = closest(&value, values.iter().map(String::as_str)) {
                            message.push_str(&format!("; did you mean `{s}`?"));
                        } else if let Some(s) =
                            values.iter().find(|v| v.eq_ignore_ascii_case(&value))
                        {
                            message.push_str(&format!("; did you mean `{s}`?"));
                        }
                        self.error(codes::YARAL_ENUM_VALUE, message, other);
                    }
                }
                TypeKind::Scalar(scalar)
                    if nocase.is_some() && scalar != "string" && scalar != "bytes" =>
                {
                    self.error(
                        codes::YARAL_TYPE,
                        format!(
                            "`{}` is a {scalar}: `nocase` applies to strings and regexes",
                            self.text(field)
                        ),
                        nocase.unwrap_or(node),
                    );
                    // One finding per `nocase`.
                    return;
                }
                _ => {}
            }
        }
        if let Some(n) = nocase
            && matches!(right.kind(), "integer" | "float")
        {
            self.error(
                codes::YARAL_TYPE,
                "`nocase` applies to strings and regexes, not to a number".into(),
                n,
            );
        }
    }

    /// `any`/`all` on a map index: a Label (`ingestion_labels["k"]`) or a
    /// Struct (`additional.fields["k"]`, Google's own unsupported example in
    /// expressions, "Unsupported use of maps").
    fn quantified(&mut self, node: Node<'_>) {
        let Some(field) = node.child_by_field_name("field") else {
            return;
        };
        let keyed = matches!(field.kind(), "udm_field" | "bare_field")
            && segments(field, self.source)
                .iter()
                .any(|s| matches!(s, Segment::Key(_)));
        if keyed {
            let q = node
                .child_by_field_name("quantifier")
                .map(|q| self.text(q))
                .unwrap_or("any");
            self.error(
                codes::YARAL_TYPE,
                format!(
                    "`{q}` applies to a repeated field, not to a map key (`{}`)",
                    self.text(field)
                ),
                node,
            );
        }
    }
}

impl Profile {
    fn noun(self) -> &'static str {
        match self {
            Profile::Rule => "rule",
            Profile::Search => "search",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re2_patterns() {
        assert!(regex_problem(r"\\(winword|excel)\.exe$").is_none());
        assert!(regex_problem(r"a{").is_none());
        assert!(regex_problem(r"\{[0-9]+}").is_none());
        assert!(regex_problem(r"a/b\/c").is_none());
        assert!(regex_problem(r"(a").is_some());
        assert!(regex_problem(r"(?=a)").is_some());
        assert!(regex_problem(r"\1").is_some());
        assert!(regex_problem(r"\0").is_none());
        assert!(regex_problem(r"\012x").is_none());
    }

    #[test]
    fn leading_wildcards() {
        assert!(leading_wildcard(".*evil"));
        assert!(leading_wildcard("(?i).*evil"));
        assert!(!leading_wildcard("^.*evil"));
        assert!(!leading_wildcard("evil.*"));
    }

    #[test]
    fn durations() {
        assert_eq!(duration("30m"), Some((30, "m")));
        assert_eq!(duration("2d"), Some((2 * DAY, "d")));
        assert_eq!(duration("10x"), Some((0, "x")));
        assert_eq!(format_minutes(14 * DAY), "14d");
        assert_eq!(format_minutes(72 * 60), "72h");
    }
}
