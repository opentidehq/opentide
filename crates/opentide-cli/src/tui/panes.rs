//! The tabs beside the catalogue (`tui_tabs/`): Coverage, Visibility,
//! Configuration and Chains, as lines and rows for ratatui.

use std::collections::BTreeMap;

use opentide_workspace::views::chains::{
    ChainEdge, ChainNode, Facts, Neighbourhood, STAGES, neighbourhood,
};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::model::{Catalogue, Kind, LogSource, TechniqueCoverage, Undeclared, Visibility};

fn dim() -> Style {
    Style::new().add_modifier(Modifier::DIM)
}

fn bold() -> Style {
    Style::new().add_modifier(Modifier::BOLD)
}

fn yellow() -> Style {
    Style::new().fg(Color::Yellow)
}

/// `13  2 own · 11 inherited`: how many rules cover a technique, and how;
/// `0` in red is a gap.
pub fn coverage_count(row: &TechniqueCoverage) -> Line<'static> {
    if row.rules.is_empty() {
        return Line::styled("0", bold().fg(Color::Red));
    }
    Line::from(vec![
        Span::raw(row.rules.len().to_string()),
        Span::styled(
            format!(
                "  {} own · {} inherited",
                row.own.len(),
                row.inherited.len()
            ),
            dim(),
        ),
    ])
}

/// The cells of a coverage row: technique, count, the rules that detect it,
/// the threats and objectives that name it.
pub fn coverage_cells(catalogue: &Catalogue, row: &TechniqueCoverage) -> [Line<'static>; 4] {
    let names = |uuids: &[String]| -> String {
        uuids
            .iter()
            .filter_map(|uuid| catalogue.entries.get(uuid))
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let rules = names(&row.rules);
    [
        Line::raw(row.technique.clone()),
        coverage_count(row),
        if rules.is_empty() {
            Line::styled("no rule", dim())
        } else {
            Line::raw(rules)
        },
        Line::raw(names(&row.referenced_by)),
    ]
}

// -- Visibility ---------------------------------------------------------------

/// The tiles: log sources per system, how many declare columns, and what
/// needs attention.
pub fn visibility_tiles(report: &Visibility) -> Vec<Line<'static>> {
    if let Some(problem) = &report.problem {
        return vec![Line::styled(problem.clone(), Style::new().fg(Color::Red))];
    }
    if !report.present {
        return vec![Line::styled(
            "This workspace has no .opentide/configurations/visibility.toml: no log source is declared.",
            dim(),
        )];
    }
    let mut first = Vec::new();
    let mut second = Vec::new();
    for (system, (logsources, with_columns, used)) in &report.systems {
        let head = format!("{logsources} {system}");
        let foot = format!("{with_columns} with columns · {used} used");
        let width = head.chars().count().max(foot.chars().count()) + 3;
        first.push(Span::styled(format!("{head:<width$}"), bold()));
        second.push(Span::styled(format!("{foot:<width$}"), dim()));
    }
    let no_columns = report
        .logsources
        .iter()
        .filter(|source| source.columns.is_empty())
        .count();
    let unused = report
        .logsources
        .iter()
        .filter(|source| !source.used())
        .count();
    let missing = report.undeclared.len();
    let flag = |count: usize, bad: Color| bold().fg(if count > 0 { bad } else { Color::Green });
    let attention = vec![
        Span::styled(no_columns.to_string(), flag(no_columns, Color::Yellow)),
        Span::raw(" without columns  "),
        Span::styled(unused.to_string(), flag(unused, Color::Yellow)),
        Span::raw(" unused  "),
        Span::styled(missing.to_string(), flag(missing, Color::Red)),
        Span::raw(" read but not declared"),
    ];
    let mut lines = Vec::new();
    if !first.is_empty() {
        lines.push(Line::from(first));
        lines.push(Line::from(second));
    }
    lines.push(Line::from(attention));
    lines
}

/// Whether a row answers the filter: `system:<id>` narrows by system, other
/// words by name or description.
pub fn matches(query: &str, system: &str, name: &str, description: &str) -> bool {
    query.to_lowercase().split_whitespace().all(|word| {
        if let Some(wanted) = word.strip_prefix("system:") {
            system.to_lowercase() == wanted
        } else {
            name.to_lowercase().contains(word) || description.to_lowercase().contains(word)
        }
    })
}

/// A row of the Visibility table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityRow<'a> {
    /// A declared log source.
    Declared(&'a LogSource),
    /// A dataset rules read that nothing declares.
    Undeclared(&'a Undeclared),
}

impl VisibilityRow<'_> {
    /// The rules that use it.
    pub fn rules(&self) -> &[String] {
        match self {
            Self::Declared(source) => &source.rules,
            Self::Undeclared(item) => &item.rules,
        }
    }
}

/// The rows the filter keeps: the log sources, then what is read and not
/// declared.
pub fn visibility_rows<'a>(report: &'a Visibility, query: &str) -> Vec<VisibilityRow<'a>> {
    report
        .logsources
        .iter()
        .filter(|source| matches(query, &source.system, &source.name, &source.description))
        .map(VisibilityRow::Declared)
        .chain(
            report
                .undeclared
                .iter()
                .filter(|item| matches(query, &item.system, &item.name, ""))
                .map(VisibilityRow::Undeclared),
        )
        .collect()
}

/// The cells of a Visibility row.
pub fn visibility_cells(row: VisibilityRow<'_>) -> [Line<'static>; 6] {
    match row {
        VisibilityRow::Declared(source) => {
            let mut flags = Vec::new();
            if source.columns.is_empty() {
                flags.push(Span::styled("no columns ", yellow()));
            }
            if !source.used() {
                flags.push(Span::styled("unused", yellow()));
            }
            let warn = |empty: bool| if empty { yellow() } else { Style::new() };
            [
                Line::styled(source.name.clone(), bold()),
                Line::raw(source.system.clone()),
                Line::styled(
                    source.columns.len().to_string(),
                    warn(source.columns.is_empty()),
                ),
                Line::styled(
                    source.rules.len().to_string(),
                    warn(source.rules.is_empty()),
                ),
                Line::from(flags),
                Line::raw(source.description.clone()),
            ]
        }
        VisibilityRow::Undeclared(item) => [
            Line::styled(item.name.clone(), bold().fg(Color::Red)),
            Line::raw(item.system.clone()),
            Line::styled("—", dim()),
            Line::raw(item.rules.len().to_string()),
            Line::styled("read, not declared", Style::new().fg(Color::Red)),
            Line::default(),
        ],
    }
}

/// The highlighted row drilled into.
pub fn visibility_detail(
    row: Option<VisibilityRow<'_>>,
    catalogue: &Catalogue,
    report: &Visibility,
) -> Vec<Line<'static>> {
    let names = |uuids: &[String]| -> Vec<Span<'static>> {
        if uuids.is_empty() {
            return vec![Span::styled("none", dim())];
        }
        let mut spans = Vec::new();
        for (index, uuid) in uuids.iter().enumerate() {
            if index > 0 {
                spans.push(Span::raw(", "));
            }
            match catalogue.entries.get(uuid) {
                Some(entry) => spans.push(Span::styled(entry.name.clone(), bold())),
                None => spans.push(Span::styled(uuid.clone(), dim())),
            }
        }
        spans
    };
    let labelled = |label: &str, uuids: &[String]| {
        let mut spans = vec![Span::styled(label.to_owned(), bold())];
        spans.extend(names(uuids));
        Line::from(spans)
    };
    match row {
        None => {
            if let Some(why) = &report.reads_unavailable {
                return vec![Line::styled(
                    format!("Datasets queries read are not known: {why}"),
                    dim(),
                )];
            }
            vec![Line::styled(
                "Highlight a log source to see its columns and the detections that use it.",
                dim(),
            )]
        }
        Some(VisibilityRow::Undeclared(item)) => {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(item.name.clone(), bold()),
                    Span::styled(format!("  {}", item.system), dim()),
                ]),
                Line::styled(
                    "Read by rules, declared by no log source",
                    bold().fg(Color::Red),
                ),
            ];
            if !item.system_declares {
                lines.push(Line::styled(
                    format!(
                        "{} declares no log source, so the query checks do not warn about it.",
                        item.system
                    ),
                    dim(),
                ));
            }
            lines.push(labelled("Rules: ", &item.rules));
            lines
        }
        Some(VisibilityRow::Declared(source)) => {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(source.name.clone(), bold()),
                    Span::styled(format!("  {}", source.system), dim()),
                ]),
                Line::styled(
                    if source.description.is_empty() {
                        "No description.".to_owned()
                    } else {
                        source.description.clone()
                    },
                    Style::new().add_modifier(Modifier::ITALIC),
                ),
            ];
            if !source.tenants.is_empty() {
                lines.push(Line::styled(
                    format!("Tenants: {}", source.tenants.join(", ")),
                    dim(),
                ));
            }
            lines.push(labelled("Read by queries: ", &source.read_by));
            lines.push(labelled("Rules through signals: ", &source.signal_rules));
            lines.push(labelled("Objectives: ", &source.objectives));
            if source.columns.is_empty() {
                lines.push(Line::styled(
                    "No columns declared: the column checks cannot run on this source.",
                    yellow(),
                ));
            } else {
                lines.push(Line::styled(
                    format!("Columns ({})", source.columns.len()),
                    bold(),
                ));
                let name_width = source
                    .columns
                    .iter()
                    .map(|(name, _, _)| name.chars().count())
                    .max()
                    .unwrap_or(0);
                let type_width = source
                    .columns
                    .iter()
                    .map(|(_, kind, _)| kind.chars().count())
                    .max()
                    .unwrap_or(0);
                for (name, kind, description) in &source.columns {
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {name:<name_width$}  "), bold()),
                        Span::styled(
                            format!("{kind:<type_width$}  "),
                            Style::new().fg(Color::Cyan),
                        ),
                        Span::raw(description.clone()),
                    ]));
                }
            }
            lines
        }
    }
}

// -- Configuration ------------------------------------------------------------

/// What the Configuration tab says: its service (`configuration_view.py`:
/// each setting's effective value, whether the workspace sets it, its
/// schema's description, the platform cards and the proven-redacted raw
/// files) has no Rust implementation yet.
pub fn configuration_refusal() -> Vec<Line<'static>> {
    vec![
        Line::styled(
            "The Configuration tab has no Rust implementation yet.",
            bold().fg(Color::Yellow),
        ),
        Line::default(),
        Line::raw(
            "deployment.toml, lint.toml, documentation.toml, sharing.toml and each platforms/*.toml, \
             read with their effective values, what sets them and the platform cards, are shown by \
             the Python UI: run opentide tui without OPENTIDE_ENGINE, or with OPENTIDE_ENGINE=python.",
        ),
        Line::default(),
        Line::styled(
            "opentide info platforms lists each platform's tenants; opentide doctor checks the credentials they name.",
            dim(),
        ),
    ]
}

// -- Chains -------------------------------------------------------------------

/// Each relation stage's style, for its links and their labels.
pub fn stage_style(stage: &str) -> Style {
    match stage {
        "sequence" => bold().fg(Color::White),
        "atomicity" => Style::new().fg(Color::Magenta),
        "support" => Style::new().fg(Color::Cyan),
        _ => Style::new(),
    }
}

/// The most hops the tab shows.
pub const MAX_HOPS: usize = 4;

/// The Chains tab's state: the threat it is drawn around and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chains {
    /// The threat the chain is drawn around.
    pub focus: Option<String>,
    /// The threat highlighted in the list.
    pub selected: Option<String>,
    /// How many hops it reaches.
    pub hops: usize,
    /// The relation stage shown, or all.
    pub stage: Option<&'static str>,
    /// The list's cursor.
    pub cursor: usize,
}

impl Default for Chains {
    fn default() -> Self {
        Self {
            focus: None,
            selected: None,
            hops: 1,
            stage: None,
            cursor: 0,
        }
    }
}

impl Chains {
    /// Draws the chain around `selected` when it is a threat, else around
    /// the last focus, else the first threat with links.
    pub fn show(&mut self, catalogue: &Catalogue, selected: Option<&str>) {
        let threats: Vec<String> = catalogue
            .of_kind(Kind::Threat)
            .iter()
            .map(|entry| entry.uuid.clone())
            .collect();
        if let Some(uuid) = selected.filter(|uuid| threats.iter().any(|threat| threat == uuid)) {
            self.focus = Some(uuid.to_owned());
        } else if !self
            .focus
            .as_ref()
            .is_some_and(|focus| threats.contains(focus))
        {
            let chained = |uuid: &String| {
                catalogue
                    .chains
                    .iter()
                    .any(|edge| &edge.source == uuid || &edge.target == uuid)
            };
            self.focus = threats
                .iter()
                .find(|uuid| chained(uuid))
                .or(threats.first())
                .cloned();
        }
        let view = self.view(catalogue);
        if !view.as_ref().is_some_and(|view| {
            self.selected
                .as_ref()
                .is_some_and(|selected| view.nodes.contains_key(selected))
        }) {
            self.selected = self.focus.clone();
        }
        self.cursor = view
            .as_ref()
            .and_then(|view| {
                ordered(view)
                    .iter()
                    .position(|node| Some(&node.uuid) == self.selected.as_ref())
            })
            .unwrap_or(0);
    }

    /// The neighbourhood shown.
    pub fn view(&self, catalogue: &Catalogue) -> Option<Neighbourhood> {
        let focus = self.focus.as_ref()?;
        let names = catalogue
            .of_kind(Kind::Threat)
            .iter()
            .map(|entry| (entry.uuid.clone(), entry.name.clone()))
            .collect();
        let rules = catalogue.threat_rules();
        let techniques = catalogue.threat_techniques();
        Some(neighbourhood(
            focus,
            &catalogue.chains,
            Facts {
                names: &names,
                rules: &rules,
                techniques: &techniques,
            },
            self.hops,
            self.stage,
        ))
    }

    /// `+` and `-`: one hop more or fewer, from 1 to [`MAX_HOPS`].
    pub fn change_hops(&mut self, catalogue: &Catalogue, more: bool) {
        self.hops = if more {
            (self.hops + 1).min(MAX_HOPS)
        } else {
            self.hops.saturating_sub(1).max(1)
        };
        self.show(catalogue, None);
    }

    /// `l`: all relations, then each stage in turn.
    pub fn cycle_stage(&mut self, catalogue: &Catalogue) {
        self.stage = match self.stage {
            None => Some(STAGES[0]),
            Some(stage) => STAGES
                .iter()
                .position(|known| *known == stage)
                .and_then(|at| STAGES.get(at + 1))
                .copied(),
        };
        self.show(catalogue, None);
    }

    /// `c`: centres the chain on the highlighted threat.
    pub fn centre(&mut self, catalogue: &Catalogue) {
        if let Some(selected) = self.selected.clone() {
            self.focus = Some(selected);
            self.show(catalogue, None);
        }
    }

    /// Moves the list's cursor by `step` rows.
    pub fn step(&mut self, catalogue: &Catalogue, step: isize) {
        let Some(view) = self.view(catalogue) else {
            return;
        };
        let nodes = ordered(&view);
        if nodes.is_empty() {
            return;
        }
        self.cursor = self.cursor.saturating_add_signed(step).min(nodes.len() - 1);
        self.selected = Some(nodes[self.cursor].uuid.clone());
    }
}

/// The list's rows: by hops, then by name.
pub fn ordered(view: &Neighbourhood) -> Vec<&ChainNode> {
    let mut nodes: Vec<&ChainNode> = view.nodes.values().collect();
    nodes.sort_by_key(|node| (node.distance, node.name.to_lowercase()));
    nodes
}

/// The header: the focus, the hops and relations shown, the links by stage.
pub fn chains_header(view: &Neighbourhood, chains: &Chains) -> Vec<Line<'static>> {
    let name = view
        .nodes
        .get(&view.focus)
        .map_or_else(|| view.focus.clone(), |node| node.name.clone());
    let plural = if chains.hops == 1 { "" } else { "s" };
    let mut lines = vec![Line::from(vec![
        Span::styled(name, bold()),
        Span::styled(format!("   {} hop{plural} (+/-)", chains.hops), dim()),
        Span::styled(
            format!("   relations: {} (l)", chains.stage.unwrap_or("all")),
            dim(),
        ),
    ])];
    let mut counts = STAGES
        .iter()
        .map(|stage| format!("{stage} {}", view.totals.get(*stage).copied().unwrap_or(0)))
        .collect::<Vec<_>>()
        .join("  ");
    if view.hidden > 0 {
        let plural = if view.hidden == 1 { "" } else { "s" };
        counts.push_str(&format!("   {} more threat{plural} beyond", view.hidden));
    }
    lines.push(Line::styled(counts, dim()));
    if view.edges.is_empty() {
        lines.push(Line::styled(
            "This threat chains to no other at this distance.",
            dim(),
        ));
    }
    lines
}

/// The width of a threat's box.
const BOX: usize = 30;

/// A threat as a box: its name, its rules (red when none: an undetected
/// step) and how many of its techniques some rule covers.
fn node_box(node: &ChainNode, focus: bool, selected: bool) -> Vec<Line<'static>> {
    let mut border = if focus {
        Style::new().fg(Color::White)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    if node.rules == 0 && !node.missing {
        border = Style::new().fg(Color::Red);
    }
    if selected {
        border = bold().fg(Color::Yellow);
    }
    let inner = BOX - 4;
    let title = super::text::fit_label(&Line::raw(node.name.clone()), inner - 1, 0);
    let title_width = title.width();
    let mut top = vec![Span::styled("╭─", border)];
    top.push(Span::styled(
        super::text::plain(&title),
        if focus { bold() } else { Style::new() },
    ));
    top.push(Span::styled(
        format!("{}╮", "─".repeat(BOX - 3 - title_width)),
        border,
    ));
    let body: Vec<Span<'static>> = if node.missing {
        vec![Span::styled(
            "not in the catalogue",
            dim().add_modifier(Modifier::ITALIC),
        )]
    } else {
        let plural = if node.rules == 1 { "" } else { "s" };
        vec![Span::styled(
            format!("{} rule{plural}", node.rules),
            if node.rules == 0 {
                bold().fg(Color::Red)
            } else {
                Style::new().fg(Color::Green)
            },
        )]
    };
    let (covered, total) = node.techniques;
    let second: Vec<Span<'static>> = if total > 0 && !node.missing {
        vec![Span::styled(
            format!("{covered}/{total} techniques"),
            Style::new().fg(if covered == total {
                Color::Green
            } else {
                Color::Yellow
            }),
        )]
    } else {
        Vec::new()
    };
    let row = |spans: Vec<Span<'static>>| {
        let used: usize = spans.iter().map(Span::width).sum();
        let mut out = vec![Span::styled("│ ", border)];
        out.extend(spans);
        out.push(Span::raw(" ".repeat(inner.saturating_sub(used))));
        out.push(Span::styled(" │", border));
        Line::from(out)
    };
    vec![
        Line::from(top),
        row(body),
        row(second),
        Line::styled(format!("╰{}╯", "─".repeat(BOX - 2)), border),
    ]
}

/// Columns of lines side by side, `between` drawn on the first line of
/// each box's middle row.
fn side_by_side(
    columns: &[Vec<Line<'static>>],
    arrow: Option<Span<'static>>,
) -> Vec<Line<'static>> {
    let height = columns.iter().map(Vec::len).max().unwrap_or(0);
    let arrow_width = arrow.as_ref().map_or(1, Span::width);
    (0..height)
        .map(|row| {
            let mut spans = Vec::new();
            for (index, column) in columns.iter().enumerate() {
                if index > 0 {
                    match &arrow {
                        Some(arrow) if row == 1 => spans.push(arrow.clone()),
                        _ => spans.push(Span::raw(" ".repeat(arrow_width))),
                    }
                }
                match column.get(row) {
                    Some(line) => spans.extend(line.spans.clone()),
                    None => spans.push(Span::raw(" ".repeat(BOX))),
                }
            }
            Line::from(spans)
        })
        .collect()
}

/// Sequence links as columns, left to right; every other threat beside.
pub fn chains_flow(view: &Neighbourhood, selected: Option<&str>) -> Vec<Line<'static>> {
    let boxed = |uuid: &str| {
        view.nodes
            .get(uuid)
            .map(|node| node_box(node, uuid == view.focus, Some(uuid) == selected))
    };
    let mut lines = Vec::new();
    if !view.layers.is_empty() {
        let columns: Vec<Vec<Line<'static>>> = view
            .layers
            .iter()
            .map(|layer| {
                layer
                    .iter()
                    .filter_map(|uuid| boxed(uuid))
                    .flatten()
                    .collect()
            })
            .collect();
        lines.extend(side_by_side(
            &columns,
            Some(Span::styled(" ──▶ ", stage_style("sequence"))),
        ));
    }
    let in_flow: Vec<&String> = view.layers.iter().flatten().collect();
    let others: Vec<Vec<Line<'static>>> = view
        .nodes
        .keys()
        .filter(|uuid| !in_flow.contains(uuid))
        .filter_map(|uuid| boxed(uuid))
        .collect();
    if !others.is_empty() {
        if !view.layers.is_empty() {
            lines.push(Line::styled("Linked, outside the sequence", dim()));
        }
        lines.extend(side_by_side(&others, None));
    }
    lines
}

fn edge_line(edge: &ChainEdge, names: &BTreeMap<String, String>) -> Line<'static> {
    let name = |uuid: &String| names.get(uuid).cloned().unwrap_or_else(|| uuid.clone());
    let arrow = if edge.directed { "─▶" } else { "◀─▶" };
    let mut spans = vec![
        Span::styled(name(&edge.source), bold()),
        Span::styled(
            format!("  ─{}{arrow}  ", edge.label),
            stage_style(&edge.stage),
        ),
        Span::styled(name(&edge.target), bold()),
    ];
    if edge.merged {
        spans.push(Span::styled("  (written from both ends)", dim()));
    }
    if edge.missing {
        spans.push(Span::styled(
            "  (names no threat)",
            Style::new().fg(Color::Red),
        ));
    }
    Line::from(spans)
}

/// Each link shown, by stage; the highlighted threat's with their
/// descriptions.
pub fn chains_links(view: &Neighbourhood, selected: Option<&str>) -> Vec<Line<'static>> {
    let names: BTreeMap<String, String> = view
        .nodes
        .iter()
        .map(|(uuid, node)| (uuid.clone(), node.name.clone()))
        .collect();
    let mut lines = Vec::new();
    for stage in STAGES {
        let edges: Vec<&ChainEdge> = view
            .edges
            .iter()
            .filter(|edge| edge.stage == stage)
            .collect();
        if edges.is_empty() {
            continue;
        }
        lines.push(Line::default());
        lines.push(Line::styled(
            format!("{stage} ({})", edges.len()),
            stage_style(stage).add_modifier(Modifier::UNDERLINED),
        ));
        for edge in edges {
            lines.push(edge_line(edge, &names));
            if selected.is_some_and(|uuid| uuid == edge.source || uuid == edge.target) {
                for description in &edge.descriptions {
                    lines.push(Line::styled(
                        format!("    {description}"),
                        dim().add_modifier(Modifier::ITALIC),
                    ));
                }
            }
        }
    }
    if lines.is_empty() {
        return vec![Line::styled("No chaining links at this distance.", dim())];
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_narrows_by_name_description_or_system() {
        assert!(matches("", "sentinel", "SecurityEvent", ""));
        assert!(matches("security", "sentinel", "SecurityEvent", ""));
        assert!(matches(
            "logon",
            "sentinel",
            "SecurityEvent",
            "Windows logon events"
        ));
        assert!(matches(
            "system:sentinel secur",
            "sentinel",
            "SecurityEvent",
            ""
        ));
        assert!(!matches("system:splunk", "sentinel", "SecurityEvent", ""));
        assert!(!matches("process", "sentinel", "SecurityEvent", ""));
    }

    #[test]
    fn a_gap_is_a_red_zero_and_coverage_says_how() {
        let mut row = TechniqueCoverage {
            technique: "T1059".into(),
            rules: Vec::new(),
            referenced_by: Vec::new(),
            own: Vec::new(),
            inherited: Vec::new(),
        };
        let gap = coverage_count(&row);
        assert_eq!(super::super::text::plain(&gap), "0");
        assert_eq!(gap.style.fg, Some(Color::Red));
        row.rules = vec!["a".into(), "b".into()];
        row.own = vec!["a".into()];
        row.inherited = vec!["b".into()];
        assert_eq!(
            super::super::text::plain(&coverage_count(&row)),
            "2  1 own · 1 inherited"
        );
    }
}
