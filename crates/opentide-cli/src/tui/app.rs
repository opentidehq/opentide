//! The UI's state, its keys and its drawing (`tui_app.py`'s `OpentideTui`).
//!
//! One command runs at a time, on a thread of its own, so the UI stays
//! responsive; when it finishes, the catalogue is read again. Quitting while
//! a command runs waits for it: a command cannot be stopped halfway, and it
//! would otherwise go on writing files after the UI had gone.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap};

use super::Launch;
use super::actions::{self, ACTIONS, Action, Outcome};
use super::detail;
use super::model::{self, Catalogue, Entry, Finding, Kind, Source};
use super::panes::{self, Chains};
use super::text::{BLUE, WHITE, empty_state, fit_label, masthead_brand, relative};

/// The tabs, in order: each is shown by its number key.
pub const TABS: [(&str, &str); 6] = [
    ("catalogue", "Catalogue"),
    ("coverage", "Coverage"),
    ("results", "Results"),
    ("visibility", "Visibility"),
    ("configuration", "Configuration"),
    ("chains", "Chains"),
];

/// The width of one level of the tree's guides.
const GUIDE: usize = 4;

/// What a row of the tree stands for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Node {
    /// An object, by UUID.
    Object(String),
    /// A group of objects or load errors.
    Group(&'static str),
    /// A file that did not load, by its place in the list.
    LoadError(usize),
    /// Nothing to select.
    Nothing,
}

/// One row of the tree.
#[derive(Debug, Clone)]
pub struct TreeRow {
    /// How many ancestors it has under the hidden root.
    pub depth: usize,
    /// For each level down to it: whether the node at that level is the last
    /// of its siblings (the guides).
    pub last: Vec<bool>,
    /// Its label, before fitting.
    pub label: Line<'static>,
    /// How many trailing characters of the label stay whole.
    pub tail: usize,
    /// What it stands for.
    pub node: Node,
}

/// What a worker sends back.
enum Done {
    /// The catalogue, read.
    Loaded(Result<Catalogue, String>),
    /// An action's outcome, and the catalogue read again after it.
    Ran(Box<Outcome>, Result<Catalogue, String>),
}

/// The command palette (`ctrl+p`).
#[derive(Debug, Clone, Default)]
pub struct Palette {
    /// What has been typed.
    pub query: String,
    /// The highlighted entry.
    pub cursor: usize,
}

/// A palette entry: its title, what it does, and what it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// An action.
    Run(Action),
    /// Read the catalogue again.
    Reload,
    /// Quit.
    Quit,
}

impl Command {
    /// The palette's title: an action's command line.
    pub fn title(&self) -> &'static str {
        match self {
            Self::Run(action) => action.command,
            Self::Reload => "Reload the catalogue",
            Self::Quit => "Quit",
        }
    }

    fn help(&self) -> &'static str {
        match self {
            Self::Run(action) => action.help,
            Self::Reload => "Read every object file again",
            Self::Quit => "Quit the application",
        }
    }
}

/// The palette's entries: the actions by their command line, then reload
/// and quit.
pub fn commands() -> Vec<Command> {
    ACTIONS
        .iter()
        .copied()
        .map(Command::Run)
        .chain([Command::Reload, Command::Quit])
        .collect()
}

/// The `opentide tui` application.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the UI's switches, one field each, as the Python app has them"
)]
pub struct App {
    launch: Launch,
    /// The snapshot shown.
    pub catalogue: Option<Catalogue>,
    /// The findings of the last validate run.
    pub findings: Vec<Finding>,
    /// False until a validate run finished: "no findings" means nothing then.
    pub validated: bool,
    /// What the detail pane shows.
    pub selected: Node,
    /// The tree's rows.
    pub rows: Vec<TreeRow>,
    /// The branches folded away (`Enter` on a branch).
    collapsed: std::collections::HashSet<Node>,
    tree_cursor: usize,
    tree_offset: usize,
    /// The tab shown, by its place in [`TABS`].
    pub tab: usize,
    /// The command running, if any: one at a time.
    pub running: Option<String>,
    worker: Option<Receiver<Done>>,
    /// Set by quit while a command runs: the UI quits when it finishes.
    pub quit_pending: bool,
    /// Set when the UI should close.
    pub quit: bool,
    /// What each action returned, in order.
    pub outcomes: Vec<Outcome>,
    /// The Results tab's text.
    pub results: Vec<Line<'static>>,
    results_scroll: usize,
    results_follow: bool,
    /// The status line.
    pub status: String,
    /// The finding of the selected object `n` and `p` moved to.
    pub current_finding: Option<usize>,
    /// Whether the detail pane shows the file rather than the page (`y`).
    pub raw: bool,
    link_index: usize,
    detail_scroll: usize,
    /// Whether the page's `Not set` list is open (`u`).
    pub unset_open: bool,
    coverage: TableState,
    /// The Visibility tab's filter.
    pub visibility_filter: String,
    /// Whether keys type into the filter (`/`).
    pub filtering: bool,
    visibility: TableState,
    /// The Chains tab.
    pub chains: Chains,
    /// The palette, when open.
    pub palette: Option<Palette>,
    /// Laid out by the last draw: the detail's row of the current finding.
    marked_row: Option<usize>,
    /// The height of the last detail pane, for paging.
    detail_height: usize,
    cwd: PathBuf,
}

impl App {
    /// The UI for `launch`, before the catalogue is read.
    pub fn new(launch: Launch) -> Self {
        let cwd = launch.cwd.clone();
        Self {
            launch,
            catalogue: None,
            findings: Vec::new(),
            validated: false,
            selected: Node::Nothing,
            rows: vec![TreeRow {
                depth: 0,
                last: vec![true],
                label: Line::raw("Loading the catalogue…"),
                tail: 0,
                node: Node::Nothing,
            }],
            collapsed: std::collections::HashSet::new(),
            tree_cursor: 0,
            tree_offset: 0,
            tab: 0,
            running: None,
            worker: None,
            quit_pending: false,
            quit: false,
            outcomes: Vec::new(),
            results: vec![Line::styled(
                "Results of validate, generate and deploy --dry-run appear here.",
                Style::new().add_modifier(Modifier::DIM),
            )],
            results_scroll: 0,
            results_follow: true,
            status: String::new(),
            current_finding: None,
            raw: false,
            link_index: 0,
            detail_scroll: 0,
            unset_open: false,
            coverage: TableState::default().with_selected(Some(0)),
            visibility_filter: String::new(),
            filtering: false,
            visibility: TableState::default().with_selected(Some(0)),
            chains: Chains::default(),
            palette: None,
            marked_row: None,
            detail_height: 10,
            cwd,
        }
    }

    // -- workers ------------------------------------------------------------

    /// Reads the catalogue, on a worker.
    pub fn start_load(&mut self) {
        let launch = self.launch.clone();
        self.start("the catalogue reload", move || Done::Loaded(load(&launch)));
    }

    /// Runs `action` on a worker, then reads the catalogue again.
    pub fn run_action(&mut self, action: Action) {
        let launch = self.launch.clone();
        self.start(action.command, move || {
            let outcome = actions::run(&launch, action);
            // generate rewrites what the catalogue reads, and any run may
            // follow an edit. A reload that fails must not lose the outcome.
            let catalogue = load(&launch);
            Done::Ran(Box::new(outcome), catalogue)
        });
    }

    fn start(&mut self, label: &str, work: impl FnOnce() -> Done + Send + 'static) {
        if self.quit_pending {
            return;
        }
        if let Some(running) = &self.running {
            self.status = format!("Wait for {running} to finish");
            return;
        }
        self.running = Some(label.to_owned());
        self.status = format!("Running {label}…");
        let (send, receive) = channel();
        std::thread::spawn(move || {
            let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or_else(
                |payload| Done::Loaded(Err(crate::crash::panic_message(payload.as_ref()))),
            );
            let _ = send.send(done);
        });
        self.worker = Some(receive);
    }

    /// Handles a worker that finished, if one did.
    pub fn poll(&mut self) {
        let Some(worker) = &self.worker else {
            return;
        };
        match worker.try_recv() {
            Ok(done) => self.finish(done),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.finish(Done::Loaded(Err("the worker stopped".into())));
            }
        }
    }

    /// Waits for the running worker and handles what it sends (tests, and
    /// nothing else: the UI polls).
    pub fn settle(&mut self) {
        if let Some(worker) = self.worker.take() {
            let done = worker
                .recv()
                .unwrap_or_else(|_| Done::Loaded(Err("the worker stopped".into())));
            self.finish(done);
        }
    }

    fn finish(&mut self, done: Done) {
        self.worker = None;
        self.running = None;
        match done {
            Done::Loaded(Ok(catalogue)) => {
                self.status = catalogue
                    .language_server
                    .unavailable
                    .clone()
                    .unwrap_or_default();
                self.show_catalogue(catalogue);
            }
            Done::Loaded(Err(error)) => self.internal_error(&error),
            Done::Ran(outcome, catalogue) => {
                self.show_outcome(*outcome);
                match catalogue {
                    Ok(catalogue) => self.show_catalogue(catalogue),
                    Err(error) => {
                        self.internal_error(&format!(
                            "the catalogue could not be read again: {error}"
                        ));
                    }
                }
            }
        }
        if self.quit_pending {
            self.quit = true;
        }
    }

    fn internal_error(&mut self, message: &str) {
        self.results.push(Line::from(vec![
            Span::styled(
                "error[internal]:",
                Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" {message}")),
        ]));
        self.status = format!("error: {message}");
    }

    fn show_outcome(&mut self, outcome: Outcome) {
        if outcome.validates {
            self.findings.clone_from(&outcome.findings);
            self.validated = true;
        }
        self.results.push(Line::default());
        self.results.extend(outcome.text().lines);
        self.results_follow = true;
        self.status = format!("{}: {}", outcome.command, outcome.said);
        self.outcomes.push(outcome);
    }

    fn show_catalogue(&mut self, catalogue: Catalogue) {
        self.catalogue = Some(catalogue);
        self.fill_tree();
        if let Some(catalogue) = &self.catalogue {
            let selected = match &self.selected {
                Node::Object(uuid) => Some(uuid.as_str()),
                _ => None,
            };
            self.chains.show(catalogue, selected);
        }
    }

    // -- the catalogue tree --------------------------------------------------

    /// What the language server reports for `entry`, and what the last
    /// validate run found. A validate finding the language server reports
    /// too (the same code on the same line) is shown once, as validate's;
    /// the queries check's findings come from the same engine as the
    /// language server's, so they are left to it.
    pub fn findings_of(&self, entry: &Entry) -> (Vec<&Finding>, Vec<&Finding>) {
        let report = self
            .catalogue
            .as_ref()
            .map(|catalogue| &catalogue.language_server);
        let available = report.is_some_and(|report| report.unavailable.is_none());
        let validated: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|item| item.concerns(entry) && !(item.source == Source::Engine && available))
            .collect();
        let seen: Vec<(&str, Option<usize>)> = validated
            .iter()
            .map(|item| (item.code.as_str(), item.line))
            .collect();
        let live = report
            .map(|report| report.for_path(entry.path.as_deref()))
            .unwrap_or_default()
            .iter()
            .filter(|item| !seen.contains(&(item.code.as_str(), item.line)))
            .collect();
        (live, validated)
    }

    /// `  ✗ 2  ! 1` after an object with errors or warnings; notes are not
    /// counted.
    fn counts(&self, entry: &Entry) -> Vec<Span<'static>> {
        let (live, validated) = self.findings_of(entry);
        let found: Vec<&&Finding> = live
            .iter()
            .chain(&validated)
            .filter(|item| item.severity != "note")
            .collect();
        let errors = found.iter().filter(|item| item.severity == "error").count();
        let warnings = found.len() - errors;
        let mut spans = Vec::new();
        if errors > 0 {
            spans.push(Span::styled(
                format!("  ✗ {errors}"),
                detail::severity_style("error"),
            ));
        }
        if warnings > 0 {
            spans.push(Span::styled(
                format!("  ! {warnings}"),
                detail::severity_style("warning"),
            ));
        }
        spans
    }

    /// The expand mark of a branch: `▼ ` open, `▶ ` folded.
    fn mark(&self, node: &Node) -> Span<'static> {
        Span::raw(if self.collapsed.contains(node) {
            "▶ "
        } else {
            "▼ "
        })
    }

    fn entry_row(
        &self,
        entry: &Entry,
        facts: &str,
        depth: usize,
        last: Vec<bool>,
        branch: bool,
    ) -> TreeRow {
        let node = Node::Object(entry.uuid.clone());
        let mut tail: Vec<Span<'static>> = Vec::new();
        if !facts.is_empty() {
            tail.push(Span::styled(
                format!("  {facts}"),
                Style::new().add_modifier(Modifier::DIM),
            ));
        }
        tail.extend(self.counts(entry));
        let tail_len: usize = tail.iter().map(|span| span.content.chars().count()).sum();
        let mut spans = Vec::new();
        if branch {
            spans.push(self.mark(&node));
        }
        spans.push(Span::raw(entry.name.clone()));
        spans.extend(tail);
        TreeRow {
            depth,
            last,
            label: Line::from(spans),
            tail: tail_len,
            node,
        }
    }

    fn objective_rows(
        &self,
        catalogue: &Catalogue,
        objective: &Entry,
        depth: usize,
        last: &[bool],
        rows: &mut Vec<TreeRow>,
    ) {
        let rules = catalogue.children(&objective.uuid);
        let facts = crate::commands::counted(rules.len(), "rule");
        let row = self.entry_row(objective, &facts, depth, last.to_vec(), !rules.is_empty());
        let open = !self.collapsed.contains(&row.node);
        rows.push(row);
        if !open {
            return;
        }
        for (index, rule) in rules.iter().enumerate() {
            let mut below = last.to_vec();
            below.push(index + 1 == rules.len());
            rows.push(self.entry_row(rule, "", depth + 1, below, false));
        }
    }

    fn fill_tree(&mut self) {
        let Some(catalogue) = self.catalogue.clone() else {
            return;
        };
        let mut rows: Vec<TreeRow> = Vec::new();
        let threats = catalogue.of_kind(Kind::Threat);
        let orphans = catalogue.unlinked(Kind::Objective);
        let loose = catalogue.unlinked(Kind::Rule);
        let groups = usize::from(!orphans.is_empty())
            + usize::from(!loose.is_empty())
            + usize::from(!catalogue.load_errors.is_empty());
        let top = threats.len() + groups;
        let mut at = 0;
        let mut next_last = || {
            at += 1;
            at == top
        };
        for threat in &threats {
            let objectives = catalogue.children(&threat.uuid);
            let rules: std::collections::BTreeSet<&str> = objectives
                .iter()
                .flat_map(|objective| catalogue.children(&objective.uuid))
                .map(|rule| rule.uuid.as_str())
                .collect();
            let facts = format!(
                "{} · {}",
                crate::commands::counted(objectives.len(), "objective"),
                crate::commands::counted(rules.len(), "rule")
            );
            let last = vec![next_last()];
            let row = self.entry_row(threat, &facts, 0, last.clone(), !objectives.is_empty());
            let open = !self.collapsed.contains(&row.node);
            rows.push(row);
            if !open {
                continue;
            }
            for (index, objective) in objectives.iter().enumerate() {
                let mut below = last.clone();
                below.push(index + 1 == objectives.len());
                self.objective_rows(&catalogue, objective, 1, &below, &mut rows);
            }
        }
        let group = |label: String, style: Style, name: &'static str, last: bool| {
            let node = Node::Group(name);
            TreeRow {
                depth: 0,
                last: vec![last],
                label: Line::from(vec![self.mark(&node), Span::styled(label, style)]),
                tail: 0,
                node,
            }
        };
        let italic = Style::new().add_modifier(Modifier::ITALIC);
        if !orphans.is_empty() {
            let last = next_last();
            rows.push(group(
                format!("Objectives without a threat ({})", orphans.len()),
                italic,
                "objective",
                last,
            ));
            if !self.collapsed.contains(&Node::Group("objective")) {
                for (index, objective) in orphans.iter().enumerate() {
                    self.objective_rows(
                        &catalogue,
                        objective,
                        1,
                        &[last, index + 1 == orphans.len()],
                        &mut rows,
                    );
                }
            }
        }
        if !loose.is_empty() {
            let last = next_last();
            rows.push(group(
                format!("Rules without an objective ({})", loose.len()),
                italic,
                "rule",
                last,
            ));
            if !self.collapsed.contains(&Node::Group("rule")) {
                for (index, rule) in loose.iter().enumerate() {
                    rows.push(self.entry_row(
                        rule,
                        "",
                        1,
                        vec![last, index + 1 == loose.len()],
                        false,
                    ));
                }
            }
        }
        if !catalogue.load_errors.is_empty() {
            let last = next_last();
            let red = Style::new().fg(Color::Red).add_modifier(Modifier::BOLD);
            rows.push(group(
                format!(
                    "Files that failed to load ({})",
                    catalogue.load_errors.len()
                ),
                red,
                "load_error",
                last,
            ));
            let open = !self.collapsed.contains(&Node::Group("load_error"));
            for (number, error) in catalogue.load_errors.iter().enumerate().filter(|_| open) {
                let name = error.path.as_deref().and_then(Path::file_name).map_or_else(
                    || "unknown file".to_owned(),
                    |name| name.to_string_lossy().into_owned(),
                );
                rows.push(TreeRow {
                    depth: 1,
                    last: vec![last, number + 1 == catalogue.load_errors.len()],
                    label: Line::raw(name),
                    tail: 0,
                    node: Node::LoadError(number),
                });
            }
        }
        if catalogue.entries.is_empty() && catalogue.load_errors.is_empty() {
            rows.push(TreeRow {
                depth: 0,
                last: vec![true],
                label: Line::styled(
                    empty_state(&catalogue.repo, &self.cwd),
                    Style::new().add_modifier(Modifier::DIM),
                ),
                tail: 0,
                node: Node::Nothing,
            });
        }
        self.rows = rows;
        // Keep the cursor on the object it was on; on the first load, on the
        // first object.
        let found = self
            .rows
            .iter()
            .position(|row| row.node == self.selected && row.node != Node::Nothing);
        self.tree_cursor = found.unwrap_or(0);
        if found.is_none() {
            let first = self
                .rows
                .first()
                .map_or(Node::Nothing, |row| row.node.clone());
            self.select_node(first);
        }
    }

    fn select_node(&mut self, node: Node) {
        if node != self.selected {
            self.current_finding = None;
            self.link_index = 0;
            // `n` showed the file at a finding; another object opens on its page.
            self.raw = false;
            self.detail_scroll = 0;
        }
        self.selected = node;
    }

    /// `Enter` on a branch of the tree: folds it, or opens it again.
    fn toggle_branch(&mut self) {
        let Some(row) = self.rows.get(self.tree_cursor) else {
            return;
        };
        let branch = row
            .label
            .spans
            .first()
            .is_some_and(|span| span.content == "▼ " || span.content == "▶ ");
        if !branch {
            return;
        }
        let node = row.node.clone();
        if !self.collapsed.remove(&node) {
            self.collapsed.insert(node.clone());
        }
        self.select_node(node);
        self.fill_tree();
    }

    /// Shows `uuid` in the Catalogue tab, with the tree's cursor on it.
    pub fn select(&mut self, uuid: &str) {
        self.tab = 0;
        let node = Node::Object(uuid.to_owned());
        self.select_node(node.clone());
        if !self.rows.iter().any(|row| row.node == node) && !self.collapsed.is_empty() {
            // Folded away: open the tree to show it.
            self.collapsed.clear();
            self.fill_tree();
        }
        if let Some(at) = self.rows.iter().position(|row| row.node == node) {
            self.tree_cursor = at;
        }
    }

    fn move_tree(&mut self, step: isize) {
        if self.rows.is_empty() {
            return;
        }
        self.tree_cursor = self
            .tree_cursor
            .saturating_add_signed(step)
            .min(self.rows.len() - 1);
        let node = self.rows[self.tree_cursor].node.clone();
        self.select_node(node);
    }

    /// The selected object, when an object is selected.
    pub fn selected_entry(&self) -> Option<&Entry> {
        match (&self.selected, &self.catalogue) {
            (Node::Object(uuid), Some(catalogue)) => catalogue.entries.get(uuid),
            _ => None,
        }
    }

    // -- keys ----------------------------------------------------------------

    /// Handles one key.
    pub fn on_key(&mut self, key: KeyEvent) {
        if self.palette.is_some() {
            self.palette_key(key);
            return;
        }
        if self.filtering {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.visibility_filter.pop();
                    self.visibility.select(Some(0));
                }
                KeyCode::Char(ch) => {
                    self.visibility_filter.push(ch);
                    self.visibility.select(Some(0));
                }
                _ => {}
            }
            return;
        }
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('p') if control => self.palette = Some(Palette::default()),
            KeyCode::Char('c' | 'q') if control => self.action_quit(),
            KeyCode::Char('q') => self.action_quit(),
            KeyCode::Char('v') => self.run_named("validate"),
            KeyCode::Char('g') => self.run_named("generate"),
            KeyCode::Char('d') => self.run_named("deploy-preview"),
            KeyCode::Char('r') => self.start_load(),
            KeyCode::Char('y') => self.toggle_source(),
            KeyCode::Char('f') => self.follow_link(),
            KeyCode::Char('n') => self.move_finding(1),
            KeyCode::Char('p') => self.move_finding(-1),
            KeyCode::Char('u') if self.tab == 0 => self.unset_open = !self.unset_open,
            KeyCode::Char(digit @ '1'..='6') => self.show_tab(usize::from(digit as u8 - b'1')),
            _ => self.tab_key(key),
        }
    }

    fn run_named(&mut self, name: &str) {
        if let Some(action) = actions::action(name) {
            self.run_action(action);
        }
    }

    /// Shows tab `index`.
    pub fn show_tab(&mut self, index: usize) {
        if index == 5
            && let Some(catalogue) = &self.catalogue
        {
            // The chain is drawn around the threat selected in the Catalogue.
            let selected = match &self.selected {
                Node::Object(uuid) => Some(uuid.as_str()),
                _ => None,
            };
            self.chains.show(catalogue, selected);
        }
        self.tab = index.min(TABS.len() - 1);
    }

    /// Quits, but never with a command half done.
    pub fn action_quit(&mut self) {
        match &self.running {
            None => self.quit = true,
            Some(running) => {
                self.quit_pending = true;
                self.status =
                    format!("Waiting for {running} to finish… The UI closes when it is done.");
            }
        }
    }

    fn tab_key(&mut self, key: KeyEvent) {
        let page = isize::try_from(self.detail_height.max(2) - 1).unwrap_or(1);
        match (self.tab, key.code) {
            (0, KeyCode::Enter) => self.toggle_branch(),
            (0, KeyCode::Up) => self.move_tree(-1),
            (0, KeyCode::Down) => self.move_tree(1),
            (0, KeyCode::Home) => self.move_tree(isize::MIN / 2),
            (0, KeyCode::End) => self.move_tree(isize::MAX / 2),
            (0, KeyCode::PageDown) => {
                self.detail_scroll = self.detail_scroll.saturating_add_signed(page);
            }
            (0, KeyCode::PageUp) => {
                self.detail_scroll = self.detail_scroll.saturating_add_signed(-page);
            }
            (1, KeyCode::Up | KeyCode::Down) => {
                let rows = self
                    .catalogue
                    .as_ref()
                    .map_or(0, |catalogue| catalogue.coverage.len());
                step_table(
                    &mut self.coverage,
                    rows,
                    if key.code == KeyCode::Up { -1 } else { 1 },
                );
            }
            (1, KeyCode::Enter) => self.open_technique(),
            (2, KeyCode::Up) => self.scroll_results(-1),
            (2, KeyCode::Down) => self.scroll_results(1),
            (2, KeyCode::PageUp) => self.scroll_results(-page),
            (2, KeyCode::PageDown) => self.scroll_results(page),
            (2, KeyCode::Home) => self.scroll_results(isize::MIN / 2),
            (2, KeyCode::End) => self.results_follow = true,
            (3, KeyCode::Char('/')) => self.filtering = true,
            (3, KeyCode::Up | KeyCode::Down) => {
                let rows = self.catalogue.as_ref().map_or(0, |catalogue| {
                    panes::visibility_rows(&catalogue.visibility, &self.visibility_filter).len()
                });
                step_table(
                    &mut self.visibility,
                    rows,
                    if key.code == KeyCode::Up { -1 } else { 1 },
                );
            }
            (3, KeyCode::Enter) => self.open_log_source(),
            (5, _) => self.chains_key(key),
            _ => {}
        }
    }

    fn chains_key(&mut self, key: KeyEvent) {
        let Some(catalogue) = self.catalogue.clone() else {
            return;
        };
        match key.code {
            KeyCode::Char('+' | '=') => self.chains.change_hops(&catalogue, true),
            KeyCode::Char('-') => self.chains.change_hops(&catalogue, false),
            KeyCode::Char('l') => self.chains.cycle_stage(&catalogue),
            KeyCode::Char('c') => self.chains.centre(&catalogue),
            KeyCode::Up => self.chains.step(&catalogue, -1),
            KeyCode::Down => self.chains.step(&catalogue, 1),
            KeyCode::Enter => {
                if let Some(uuid) = self.chains.selected.clone()
                    && catalogue.entries.contains_key(&uuid)
                {
                    self.select(&uuid);
                }
            }
            _ => {}
        }
    }

    fn palette_key(&mut self, key: KeyEvent) {
        let Some(palette) = self.palette.as_mut() else {
            return;
        };
        let shown = palette_entries(&palette.query);
        match key.code {
            KeyCode::Esc => self.palette = None,
            KeyCode::Up => palette.cursor = palette.cursor.saturating_sub(1),
            KeyCode::Down => {
                palette.cursor = (palette.cursor + 1).min(shown.len().saturating_sub(1));
            }
            KeyCode::Backspace => {
                palette.query.pop();
                palette.cursor = 0;
            }
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                palette.query.push(ch);
                palette.cursor = 0;
            }
            KeyCode::Enter => {
                let chosen = shown.get(palette.cursor).copied();
                self.palette = None;
                match chosen {
                    Some(Command::Run(action)) => self.run_action(action),
                    Some(Command::Reload) => self.start_load(),
                    Some(Command::Quit) => self.action_quit(),
                    None => {}
                }
            }
            _ => {}
        }
    }

    /// Handles the mouse: the wheel scrolls the detail pane or the Results.
    pub fn on_mouse(&mut self, mouse: MouseEvent) {
        let step = match mouse.kind {
            MouseEventKind::ScrollDown => 3,
            MouseEventKind::ScrollUp => -3,
            _ => return,
        };
        match self.tab {
            0 => self.detail_scroll = self.detail_scroll.saturating_add_signed(step),
            2 => self.scroll_results(step),
            _ => {}
        }
    }

    fn scroll_results(&mut self, step: isize) {
        self.results_follow = false;
        self.results_scroll = self.results_scroll.saturating_add_signed(step);
    }

    fn open_technique(&mut self) {
        let Some(catalogue) = &self.catalogue else {
            return;
        };
        let rule = self
            .coverage
            .selected()
            .and_then(|at| catalogue.coverage.get(at))
            .and_then(|row| row.rules.first().cloned());
        if let Some(rule) = rule {
            self.select(&rule);
        }
    }

    fn open_log_source(&mut self) {
        let Some(catalogue) = &self.catalogue else {
            return;
        };
        let rows = panes::visibility_rows(&catalogue.visibility, &self.visibility_filter);
        let rule = self
            .visibility
            .selected()
            .and_then(|at| rows.get(at))
            .and_then(|row| row.rules().first().cloned());
        if let Some(rule) = rule {
            self.select(&rule);
        }
    }

    fn toggle_source(&mut self) {
        self.raw = !self.raw;
        self.current_finding = None;
        let said = if self.raw {
            "Showing the file"
        } else {
            "Showing the object's page"
        };
        said.clone_into(&mut self.status);
    }

    fn follow_link(&mut self) {
        let Some(catalogue) = &self.catalogue else {
            return;
        };
        let Node::Object(uuid) = &self.selected else {
            return;
        };
        let Some(view) = catalogue.object_view(uuid) else {
            return;
        };
        if view.links.is_empty() {
            self.status = "This object references nothing in the catalogue".into();
            return;
        }
        let target = view.links[self.link_index % view.links.len()].clone();
        self.link_index += 1;
        if !catalogue.entries.contains_key(&target.opens) {
            self.status = format!("{} is not in the catalogue", target.name);
            return;
        }
        let index = self.link_index;
        self.select(&target.opens);
        self.link_index = index;
        self.status = format!("Opened {} {}", target.kind, target.name);
    }

    /// The selected object's findings in the order its file shows them.
    fn placed_findings(&self) -> Vec<Finding> {
        let Some(entry) = self.selected_entry() else {
            return Vec::new();
        };
        let (live, validated) = self.findings_of(entry);
        let all: Vec<&Finding> = live.into_iter().chain(validated).collect();
        detail::placed(&all)
    }

    /// `n` and `p`: the selected object's next or previous finding, in its
    /// file. The status line carries its message and the hover for its span.
    pub fn move_finding(&mut self, step: isize) {
        let findings = self.placed_findings();
        if findings.is_empty() {
            self.status = "No findings on this object".into();
            return;
        }
        self.tab = 0;
        // A finding is read at its line, in the file.
        self.raw = true;
        let count = findings.len();
        let next = match self.current_finding {
            None if step > 0 => 0,
            None => count - 1,
            Some(at) => (at + count).saturating_add_signed(step) % count,
        };
        self.current_finding = Some(next);
        let finding = &findings[next];
        let mut said = format!(
            "{}/{count} {}[{}]: {}",
            next + 1,
            finding.severity,
            finding.code,
            finding.message
        );
        if let Some(hover) = self.hover(finding) {
            said = format!("{said} · {}", first_line(&hover));
        }
        self.status = said;
        // The next draw scrolls to the finding's annotation.
        self.marked_row = None;
        self.detail_scroll = usize::MAX;
    }

    /// What an editor's hover shows at the start of `finding`'s span.
    pub fn hover(&self, finding: &Finding) -> Option<String> {
        let catalogue = self.catalogue.as_ref()?;
        let path = finding.path.as_deref()?;
        let text = std::fs::read(path)
            .ok()
            .and_then(|bytes| crate::queries::decode(&bytes).ok())?;
        catalogue
            .language_server
            .hover(&text, finding.line?, finding.column.unwrap_or(1))
    }

    // -- drawing -------------------------------------------------------------

    /// Draws the whole UI.
    pub fn draw(&mut self, frame: &mut Frame<'_>) {
        let [masthead, tabs, body, status, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        self.draw_masthead(frame, masthead);
        let titles: Vec<Line<'static>> = TABS
            .iter()
            .enumerate()
            .map(|(index, (_, title))| Line::raw(format!("{} {title}", index + 1)))
            .collect();
        frame.render_widget(
            Tabs::new(titles)
                .select(self.tab)
                .highlight_style(Style::new().fg(WHITE).bg(BLUE).add_modifier(Modifier::BOLD)),
            tabs,
        );
        match self.tab {
            0 => self.draw_catalogue(frame, body),
            1 => self.draw_coverage(frame, body),
            2 => self.draw_results(frame, body),
            3 => self.draw_visibility(frame, body),
            4 => frame.render_widget(
                Paragraph::new(panes::configuration_refusal()).wrap(Wrap { trim: false }),
                pad(body),
            ),
            _ => self.draw_chains(frame, body),
        }
        frame.render_widget(
            Paragraph::new(Line::styled(
                self.status.clone(),
                Style::new().add_modifier(Modifier::DIM),
            )),
            pad(status),
        );
        frame.render_widget(Paragraph::new(self.footer()), footer);
        if let Some(palette) = &self.palette {
            draw_palette(frame, palette);
        }
    }

    fn footer(&self) -> Line<'static> {
        let mut keys = vec![
            ("v", "Validate"),
            ("g", "Generate"),
            ("d", "Deploy dry run"),
            ("r", "Reload"),
            ("y", "YAML / page"),
            ("f", "Follow reference"),
            ("n", "Next finding"),
            ("q", "Quit"),
            ("^p", "Palette"),
        ];
        match self.tab {
            3 => keys.insert(0, ("/", "Filter")),
            5 => keys
                .splice(0..0, [("+/-", "Hops"), ("l", "Relations"), ("c", "Centre")])
                .for_each(drop),
            _ => {}
        }
        let mut spans = Vec::new();
        for (key, what) in keys {
            spans.push(Span::styled(
                format!(" {key} "),
                Style::new().fg(WHITE).bg(BLUE).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::raw(format!(" {what} ")));
        }
        Line::from(spans)
    }

    fn draw_masthead(&self, frame: &mut Frame<'_>, area: Rect) {
        let summary = self
            .catalogue
            .as_ref()
            .map_or_else(String::new, |catalogue| {
                let name = catalogue
                    .repo
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                format!("{name} · {}", catalogue.summary_line())
            });
        let inner = pad(area);
        let summary_width = summary.chars().count();
        let brand = masthead_brand(usize::from(inner.width), summary_width);
        let [left, right] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Length(u16::try_from(summary_width).unwrap_or(u16::MAX)),
        ])
        .areas(inner);
        frame.render_widget(Paragraph::new(brand), left);
        frame.render_widget(
            Paragraph::new(Line::styled(
                summary,
                Style::new().add_modifier(Modifier::DIM),
            )),
            right,
        );
    }

    /// The tree's lines as drawn at `width` cells: guides, then the label
    /// fitted, so nothing scrolls sideways.
    pub fn tree_lines(&self, width: usize) -> Vec<Line<'static>> {
        self.rows
            .iter()
            .map(|row| {
                let mut guides = String::new();
                for level in 1..=row.depth {
                    let last = row.last.get(level).copied().unwrap_or(true);
                    if level == row.depth {
                        guides.push_str(if last { "└── " } else { "├── " });
                    } else {
                        guides.push_str(if last { "    " } else { "│   " });
                    }
                }
                let room = width.saturating_sub(row.depth * GUIDE);
                let label = fit_label(&row.label, room, row.tail);
                let mut spans = vec![Span::styled(guides, Style::new().fg(Color::DarkGray))];
                spans.extend(label.spans);
                Line::from(spans)
            })
            .collect()
    }

    fn draw_catalogue(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let tree_width = (area.width * 2 / 5).max(30).min(area.width);
        let [tree, detail] =
            Layout::horizontal([Constraint::Length(tree_width), Constraint::Fill(1)]).areas(area);
        let block = Block::new()
            .borders(Borders::RIGHT)
            .border_style(Style::new().fg(Color::DarkGray));
        let inner = block.inner(tree);
        frame.render_widget(block, tree);
        let height = usize::from(inner.height).max(1);
        if self.tree_cursor < self.tree_offset {
            self.tree_offset = self.tree_cursor;
        } else if self.tree_cursor >= self.tree_offset + height {
            self.tree_offset = self.tree_cursor + 1 - height;
        }
        let lines: Vec<Line<'static>> = self
            .tree_lines(usize::from(inner.width))
            .into_iter()
            .enumerate()
            .map(|(index, line)| {
                if index == self.tree_cursor {
                    line.patch_style(Style::new().fg(WHITE).bg(BLUE))
                } else {
                    line
                }
            })
            .skip(self.tree_offset)
            .take(height)
            .collect();
        frame.render_widget(Paragraph::new(lines), inner);
        let inner = pad(detail);
        let (lines, marked) = self.detail_lines(usize::from(inner.width));
        self.detail_height = usize::from(inner.height);
        let most = lines.len().saturating_sub(1);
        if self.detail_scroll == usize::MAX {
            self.detail_scroll = marked.map_or(0, |row| row.saturating_sub(3));
        }
        self.marked_row = marked;
        self.detail_scroll = self.detail_scroll.min(most);
        frame.render_widget(
            Paragraph::new(lines)
                .scroll((u16::try_from(self.detail_scroll).unwrap_or(u16::MAX), 0)),
            inner,
        );
    }

    /// The detail pane's lines at `width` cells, and the row of the current
    /// finding's annotation.
    pub fn detail_lines(&self, width: usize) -> (Vec<Line<'static>>, Option<usize>) {
        let Some(catalogue) = &self.catalogue else {
            return (Vec::new(), None);
        };
        let dim = Style::new().add_modifier(Modifier::DIM);
        let bold = Style::new().add_modifier(Modifier::BOLD);
        let mut lines: Vec<Line<'static>> = Vec::new();
        match &self.selected {
            Node::LoadError(number) => {
                let Some(error) = catalogue.load_errors.get(*number) else {
                    return (lines, None);
                };
                lines.push(Line::styled(
                    relative(error.path.as_deref(), &catalogue.repo),
                    bold,
                ));
                lines.push(Line::default());
                lines.extend(detail::fold_line(
                    &Line::from(vec![
                        Span::styled("error[yaml_parse]:", detail::severity_style("error")),
                        Span::raw(format!(" {}", error.message)),
                    ]),
                    width,
                ));
                lines.push(Line::default());
                lines.extend(detail::source_view(error.path.as_deref(), &[], None, width).lines);
                return (lines, None);
            }
            Node::Object(uuid) if catalogue.entries.contains_key(uuid) => {}
            _ => {
                let name = catalogue
                    .repo
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                lines.push(Line::styled(name, bold));
                lines.push(Line::styled(catalogue.summary_line(), dim));
                lines.push(Line::default());
                lines.push(Line::raw(
                    "Select an object to see its YAML and diagnostics.",
                ));
                return (lines, None);
            }
        }
        let Some(entry) = self.selected_entry() else {
            return (lines, None);
        };
        lines.extend(detail::fold_line(
            &Line::from(vec![
                Span::styled(entry.name.clone(), bold),
                Span::styled(format!("  {}", entry.kind.as_str()), dim),
            ]),
            width,
        ));
        lines.push(Line::styled(entry.uuid.clone(), dim));
        lines.push(Line::raw(relative(entry.path.as_deref(), &catalogue.repo)));
        lines.push(Line::default());
        let (live, validated) = self.findings_of(entry);
        lines.extend(self.diagnostics_view(&live, &validated, catalogue, width));
        lines.push(Line::default());
        let all: Vec<&Finding> = live.iter().chain(&validated).copied().collect();
        let view = if self.current_finding.is_some() {
            None
        } else {
            catalogue.object_view(&entry.uuid)
        };
        match view.filter(|_| !self.raw) {
            Some(view) => {
                let languages = query_languages(entry.path.as_deref());
                lines.extend(detail::object_page(&view, &all, &languages, width));
                lines.extend(detail::unset_fields(&view, self.unset_open, width));
                (lines, None)
            }
            None => {
                let start = lines.len();
                let source =
                    detail::source_view(entry.path.as_deref(), &all, self.current_finding, width);
                lines.extend(source.lines);
                (lines, source.marked_row.map(|row| start + row))
            }
        }
    }

    fn diagnostics_view(
        &self,
        live: &[&Finding],
        validated: &[&Finding],
        catalogue: &Catalogue,
        width: usize,
    ) -> Vec<Line<'static>> {
        let heading = Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
        let dim = Style::new().add_modifier(Modifier::DIM);
        let tick = |text: &str| {
            Line::from(vec![
                Span::styled(
                    "✓",
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(" {text}")),
            ])
        };
        let mut lines = vec![Line::styled("Language server", heading)];
        let report = &catalogue.language_server;
        if let Some(unavailable) = &report.unavailable {
            lines.push(Line::styled(unavailable.clone(), dim));
            if let Some(advice) = &report.advice {
                lines.push(Line::from(vec![
                    Span::styled("  ╰─", Style::new().fg(Color::Blue)),
                    Span::styled(
                        " help:",
                        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(" {advice}")),
                ]));
            }
        } else if live.is_empty() {
            lines.push(tick("Nothing to report"));
        } else {
            lines.extend(detail::findings_summary(live, &catalogue.repo, &self.cwd));
        }
        lines.push(Line::default());
        lines.push(Line::styled("Last validate run", heading));
        if !self.validated {
            lines.push(Line::styled(
                "Not validated yet: press v to run opentide validate.",
                dim,
            ));
        } else if validated.is_empty() {
            lines.push(tick("No diagnostics from the last validate run"));
        } else {
            lines.extend(detail::findings_summary(
                validated,
                &catalogue.repo,
                &self.cwd,
            ));
        }
        lines
            .iter()
            .flat_map(|line| detail::fold_line(line, width))
            .collect()
    }

    fn draw_coverage(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let Some(catalogue) = &self.catalogue else {
            return;
        };
        let rows: Vec<Row<'static>> = catalogue
            .coverage
            .iter()
            .map(|row| {
                Row::new(panes::coverage_cells(catalogue, row).map(ratatui::widgets::Cell::from))
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(11),
                Constraint::Length(26),
                Constraint::Fill(2),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(["Technique", "Rules", "Detected by", "Named by"])
                .style(Style::new().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::new().fg(WHITE).bg(BLUE));
        frame.render_stateful_widget(table, area, &mut self.coverage);
    }

    fn draw_results(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let inner = pad(area);
        // Folded here, not by the paragraph: the scroll needs the row count.
        let lines: Vec<Line<'static>> = self
            .results
            .iter()
            .flat_map(|line| detail::fold_line(line, usize::from(inner.width)))
            .collect();
        let most = lines.len().saturating_sub(usize::from(inner.height));
        let paragraph = Paragraph::new(Text::from(lines));
        if self.results_follow {
            self.results_scroll = most;
        }
        self.results_scroll = self.results_scroll.min(most);
        frame.render_widget(
            paragraph.scroll((u16::try_from(self.results_scroll).unwrap_or(u16::MAX), 0)),
            inner,
        );
    }

    fn draw_visibility(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let Some(catalogue) = &self.catalogue else {
            return;
        };
        let report = &catalogue.visibility;
        let tiles = panes::visibility_tiles(report);
        let [top, filter, table, detail] = Layout::vertical([
            Constraint::Length(u16::try_from(tiles.len() + 1).unwrap_or(4)),
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ])
        .areas(area);
        frame.render_widget(Paragraph::new(tiles).wrap(Wrap { trim: false }), pad(top));
        let filter_line = if self.visibility_filter.is_empty() && !self.filtering {
            Line::styled(
                "/ Filter: a name, or system:sentinel",
                Style::new().add_modifier(Modifier::DIM),
            )
        } else {
            Line::from(vec![
                Span::styled("Filter: ", Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(self.visibility_filter.clone()),
                Span::styled(
                    if self.filtering { "▏" } else { "" },
                    Style::new().fg(WHITE),
                ),
            ])
        };
        frame.render_widget(Paragraph::new(filter_line), pad(filter));
        let rows = panes::visibility_rows(report, &self.visibility_filter);
        let shown: Vec<Row<'static>> = rows
            .iter()
            .map(|row| Row::new(panes::visibility_cells(*row).map(ratatui::widgets::Cell::from)))
            .collect();
        let widget = Table::new(
            shown,
            [
                Constraint::Fill(2),
                Constraint::Length(22),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Length(19),
                Constraint::Fill(3),
            ],
        )
        .header(
            Row::new([
                "Log source",
                "System",
                "Columns",
                "Rules",
                "Attention",
                "Description",
            ])
            .style(Style::new().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::new().fg(WHITE).bg(BLUE));
        if self
            .visibility
            .selected()
            .is_some_and(|at| at >= rows.len())
        {
            self.visibility.select(Some(rows.len().saturating_sub(1)));
        }
        let highlighted = self
            .visibility
            .selected()
            .and_then(|at| rows.get(at))
            .copied();
        let lines = panes::visibility_detail(highlighted, catalogue, report);
        frame.render_stateful_widget(widget, table, &mut self.visibility);
        let block = Block::new()
            .borders(Borders::TOP)
            .border_style(Style::new().fg(Color::DarkGray));
        let inner = pad(block.inner(detail));
        frame.render_widget(block, detail);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    fn draw_chains(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let Some(catalogue) = &self.catalogue else {
            return;
        };
        let [list, right] =
            Layout::horizontal([Constraint::Length(40.min(area.width)), Constraint::Fill(1)])
                .areas(area);
        let Some(view) = self.chains.view(catalogue) else {
            frame.render_widget(
                Paragraph::new(Line::styled(
                    "No threat in this catalogue.",
                    Style::new().add_modifier(Modifier::DIM),
                )),
                pad(right),
            );
            return;
        };
        let rows: Vec<Row<'static>> = panes::ordered(&view)
            .into_iter()
            .map(|node| {
                Row::new([
                    Line::styled(
                        node.name.clone(),
                        if node.uuid == view.focus {
                            Style::new().add_modifier(Modifier::BOLD)
                        } else {
                            Style::new()
                        },
                    ),
                    Line::raw(node.distance.to_string()),
                    Line::styled(
                        node.rules.to_string(),
                        if node.rules == 0 {
                            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)
                        } else {
                            Style::new()
                        },
                    ),
                ])
            })
            .collect();
        let block = Block::new()
            .borders(Borders::RIGHT)
            .border_style(Style::new().fg(Color::DarkGray));
        let table = Table::new(
            rows,
            [
                Constraint::Fill(1),
                Constraint::Length(4),
                Constraint::Length(5),
            ],
        )
        .header(
            Row::new(["Threat", "Hops", "Rules"]).style(Style::new().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::new().fg(WHITE).bg(BLUE))
        .block(block);
        let mut state = TableState::default().with_selected(Some(self.chains.cursor));
        frame.render_stateful_widget(table, list, &mut state);
        let selected = self.chains.selected.as_deref();
        let mut lines = panes::chains_header(&view, &self.chains);
        lines.push(Line::default());
        lines.extend(panes::chains_flow(&view, selected));
        lines.extend(panes::chains_links(&view, selected));
        frame.render_widget(Paragraph::new(lines), pad(right));
    }
}

/// `area` with one cell of padding on each side.
fn pad(area: Rect) -> Rect {
    Rect {
        x: area.x.saturating_add(1),
        width: area.width.saturating_sub(2),
        ..area
    }
}

fn step_table(state: &mut TableState, rows: usize, step: isize) {
    if rows == 0 {
        return;
    }
    let at = state
        .selected()
        .unwrap_or(0)
        .saturating_add_signed(step)
        .min(rows - 1);
    state.select(Some(at));
}

/// The palette's entries whose title holds every word typed.
fn palette_entries(query: &str) -> Vec<Command> {
    let words: Vec<String> = query
        .to_lowercase()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    commands()
        .into_iter()
        .filter(|command| {
            let title = command.title().to_lowercase();
            words.iter().all(|word| title.contains(word))
        })
        .collect()
}

fn draw_palette(frame: &mut Frame<'_>, palette: &Palette) {
    let area = frame.area();
    let width = area.width.saturating_sub(8).min(90);
    let entries = palette_entries(&palette.query);
    let height = u16::try_from(entries.len() * 2 + 3)
        .unwrap_or(u16::MAX)
        .min(area.height);
    let popup = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + 2.min(area.height.saturating_sub(height)),
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::bordered()
        .title(" Commands ")
        .border_style(Style::new().fg(WHITE));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let mut lines = vec![Line::from(vec![
        Span::styled("> ", Style::new().add_modifier(Modifier::BOLD)),
        Span::raw(palette.query.clone()),
    ])];
    for (index, command) in entries.iter().enumerate() {
        let style = if index == palette.cursor {
            Style::new().fg(WHITE).bg(BLUE).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::BOLD)
        };
        lines.push(Line::styled(command.title(), style));
        lines.push(Line::styled(
            format!("  {}", command.help()),
            Style::new().add_modifier(Modifier::DIM),
        ));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Each query's field path in the object, to its language, as the engine
/// reads them.
fn query_languages(path: Option<&Path>) -> BTreeMap<String, String> {
    let Some(text) = path
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| crate::queries::decode(&bytes).ok())
    else {
        return BTreeMap::new();
    };
    let host = opentide_analysis::MemoryWorkspace { files: Vec::new() };
    opentide_analysis::analyze_queries(&host, &text)
        .into_iter()
        .map(|report| {
            (
                report.field_path.join("."),
                report.language.as_str().to_owned(),
            )
        })
        .collect()
}

/// The first line of hover Markdown with its emphasis marks dropped.
fn first_line(markdown: &str) -> String {
    markdown
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .replace("**", "")
        .replace('`', "")
        .trim()
        .to_owned()
}

/// The catalogue read for `launch`, or why it could not be; a panic is
/// reported as one.
fn load(launch: &Launch) -> Result<Catalogue, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| model::load(launch)))
        .unwrap_or_else(|payload| Err(crate::crash::panic_message(payload.as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new(Launch {
            repo: None,
            env: crate::env::Env::default(),
            cwd: std::env::temp_dir(),
            version: "0.0.0".into(),
        })
    }

    fn results(app: &App) -> String {
        app.results
            .iter()
            .map(super::super::text::plain)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_worker_that_panics_is_reported_as_an_internal_error() {
        let mut app = app();
        app.start("the catalogue reload", || panic!("index unreadable"));
        assert_eq!(app.running.as_deref(), Some("the catalogue reload"));
        app.settle();
        assert!(
            results(&app).contains("error[internal]: index unreadable"),
            "{}",
            results(&app)
        );
        assert_eq!(app.status, "error: index unreadable");
        assert!(app.running.is_none());
    }

    #[test]
    fn a_failed_reload_keeps_the_outcome() {
        let mut app = app();
        let outcome = Outcome {
            command: "opentide validate".into(),
            validates: true,
            exit_code: 0,
            output: "\x1b[1;32m✓\x1b[0m 3 objects valid · 0.1s\n".into(),
            findings: Vec::new(),
            said: "✓ 3 objects valid · 0.1s".into(),
        };
        app.start("opentide validate", move || {
            Done::Ran(Box::new(outcome), Err("index unreadable".into()))
        });
        app.settle();
        assert!(app.validated);
        let log = results(&app);
        assert!(log.contains("✓ 3 objects valid · "), "{log}");
        assert!(
            log.contains(
                "error[internal]: the catalogue could not be read again: index unreadable"
            ),
            "{log}"
        );
        assert_eq!(app.outcomes.len(), 1);
        assert!(app.running.is_none());
    }

    #[test]
    fn the_hover_s_first_line_drops_its_emphasis() {
        assert_eq!(
            first_line("\n**Tlp** `string` — required\n\nmore"),
            "Tlp string — required"
        );
    }

    #[test]
    fn keys_type_into_the_palette_and_the_filter_not_the_ui() {
        let mut app = app();
        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        for ch in "q".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert!(!app.quit);
        assert_eq!(
            app.palette.as_ref().map(|palette| palette.query.as_str()),
            Some("q")
        );
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.palette.is_none());
        app.show_tab(3);
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!app.quit);
        assert_eq!(app.visibility_filter, "q");
    }
}
