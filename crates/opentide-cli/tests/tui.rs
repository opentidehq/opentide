//! `opentide tui` on ratatui (UC-3.6d, #951), drawn on ratatui's
//! `TestBackend` against the tutorial repository: what
//! `tests/test_cli/test_tui.py` asserts of the Python UI, key by key, and
//! the layout at a width: names cut with an ellipsis, counts kept whole,
//! nothing wider than its column.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here is written to a fresh folder"
)]

#[path = "common/tutorial.rs"]
mod tutorial;

use std::path::Path;

use opentide_cli::tui::Launch;
use opentide_cli::tui::app::{App, Node, commands};
use opentide_cli::tui::model::Kind;
use opentide_cli::tui::text::{BLUE, TAGLINE, plain};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use regex::Regex;
use tutorial::{OBJECTIVE, RULE, RULE_FILE, THREAT, break_tlp, edit, tutorial};

const LONG_RULE: &str = "LSASS memory read by an unsigned process from a user-writable directory";

fn launch(repo: &Path, cwd: &Path) -> Launch {
    Launch {
        repo: Some(repo.display().to_string()),
        env: opentide_cli::env::Env::from_pairs([("HOME", cwd.display().to_string())]),
        cwd: cwd.to_path_buf(),
        version: "0.23.0".into(),
    }
}

/// The UI on `repo`, its catalogue read.
fn open(repo: &Path) -> App {
    open_from(repo, repo)
}

fn open_from(repo: &Path, cwd: &Path) -> App {
    let mut app = App::new(launch(repo, cwd));
    app.start_load();
    app.settle();
    assert!(app.catalogue.is_some(), "{}", app.status);
    app
}

fn key(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn press(app: &mut App, keys: &str) {
    for ch in keys.chars() {
        key(app, KeyCode::Char(ch));
    }
}

/// The screen at `width` × `height`, row by row.
fn screen(app: &mut App, width: u16, height: u16) -> (Vec<String>, ratatui::buffer::Buffer) {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| app.draw(frame)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows = (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol().to_owned())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect();
    (rows, buffer)
}

/// The tree's rows as drawn at `width` cells.
fn tree(app: &App, width: usize) -> Vec<String> {
    app.tree_lines(width).iter().map(plain).collect()
}

fn detail(app: &App) -> String {
    app.detail_lines(200)
        .0
        .iter()
        .map(plain)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every file under `root`, with its bytes.
fn files(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut found = std::collections::BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.insert(path.clone(), std::fs::read(&path).unwrap());
            }
        }
    }
    found
}

fn results(app: &App) -> String {
    app.results.iter().map(plain).collect::<Vec<_>>().join("\n")
}

// -- the catalogue ----------------------------------------------------------

#[test]
fn the_catalogue_comes_from_the_workspace() {
    let (_base, repo) = tutorial();
    let app = open(&repo);
    let catalogue = app.catalogue.as_ref().unwrap();
    let uuids = |entries: Vec<&opentide_cli::tui::model::Entry>| -> Vec<String> {
        entries.iter().map(|entry| entry.uuid.clone()).collect()
    };
    assert_eq!(uuids(catalogue.of_kind(Kind::Threat)), [THREAT]);
    assert_eq!(uuids(catalogue.children(THREAT)), [OBJECTIVE]);
    assert_eq!(uuids(catalogue.children(OBJECTIVE)), [RULE]);
    let rule = &catalogue.entries[RULE];
    assert_eq!(rule.name, "Sentinel KQL Rule");
    assert!(
        rule.path
            .as_ref()
            .unwrap()
            .ends_with("sentinel-kql-rule.yaml")
    );
    assert!(catalogue.unlinked(Kind::Rule).is_empty());
    assert_eq!(catalogue.summary_line(), "1 threat · 1 objective · 1 rule");
    let [row] = catalogue.coverage.as_slice() else {
        panic!("{:?}", catalogue.coverage)
    };
    assert_eq!(
        (
            row.technique.as_str(),
            row.rules.clone(),
            row.referenced_by.clone()
        ),
        ("T1059", vec![RULE.to_owned()], vec![THREAT.to_owned()])
    );
}

#[test]
fn the_tree_nests_threats_objectives_and_rules_with_counts() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    assert_eq!(
        tree(&app, 80),
        [
            "▼ Simulated Actor  1 objective · 1 rule",
            "└── ▼ Credential Access Objective  1 rule",
            "    └── Sentinel KQL Rule",
        ]
    );
    let (rows, buffer) = screen(&mut app, 140, 40);
    assert!(
        rows[0].contains("1 threat · 1 objective · 1 rule"),
        "{}",
        rows[0]
    );
    assert!(rows[0].contains(TAGLINE), "{}", rows[0]);
    // The first object is shown before anything is selected, its row the
    // cursor's: white on Reflex Blue.
    assert_eq!(app.selected, Node::Object(THREAT.into()));
    let row = rows
        .iter()
        .position(|row| row.starts_with("▼ Simulated Actor"))
        .unwrap();
    let cell = &buffer[(0, u16::try_from(row).unwrap())];
    assert_eq!(cell.bg, BLUE);
    assert!(detail(&app).contains("Not validated yet"));
}

#[test]
fn select_a_rule_run_validate_and_see_its_diagnostic() {
    let (_base, repo) = tutorial();
    break_tlp(&repo);
    let mut app = open(&repo);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    assert_eq!(app.selected, Node::Object(RULE.into()));
    press(&mut app, "v");
    assert_eq!(app.running.as_deref(), Some("opentide validate"));
    app.settle();
    // The top block counts the finding; the file shows it at its line.
    let shown = detail(&app);
    assert!(
        shown.contains("Last validate run\n✗ 1  on line 8"),
        "{shown}"
    );
    // The status line says the counted outcome the command printed.
    assert!(
        app.status
            .starts_with("opentide validate: ✗ 1 error in 1 file · "),
        "{}",
        app.status
    );
    press(&mut app, "y");
    let source = detail(&app);
    let at = |text: &str| {
        source
            .find(text)
            .unwrap_or_else(|| panic!("{text} not in {source}"))
    };
    assert!(at("tlp: clearr") < at("error[vocab_unknown]:"));
    at("help: did you mean 'clear'?");
    assert_eq!(
        tree(&app, 80).last().unwrap(),
        "    └── Sentinel KQL Rule  ✗ 1"
    );
    // The cursor stays on the rule after the tree is rebuilt.
    assert_eq!(app.selected, Node::Object(RULE.into()));
    // As `opentide validate` prints it: the code frame, with the source line
    // underlined, and the counted outcome line.
    let log = results(&app);
    assert!(log.contains("$ opentide validate"), "{log}");
    assert!(
        log.contains("error[vocab_unknown]: 'clearr' is not a TLP value"),
        "{log}"
    );
    assert!(log.contains(&format!("╭─▶ {RULE_FILE}:8:8")), "{log}");
    assert!(log.contains("8 │   tlp: clearr"), "{log}");
    assert!(log.contains("━━━━━━ not in tlp::1.0"), "{log}");
    let counted = Regex::new(r"✗ 1 error in 1 file · 3 objects checked · 1 query · \d").unwrap();
    assert!(counted.is_match(&log), "{log}");
    assert!(!log.contains("error: Validation failed"), "{log}");
}

#[test]
fn a_clean_validate_reports_success() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    press(&mut app, "v");
    app.settle();
    let log = results(&app);
    assert!(
        Regex::new(r"✓ 3 objects valid · \d")
            .unwrap()
            .is_match(&log),
        "{log}"
    );
    assert!(app.validated);
    assert!(app.findings.is_empty());
    assert!(detail(&app).contains("✓ No diagnostics from the last validate run"));
}

#[test]
fn a_file_that_failed_to_load_has_its_own_node() {
    let (_base, repo) = tutorial();
    std::fs::write(repo.join("objects/rules/broken.yaml"), "name: [unclosed\n").unwrap();
    let mut app = open(&repo);
    let rows = tree(&app, 80);
    assert_eq!(
        rows[rows.len() - 2..],
        ["▼ Files that failed to load (1)", "└── broken.yaml"]
    );
    assert!(
        app.catalogue
            .as_ref()
            .unwrap()
            .summary_line()
            .ends_with("1 load error")
    );
    for _ in 0..4 {
        key(&mut app, KeyCode::Down);
    }
    assert_eq!(app.selected, Node::LoadError(0));
    let shown = detail(&app);
    assert!(shown.contains("error[yaml_parse]:"), "{shown}");
    assert!(shown.contains("objects/rules/broken.yaml"), "{shown}");
}

#[test]
fn unlinked_objects_are_grouped() {
    let (_base, repo) = tutorial();
    edit(
        &repo,
        RULE_FILE,
        OBJECTIVE,
        "00000000-0000-4000-8002-00000000ffff",
    );
    let mut app = open(&repo);
    let rows = tree(&app, 80);
    // The language server reports the dangling reference before any validate run.
    assert_eq!(
        rows[rows.len() - 2..],
        [
            "▼ Rules without an objective (1)",
            "└── Sentinel KQL Rule  ✗ 1"
        ]
    );
    assert_eq!(rows[1], "└── Credential Access Objective  0 rules");
    // Enter collapses a branch and opens it again.
    let shown = rows.len();
    key(&mut app, KeyCode::Enter);
    assert_eq!(tree(&app, 80).len(), shown - 1);
    assert!(tree(&app, 80)[0].starts_with("▶ Simulated Actor"));
    key(&mut app, KeyCode::Enter);
    assert_eq!(tree(&app, 80).len(), shown);
}

#[test]
fn coverage_lists_techniques_and_opens_the_rule() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    press(&mut app, "2");
    assert_eq!(app.tab, 1);
    let (rows, _) = screen(&mut app, 140, 20);
    let row = rows.iter().find(|row| row.starts_with("T1059")).unwrap();
    let cells: Vec<&str> = row
        .split("  ")
        .map(str::trim)
        .filter(|cell| !cell.is_empty())
        .collect();
    assert_eq!(
        cells,
        [
            "T1059",
            "1",
            "1 own · 0 inherited",
            "Sentinel KQL Rule",
            "Simulated Actor"
        ]
    );
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.tab, 0);
    assert_eq!(app.selected, Node::Object(RULE.into()));
}

#[test]
fn the_palette_offers_the_actions() {
    let titles: Vec<&str> = commands().iter().map(|command| command.title()).collect();
    assert_eq!(
        titles,
        [
            "opentide validate",
            "opentide generate",
            "opentide deploy --dry-run --strategy PREVIEW --all",
            "opentide deploy --dry-run --strategy RELEASE --all",
            "Reload the catalogue",
            "Quit",
        ]
    );
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
    let (rows, _) = screen(&mut app, 120, 30);
    assert!(
        rows.iter()
            .any(|row| row.contains("opentide deploy --dry-run --strategy RELEASE --all"))
    );
    // Typing narrows it; Enter runs the one highlighted.
    press(&mut app, "release");
    key(&mut app, KeyCode::Enter);
    assert!(app.palette.is_none());
    assert_eq!(
        app.running.as_deref(),
        Some("opentide deploy --dry-run --strategy RELEASE --all")
    );
    app.settle();
    assert!(results(&app).contains("strategy RELEASE"));
}

#[test]
fn deploy_runs_as_a_dry_run_and_shows_the_plan() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    press(&mut app, "d");
    app.settle();
    let log = results(&app);
    assert!(
        log.contains("$ opentide deploy --dry-run --strategy PREVIEW --all"),
        "{log}"
    );
    assert!(
        log.contains("Deploy plan · strategy PREVIEW · 1 platform, 0 tenants"),
        "{log}"
    );
    assert!(
        log.contains("+ create or update  Sentinel KQL Rule"),
        "{log}"
    );
    assert!(
        log.contains("Plan: 0 to create, 0 to update, 1 to create or update"),
        "{log}"
    );
    assert!(
        log.contains("warning: sentinel has no tenants configured"),
        "{log}"
    );
    // The renderers' text: no OSC 8 link and no cursor switch reaches the tab.
    let output = &app.outcomes.last().unwrap().output;
    assert!(!opentide_cli::tui::actions::clean(output).contains("\x1b]8;"));
}

#[test]
fn generate_runs_the_command_line_and_says_what_it_cannot_do() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    let before = files(&repo);
    press(&mut app, "g");
    app.settle();
    let outcome = app.outcomes.last().unwrap();
    assert_eq!(outcome.command, "opentide generate");
    // The full pipeline has no Rust implementation yet: the run says so, as
    // `opentide generate` on the Rust command line does, and writes nothing.
    assert_eq!(outcome.exit_code, 2, "{}", outcome.output);
    assert!(
        results(&app).contains("no Rust implementation yet"),
        "{}",
        results(&app)
    );
    assert_eq!(files(&repo), before);
}

// -- one command at a time, and quitting --------------------------------------

#[test]
fn quit_waits_for_the_running_command() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    press(&mut app, "v");
    press(&mut app, "q");
    assert!(!app.quit);
    assert!(
        app.status
            .contains("Waiting for opentide validate to finish"),
        "{}",
        app.status
    );
    // Nothing new starts while it waits.
    press(&mut app, "d");
    assert_eq!(app.running.as_deref(), Some("opentide validate"));
    app.settle();
    assert!(app.quit);
    assert_eq!(app.outcomes.len(), 1);
    assert_eq!(app.outcomes[0].command, "opentide validate");
}

#[test]
fn quit_with_nothing_running_exits_at_once() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    press(&mut app, "q");
    assert!(app.quit);
}

#[test]
fn one_command_at_a_time() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    press(&mut app, "g");
    press(&mut app, "v");
    assert_eq!(app.status, "Wait for opentide generate to finish");
    app.settle();
    press(&mut app, "r");
    assert_eq!(app.running.as_deref(), Some("the catalogue reload"));
    app.settle();
    assert!(app.running.is_none());
    assert_eq!(app.outcomes.len(), 1);
    assert_eq!(app.catalogue.as_ref().unwrap().count(Kind::Rule), 1);
}

// -- layout at a width ----------------------------------------------------------

#[test]
fn at_100_columns_names_end_in_an_ellipsis_and_nothing_scrolls_sideways() {
    let (_base, repo) = tutorial();
    edit(
        &repo,
        RULE_FILE,
        "name: Sentinel KQL Rule",
        &format!("name: {LONG_RULE}"),
    );
    break_tlp(&repo);
    let mut app = open(&repo);
    let (rows, _) = screen(&mut app, 100, 30);
    // The tree's column: two fifths of the screen, its right border included.
    let width = 40 - 1;
    let lines = tree(&app, width);
    assert!(
        lines.iter().all(|line| line.chars().count() <= width),
        "{lines:?}"
    );
    let [threat, objective, leaf] = lines.as_slice() else {
        panic!("{lines:?}")
    };
    // The counts stay whole; the name gives way.
    assert!(threat.ends_with("  1 objective · 1 rule"), "{threat}");
    assert!(objective.ends_with("…  1 rule"), "{objective}");
    // The language server's finding (validate's `vocab_unknown` on the TLP)
    // stays whole too.
    assert!(leaf.contains("…  ✗ 1") && !leaf.contains(" …"), "{leaf}");
    assert!(!leaf.contains(LONG_RULE));
    // Every drawn row fits the screen: nothing scrolls sideways.
    assert!(rows.iter().all(|row| row.chars().count() <= 100));
    // The tagline does not fit beside the counts: it goes, whole.
    assert!(rows[0].starts_with(" ▐ ≋ opentide ▌"), "{}", rows[0]);
    assert!(!rows[0].contains("Spec-driven"), "{}", rows[0]);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    assert_eq!(app.selected, Node::Object(RULE.into()));
    // The detail pane shows the full name.
    let (rows, _) = screen(&mut app, 100, 30);
    let screen_text = rows.join("\n");
    assert!(
        screen_text.contains("LSASS memory read by an unsigned process"),
        "{screen_text}"
    );
}

#[test]
fn an_empty_workspace_names_its_path_relative_to_the_current_directory() {
    let base = tempfile::tempdir().unwrap();
    let repo = base.path().join("acme-detections");
    std::fs::create_dir_all(repo.join("objects")).unwrap();
    std::fs::create_dir_all(repo.join(".opentide")).unwrap();
    let mut app = open_from(&repo, base.path());
    assert_eq!(
        tree(&app, 60),
        ["No detection objects under acme-detections"]
    );
    let (rows, _) = screen(&mut app, 100, 30);
    assert!(!rows.join("\n").contains(&base.path().display().to_string()));
}

// -- the language server and the detail pane ----------------------------------

#[test]
fn the_language_server_reports_each_object_before_any_validate_run() {
    let (_base, repo) = tutorial();
    break_tlp(&repo);
    let mut app = open(&repo);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    let shown = detail(&app);
    assert!(shown.contains("Language server\n✗ 1  on line 8"), "{shown}");
    assert!(shown.contains("Not validated yet: press v to run opentide validate."));
    // The tree counts it already.
    assert!(tree(&app, 80)[2].ends_with("Sentinel KQL Rule  ✗ 1"));
}

#[test]
fn a_finding_both_report_is_shown_and_counted_once() {
    let (_base, repo) = tutorial();
    break_tlp(&repo);
    let mut app = open(&repo);
    press(&mut app, "v");
    app.settle();
    let catalogue = app.catalogue.as_ref().unwrap();
    let entry = catalogue.entries[RULE].clone();
    let (live, validated) = app.findings_of(&entry);
    assert!(
        live.iter().all(|item| item.code != "vocab_unknown"),
        "{live:?}"
    );
    assert_eq!(
        validated
            .iter()
            .filter(|item| item.code == "vocab_unknown")
            .count(),
        1
    );
    assert!(tree(&app, 80)[2].ends_with("Sentinel KQL Rule  ✗ 1"));
}

#[test]
fn n_moves_to_each_finding_and_says_it_on_the_status_line() {
    let (_base, repo) = tutorial();
    // An unknown KQL operator on line 28, and the TLP on line 8.
    edit(&repo, RULE_FILE, "| take 1", "| tak 1");
    break_tlp(&repo);
    let mut app = open(&repo);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    press(&mut app, "n");
    assert!(app.raw);
    assert_eq!(app.current_finding, Some(0));
    assert!(
        app.status.starts_with("1/2 error[vocab_unknown]:"),
        "{}",
        app.status
    );
    // The status line carries the hover at the finding's span.
    assert!(app.status.contains(" · Tlp"), "{}", app.status);
    let source = detail(&app);
    // The current finding is marked where it is, under its line.
    assert!(source.contains("▶ error[vocab_unknown]"), "{source}");
    assert!(
        source.contains("╰─ error[kql_unknown_operator]"),
        "{source}"
    );
    press(&mut app, "n");
    assert!(
        app.status.starts_with("2/2 error[kql_unknown_operator]:"),
        "{}",
        app.status
    );
    // The pane scrolls the finding at line 28 into view.
    let (rows, _) = screen(&mut app, 120, 20);
    assert!(
        rows.iter()
            .any(|row| row.contains("▶ error[kql_unknown_operator]")),
        "{rows:#?}"
    );
    assert!(
        !rows.iter().any(|row| row.contains("Language server")),
        "{rows:#?}"
    );
    press(&mut app, "p");
    assert_eq!(app.current_finding, Some(0));
    // Another object starts again from its first finding.
    key(&mut app, KeyCode::Up);
    assert_eq!(app.current_finding, None);
    press(&mut app, "n");
    assert_eq!(app.status, "No findings on this object");
}

#[test]
fn the_source_is_coloured_by_the_engine_and_findings_are_underlined() {
    use ratatui::style::Modifier;
    let (_base, repo) = tutorial();
    break_tlp(&repo);
    let mut app = open(&repo);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    press(&mut app, "y");
    let (lines, _) = app.detail_lines(100);
    let tlp = lines
        .iter()
        .find(|line| plain(line).contains("tlp: clearr"))
        .unwrap();
    let underlined: String = tlp
        .spans
        .iter()
        .filter(|span| span.style.add_modifier.contains(Modifier::UNDERLINED))
        .map(|span| span.content.as_ref())
        .collect();
    assert_eq!(underlined, "clearr");
    // Tide keys are coloured as the editor colours them.
    let name = lines
        .iter()
        .find(|line| plain(line).contains("name: "))
        .unwrap();
    assert!(
        name.spans.iter().any(|span| span.content.contains("name")
            && span.style.add_modifier.contains(Modifier::BOLD))
    );
}

#[test]
fn the_page_is_the_default_y_shows_the_file_and_f_follows_a_reference() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    let page = detail(&app);
    assert!(page.contains("Overview"), "{page}");
    assert!(page.contains("TLP:CLEAR"), "{page}");
    assert!(
        page.contains("→ Credential Access Objective  objective"),
        "{page}"
    );
    assert!(page.contains("sentinel  kql"), "{page}");
    assert!(page.contains("Not set ("), "{page}");
    assert!(!page.contains(" 1 name: Sentinel KQL Rule"));
    press(&mut app, "y");
    assert!(
        detail(&app).contains("1   name: Sentinel KQL Rule"),
        "{}",
        detail(&app)
    );
    assert_eq!(app.status, "Showing the file");
    press(&mut app, "y");
    press(&mut app, "f");
    assert_eq!(app.selected, Node::Object(OBJECTIVE.into()));
    assert_eq!(app.status, "Opened objective Credential Access Objective");
}

#[test]
fn the_object_page_lists_the_fields_not_set() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    let view = app.catalogue.as_ref().unwrap().object_view(RULE).unwrap();
    assert!(view.unknown_schema.is_none());
    assert!(!view.unset.is_empty());
    // A required field is never offered as an option.
    assert!(view.unset.iter().all(|field| field.path != "name"));
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Down);
    assert!(!detail(&app).contains("one of:") || app.unset_open);
    press(&mut app, "u");
    let page = detail(&app);
    assert!(
        page.contains(&format!("▼ Not set ({})", view.unset.len())),
        "{page}"
    );
}

// -- Visibility, Configuration and Chains --------------------------------------

#[test]
fn visibility_lists_the_log_sources_and_what_reads_them() {
    let (_base, repo) = tutorial();
    std::fs::write(
        repo.join(".opentide/configurations/visibility.toml"),
        "[[logsources]]\nname = \"SecurityEvent\"\nsystem = \"sentinel\"\n\
         description = \"Windows security events\"\n\n\
         [logsources.columns.EventID]\ntype = \"int\"\ndescription = \"The event\"\n\n\
         [[logsources]]\nname = \"Syslog\"\nsystem = \"sentinel\"\ndescription = \"Unix logs\"\n",
    )
    .unwrap();
    let mut app = open(&repo);
    press(&mut app, "4");
    let (rows, _) = screen(&mut app, 140, 30);
    let text = rows.join("\n");
    assert!(text.contains("2 sentinel"), "{text}");
    assert!(text.contains("1 without columns"), "{text}");
    assert!(text.contains("1 unused"), "{text}");
    assert!(
        text.contains("Read by queries: Sentinel KQL Rule"),
        "{text}"
    );
    assert!(text.contains("EventID"), "{text}");
    // The filter narrows the table; Enter opens the first rule that uses it.
    press(&mut app, "/sys");
    key(&mut app, KeyCode::Enter);
    let (rows, _) = screen(&mut app, 140, 30);
    assert!(rows.iter().any(|row| row.contains("Syslog")));
    assert!(
        !rows
            .iter()
            .any(|row| row.trim_start().starts_with("SecurityEvent"))
    );
    press(&mut app, "/");
    for _ in 0..3 {
        key(&mut app, KeyCode::Backspace);
    }
    key(&mut app, KeyCode::Esc);
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.selected, Node::Object(RULE.into()));
}

#[test]
fn the_configuration_tab_says_it_is_not_ported() {
    let (_base, repo) = tutorial();
    let mut app = open(&repo);
    press(&mut app, "5");
    let (rows, _) = screen(&mut app, 120, 20);
    assert!(
        rows.join("\n")
            .contains("The Configuration tab has no Rust implementation yet.")
    );
}

#[test]
fn chains_draw_the_attack_flow_around_the_selected_threat() {
    let (_base, repo) = tutorial();
    let second = "00000000-0000-4000-8001-000000000002";
    let threat =
        std::fs::read_to_string(repo.join("objects/threats/simulated-actor.yaml")).unwrap();
    std::fs::write(
        repo.join("objects/threats/follow-up.yaml"),
        threat
            .replace("name: Simulated Actor", "name: Follow Up")
            .replace(THREAT, second)
            .replace(
                "  mitre_attack:",
                &format!(
                    "  chaining:\n    - relation: sequence::succeeds\n      vector: {THREAT}\n      description: After the actor\n  mitre_attack:"
                ),
            ),
    )
    .unwrap();
    let mut app = open(&repo);
    press(&mut app, "6");
    assert_eq!(app.tab, 5);
    let (rows, _) = screen(&mut app, 160, 40);
    let text = rows.join("\n");
    // Drawn around the threat selected in the Catalogue: the first, by name.
    assert!(
        text.contains("Follow Up   1 hop (+/-)   relations: all (l)"),
        "{text}"
    );
    assert!(text.contains("──▶"), "{text}");
    assert!(
        text.contains("Simulated Actor  ─then─▶  Follow Up"),
        "{text}"
    );
    // The undetected step is red; its box says it has no rule.
    assert!(text.contains("0 rules"), "{text}");
    // The highlighted threat's links carry their descriptions.
    assert!(text.contains("After the actor"), "{text}");
    press(&mut app, "l");
    assert_eq!(app.chains.stage, Some("sequence"));
    press(&mut app, "+");
    assert_eq!(app.chains.hops, 2);
    key(&mut app, KeyCode::Down);
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.tab, 0);
    assert_eq!(app.selected, Node::Object(THREAT.into()));
}
