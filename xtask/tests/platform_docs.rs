//! The docs' platform tables and lists say what the registry says.
//!
//! The registry, `opentide_schema::platforms::PLATFORMS`, is the one source
//! of truth for what each platform can do (`opentide info --json` prints part
//! of it: `can_deploy`, `can_validate` and `can_query`). These pages restate
//! it in tables a person reads, and went stale when a platform gained an
//! offline engine: each check here names the page, the platform and the
//! column that disagrees.

#![expect(
    clippy::expect_used,
    reason = "test helpers: a panic naming the missing page or section is how the test fails"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use opentide_schema::platforms::{PLATFORMS, Platform};

fn read(relative: &str) -> String {
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/..")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// The text of `page` from the line that is `heading` to the next heading,
/// a `#` line outside a code fence.
fn section<'t>(page: &'t str, heading: &str) -> &'t str {
    let start = page
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("no section {heading:?}"))
        + heading.len()
        + 2;
    let rest = &page[start..];
    let mut fenced = false;
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        if line.starts_with("```") {
            fenced = !fenced;
        } else if !fenced && line.starts_with('#') {
            return &rest[..offset];
        }
        offset += line.len();
    }
    rest
}

/// A table row's cells: split on `|`, but not on an escaped `\|` (`ES\|QL`).
fn cells(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut escaped = false;
    for c in inner.chars() {
        if c == '|' && !escaped {
            cells.push(cell.trim().to_owned());
            cell.clear();
        } else {
            cell.push(c);
        }
        escaped = c == '\\';
    }
    cells.push(cell.trim().to_owned());
    cells
}

/// A row of a platform: its id, its cells, and the cell count of its table's
/// header.
struct Row {
    id: String,
    cells: Vec<String>,
    columns: usize,
}

impl Row {
    fn cell(&self, column: usize) -> &str {
        self.cells.get(column).map_or("", String::as_str)
    }
}

/// Each table row of `text` whose first or second cell names a platform
/// (`` `id` ``, or `` `id` (...) ``).
fn rows(text: &str) -> Vec<Row> {
    let mut found = Vec::new();
    let mut columns = 0;
    let mut in_table = false;
    for line in text.lines() {
        if !line.starts_with('|') {
            in_table = false;
            continue;
        }
        let row = cells(line);
        if !in_table {
            in_table = true;
            columns = row.len();
            continue;
        }
        if line.starts_with("|-") || line.starts_with("|:") {
            continue;
        }
        let id = row.iter().take(2).find_map(|cell| {
            let name = cell.strip_prefix('`')?.split('`').next()?;
            PLATFORMS
                .iter()
                .any(|p| p.id == name)
                .then(|| name.to_owned())
        });
        if let Some(id) = id {
            found.push(Row {
                id,
                cells: row,
                columns,
            });
        }
    }
    found
}

fn platform(id: &str) -> &'static Platform {
    PLATFORMS
        .iter()
        .find(|p| p.id == id)
        .expect("a registry platform")
}

/// The names a page may give a registry language, any of which will do.
fn display_names(language: &str) -> &'static [&'static str] {
    match language {
        "kql" => &["KQL"],
        "spl" => &["SPL"],
        "esql" => &["ES\\|QL", "ES|QL"],
        "eql" => &["EQL"],
        "kuery" => &["Kibana KQL", "Kuery"],
        "lucene" => &["Lucene"],
        "falco" => &["Falco"],
        "cql" => &["CQL"],
        "yara" => &["YARA"],
        "exabeam" => &["Exabeam Query Language"],
        "yaral" => &["YARA-L"],
        "powerquery" => &["PowerQuery"],
        "telemetry" => &["telemetry"],
        other => panic!("no display name for the registry language {other:?}: add one here"),
    }
}

/// Each of `languages` that `cell` does not name.
fn unnamed<'l>(cell: &str, languages: &[&'l str]) -> Vec<&'l str> {
    languages
        .iter()
        .copied()
        .filter(|language| {
            !display_names(language)
                .iter()
                .any(|name| cell.contains(name))
        })
        .collect()
}

/// Every registry platform has exactly one row, each as wide as its header.
fn one_row_each(page: &str, rows: &[Row], wrong: &mut Vec<String>) {
    for p in PLATFORMS {
        let count = rows.iter().filter(|row| row.id == p.id).count();
        if count != 1 {
            wrong.push(format!("{page}: `{}` has {count} rows, not 1", p.id));
        }
    }
    for row in rows {
        if row.cells.len() != row.columns {
            wrong.push(format!(
                "{page}: `{}`'s row has {} cells, its header {}",
                row.id,
                row.cells.len(),
                row.columns
            ));
        }
    }
}

fn check(wrong: &[String]) {
    assert!(
        wrong.is_empty(),
        "the docs disagree with the registry (crates/opentide-schema/src/platforms.rs):\n  {}",
        wrong.join("\n  ")
    );
}

fn count(keep: fn(&Platform) -> bool) -> usize {
    PLATFORMS.iter().filter(|p| keep(p)).count()
}

#[test]
fn agents_md_s_platforms_table_and_counts_are_the_registry_s() {
    let page = read("AGENTS.md");
    let text = section(&page, "## Platforms");
    let table = rows(text);
    let mut wrong = Vec::new();
    one_row_each("AGENTS.md", &table, &mut wrong);
    for row in &table {
        let p = platform(&row.id);
        let mut expect = |column: usize, name: &str, ok: bool| {
            if !ok {
                wrong.push(format!(
                    "AGENTS.md: `{}`'s {name} is {:?}",
                    row.id,
                    row.cell(column)
                ));
            }
        };
        expect(1, "product", row.cell(1) == p.label);
        expect(2, "deploy", (row.cell(2) == "✅") == p.deploys);
        expect(
            3,
            "compile without a tenant",
            (row.cell(3) == "✅") == p.compiles_offline,
        );
        expect(4, "tenant check", (row.cell(4) == "✅") == p.live_check);
        let offline = row.cell(5);
        expect(
            5,
            "offline engine",
            !offline.is_empty() && offline.starts_with('—') == p.offline_languages.is_empty(),
        );
        expect(
            5,
            "offline engine's languages",
            unnamed(offline, p.offline_languages).is_empty(),
        );
        let query = row.cell(6);
        expect(
            6,
            "`opentide query`",
            !query.is_empty() && (query == "—") != p.query_runner,
        );
        expect(
            6,
            "`opentide query`'s languages",
            unnamed(query, p.runner_languages).is_empty(),
        );
    }
    let sentence = format!(
        "All {} deploy; {} have a tenant check, {} an offline engine, {} `opentide query`.",
        count(|p| p.deploys),
        count(|p| p.live_check),
        count(|p| !p.offline_languages.is_empty()),
        count(|p| p.query_runner),
    );
    if !text.replace('\n', " ").contains(&sentence) {
        wrong.push(format!("AGENTS.md: the counts are not {sentence:?}"));
    }
    check(&wrong);
}

#[test]
fn new_s_platform_choices_are_every_platform() {
    let page = read("docs/cli/new.md");
    let row = page
        .lines()
        .find(|line| line.starts_with("| `--platform` |"))
        .expect("docs/cli/new.md's --platform row");
    let named: BTreeSet<&str> = row.split('`').skip(3).step_by(2).collect();
    let registry: BTreeSet<&str> = PLATFORMS.iter().map(|p| p.id).collect();
    let mut wrong = Vec::new();
    if named != registry {
        wrong.push(format!(
            "docs/cli/new.md: `--platform` lists {named:?}, the registry has {registry:?}"
        ));
    }
    check(&wrong);
}

#[test]
fn installation_s_platform_identifiers_are_every_platform() {
    let page = read("docs/usage/installation.md");
    let table = rows(section(&page, "### Platform identifiers"));
    let mut wrong = Vec::new();
    one_row_each("docs/usage/installation.md", &table, &mut wrong);
    check(&wrong);
}

#[test]
fn query_md_s_platform_choices_are_the_query_runners() {
    let page = read("docs/cli/query.md");
    let row = page
        .lines()
        .find(|line| line.starts_with("| `--platform` |"))
        .expect("docs/cli/query.md's --platform row");
    let named: BTreeSet<&str> = row.split('`').skip(1).step_by(2).collect();
    let mut wrong = Vec::new();
    for p in PLATFORMS {
        let said = named.contains(p.id);
        if p.query_runner && !said {
            wrong.push(format!(
                "docs/cli/query.md: `--platform` does not list `{}`",
                p.id
            ));
        }
        if !p.query_runner && said && !row.contains(&format!("`{}` has no query runner", p.id)) {
            wrong.push(format!(
                "docs/cli/query.md: `--platform` lists `{}`, which has no query runner",
                p.id
            ));
        }
    }
    check(&wrong);
}

#[test]
fn setup_md_has_a_flag_for_every_platform() {
    let page = read("docs/cli/setup.md");
    let text = section(&page, "### setup platforms");
    let mut wrong = Vec::new();
    for p in PLATFORMS {
        let flag = format!("| `--{}` |", p.id.replace('_', "-"));
        if text.lines().filter(|line| line.starts_with(&flag)).count() != 1 {
            wrong.push(format!(
                "docs/cli/setup.md: `setup platforms` has no one {flag:?} row"
            ));
        }
    }
    check(&wrong);
}

#[test]
fn validate_md_s_offline_and_live_tables_are_the_registry_s() {
    let page = read("docs/cli/validate.md");
    let mut wrong = Vec::new();
    // The offline engine: one row per platform that has one, and no other,
    // naming the platform's languages.
    let offline = rows(section(&page, "### Offline: the analysis engine"));
    let listed: BTreeSet<&str> = offline.iter().map(|row| row.id.as_str()).collect();
    let registry: BTreeSet<&str> = PLATFORMS
        .iter()
        .filter(|p| !p.offline_languages.is_empty())
        .map(|p| p.id)
        .collect();
    if listed != registry {
        wrong.push(format!(
            "docs/cli/validate.md, offline engine: lists {listed:?}, the registry has {registry:?}"
        ));
    }
    for row in &offline {
        let missing = unnamed(row.cell(1), platform(&row.id).offline_languages);
        if !missing.is_empty() || row.cells.len() != row.columns {
            wrong.push(format!(
                "docs/cli/validate.md, offline engine: `{}`'s row {:?} does not name {missing:?}",
                row.id,
                row.cell(1)
            ));
        }
    }
    // The supported platforms: `--live` and offline per platform.
    let text = section(&page, "### Supported platforms");
    let supported = rows(text);
    one_row_each(
        "docs/cli/validate.md, supported platforms",
        &supported,
        &mut wrong,
    );
    for row in &supported {
        let p = platform(&row.id);
        if row.cell(1).starts_with('✅') != p.live_check {
            wrong.push(format!(
                "docs/cli/validate.md: `{}`'s --live is {:?}",
                row.id,
                row.cell(1)
            ));
        }
        if row.cell(2).starts_with('✅') == p.offline_languages.is_empty() {
            wrong.push(format!(
                "docs/cli/validate.md: `{}`'s offline is {:?}",
                row.id,
                row.cell(2)
            ));
        }
    }
    let words = |n: usize| {
        [
            "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
            "eleven", "twelve", "thirteen",
        ]
        .get(n)
        .copied()
        .expect("a count of platforms")
    };
    let sentence = format!(
        "Live query validation works on **{} platforms**; the offline engine on {}, {} of them the same",
        words(count(|p| p.live_check)),
        words(count(|p| !p.offline_languages.is_empty())),
        words(count(|p| p.live_check && !p.offline_languages.is_empty())),
    );
    if !text.replace('\n', " ").contains(&sentence) {
        wrong.push(format!(
            "docs/cli/validate.md: the counts are not {sentence:?}"
        ));
    }
    check(&wrong);
}

#[test]
fn the_platforms_page_s_capability_matrix_is_the_registry_s() {
    let page = read("docs/usage/concepts/platforms.md");
    let table = rows(section(&page, "## Capability matrix"));
    let mut wrong = Vec::new();
    one_row_each("docs/usage/concepts/platforms.md", &table, &mut wrong);
    for row in &table {
        let p = platform(&row.id);
        for (column, name, value) in [
            (2, "deploy", p.deploys),
            (3, "query validate (live)", p.live_check),
            (4, "offline query check", !p.offline_languages.is_empty()),
            (5, "query", p.query_runner),
        ] {
            let cell = row.cell(column);
            if cell.is_empty() || (cell != "no") != value {
                wrong.push(format!(
                    "docs/usage/concepts/platforms.md: `{}`'s {name} is {cell:?}",
                    row.id
                ));
            }
        }
    }
    check(&wrong);
}
