//! The docs' platform tables and lists say what the registry says.
//!
//! The registry, `opentide_schema::platforms::PLATFORMS`, is the one source
//! of truth for what each platform can do (it is what `opentide info --json`
//! prints as `can_deploy`, `can_validate` and `can_query`). These pages
//! restate it in tables a person reads, and went stale when a platform gained
//! an offline engine: each check here names the page, the platform and the
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

/// The text of `page` from the line that is `heading` to the next heading.
fn section<'t>(page: &'t str, heading: &str) -> &'t str {
    let start = page
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("no section {heading:?}"));
    let rest = &page[start + heading.len() + 2..];
    let end = rest.find("\n#").unwrap_or(rest.len());
    &rest[..end]
}

/// The cells of each table row of `text` whose first or second cell names a
/// platform (`` `id` ``, or `` `id` (...) ``), by platform id.
fn rows(text: &str) -> Vec<(String, Vec<String>)> {
    text.lines()
        .filter(|line| line.starts_with('|') && !line.starts_with("|-") && !line.starts_with("|:"))
        .filter_map(|line| {
            let cells: Vec<String> = line
                .trim_matches('|')
                .split(" | ")
                .map(|cell| cell.trim().to_owned())
                .collect();
            let id = cells.iter().take(2).find_map(|cell| {
                let name = cell.strip_prefix('`')?.split('`').next()?;
                PLATFORMS
                    .iter()
                    .any(|p| p.id == name)
                    .then(|| name.to_owned())
            })?;
            Some((id, cells))
        })
        .collect()
}

fn platform(id: &str) -> &'static Platform {
    PLATFORMS
        .iter()
        .find(|p| p.id == id)
        .expect("a registry platform")
}

/// Every registry platform has exactly one row; the rows' ids, in order.
fn one_row_each(page: &str, rows: &[(String, Vec<String>)], wrong: &mut Vec<String>) {
    let ids: Vec<&str> = rows.iter().map(|(id, _)| id.as_str()).collect();
    for p in PLATFORMS {
        let count = ids.iter().filter(|id| **id == p.id).count();
        if count != 1 {
            wrong.push(format!("{page}: `{}` has {count} rows, not 1", p.id));
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

#[test]
fn agents_md_s_platforms_table_and_counts_are_the_registry_s() {
    let page = read("AGENTS.md");
    let text = section(&page, "## Platforms");
    let table = rows(text);
    let mut wrong = Vec::new();
    one_row_each("AGENTS.md", &table, &mut wrong);
    for (id, cells) in &table {
        let p = platform(id);
        let mut expect = |column: usize, name: &str, ok: bool| {
            if !ok {
                wrong.push(format!(
                    "AGENTS.md: `{id}`'s {name} is {:?}",
                    cells.get(column).map_or("", String::as_str)
                ));
            }
        };
        let cell = |column: usize| cells.get(column).map_or("", String::as_str);
        expect(1, "product", cell(1) == p.label);
        expect(2, "deploy", (cell(2) == "✅") == p.deploys);
        expect(
            3,
            "compile without a tenant",
            (cell(3) == "✅") == p.compiles_offline,
        );
        expect(4, "tenant check", (cell(4) == "✅") == p.live_check);
        expect(
            5,
            "offline engine",
            cell(5).starts_with('—') == p.offline_languages.is_empty(),
        );
        expect(6, "`opentide query`", (cell(6) == "—") != p.query_runner);
    }
    let count = |keep: fn(&Platform) -> bool| PLATFORMS.iter().filter(|p| keep(p)).count();
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
fn validate_md_s_offline_and_live_tables_are_the_registry_s() {
    let page = read("docs/cli/validate.md");
    let mut wrong = Vec::new();
    // The offline engine: one row per platform that has one, and no other.
    let offline = rows(section(&page, "### Offline: the analysis engine"));
    let listed: BTreeSet<&str> = offline.iter().map(|(id, _)| id.as_str()).collect();
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
    // The supported platforms: `--live` and offline per platform.
    let supported = rows(section(&page, "### Supported platforms"));
    one_row_each(
        "docs/cli/validate.md, supported platforms",
        &supported,
        &mut wrong,
    );
    for (id, cells) in &supported {
        let p = platform(id);
        let cell = |column: usize| cells.get(column).map_or("", String::as_str);
        if cell(1).starts_with('✅') != p.live_check {
            wrong.push(format!(
                "docs/cli/validate.md: `{id}`'s --live is {:?}",
                cell(1)
            ));
        }
        if cell(2).starts_with('✅') == p.offline_languages.is_empty() {
            wrong.push(format!(
                "docs/cli/validate.md: `{id}`'s offline is {:?}",
                cell(2)
            ));
        }
    }
    check(&wrong);
}

#[test]
fn the_platforms_page_s_capability_matrix_is_the_registry_s() {
    let page = read("docs/usage/concepts/platforms.md");
    let table = rows(section(&page, "## Capability matrix"));
    let mut wrong = Vec::new();
    one_row_each("docs/usage/concepts/platforms.md", &table, &mut wrong);
    for (id, cells) in &table {
        let p = platform(id);
        let cell = |column: usize| cells.get(column).map_or("", String::as_str);
        let says = |column: usize| cell(column) != "no";
        for (column, name, value) in [
            (2, "deploy", p.deploys),
            (3, "query validate (live)", p.live_check),
            (4, "offline query check", !p.offline_languages.is_empty()),
            (5, "query", p.query_runner),
        ] {
            if says(column) != value {
                wrong.push(format!(
                    "docs/usage/concepts/platforms.md: `{id}`'s {name} is {:?}",
                    cell(column)
                ));
            }
        }
    }
    check(&wrong);
}
