//! The home screen: what a bare `opentide` shows a person at a terminal
//! (`cli/ui/home.py`, #841 decision D3).
//!
//! ```text
//!   ████████   ▐ ≋ opentide ▌  0.23.0
//!   ██ icon █  Spec-driven development for agentic detection engineering
//!   ████████
//!               workspace  .  git: main, clean
//!               catalogue  10 rules · 1 threat · 1 objective
//!                  health  ! schemas not generated yet
//!               platforms  sentinel (no tenant yet)
//!
//!    ≋  Suggested next
//!     opentide generate   schemas, templates and editor snippets
//!
//!   opentide --help for every command · opentide --json <command> for agents
//! ```
//!
//! Only in `human` mode; every other mode gets the help. The facts are read
//! from the files on disk (no workspace load, no network), so the screen
//! costs what `--help` does. [`gather`] collects, [`render`] draws, cell for
//! cell as the oracle's Rich layout: the icon and the facts side by side with
//! three columns between them, every line indented by two and padded to the
//! widest.

use std::path::{Path, PathBuf};

use crate::render::brand;
use crate::render::text::{Colour, Style, Text};

/// Narrower than this, the icon gives way to the facts alone.
pub const ICON_MIN_WIDTH: usize = 76;

/// The icon (`brand.ICON`): a Reflex Blue disc holding the white Tsunami
/// glyph, 28 × 28 pixels, `B` blue, `W` white.
const ICON: [&str; 28] = [
    "..........BBBBBBBB..........",
    "........BBBBBBBBBBBB........",
    "......BBBBBBBBBBBBBBBB......",
    ".....BBBBBBBBBBBBBBBBBB.....",
    "....BBBBBBBBBBBBBBBBBBBB....",
    "...BBBBBBBBBBBBBBBBBBBBBB...",
    "..BBBBBBBBBBWWWWWWWBBBBBBB..",
    "..BBBBBBBBWWWWWWWWBBBBBBBB..",
    ".BBBBBBBWWWWWWWBWWBBBBBBBBB.",
    ".BBBBBBWWWBWWBBBWWBBBBBBBBB.",
    "BBBBBBBWWBBWWBBBWWBBBBBBBBBB",
    "BBBBBBWWBBWWBBBBWWWBBBBBBBBB",
    "BBBBBWWWBBWWBBBBBWWWWWWBBBBB",
    "BBBBBWWBBBWWBBBBBBWWWWWBBBBB",
    "BBBBBWWBBBWWWBBBBBBBBBBBBBBB",
    "BBBBBWWWWBBWWWWBBBBWWBBBBBBB",
    "BBBBBWWWWWWWWWWWWWWWWWWBBBBB",
    "BBBBBWWWWWWWWWWWWWWWWWWBBBBB",
    ".BBBBBBBBBBBBBBBBBBBBBBBBBB.",
    ".BBBBBBWWBBBBWWBBBBWWBBBBBB.",
    "..BBBWWWWWWWWWWWWWWWWWWBBB..",
    "..BBBWWWWWWWWWWWWWWWWWWBBB..",
    "...BBBBBBBBBBBBBBBBBBBBBB...",
    "....BBBBBBBBBBBBBBBBBBBB....",
    ".....BBBBBBBBBBBBBBBBBB.....",
    "......BBBBBBBBBBBBBBBB......",
    "........BBBBBBBBBBBB........",
    "..........BBBBBBBB..........",
];

/// The object folders the catalogue counts, and each one's noun.
const KINDS: [(&str, &str); 3] = [
    ("rules", "rule"),
    ("threats", "threat"),
    ("objectives", "objective"),
];

/// What the home screen says about the working directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// opentide's version.
    pub version: String,
    /// The workspace, or `None` where there is none.
    pub workspace: Option<PathBuf>,
    /// `main, clean`, `main, 3 changed`; `None` outside git.
    pub git: Option<String>,
    /// Object files per folder: `rules`, `threats`, `objectives`.
    pub catalogue: Vec<(String, usize)>,
    /// Whether `.opentide/schemas/` holds a generated schema.
    pub schemas: bool,
    /// Each enabled platform and its number of `[[tenants]]`, by name.
    pub platforms: Vec<(String, usize)>,
}

/// The facts for the working directory `cwd`: the workspace
/// `OPENTIDE_REPO_ROOT` names, else the nearest one (`gather`).
pub fn gather(version: &str, cwd: &Path, repo_root: Option<&str>) -> Facts {
    use opentide_workspace::root::{OPENTIDE_DIR, find_workspace_root, is_workspace_root};
    let fs = opentide_workspace::OsFs;
    let root = match repo_root.filter(|root| !root.is_empty()) {
        Some(root) => cwd.join(root),
        None => find_workspace_root(&fs, cwd),
    };
    if !is_workspace_root(&fs, &root) {
        return Facts {
            version: version.to_owned(),
            git: git_state(&root),
            ..Facts::default()
        };
    }
    // Only files directly in each folder are objects (#584).
    #[expect(
        clippy::case_sensitive_file_extension_comparisons,
        reason = "the oracle's glob (`*.yaml`, `*.yml`) is case-sensitive, as the catalogue's"
    )]
    let catalogue = KINDS
        .iter()
        .map(|(kind, _)| {
            let count = files_in(&root.join("objects").join(kind))
                .iter()
                .filter(|name| {
                    (name.ends_with(".yaml") || name.ends_with(".yml"))
                        && !name.ends_with(".debug.yaml")
                        && !name.ends_with(".debug.yml")
                })
                .count();
            ((*kind).to_owned(), count)
        })
        .collect();
    let schemas = files_in(&root.join(OPENTIDE_DIR).join("schemas"))
        .iter()
        .any(|name| name.ends_with(".schema.json"));
    let platforms = platforms(
        &root
            .join(OPENTIDE_DIR)
            .join("configurations")
            .join("platforms"),
    );
    Facts {
        version: version.to_owned(),
        git: git_state(&root),
        workspace: Some(root),
        catalogue,
        schemas,
        platforms,
    }
}

/// The names of the files directly in `folder`, sorted; none when it cannot
/// be read.
fn files_in(folder: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Each enabled platform in `folder` (`<name>.toml` with `[platform]
/// enabled = true`) and its number of `[[tenants]]`, in name order. A file
/// that does not read as TOML is left out.
fn platforms(folder: &Path) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    for name in files_in(folder) {
        let Some(stem) = name.strip_suffix(".toml") else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(folder.join(&name)) else {
            continue;
        };
        let Ok(document) = text.parse::<toml::Table>() else {
            continue;
        };
        let enabled = document
            .get("platform")
            .and_then(toml::Value::as_table)
            .and_then(|platform| platform.get("enabled"))
            .and_then(toml::Value::as_bool)
            == Some(true);
        if !enabled {
            continue;
        }
        let tenants = document
            .get("tenants")
            .and_then(toml::Value::as_array)
            .map_or(0, Vec::len);
        found.push((stem.to_owned(), tenants));
    }
    found
}

/// The branch and the state of the work tree at `path` (`main, clean`,
/// `main, 3 changed`), or `None` when git does not answer in time.
fn git_state(path: &Path) -> Option<String> {
    let branch = git(path, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    let name = match branch.trim() {
        "" => "no branch".to_owned(),
        name => name.to_owned(),
    };
    let Some(status) = git(path, &["status", "--porcelain"]) else {
        // git did not answer: nothing about the tree.
        return Some(name);
    };
    let changed = status
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    let state = if changed == 0 {
        "clean".to_owned()
    } else {
        format!("{changed} changed")
    };
    Some(format!("{name}, {state}"))
}

/// What `git <args>` prints in `path`, if it exits 0 within two seconds.
fn git(path: &Path, args: &[&str]) -> Option<String> {
    let mut child = std::process::Command::new("git")
        .args(args)
        .current_dir(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut text = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    std::io::Read::read_to_string(&mut stdout, &mut text).ok()?;
                }
                return status.success().then_some(text);
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            _ => {
                let _ignored = child.kill();
                let _ignored = child.wait();
                return None;
            }
        }
    }
}

/// `1 rule`, `7 rules`, `0 rules`.
fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// Up to three commands worth running here, most useful first, each with why.
pub fn next_steps(facts: &Facts) -> Vec<(&'static str, &'static str)> {
    if facts.workspace.is_none() {
        return vec![("opentide setup", "create a detection repository here")];
    }
    let mut steps = Vec::new();
    if !facts.schemas {
        steps.push((
            "opentide generate",
            "schemas, templates and editor snippets",
        ));
    }
    let count = |kind: &str| {
        facts
            .catalogue
            .iter()
            .find(|(name, _)| name == kind)
            .map_or(0, |(_, count)| *count)
    };
    if facts.catalogue.iter().all(|(_, count)| *count == 0) {
        // Nothing to validate or deploy yet: the first object is the next step.
        steps.push(("opentide new threat", "scaffold the first object"));
    } else {
        steps.push(("opentide validate", "check every object before you commit"));
    }
    if facts.platforms.is_empty() {
        steps.push(("opentide setup platforms --sentinel", "enable a platform"));
    } else if count("rules") == 0 {
        steps.push(("opentide new rule", "a rule for an enabled platform"));
    } else if facts.platforms.iter().any(|(_, tenants)| *tenants == 0) {
        steps.push((
            "opentide deploy --strategy PREVIEW --all --dry-run",
            "see what a deploy would do",
        ));
    } else {
        steps.push(("opentide info", "the catalogue and its coverage"));
    }
    steps.truncate(3);
    steps
}

/// `path` as the reader types it from `cwd`: `.`, `../..` or `detections`
/// where one holds the other, else `~/…`, else whole.
pub fn workspace_path(path: &Path, cwd: &Path, home: Option<&Path>) -> String {
    let resolve = |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let here = resolve(cwd);
    let target = resolve(path);
    if target.starts_with(&here) || here.starts_with(&target) {
        let relative = pathdiff::diff_paths(&target, &here).unwrap_or_default();
        let text = relative.to_string_lossy().replace('\\', "/");
        return if text.is_empty() {
            ".".to_owned()
        } else {
            text
        };
    }
    if let Some(home) = home
        && let Ok(relative) = target.strip_prefix(resolve(home))
    {
        return format!("~/{}", relative.to_string_lossy().replace('\\', "/"));
    }
    target.to_string_lossy().replace('\\', "/")
}

/// The `workspace`, `catalogue`, `health` and `platforms` rows: each label
/// right-aligned, two columns before its value.
fn facts_rows(facts: &Facts, screen: &Screen<'_>) -> Vec<Text> {
    let label = |text: &str| Text::styled(text, &Style::new("bold dim"));
    let dim = Style::new("dim");
    let mut rows: Vec<Vec<Text>> = Vec::new();
    match &facts.workspace {
        None => rows.push(vec![label("workspace"), Text::styled("none here", &dim)]),
        Some(workspace) => {
            let mut place = Text::styled(
                &workspace_path(workspace, screen.cwd, screen.home),
                &Style::new("underline"),
            );
            if let Some(git) = &facts.git {
                // Rich's base style (underline) runs under what is appended.
                place.append(&format!("  git: {git}"), &Style::new("underline dim"));
            }
            rows.push(vec![label("workspace"), place]);
            let counts: Vec<String> = KINDS
                .iter()
                .map(|(kind, noun)| {
                    let count = facts
                        .catalogue
                        .iter()
                        .find(|(name, _)| name == kind)
                        .map_or(0, |(_, count)| *count);
                    plural(count, noun)
                })
                .collect();
            rows.push(vec![label("catalogue"), Text::plain(&counts.join(" · "))]);
            let mut health = Text::default();
            if facts.schemas {
                health.append("✓ ", &Style::new("green"));
                health.push_str("schemas generated");
            } else {
                health.append("! ", &Style::new("yellow"));
                health.push_str("schemas not generated yet");
            }
            rows.push(vec![label("health"), health]);
            if facts.platforms.is_empty() {
                rows.push(vec![label("platforms"), Text::styled("none enabled", &dim)]);
            }
            for (number, (name, tenants)) in facts.platforms.iter().enumerate() {
                let mut value = Text::styled(name, &Style::new("bold"));
                let count = if *tenants == 0 {
                    " (no tenant yet)".to_owned()
                } else {
                    format!(" ({})", plural(*tenants, "tenant"))
                };
                // Rich's base style (bold) runs under what is appended.
                value.append(&count, &Style::new("bold dim"));
                rows.push(vec![
                    label(if number == 0 { "platforms" } else { "" }),
                    value,
                ]);
            }
        }
    }
    crate::render::progress::columns(&rows, 2, 0, &[0])
}

/// Where the screen is drawn.
#[derive(Debug, Clone, Copy)]
pub struct Screen<'a> {
    /// The styles the terminal gets.
    pub colour: Colour,
    /// The terminal's width in columns.
    pub width: usize,
    /// The working directory, which the workspace's place is shown from.
    pub cwd: &'a Path,
    /// The home folder, for `~/…`.
    pub home: Option<&'a Path>,
}

/// The whole screen for `facts` (`home_view`), each line ending in `\n`.
pub fn render(facts: &Facts, screen: &Screen<'_>) -> String {
    let colour = screen.colour;
    let mut title = brand::pill(colour);
    title.append(&format!("  {}", facts.version), &Style::new("dim"));
    let mut right = vec![
        title,
        Text::styled(brand::TAGLINE, &Style::new("italic")),
        Text::default(),
    ];
    right.extend(facts_rows(facts, screen));
    let mut lines: Vec<Text> = Vec::new();
    if screen.width >= ICON_MIN_WIDTH {
        // The icon beside an empty line, then the right-hand column; the
        // grid's columns padded to their widest, three columns between.
        let icon = brand::grid(&ICON, colour);
        let column: Vec<Text> = std::iter::once(Text::default()).chain(right).collect();
        let width = column.iter().map(Text::cell_len).max().unwrap_or(0);
        let icon_width = ICON[0].chars().count();
        for row in 0..icon.len().max(column.len()) {
            let mut line = icon
                .get(row)
                .cloned()
                .unwrap_or_else(|| Text::plain(&" ".repeat(icon_width)));
            line.push_str("   ");
            let cell = column.get(row).cloned().unwrap_or_default();
            let pad = width - cell.cell_len();
            line.append_text(&cell);
            line.push_str(&" ".repeat(pad));
            lines.push(line);
        }
    } else {
        lines.extend(right);
    }
    lines.push(Text::default());
    lines.push(brand::header("Suggested next", colour));
    // The screen is indented by 2: a line wider than what is left would wrap
    // mid-phrase, so a narrow terminal drops the descriptions instead.
    let room = screen.width.saturating_sub(2);
    let steps = next_steps(facts);
    let described: Vec<Vec<Text>> = steps
        .iter()
        .map(|(command, reason)| {
            vec![
                Text::styled(command, &Style::new("bold")),
                Text::styled(reason, &Style::new("dim")),
            ]
        })
        .collect();
    let mut rows = crate::render::progress::columns(&described, 3, 2, &[]);
    if rows.iter().any(|row| row.cell_len() > room) {
        let commands: Vec<Vec<Text>> = described.iter().map(|row| vec![row[0].clone()]).collect();
        rows = crate::render::progress::columns(&commands, 2, 2, &[]);
    }
    lines.extend(rows);
    lines.push(Text::default());
    let bold = Style::new("bold");
    let dim = Style::new("dim");
    let mut help = Text::styled("opentide --help", &bold);
    help.append(" for every command", &dim);
    let mut agents = Text::styled("opentide --json <command>", &bold);
    agents.append(" for agents", &dim);
    let mut footer = help.clone();
    footer.append(" · ", &dim);
    footer.append_text(&agents);
    if footer.cell_len() > room {
        lines.push(help);
        lines.push(agents);
    } else {
        lines.push(footer);
    }
    // Indented by two, every line padded to the widest, one blank line above.
    let width = lines.iter().map(Text::cell_len).max().unwrap_or(0);
    let mut out = format!("{}\n", " ".repeat(width + 2));
    for line in &lines {
        let mut padded = Text::plain("  ");
        padded.append_text(line);
        padded.push_str(&" ".repeat(width - line.cell_len()));
        out.push_str(&padded.render(colour, false));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            version: "1.0.0".into(),
            workspace: Some(PathBuf::from("/w")),
            git: None,
            catalogue: vec![
                ("rules".into(), 2),
                ("threats".into(), 1),
                ("objectives".into(), 0),
            ],
            schemas: true,
            platforms: vec![("elastic".into(), 1), ("sentinel".into(), 2)],
        }
    }

    #[test]
    fn the_next_steps_follow_the_workspace() {
        assert_eq!(
            next_steps(&Facts::default()),
            [("opentide setup", "create a detection repository here")]
        );
        assert_eq!(
            next_steps(&facts()),
            [
                ("opentide validate", "check every object before you commit"),
                ("opentide info", "the catalogue and its coverage")
            ]
        );
        let mut empty = facts();
        empty.schemas = false;
        empty.catalogue.iter_mut().for_each(|(_, count)| *count = 0);
        empty.platforms.clear();
        assert_eq!(
            next_steps(&empty),
            [
                (
                    "opentide generate",
                    "schemas, templates and editor snippets"
                ),
                ("opentide new threat", "scaffold the first object"),
                ("opentide setup platforms --sentinel", "enable a platform")
            ]
        );
        let mut no_rules = facts();
        no_rules.catalogue[0].1 = 0;
        assert_eq!(next_steps(&no_rules)[1].0, "opentide new rule");
    }

    #[test]
    fn a_narrow_terminal_gets_no_icon_and_no_descriptions() {
        let cwd = Path::new("/w");
        let screen = Screen {
            colour: Colour::None,
            width: 40,
            cwd,
            home: None,
        };
        let text = render(&facts(), &screen);
        assert!(!text.contains('█'), "{text}");
        assert!(
            text.contains("  opentide info\n") || text.contains("  opentide info "),
            "{text}"
        );
        assert!(!text.contains("the catalogue and its coverage"), "{text}");
        assert!(
            text.contains("  opentide --help for every command"),
            "{text}"
        );
        assert!(
            text.contains("\n  opentide --json <command> for agents"),
            "{text}"
        );
        assert!(text.contains("platforms  elastic (1 tenant)"), "{text}");
        assert!(text.contains("sentinel (2 tenants)"), "{text}");
        assert!(text.contains("health  ✓ schemas generated"), "{text}");
    }

    #[test]
    fn a_workspace_is_read_from_its_files() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        std::fs::create_dir_all(root.join("objects/rules/nested")).unwrap();
        std::fs::write(root.join("objects/rules/a.yaml"), "x").unwrap();
        std::fs::write(root.join("objects/rules/a.debug.yaml"), "x").unwrap();
        std::fs::write(root.join("objects/rules/nested/b.yaml"), "x").unwrap();
        let platforms = root.join(".opentide/configurations/platforms");
        std::fs::create_dir_all(&platforms).unwrap();
        std::fs::write(
            platforms.join("splunk.toml"),
            "[platform]\nenabled = true\n[[tenants]]\nname = 'a'\n",
        )
        .unwrap();
        std::fs::write(
            platforms.join("elastic.toml"),
            "[platform]\nenabled = false\n",
        )
        .unwrap();
        std::fs::write(platforms.join("broken.toml"), "[platform\n").unwrap();
        let facts = gather("1", root, None);
        assert_eq!(facts.workspace.as_deref(), Some(root));
        assert_eq!(facts.catalogue[0], ("rules".to_owned(), 1));
        assert!(!facts.schemas);
        assert_eq!(facts.platforms, [("splunk".to_owned(), 1)]);
        let outside = tempfile::tempdir().unwrap();
        assert_eq!(gather("1", outside.path(), None).workspace, None);
        assert_eq!(
            gather("1", outside.path(), Some(&root.to_string_lossy()))
                .workspace
                .as_deref(),
            Some(root)
        );
        assert_eq!(workspace_path(root, root, None), ".");
        assert_eq!(
            workspace_path(root, &root.join("objects/rules"), None),
            "../.."
        );
        assert_eq!(workspace_path(&root.join("objects"), root, None), "objects");
    }
}
