//! Help screens compared by what they say, not how they are laid out (#841).
//!
//! The oracle prints `--help` with Typer and Rich (boxed panels, two aligned
//! columns, wrapped at the terminal, a long word cut with `…`); the Rust
//! command line prints clap's long help (an indented list, one option per
//! paragraph). A `help` entry of the ledger approves that layout for the
//! cases it names, and only where both screens say the same thing. Each side
//! is read into a [`Screen`]:
//!
//! - the usage line's command path (`opentide validate`);
//! - the about text, before the first section;
//! - each section (`Options`, `Arguments`, `Commands`, the root's headings)
//!   with its items in order: an item's names (an option's flags, a command's
//!   or an argument's name), its description, and the `[default: …]` and
//!   environment variable it names;
//! - the epilog (the examples), as words.
//!
//! What each side says about its own layout is set aside: an option's value
//! name (`<str>`, `<FILE>`), clap's `[possible values: …]` (the choices are
//! in the description and in `opentide --json commands`), Typer's
//! `[required]` and a heading's colon. Two screens agree when the path, the
//! about text, every section (by title, in any order) with its items in
//! order, and the epilog are equal, words compared one by one, where an
//! oracle word Rich cut short (`defender_for_endpoin…`) matches any candidate
//! word it begins.

use regex::Regex;
use std::sync::OnceLock;

/// One item of a section: an option, an argument or a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Its flags (`--path`, `-C`), sorted, or its name.
    pub names: Vec<String>,
    /// Its description, words separated by one space, markers removed.
    pub description: String,
    /// The value of `[default: …]`, if the screen names one.
    pub default: Option<String>,
    /// The environment variable it reads, if the screen names one.
    pub env: Option<String>,
}

/// A titled list of items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// `Options`, `Arguments`, `Commands`, or a heading of the root's.
    pub title: String,
    /// Its items, in order.
    pub items: Vec<Item>,
}

/// What a help screen says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    /// The command path of the usage line: `opentide validate`.
    pub path: String,
    /// The about text, words separated by one space.
    pub about: String,
    /// The sections, in the order the screen lists them.
    pub sections: Vec<Section>,
    /// The epilog, words separated by one space.
    pub epilog: String,
}

/// One way two screens differ: where, and each side's text there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// `about`, `epilog`, `path`, `section Options`, `Options --path description`.
    pub at: String,
    /// The oracle's text there, or `(absent)`.
    pub oracle: String,
    /// The candidate's text there, or `(absent)`.
    pub candidate: String,
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| match Regex::new(pattern) {
        Ok(regex) => regex,
        // A pattern compiled in: a test runs every one.
        Err(error) => unreachable!("help pattern {pattern:?}: {error}"),
    })
}

/// SGR codes and OSC 8 hyperlinks: what a terminal's help carries.
fn strip_ansi(text: &str) -> String {
    static ANSI: OnceLock<Regex> = OnceLock::new();
    regex(
        &ANSI,
        r"\x1b\[[0-9;:]*[A-Za-z]|\x1b\]8;[^\x1b\x07]*(?:\x1b\\|\x07)",
    )
    .replace_all(text, "")
    .into_owned()
}

/// Words separated by one space.
fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `description` without its markers, and the default and environment
/// variable they name.
fn markers(description: &str) -> (String, Option<String>, Option<String>) {
    static MARKER: OnceLock<Regex> = OnceLock::new();
    let marker = regex(
        &MARKER,
        r"\[(default|env var|env|possible values|required)(?::\s*([^\]]*))?\]",
    );
    let mut default = None;
    let mut env = None;
    let text = marker.replace_all(description, |found: &regex::Captures<'_>| {
        let value = found
            .get(2)
            .map(|value| value.as_str().trim().trim_end_matches('=').to_owned());
        match &found[1] {
            "default" => default = value,
            "env var" | "env" => env = value,
            _ => {}
        }
        " "
    });
    (words(&text), default, env)
}

/// The command path of a usage line: the words after `Usage:` up to the
/// first that is not a command word (`[OPTIONS]`, `<COMMAND>`, `COMMAND`,
/// `{name}`).
fn usage_path(line: &str) -> String {
    line.split_whitespace()
        .skip(1)
        .take_while(|word| {
            let placeholder =
                word.len() > 1 && word.chars().all(|c| c.is_ascii_uppercase() || c == '_');
            !(word.starts_with(['[', '<', '{']) || placeholder)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// An item from its head (names and value name) and its description.
fn item(head: &str, description: &str, arguments: bool) -> Item {
    let tokens: Vec<&str> = head
        .split_whitespace()
        .filter(|token| *token != "*")
        .collect();
    let mut names: Vec<String> = if arguments {
        tokens
            .first()
            .map(|name| {
                vec![
                    name.trim_matches(|c| matches!(c, '[' | ']' | '<' | '>' | '{' | '}' | '.'))
                        .to_owned(),
                ]
            })
            .unwrap_or_default()
    } else if tokens.first().is_some_and(|token| token.starts_with('-')) {
        tokens
            .iter()
            .filter(|token| token.starts_with('-'))
            .map(|token| token.trim_end_matches(',').to_owned())
            .collect()
    } else {
        tokens
            .first()
            .map(|name| vec![(*name).to_owned()])
            .unwrap_or_default()
    };
    names.sort();
    let (description, default, env) = markers(description);
    Item {
        names,
        description,
        default,
        env,
    }
}

/// The start of each run of text after two spaces (or at the start) in `row`.
fn segment_starts(row: &[char]) -> Vec<usize> {
    (0..row.len())
        .filter(|&at| {
            row[at] != ' ' && (at == 0 || (at >= 2 && row[at - 1] == ' ' && row[at - 2] == ' '))
        })
        .collect()
}

/// A Rich panel's rows (the text between `│ ` and ` │`) as items.
fn panel_items(title: &str, rows: &[Vec<char>]) -> Vec<Item> {
    // A required item's `*` sits in a column of its own.
    let rows: Vec<Vec<char>> = rows
        .iter()
        .map(|row| {
            let mut row = row.clone();
            if let Some(at) = row.iter().position(|c| *c != ' ')
                && row[at] == '*'
            {
                row[at] = ' ';
            }
            row
        })
        .collect();
    let indent = |row: &Vec<char>| row.iter().position(|c| *c != ' ');
    let Some(name_column) = rows.iter().filter_map(indent).min() else {
        return Vec::new();
    };
    let starts = |row: &Vec<char>| row.get(name_column).is_some_and(|c| *c != ' ');
    let continued: Vec<usize> = rows
        .iter()
        .filter(|row| !starts(row))
        .filter_map(indent)
        .collect();
    // The description column: where the continuation lines start, else the
    // last column a first line has text at after two spaces (an item without
    // a value name or a description has fewer columns, never a later one).
    let description_column = continued.iter().copied().min().or_else(|| {
        rows.iter()
            .filter(|row| starts(row))
            .filter_map(|row| {
                segment_starts(row)
                    .into_iter()
                    .rfind(|&at| at > name_column)
            })
            .max()
    });
    let arguments = title == "Arguments";
    let mut items: Vec<(String, String)> = Vec::new();
    for row in &rows {
        let split = description_column.unwrap_or(row.len()).min(row.len());
        let head: String = row[..split].iter().collect();
        let tail: String = row[split..].iter().collect();
        if starts(row) {
            items.push((head, tail));
        } else if let Some((_, description)) = items.last_mut() {
            description.push(' ');
            description.push_str(&tail);
        }
    }
    items
        .iter()
        .map(|(head, description)| item(head, description, arguments))
        .collect()
}

/// Reads a help screen Typer and Rich drew: `None` when `text` is not one.
pub fn parse_typer(text: &str) -> Option<Screen> {
    let text = strip_ansi(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut path = None;
    let mut about = Vec::new();
    let mut epilog = Vec::new();
    let mut sections = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim();
        index += 1;
        if path.is_none() {
            if line.starts_with("Usage:") {
                path = Some(usage_path(line));
            }
            continue;
        }
        if let Some(top) = line.strip_prefix('╭') {
            let title = words(
                top.trim_end_matches('╮')
                    .trim_matches(|c| c == '─' || c == ' '),
            );
            let mut rows = Vec::new();
            while index < lines.len() && !lines[index].trim().starts_with('╰') {
                let row = lines[index].trim();
                let inner = row.strip_prefix('│')?.strip_suffix('│')?;
                rows.push(inner.strip_prefix(' ').unwrap_or(inner).chars().collect());
                index += 1;
            }
            index += 1;
            sections.push(Section {
                items: panel_items(&title, &rows),
                title,
            });
            continue;
        }
        if sections.is_empty() {
            about.push(line);
        } else {
            epilog.push(line);
        }
    }
    Some(Screen {
        path: path?,
        about: words(&about.join(" ")),
        sections,
        epilog: epilog_words(&epilog),
    })
}

/// The epilog's words; a line that is one word ending in `:` (clap's
/// heading, `Examples:`) without it.
fn epilog_words(lines: &[&str]) -> String {
    let lines: Vec<String> = lines
        .iter()
        .map(|line| {
            let line = line.trim();
            match line.strip_suffix(':') {
                Some(heading) if !heading.contains(char::is_whitespace) => heading.to_owned(),
                _ => line.to_owned(),
            }
        })
        .collect();
    words(&lines.join(" "))
}

/// Whether `line` is a heading of clap's help (`Options:`, `Agents and
/// integrations:`).
fn clap_heading(line: &str) -> bool {
    line.strip_suffix(':').is_some_and(|title| {
        title.starts_with(|c: char| c.is_ascii_uppercase())
            && title.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ')
    })
}

/// Reads a long help clap printed: `None` when `text` is not one.
pub fn parse_clap(text: &str) -> Option<Screen> {
    let text = strip_ansi(text);
    let lines: Vec<&str> = text.lines().collect();
    let usage = lines.iter().position(|line| line.starts_with("Usage:"))?;
    let about = words(&lines[..usage].join(" "));
    let path = usage_path(lines[usage]);
    let mut sections: Vec<Section> = Vec::new();
    let mut raw: Vec<(String, String)> = Vec::new();
    let mut epilog: Vec<&str> = Vec::new();
    let mut title: Option<String> = None;
    let finish =
        |title: &Option<String>, raw: &mut Vec<(String, String)>, sections: &mut Vec<Section>| {
            if let Some(title) = title {
                let arguments = title == "Arguments";
                sections.push(Section {
                    title: title.clone(),
                    items: raw
                        .drain(..)
                        .map(|(head, description)| item(&head, &description, arguments))
                        .collect(),
                });
            }
        };
    let mut index = usage + 1;
    while index < lines.len() {
        let line = lines[index];
        index += 1;
        if !epilog.is_empty() {
            epilog.push(line);
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            // A heading starts a section, unless what follows it is an
            // example (`Examples:` then `  $ opentide …`): the epilog.
            let next = lines[index..]
                .iter()
                .find(|next| !next.trim().is_empty())
                .map_or("", |next| next.trim());
            finish(&title, &mut raw, &mut sections);
            if clap_heading(line) && !next.starts_with('$') {
                title = Some(line.trim_end_matches(':').to_owned());
            } else {
                title = None;
                epilog.push(line);
            }
            continue;
        }
        let in_list = title
            .as_deref()
            .is_some_and(|title| title != "Options" && title != "Arguments");
        if indent >= 10 {
            if let Some((_, description)) = raw.last_mut() {
                description.push(' ');
                description.push_str(line.trim());
            }
        } else if in_list {
            // `  validate  Validate objects and queries`.
            let trimmed = line.trim();
            let (name, description) = trimmed
                .split_once("  ")
                .map_or((trimmed, ""), |(name, rest)| (name, rest.trim()));
            raw.push((name.to_owned(), description.to_owned()));
        } else {
            raw.push((line.trim().to_owned(), String::new()));
        }
    }
    finish(&title, &mut raw, &mut sections);
    Some(Screen {
        path,
        about,
        sections,
        epilog: epilog_words(&epilog),
    })
}

/// Whether the oracle's word reads as the candidate's: equal, or cut short
/// by Rich with `…` where the candidate's begins with what is left.
fn word_matches(oracle: &str, candidate: &str) -> bool {
    match oracle.strip_suffix('…') {
        Some(prefix) => candidate.starts_with(prefix),
        None => oracle == candidate,
    }
}

/// Whether two texts say the same, word by word ([`word_matches`]).
pub fn text_matches(oracle: &str, candidate: &str) -> bool {
    let oracle: Vec<&str> = oracle.split_whitespace().collect();
    let candidate: Vec<&str> = candidate.split_whitespace().collect();
    oracle.len() == candidate.len()
        && oracle
            .iter()
            .zip(&candidate)
            .all(|(oracle, candidate)| word_matches(oracle, candidate))
}

/// The ways `candidate` says something else than `oracle`. `texts` are the
/// approved changes of wording (`help-text` entries: the oracle's text and
/// the candidate's, each a whole description, about text or epilog), and
/// `used` gets the index of each one that applied.
pub fn mismatches(
    oracle: &Screen,
    candidate: &Screen,
    texts: &[(usize, &str, &str)],
    used: &mut Vec<usize>,
) -> Vec<Mismatch> {
    let mut found = Vec::new();
    let absent = || "(absent)".to_owned();
    let mut text = |at: String, oracle: &str, candidate: &str, found: &mut Vec<Mismatch>| {
        if text_matches(oracle, candidate) {
            return;
        }
        if let Some((index, ..)) = texts
            .iter()
            .find(|(_, from, to)| words(from) == oracle && words(to) == candidate)
        {
            used.push(*index);
            return;
        }
        found.push(Mismatch {
            at,
            oracle: oracle.to_owned(),
            candidate: candidate.to_owned(),
        });
    };
    if oracle.path != candidate.path {
        found.push(Mismatch {
            at: "path".into(),
            oracle: oracle.path.clone(),
            candidate: candidate.path.clone(),
        });
    }
    text("about".into(), &oracle.about, &candidate.about, &mut found);
    text(
        "epilog".into(),
        &oracle.epilog,
        &candidate.epilog,
        &mut found,
    );
    for section in &oracle.sections {
        let Some(other) = candidate
            .sections
            .iter()
            .find(|other| other.title == section.title)
        else {
            found.push(Mismatch {
                at: format!("section {}", section.title),
                oracle: section.title.clone(),
                candidate: absent(),
            });
            continue;
        };
        let longest = section.items.len().max(other.items.len());
        for at in 0..longest {
            match (section.items.get(at), other.items.get(at)) {
                (Some(left), Some(right)) => {
                    let label = |item: &Item| item.names.join(" ");
                    let names_match = left.names.len() == right.names.len()
                        && left
                            .names
                            .iter()
                            .zip(&right.names)
                            .all(|(left, right)| word_matches(left, right));
                    if !names_match {
                        found.push(Mismatch {
                            at: format!("{} item {}", section.title, at + 1),
                            oracle: label(left),
                            candidate: label(right),
                        });
                        continue;
                    }
                    let place = format!("{} {}", section.title, label(right));
                    text(
                        format!("{place} description"),
                        &left.description,
                        &right.description,
                        &mut found,
                    );
                    for (what, left, right) in [
                        ("default", &left.default, &right.default),
                        ("environment variable", &left.env, &right.env),
                    ] {
                        if left != right {
                            found.push(Mismatch {
                                at: format!("{place} {what}"),
                                oracle: left.clone().unwrap_or_else(absent),
                                candidate: right.clone().unwrap_or_else(absent),
                            });
                        }
                    }
                }
                (Some(left), None) => found.push(Mismatch {
                    at: format!("{} item {}", section.title, at + 1),
                    oracle: left.names.join(" "),
                    candidate: absent(),
                }),
                (None, Some(right)) => found.push(Mismatch {
                    at: format!("{} item {}", section.title, at + 1),
                    oracle: absent(),
                    candidate: right.names.join(" "),
                }),
                (None, None) => {}
            }
        }
    }
    for section in &candidate.sections {
        if !oracle
            .sections
            .iter()
            .any(|other| other.title == section.title)
        {
            found.push(Mismatch {
                at: format!("section {}", section.title),
                oracle: absent(),
                candidate: section.title.clone(),
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const TYPER: &str = "
 Usage: opentide setup ci [OPTIONS] {ci_platform}

 Generate CI/CD pipeline files (platforms discovered from repo config).

╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    ci_platform      <github|gitlab|azure>  github, gitlab, or azure        │
│                                              [required]                      │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --path              -C               <str>   Repository path [default: .]    │
│ --staging               --no-staging         Deploy to staging tenants from  │
│                                              pull requests                   │
│                                              [default: staging]              │
│ --platform                           <str>   Detection platform: sentinel,   │
│                                              defender_for_endpoin… sysdig    │
│                                              [env var: OPENTIDE_PLATFORM]    │
│ --help                                       Show this message and exit.     │
╰──────────────────────────────────────────────────────────────────────────────╯

 Examples
   $ opentide setup ci github
";

    const CLAP: &str = "Generate CI/CD pipeline files (platforms discovered from repo config).

Usage: opentide setup ci [OPTIONS] <ci_platform>

Arguments:
  <ci_platform>
          github, gitlab, or azure

          [possible values: github, gitlab, azure]

Options:
  -C, --path <PATH>
          Repository path

          [default: .]

      --staging, --no-staging
          Deploy to staging tenants from pull requests

          [default: staging]

      --platform <PLATFORM>
          Detection platform: sentinel, defender_for_endpoint, sysdig

          [env: OPENTIDE_PLATFORM]

      --help
          Show this message and exit.

Examples:
  $ opentide setup ci github
";

    #[test]
    fn typer_and_clap_say_the_same() {
        let oracle = parse_typer(TYPER).unwrap();
        let candidate = parse_clap(CLAP).unwrap();
        assert_eq!(oracle.path, "opentide setup ci");
        assert_eq!(oracle.sections.len(), 2);
        assert_eq!(oracle.sections[1].items[0].names, ["--path", "-C"]);
        assert_eq!(oracle.sections[1].items[0].default.as_deref(), Some("."));
        assert_eq!(
            oracle.sections[1].items[2].env.as_deref(),
            Some("OPENTIDE_PLATFORM")
        );
        assert_eq!(
            candidate.sections[1].items[1].names,
            ["--no-staging", "--staging"]
        );
        assert_eq!(candidate.epilog, "Examples $ opentide setup ci github");
        let mut used = Vec::new();
        assert_eq!(mismatches(&oracle, &candidate, &[], &mut used), []);
    }

    #[test]
    fn a_different_word_option_or_default_is_a_mismatch() {
        let oracle = parse_typer(TYPER).unwrap();
        for (from, to, at) in [
            (
                "Deploy to staging tenants",
                "Deploy to staged tenants",
                "Options --no-staging --staging description",
            ),
            (
                "      --platform <PLATFORM>",
                "      --platforms <PLATFORM>",
                "Options item 3",
            ),
            (
                "[default: staging]",
                "[default: no-staging]",
                "Options --no-staging --staging default",
            ),
            (
                "[env: OPENTIDE_PLATFORM]",
                "",
                "Options --platform environment variable",
            ),
            (
                "  $ opentide setup ci github",
                "  $ opentide setup ci gitlab",
                "epilog",
            ),
            ("Generate CI/CD", "Write CI/CD", "about"),
            ("Arguments:", "Positionals:", "section Arguments"),
        ] {
            let candidate = parse_clap(&CLAP.replace(from, to)).unwrap();
            let found = mismatches(&oracle, &candidate, &[], &mut Vec::new());
            assert!(
                found.iter().any(|found| found.at == at),
                "{from}: {found:?}"
            );
        }
        // An option the candidate drops.
        let dropped = CLAP.replace("      --platform <PLATFORM>\n          Detection platform: sentinel, defender_for_endpoint, sysdig\n\n          [env: OPENTIDE_PLATFORM]\n\n", "");
        let found = mismatches(
            &oracle,
            &parse_clap(&dropped).unwrap(),
            &[],
            &mut Vec::new(),
        );
        assert!(!found.is_empty());
    }

    #[test]
    fn an_approved_wording_applies_where_both_texts_are_found() {
        let oracle = parse_typer(TYPER).unwrap();
        let candidate = parse_clap(&CLAP.replace("Repository path", "Workspace path")).unwrap();
        let texts = [(7, "Repository path", "Workspace path")];
        let mut used = Vec::new();
        assert_eq!(mismatches(&oracle, &candidate, &texts, &mut used), []);
        assert_eq!(used, [7]);
        let other = [(7, "Repository path", "Repo path")];
        assert_eq!(
            mismatches(&oracle, &candidate, &other, &mut Vec::new()).len(),
            1
        );
    }

    #[test]
    fn a_word_rich_cut_short_matches_only_its_prefix() {
        assert!(word_matches(
            "defender_for_endpoin…",
            "defender_for_endpoint,"
        ));
        assert!(!word_matches("defender_for_endpoin…", "defender,"));
        assert!(text_matches("a b… c", "a bee c"));
        assert!(!text_matches("a b… c", "a bee"));
    }

    #[test]
    fn terminal_codes_are_not_content() {
        let styled = TYPER
            .replace("Usage:", "\u{1b}[1;33mUsage: \u{1b}[0m")
            .replace("--help", "\u{1b}[1;36m-\u{1b}[0m\u{1b}[1;36m-help\u{1b}[0m");
        assert_eq!(parse_typer(&styled), parse_typer(TYPER));
        let styled = CLAP.replace("Options:", "\u{1b}[1m\u{1b}[4mOptions:\u{1b}[0m");
        assert_eq!(parse_clap(&styled), parse_clap(CLAP));
    }

    #[test]
    fn a_screen_without_a_usage_line_is_no_help() {
        assert_eq!(parse_typer("error: No such option\n"), None);
        assert_eq!(parse_clap("{\"ok\": true}\n"), None);
    }

    #[test]
    fn the_root_headings_are_sections_and_the_examples_are_the_epilog() {
        let clap = "About\n\nUsage: opentide [OPTIONS] <COMMAND>\n\nOptions:\n      --json\n          Machine-readable output\n\nAuthor:\n  validate  Validate objects\n  lint      Check names\n\nAgents and integrations:\n  serve     Run commands\n\nExamples:\n  $ opentide validate\n";
        let screen = parse_clap(clap).unwrap();
        let titles: Vec<&str> = screen.sections.iter().map(|s| s.title.as_str()).collect();
        assert_eq!(titles, ["Options", "Author", "Agents and integrations"]);
        assert_eq!(screen.sections[1].items[1].names, ["lint"]);
        assert_eq!(screen.sections[1].items[1].description, "Check names");
        assert_eq!(screen.epilog, "Examples $ opentide validate");
        assert_eq!(screen.path, "opentide");
    }
}
