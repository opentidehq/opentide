//! `opentide info`: the repository and the platforms; with a section, the
//! objects of a family, a technique's coverage, the vocabularies or the
//! catalogue (`cli/commands/info.py`, `cli/services/info.py`).

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use opentide_schema::vocab::Vocabularies;
use opentide_workspace::catalogue::{self, EDGE_KINDS};
use opentide_workspace::coverage::{match_technique, rule_technique_index};
use opentide_workspace::fields::{get, platforms as object_platforms};
use opentide_workspace::index::truthy;
use opentide_workspace::info::{self as data, PlatformInfo};
use opentide_workspace::{Index, Workspace};

use super::{
    Block, ISSUES_FOUND, Report, USAGE_INVALID_CHOICE, USAGE_INVALID_VALUE, USAGE_MISSING_OPTION,
    counted, json, placement,
};
use crate::env::Env;
use crate::envelope::Failure;
use crate::json::Json;
use crate::render::glyphs::SEPARATOR;
use crate::render::table::{Column, Table, columns};
use crate::render::text::{Style, Text};

/// The sections, in the order the usage error lists them.
pub const SECTIONS: [&str; 6] = [
    "rules",
    "threats",
    "objectives",
    "coverage",
    "vocab",
    "catalog",
];

/// The command's arguments.
#[derive(Clone, Debug, Default)]
pub struct Args {
    /// `--platform`.
    pub platform: Option<String>,
    /// The section.
    pub section: Option<String>,
    /// The vocabulary, with `vocab`.
    pub name: Option<String>,
    /// `--technique`.
    pub technique: Option<String>,
    /// `--strict`.
    pub strict: bool,
}

/// What the run knows about where it is.
pub struct Context<'a> {
    /// `--repo`, as typed.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// opentide's version.
    pub version: &'a str,
    /// Whether the text modes print a body (not `--json`).
    pub text: bool,
}

const COMMAND: &str = "info";

/// Runs `opentide info`.
pub fn run(args: &Args, cx: &Context<'_>) -> Report {
    let section = args.section.as_deref();
    if let Some(section) = section
        && !SECTIONS.contains(&section)
    {
        return Report::usage(
            COMMAND,
            format!(
                "Unknown info section: {section}. Choose {}.",
                SECTIONS.join(", ")
            ),
            USAGE_INVALID_CHOICE,
            "section",
            Some(section),
            &SECTIONS,
        );
    }
    if section == Some("coverage") && args.technique.as_deref().is_none_or(str::is_empty) {
        return Report::usage(
            COMMAND,
            "The coverage section requires --technique",
            USAGE_MISSING_OPTION,
            "--technique",
            None,
            &[],
        );
    }
    if let Some(name) = &args.name
        && section != Some("vocab")
    {
        return Report::usage(
            COMMAND,
            format!(
                "Only the vocab section takes a name; got {name:?} after {}",
                section.map_or_else(|| "no section".to_owned(), |section| format!("{section:?}"))
            ),
            USAGE_INVALID_VALUE,
            "name",
            None,
            &[],
        );
    }
    let (repo, options) = placement(cx.repo, cx.env, cx.cwd);
    // The catalogue's ATT&CK matrix and field roles are parsed while the
    // workspace loads: both are cached for the run.
    let opened = std::thread::scope(|scope| {
        if section == Some("catalog") {
            scope.spawn(catalogue::warm);
        }
        super::open(options)
    });
    let workspace = match opened {
        Ok(workspace) => workspace,
        Err(message) => return Report::error(COMMAND, message),
    };
    let index = workspace.index();
    let vocabularies = Vocabularies::bundled();
    let is_set = |name: &str| cx.env.get(name).is_some_and(|value| !value.is_empty());
    let platforms = data::platforms(
        workspace.configuration().resolved.get("systems"),
        args.platform.as_deref(),
        &is_set,
    );
    let count = |family: &str| index.objects.get(family).map_or(0, indexmap::IndexMap::len);
    let load_errors = index.load_errors.len() + index.duplicates.len();
    let mut out: Vec<(String, Json)> = vec![
        ("version".into(), Json::str(cx.version)),
        ("repo".into(), Json::str(&repo)),
        (
            "counts".into(),
            Json::object([
                ("rules", count_json(count("rule"))),
                ("threats", count_json(count("threat"))),
                ("objectives", count_json(count("objective"))),
            ]),
        ),
        ("parse_error_count".into(), count_json(load_errors)),
        ("platforms".into(), json(&platforms)),
    ];
    let mut summary: Vec<(String, Json)> = vec![
        ("rules".into(), count_json(count("rule"))),
        ("threats".into(), count_json(count("threat"))),
        ("objectives".into(), count_json(count("objective"))),
        ("load_errors".into(), count_json(load_errors)),
    ];
    let mut body: Vec<Block> = Vec::new();
    match section {
        Some(family @ ("rules" | "threats" | "objectives")) => {
            let uuids = uuids(index, singular(family));
            out.push((family.to_owned(), json(&uuids)));
            body.push(if uuids.is_empty() {
                Block::Lines(vec![Text::plain(&format!("No {family} found"))])
            } else {
                Block::Table(objects_table(index, family, &uuids))
            });
        }
        Some("catalog") => {
            let catalogue = catalogue::build(&workspace);
            out.push(("objects".into(), json(&catalogue.objects)));
            out.push(("edges".into(), json(&catalogue.edges)));
            out.push(("signals".into(), json(&catalogue.signals)));
            out.push(("attack".into(), json(&catalogue.attack)));
            if let Json::Object(members) = json(&catalogue.summary) {
                for (key, value) in members {
                    match summary.iter_mut().find(|(k, _)| *k == key) {
                        Some(slot) => slot.1 = value,
                        None => summary.push((key, value)),
                    }
                }
            }
            if cx.text {
                body.push(Block::Lines(catalogue_lines(&catalogue)));
            }
            crate::app::release(catalogue);
        }
        Some("coverage") => {
            let technique = args.technique.clone().unwrap_or_default();
            let found = match_technique(&technique, &rule_technique_index(index));
            out.push(("coverage".into(), json(&found)));
            let split = if found.count > 0 {
                format!(
                    " ({} own, {} inherited)",
                    found.own.len(),
                    found.inherited.len()
                )
            } else {
                String::new()
            };
            body.push(Block::Lines(vec![Text::plain(&format!(
                "Coverage for {}: {} rule{}{split}",
                found.technique,
                found.count,
                if found.count == 1 { "" } else { "s" }
            ))]));
            if !found.rules.is_empty() {
                body.push(Block::Table(objects_table(index, "rules", &found.rules)));
            }
        }
        Some("vocab") => {
            let files = data::file_vocabularies(&vocabularies, &workspace.configuration().families);
            match &args.name {
                None => {
                    let rows: Vec<data::VocabOverview> =
                        files.iter().map(|v| data::overview(v)).collect();
                    out.push(("vocabularies".into(), json(&rows)));
                    body.push(Block::Table(vocab_list_table(&rows)));
                }
                Some(name) => {
                    let Some(vocabulary) = files.iter().find(|v| v.field() == name) else {
                        let available: Vec<&str> = files.iter().map(|v| v.field()).collect();
                        return Report::usage(
                            COMMAND,
                            format!(
                                "Unknown vocabulary: {name}. Available: {}",
                                available.join(", ")
                            ),
                            USAGE_INVALID_CHOICE,
                            "name",
                            Some(name),
                            &available,
                        );
                    };
                    let detail = data::detail(vocabulary);
                    out.push(("vocabulary".into(), json(&detail)));
                    body.extend(vocab_detail_tables(&detail).into_iter().map(Block::Table));
                }
            }
        }
        _ => body.push(Block::Lines(summary_lines(cx.version, &platforms))),
    }

    let outcome = outcome_line(
        count("rule"),
        count("threat"),
        count("objective"),
        load_errors,
    );
    let mut report = Report::completed(COMMAND, out);
    report.outcome.summary = summary;
    report.outcome_line = Some(outcome);
    if load_errors > 0 {
        report.next("opentide validate", "show where each object failed to load");
        report.outcome.status = "issues".into();
    }
    if args.strict && load_errors > 0 {
        report.outcome.status = "failed".into();
        report.outcome.message = "Repository has objects that failed to load".into();
        report.outcome.exit_code = 1;
        report.outcome.failure = Some(Failure::new(
            ISSUES_FOUND,
            "Repository has objects that failed to load",
        ));
    }
    if cx.text {
        report.body = body;
    }
    // The index is a document tree per object (see `release`).
    crate::app::release(workspace);
    report
}

fn count_json(count: usize) -> Json {
    Json::Int(i64::try_from(count).unwrap_or(i64::MAX))
}

fn singular(section: &str) -> &str {
    match section {
        "rules" => "rule",
        "threats" => "threat",
        _ => "objective",
    }
}

fn uuids(index: &Index, family: &str) -> Vec<String> {
    index
        .objects
        .get(family)
        .map(|objects| objects.keys().cloned().collect())
        .unwrap_or_default()
}

/// `1 rule · 1 threat · 1 objective · 0 load errors`.
fn outcome_line(rules: usize, threats: usize, objectives: usize, load_errors: usize) -> String {
    [
        counted(rules, "rule"),
        counted(threats, "threat"),
        counted(objectives, "objective"),
        counted(load_errors, "load error"),
    ]
    .join(&format!(" {SEPARATOR} "))
}

/// The version and every platform, enabled first.
fn summary_lines(version: &str, platforms: &[PlatformInfo]) -> Vec<Text> {
    let label = Style::new("bold dim");
    let dim = Style::new("dim");
    let mut rows = vec![vec![
        Text::styled("version", &label),
        Text::plain(version),
        Text::default(),
    ]];
    let mut ordered: Vec<&PlatformInfo> = platforms.iter().collect();
    ordered.sort_by_key(|platform| !platform.enabled);
    for (number, platform) in ordered.into_iter().enumerate() {
        let mut caps = Vec::new();
        if platform.can_deploy {
            caps.push("deploy");
        }
        if platform.can_validate {
            caps.push("validate");
        }
        if platform.can_query {
            caps.push("query");
        }
        let mut detail = Text::default();
        if platform.enabled {
            detail.append("enabled", &Style::new("green"));
        } else {
            detail.append("disabled", &dim);
        }
        detail.append(&format!(" {SEPARATOR} "), &dim);
        let caps = if caps.is_empty() {
            "none".to_owned()
        } else {
            caps.join(", ")
        };
        detail.append(&caps, &dim);
        rows.push(vec![
            Text::styled(if number == 0 { "platforms" } else { "" }, &label),
            Text::styled(
                data::label(&platform.name),
                &Style::new(if platform.enabled { "bold" } else { "dim" }),
            ),
            detail,
        ]);
    }
    columns(&rows, 2, &[0])
}

fn title(section: &str) -> &str {
    match section {
        "rules" => "Rules",
        "threats" => "Threats",
        _ => "Objectives",
    }
}

/// UUID and name per object; rules also list their platforms.
fn objects_table(index: &Index, section: &str, uuids: &[String]) -> Table {
    let family = singular(section);
    let mut columns = vec![Column::new("UUID").no_wrap(), Column::new("Name")];
    if family == "rule" {
        columns.push(Column::new("Platforms"));
    }
    let rows = uuids
        .iter()
        .map(|uuid| {
            let root = index
                .objects
                .get(family)
                .and_then(|objects| objects.get(uuid))
                .and_then(opentide_workspace::Object::root);
            let name = root
                .and_then(|root| get(root, "name"))
                .filter(|node| truthy(node))
                .map(|node| node.value.to_string())
                .unwrap_or_default();
            let mut row = vec![uuid.clone(), name];
            if family == "rule" {
                let platforms: Vec<String> = root
                    .map(object_platforms)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                row.push(platforms.join(", "));
            }
            row
        })
        .collect();
    Table {
        title: Some(format!("{} ({})", title(section), uuids.len())),
        caption: None,
        columns,
        rows,
    }
}

/// The catalogue in a few lines: objects, signals, edges by kind, ATT&CK.
fn catalogue_lines(catalogue: &catalogue::Catalogue) -> Vec<Text> {
    let label = Style::new("bold dim");
    let dim = Style::new("dim");
    let row = |name: &str, value: String, detail: String| {
        vec![
            Text::styled(name, &label),
            Text::plain(&value),
            Text::styled(&detail, &dim),
        ]
    };
    let mut families: HashMap<&str, usize> = HashMap::new();
    let mut errors = 0;
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for object in &catalogue.objects {
        match object.loaded_family() {
            Some(family) => *families.entry(family).or_default() += 1,
            None => errors += 1,
        }
        let techniques = object.techniques();
        covered.extend(
            techniques
                .own
                .iter()
                .chain(&techniques.inherited)
                .map(String::as_str),
        );
    }
    let mut kinds: HashMap<&str, usize> = HashMap::new();
    for edge in &catalogue.edges {
        *kinds.entry(edge.kind).or_default() += 1;
    }
    let missing = catalogue.edges.iter().filter(|edge| edge.missing).count();
    let separator = format!(" {SEPARATOR} ");
    let matrix = &catalogue.attack.techniques;
    let reached = covered.iter().filter(|t| matrix.contains_key(**t)).count();
    let mut rows = vec![
        row(
            "objects",
            catalogue.objects.len().to_string(),
            ["threat", "objective", "rule"]
                .iter()
                .map(|family| counted(families.get(family).copied().unwrap_or(0), family))
                .collect::<Vec<_>>()
                .join(&separator),
        ),
        row(
            "signals",
            catalogue.signals.len().to_string(),
            String::new(),
        ),
        row("edges", catalogue.edges.len().to_string(), String::new()),
    ];
    for kind in EDGE_KINDS {
        if let Some(count) = kinds.get(kind).filter(|count| **count > 0) {
            rows.push(row("", count.to_string(), kind.to_owned()));
        }
    }
    if missing > 0 {
        rows.push(row(
            "",
            missing.to_string(),
            "missing: name no object".into(),
        ));
    }
    rows.push(row(
        "att&ck",
        format!("{reached} of {} techniques", matrix.len()),
        format!("{} tactics", catalogue.attack.tactics.len()),
    ));
    rows.push(row("load errors", errors.to_string(), String::new()));
    columns(&rows, 2, &[0])
}

fn yes_no(value: Option<bool>) -> String {
    match value {
        None => "?",
        Some(true) => "yes",
        Some(false) => "no",
    }
    .to_owned()
}

fn vocab_list_table(rows: &[data::VocabOverview]) -> Table {
    Table {
        title: Some(format!("Vocabularies ({})", rows.len())),
        caption: None,
        columns: vec![
            Column::new("Name").no_wrap(),
            Column::new("Entries").right(),
            Column::new("Removed").right(),
            Column::new("Latest revision"),
            Column::new("Staged"),
        ],
        rows: rows
            .iter()
            .map(|vocab| {
                vec![
                    vocab.name.clone(),
                    vocab.entries.to_string(),
                    vocab.removed.to_string(),
                    vocab.latest_revision.clone().unwrap_or_else(|| "-".into()),
                    yes_no(Some(vocab.staged)),
                ]
            })
            .collect(),
    }
}

fn vocab_detail_tables(vocab: &data::VocabDetail) -> Vec<Table> {
    let overview = &vocab.overview;
    let mut summary = vec![
        vec!["Title".to_owned(), overview.title.clone()],
        vec!["Keyed by".to_owned(), vocab.key.to_owned()],
        vec!["Entries".to_owned(), overview.entries.to_string()],
        vec!["Removed keys".to_owned(), overview.removed.to_string()],
        vec![
            "Latest revision".to_owned(),
            overview
                .latest_revision
                .clone()
                .unwrap_or_else(|| "-".into()),
        ],
        vec!["Staged".to_owned(), yes_no(Some(overview.staged))],
    ];
    if !vocab.stages.is_empty() {
        summary.push(vec!["Stages".to_owned(), vocab.stages.join(", ")]);
    }
    vec![
        Table {
            title: Some(format!("Vocabulary {}", overview.name)),
            caption: None,
            columns: vec![Column::new("Key"), Column::new("Value")],
            rows: summary,
        },
        Table {
            title: Some("Revisions".into()),
            caption: None,
            columns: vec![
                Column::new("Revision"),
                Column::new("Introduced").right(),
                Column::new("Removed").right(),
                Column::new("Admitted").right(),
            ],
            rows: vocab
                .revisions
                .iter()
                .map(|r| {
                    vec![
                        r.revision.clone(),
                        r.introduced.to_string(),
                        r.removed.to_string(),
                        r.admitted.to_string(),
                    ]
                })
                .collect(),
        },
        Table {
            title: Some("Pins".into()),
            caption: vocab
                .pins
                .is_empty()
                .then(|| "No object schema pins this vocabulary".to_owned()),
            columns: vec![
                Column::new("Schema").no_wrap(),
                Column::new("Field"),
                Column::new("Revision"),
                Column::new("Admitted").right(),
                Column::new("Scoped"),
            ],
            rows: vocab
                .pins
                .iter()
                .map(|pin| {
                    vec![
                        pin.schema.clone(),
                        pin.field.clone(),
                        if pin.defined {
                            pin.revision.clone()
                        } else {
                            format!("{} (undefined)", pin.revision)
                        },
                        pin.admitted.to_string(),
                        yes_no(pin.scoped),
                    ]
                })
                .collect(),
        },
    ]
}

/// The workspace `info` reads, for the benchmark: the catalogue's document.
pub fn catalogue_document(workspace: &Workspace) -> Json {
    let catalogue = catalogue::build(workspace);
    Json::object([
        ("objects", json(&catalogue.objects)),
        ("edges", json(&catalogue.edges)),
        ("signals", json(&catalogue.signals)),
        ("attack", json(&catalogue.attack)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outcome_line() {
        assert_eq!(
            outcome_line(1, 0, 2, 1),
            "1 rule · 0 threats · 2 objectives · 1 load error"
        );
    }

    #[test]
    fn usage_errors_come_before_the_workspace() {
        let env = Env::default();
        let cx = Context {
            repo: Some("/nonexistent/opentide-test"),
            env: &env,
            cwd: Path::new("/"),
            version: "0",
            text: false,
        };
        let report = run(
            &Args {
                section: Some("rulez".into()),
                ..Args::default()
            },
            &cx,
        );
        let failure = report.outcome.failure.unwrap();
        assert_eq!(failure.code, USAGE_INVALID_CHOICE);
        assert_eq!(failure.suggestion.as_deref(), Some("rules"));
        let report = run(
            &Args {
                section: Some("coverage".into()),
                ..Args::default()
            },
            &cx,
        );
        assert_eq!(report.outcome.failure.unwrap().code, USAGE_MISSING_OPTION);
        let report = run(
            &Args {
                name: Some("it's".into()),
                ..Args::default()
            },
            &cx,
        );
        assert_eq!(
            report.outcome.message,
            "Only the vocab section takes a name; got \"it's\" after no section"
        );
        let report = run(
            &Args {
                section: Some("rules".into()),
                name: Some("a\nb".into()),
                ..Args::default()
            },
            &cx,
        );
        assert_eq!(
            report.outcome.message,
            "Only the vocab section takes a name; got \"a\\nb\" after \"rules\""
        );
        assert_eq!(report.outcome.failure.unwrap().code, USAGE_INVALID_VALUE);
    }
}
