//! Reads the parity dashboard's [`Inputs`](crate::parity::Inputs) from a
//! repository checkout. Each source is optional until the work item that
//! creates it lands; a missing source reads as "not there yet", never as an
//! error, and the page says so.
//!
//! | Source | Path | Work item |
//! |--------|------|-----------|
//! | Recordings | `tests/golden/cases/<command>/<mode>/<fixture>/<case>/` (a multi-word command joined with `.`) | UC-0.5 (#803) |
//! | Approved diffs | `tests/golden/APPROVED_DIFFS.toml`, parsed and checked by `opentide-compare` | UC-0.7 (#805) |
//! | Engine state | `--engines FILE`: `{"rust": [["validate"], ...], "flipped": [...]}`, which `scripts/parity_engines.py` writes from `RUST_COMMANDS` in `src/opentide/cli/engines.py` | UC-0.7 (#805) |
//! | Compare results | `--compare FILE`: the `opentide_compare::RunReport` JSON of `golden check --engine compare`; case ids `<command>/<mode>/<fixture>/<variant>`; CI uploads it as `golden-compare` from `golden.yml` | UC-0.5, UC-0.7 |

use crate::parity::{Cell, Engine, Inputs};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The directory of the recordings of `opentide` itself (UC-0.5).
const ROOT_COMMAND: &str = "_root";

/// The recordings under `cases` (`tests/golden/cases`): one [`Cell`] per
/// command × mode × fixture that holds at least one case directory. Missing
/// directory: none.
///
/// # Errors
///
/// A directory that cannot be read, or a name that is not UTF-8.
pub fn goldens(cases: &Path) -> Result<BTreeSet<Cell>> {
    let mut cells = BTreeSet::new();
    if !cases.is_dir() {
        return Ok(cells);
    }
    for command in dirs(cases)? {
        for mode in dirs(&cases.join(&command))? {
            for fixture in dirs(&cases.join(&command).join(&mode))? {
                let fixture_dir = cases.join(&command).join(&mode).join(&fixture);
                if !dirs(&fixture_dir)?.is_empty() {
                    // `_root` holds the recordings of `opentide` with no
                    // subcommand; its command path is empty.
                    let path = if command == ROOT_COMMAND {
                        String::new()
                    } else {
                        command.replace('.', " ")
                    };
                    cells.insert(Cell {
                        command: path,
                        mode: mode.clone(),
                        corpus: fixture,
                    });
                }
            }
        }
    }
    Ok(cells)
}

/// The names of the directories in `dir`, sorted.
fn dirs(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        if entry.file_type()?.is_dir() {
            let name = entry.file_name();
            names.push(
                name.to_str()
                    .with_context(|| format!("{} is not UTF-8", entry.path().display()))?
                    .to_owned(),
            );
        }
    }
    names.sort();
    Ok(names)
}

/// The approved diffs per command, from the ledger's text.
///
/// # Errors
///
/// The ledger does not parse or fails its own checks.
pub fn approved_diffs(text: &str) -> Result<BTreeMap<String, usize>> {
    let ledger = opentide_compare::ledger::Ledger::parse(text)
        .map_err(|error| anyhow::anyhow!("{}", error.problems.join("\n")))?;
    let mut counts = BTreeMap::new();
    for entry in ledger.entries {
        *counts.entry(entry.command).or_default() += 1;
    }
    Ok(counts)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnginesFile {
    rust: Vec<Vec<String>>,
    #[serde(default)]
    flipped: Vec<Vec<String>>,
}

/// The engine state, from the JSON `scripts/parity_engines.py` writes. A
/// flipped command must have a Rust implementation.
///
/// # Errors
///
/// The text is not that document, or a flipped command has no Rust
/// implementation.
pub fn engines(json: &str) -> Result<BTreeMap<String, Engine>> {
    let file: EnginesFile = serde_json::from_str(json).context("read the engine state")?;
    let mut engines: BTreeMap<String, Engine> = file
        .rust
        .iter()
        .map(|words| (words.join(" "), Engine::Shadow))
        .collect();
    for words in &file.flipped {
        let command = words.join(" ");
        match engines.get_mut(&command) {
            Some(engine) => *engine = Engine::Flipped,
            None => bail!("`{command}` is flipped but has no Rust implementation"),
        }
    }
    Ok(engines)
}

#[derive(Deserialize)]
struct RunReport {
    schema_version: u32,
    cases: Vec<CaseReport>,
    #[serde(default)]
    stale: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct CaseReport {
    command: String,
    case: String,
    equal: bool,
}

/// The compare results per recording, from a `RunReport`: a recording passes
/// when every one of its cases is equal. Also the number of stale ledger
/// entries the run found.
///
/// # Errors
///
/// The text is not a `RunReport` of schema version 1, or a case id is not
/// `<command>/<mode>/<fixture>/<variant>` for its command.
pub fn compare(json: &str) -> Result<(BTreeMap<Cell, bool>, usize)> {
    let report: RunReport = serde_json::from_str(json).context("read the compare report")?;
    if report.schema_version != 1 {
        bail!(
            "the compare report has schema_version {}; this dashboard reads 1",
            report.schema_version
        );
    }
    let mut cells: BTreeMap<Cell, bool> = BTreeMap::new();
    for case in report.cases {
        // UC-0.5's case id: <command dir>/<mode>/<fixture>/<variant>, the
        // command's words joined by `.` (`_root` for `opentide` itself).
        let parts: Vec<&str> = case.case.splitn(4, '/').collect();
        let [dir, mode, corpus, _variant] = parts[..] else {
            bail!(
                "case `{}` of `{}` is not <command>/<mode>/<fixture>/<variant>",
                case.case,
                case.command
            );
        };
        let expected = if case.command.is_empty() {
            ROOT_COMMAND.to_owned()
        } else {
            case.command.replace(' ', ".")
        };
        if dir != expected {
            bail!(
                "case `{}` names command directory `{dir}`, but its command is `{}`",
                case.case,
                case.command
            );
        }
        let cell = Cell {
            command: case.command.clone(),
            mode: mode.to_owned(),
            corpus: corpus.to_owned(),
        };
        let equal = cells.entry(cell).or_insert(true);
        *equal &= case.equal;
    }
    Ok((cells, report.stale.len()))
}

/// Every input: the repository's under `root`, plus the engine state and the
/// compare results when their files are given.
///
/// # Errors
///
/// A source exists but cannot be read or does not parse.
pub fn read(
    root: &Path,
    engines_file: Option<&Path>,
    compare_file: Option<&Path>,
) -> Result<Inputs> {
    let ledger_path = root
        .join("tests")
        .join("golden")
        .join("APPROVED_DIFFS.toml");
    let approved = if ledger_path.is_file() {
        let text = std::fs::read_to_string(&ledger_path)
            .with_context(|| format!("read {}", ledger_path.display()))?;
        Some(approved_diffs(&text).with_context(|| format!("parse {}", ledger_path.display()))?)
    } else {
        None
    };
    let read_file = |path: &Path| {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
    };
    let engines = match engines_file {
        Some(path) => {
            engines(&read_file(path)?).with_context(|| format!("parse {}", path.display()))?
        }
        None => BTreeMap::new(),
    };
    let (compare, stale) = match compare_file {
        Some(path) => {
            let (cells, stale) =
                compare(&read_file(path)?).with_context(|| format!("parse {}", path.display()))?;
            (Some(cells), Some(stale))
        }
        None => (None, None),
    };
    Ok(Inputs {
        goldens: goldens(&root.join("tests").join("golden").join("cases"))?,
        engines,
        compare,
        stale_entries: stale,
        approved_diffs: approved,
        faults: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_one_cell_per_command_mode_and_fixture_with_a_case() {
        let root = std::env::temp_dir().join(format!("xtask-parity-{}", std::process::id()));
        let cases = root.join("cases");
        for dir in [
            "info.catalog/json/tide_corpus/default",
            "info.catalog/json/tide_corpus/other",
            "validate/plain/heavy/default",
            "validate/json/empty", // no case: not a recording
            "_root/plain/none/help",
        ] {
            std::fs::create_dir_all(cases.join(dir)).unwrap();
        }
        std::fs::write(cases.join("README.md"), "not a command").unwrap();
        let cells = goldens(&cases).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        let cells: Vec<(String, String, String)> = cells
            .into_iter()
            .map(|c| (c.command, c.mode, c.corpus))
            .collect();
        assert_eq!(
            cells,
            [
                (String::new(), "plain".into(), "none".into()),
                ("info catalog".into(), "json".into(), "tide_corpus".into()),
                ("validate".into(), "plain".into(), "heavy".into()),
            ]
        );
    }

    #[test]
    fn a_missing_source_is_empty() {
        let inputs = read(Path::new("/nonexistent/opentide"), None, None).unwrap();
        assert_eq!(inputs, Inputs::default());
    }

    #[test]
    fn counts_the_ledgers_entries_per_command() {
        let entry = |command: &str, case: &str| {
            format!(
                "[[diff]]\ncommand = \"{command}\"\ncase = \"{case}\"\ntarget = \"stdout\"\n\
                 rule = \"json:/summary/rules\"\noracle = \"3\"\ncandidate = \"4\"\n\
                 reason = \"r\"\nissue = \"https://github.com/opentidehq/opentide/issues/817\"\n\
                 changelog = \"**c**\"\n"
            )
        };
        let text = [
            entry("info", "json/*"),
            entry("info", "plain/*"),
            entry("validate", "*"),
        ]
        .join("\n");
        assert_eq!(
            approved_diffs(&text).unwrap(),
            [("info".to_owned(), 2), ("validate".to_owned(), 1)].into()
        );
        assert_eq!(
            approved_diffs("# only comments\n").unwrap(),
            BTreeMap::new()
        );
        assert!(approved_diffs("[[diff]]\ncommand = \"info\"\n").is_err());
    }

    #[test]
    fn reads_the_engine_state() {
        let engines =
            engines(r#"{"rust": [["validate"], ["info", "catalog"]], "flipped": [["validate"]]}"#)
                .unwrap();
        assert_eq!(
            engines,
            [
                ("info catalog".to_owned(), Engine::Shadow),
                ("validate".to_owned(), Engine::Flipped)
            ]
            .into()
        );
        assert!(engines_err(r#"{"rust": [], "flipped": [["validate"]]}"#).contains("no Rust"));
        assert!(engines_err(r#"{"rust": [], "default": []}"#).contains("engine state"));
    }

    fn engines_err(json: &str) -> String {
        format!("{:#}", engines(json).unwrap_err())
    }

    #[test]
    fn a_recording_passes_compare_when_every_case_is_equal() {
        let (cells, stale) = compare(
            r#"{"schema_version": 1, "equal": false, "stale": [{"entry": 1}], "cases": [
                {"command": "validate", "case": "validate/json/tide_corpus/default", "equal": true, "differences": [], "omitted": 0, "approved": []},
                {"command": "validate", "case": "validate/json/tide_corpus/strict", "equal": false, "differences": [], "omitted": 0, "approved": []},
                {"command": "validate", "case": "validate/plain/tide_corpus/default", "equal": true, "differences": [], "omitted": 0, "approved": []}
            ]}"#,
        )
        .unwrap();
        let cell = |mode: &str| Cell {
            command: "validate".into(),
            mode: mode.into(),
            corpus: "tide_corpus".into(),
        };
        assert_eq!(cells, [(cell("json"), false), (cell("plain"), true)].into());
        assert_eq!(stale, 1);
        let bad = compare(
            r#"{"schema_version": 1, "cases": [{"command": "x", "case": "json", "equal": true}]}"#,
        );
        assert!(format!("{:#}", bad.unwrap_err()).contains("<mode>/<fixture>/"));
        let future = compare(r#"{"schema_version": 2, "cases": []}"#);
        assert!(format!("{:#}", future.unwrap_err()).contains("schema_version 2"));
    }
}
