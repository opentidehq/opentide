//! Reads the parity dashboard's [`Inputs`](crate::parity::Inputs) from a
//! repository checkout. Each source is optional until the work item that
//! creates it lands; a missing source reads as "not there yet", never as an
//! error, and the page says so.
//!
//! | Source | Path | Work item |
//! |--------|------|-----------|
//! | Recordings | `tests/golden/cases/<command>/<mode>/<fixture>/<case>/` (a multi-word command joined with `.`) | UC-0.5 (#803) |

use crate::parity::{Cell, Inputs};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::Path;

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
                    cells.insert(Cell {
                        command: command.replace('.', " "),
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

/// Every input under the repository `root`.
///
/// # Errors
///
/// A source exists but cannot be read.
pub fn read(root: &Path) -> Result<Inputs> {
    Ok(Inputs {
        goldens: goldens(&root.join("tests").join("golden").join("cases"))?,
        ..Inputs::default()
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
                ("info catalog".into(), "json".into(), "tide_corpus".into()),
                ("validate".into(), "plain".into(), "heavy".into()),
            ]
        );
    }

    #[test]
    fn a_missing_source_is_empty() {
        let inputs = read(Path::new("/nonexistent/opentide")).unwrap();
        assert_eq!(inputs, Inputs::default());
    }
}
