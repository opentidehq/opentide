//! `setup ci`'s pipelines against the oracle's (UC-3.2c, #916): each case of
//! `tests/ci/` (recorded by `tests/ci/oracle.py` from the Python CLI) is
//! rendered from its inputs and compared with the oracle's file: first as
//! the YAML data it holds (the jobs, steps, commands and triggers), then as
//! text, line for line. GitLab's oracle wrote its pipeline with PyYAML's
//! dumper; the template writes the same layout, quoting a value only where
//! YAML would read it as something else.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken case is a failure"
)]

use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use opentide_compile::Json;
use opentide_compile::ci::{Options, Provider, render};

fn cases() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ci");
    let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    found.sort();
    found
}

fn options(inputs: &toml::Table) -> Options {
    let text = |key: &str| inputs[key].as_str().unwrap().to_owned();
    let flag = |key: &str| inputs[key].as_bool().unwrap();
    let list = |value: &toml::Value| -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect()
    };
    let credentials: IndexMap<String, Vec<String>> = inputs["credentials"]
        .as_table()
        .unwrap()
        .iter()
        .map(|(platform, names)| (platform.clone(), list(names)))
        .collect();
    Options {
        provider: Provider::from_name(&text("ci")).unwrap(),
        platforms: list(&inputs["platforms"]),
        staging: flag("staging"),
        inflight: flag("inflight"),
        sharing: flag("sharing"),
        lint_changed: flag("lint_changed"),
        explorer_pages: flag("explorer_pages"),
        python_version: text("python_version"),
        opentide_version: text("opentide_version"),
        default_branch: text("default_branch"),
        docs_output: "docs".into(),
        rules_folder: text("rules_folder"),
        credentials,
    }
}

/// `text` without the lines that name a variable of a platform the recorded
/// oracle lacks (`opentide_schema::platforms::SINCE_ORACLE`): their bundled
/// files name them (`GRAYLOG_TOKEN`), so the pipeline's header lists them
/// where the oracle's has none. A line names one by its `ID_` prefix: its
/// line in the header (`#   NAME`) and in a job's environment
/// (`NAME: ${{ secrets.NAME }}`).
fn without_since_oracle(text: &str) -> String {
    let prefixes: Vec<String> = opentide_schema::platforms::SINCE_ORACLE
        .iter()
        .map(|id| format!("{}_", id.to_ascii_uppercase()))
        .collect();
    text.split_inclusive('\n')
        .filter(|line| {
            !line
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|word| {
                    prefixes
                        .iter()
                        .any(|prefix| word.starts_with(prefix.as_str()))
                })
        })
        .collect()
}

/// The first line the two texts differ on.
fn first_difference(oracle: &str, rendered: &str) -> Option<String> {
    let (a, b): (Vec<&str>, Vec<&str>) = (oracle.lines().collect(), rendered.lines().collect());
    for index in 0..a.len().max(b.len()) {
        let (left, right) = (a.get(index), b.get(index));
        if left != right {
            return Some(format!(
                "line {}:\n  oracle: {left:?}\n  rust:   {right:?}",
                index + 1
            ));
        }
    }
    (oracle != rendered).then(|| "line endings differ".to_owned())
}

/// The pipeline with every line that mentions a platform the recorded oracle
/// lacks (`opentide_schema::platforms::SINCE_ORACLE`) removed: its id in
/// underscore or hyphen form, matched case-insensitively, which also catches
/// its credential variables (`$EXABEAM_CLIENT_ID`). No other platform id is a
/// substring of these, and 0.23.0 output holds none of them, so a 0.23.0
/// render is returned unchanged.
fn without_since_oracle_lines(text: &str) -> String {
    let tokens: Vec<String> = opentide_schema::platforms::SINCE_ORACLE
        .iter()
        .flat_map(|id| [(*id).to_owned(), id.replace('_', "-")])
        .collect();
    text.split_inclusive('\n')
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !tokens.iter().any(|token| lower.contains(token.as_str()))
        })
        .collect()
}

fn data(text: &str) -> Option<Json> {
    let document = opentide_schema::node::load(text).ok()?;
    document.root().map(|root| Json::from_node(root))
}

#[test]
fn pipelines_are_the_oracles() {
    let mut problems = Vec::new();
    let found = cases();
    assert!(found.len() >= 12, "only {} cases", found.len());
    for case in found {
        let name = case.file_stem().unwrap().to_string_lossy().into_owned();
        let inputs: toml::Table = std::fs::read_to_string(&case).unwrap().parse().unwrap();
        let options = options(&inputs);
        assert_eq!(options.provider.path(), inputs["path"].as_str().unwrap());
        let oracle = std::fs::read_to_string(case.with_extension("yml")).unwrap();
        let rendered = match render(&options) {
            Ok(rendered) => without_since_oracle(&rendered),
            Err(error) => {
                problems.push(format!("{name}: {error}"));
                continue;
            }
        };
        // A file the user commits: LF on every OS, as the oracle recorded it.
        if rendered.contains('\r') || oracle.contains('\r') {
            problems.push(format!(
                "{name}: CR in the {} pipeline",
                if rendered.contains('\r') {
                    "rendered"
                } else {
                    "oracle's"
                }
            ));
            continue;
        }
        if let Some(dir) = std::env::var_os("OPENTIDE_CI_RENDERED") {
            std::fs::write(Path::new(&dir).join(format!("{name}.yml")), &rendered).unwrap();
        }
        // The recorded pipeline (0.23.0) predates the platforms the train ports
        // onto it; their bundled credentials and query stages add lines the
        // oracle lacks. Drop those lines before comparing. On this oracle none
        // are present, so this is a no-op until a row lands.
        let rendered = without_since_oracle_lines(&rendered);
        let same_data = data(&rendered).is_some() && data(&oracle) == data(&rendered);
        if !same_data {
            problems.push(format!(
                "{name}: the pipeline holds other data\n{}",
                first_difference(&oracle, &rendered).unwrap_or_default()
            ));
        } else if let Some(difference) = first_difference(&oracle, &rendered) {
            problems.push(format!("{name}: {difference}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n\n"));
}
