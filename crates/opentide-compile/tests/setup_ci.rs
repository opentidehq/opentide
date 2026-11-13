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

/// The variables only a platform ported on the catch-up train names in its
/// bundled file: a platform no case of the oracle (0.23.0) lists. The
/// pipeline's header and GitHub's deploy jobs name them; the recordings do
/// not, until the oracle moves (O2).
fn ported_variables(oracle_platforms: &[String]) -> Vec<String> {
    let references = |text: &str| -> Vec<String> {
        text.split('$')
            .skip(1)
            .map(|rest| {
                rest.chars()
                    .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                    .collect::<String>()
            })
            .filter(|name| name.starts_with(|c: char| c.is_ascii_uppercase()))
            .collect()
    };
    let file_of = |id: &str| format!("platforms/{id}.toml");
    let mut known = Vec::new();
    let mut ported = Vec::new();
    for (path, text) in opentide_schema::configuration::bundled::FILES {
        let Some(id) = path
            .strip_prefix("platforms/")
            .and_then(|name| name.strip_suffix(".toml"))
        else {
            continue;
        };
        if oracle_platforms
            .iter()
            .any(|known| file_of(known) == file_of(id))
        {
            known.extend(references(text));
        } else {
            ported.extend(references(text));
        }
    }
    ported.retain(|name| !known.contains(name));
    ported
}

/// `text` without the lines that name one of `variables`.
fn without_lines_naming(text: &str, variables: &[String]) -> String {
    text.split_inclusive('\n')
        .filter(|line| !variables.iter().any(|name| line.contains(name.as_str())))
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
    let mut oracle_platforms: Vec<String> = Vec::new();
    for case in &found {
        let inputs: toml::Table = std::fs::read_to_string(case).unwrap().parse().unwrap();
        for platform in options(&inputs).platforms {
            if !oracle_platforms.contains(&platform) {
                oracle_platforms.push(platform);
            }
        }
    }
    let ported = ported_variables(&oracle_platforms);
    for case in found {
        let name = case.file_stem().unwrap().to_string_lossy().into_owned();
        let inputs: toml::Table = std::fs::read_to_string(&case).unwrap().parse().unwrap();
        let options = options(&inputs);
        assert_eq!(options.provider.path(), inputs["path"].as_str().unwrap());
        let oracle = std::fs::read_to_string(case.with_extension("yml")).unwrap();
        let rendered = match render(&options) {
            Ok(rendered) => without_lines_naming(&rendered, &ported),
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
