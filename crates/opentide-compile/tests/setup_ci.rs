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

fn data(text: &str) -> Option<Json> {
    let document = opentide_schema::node::load(text).ok()?;
    document.root().map(|root| Json::from_node(root))
}

/// The platforms the 0.23.0 recordings predate: the `platforms-after-0.23`
/// difference of opentide-schema's `tests/oracle/config_cases.toml`, the one
/// list the oracle tests share until the oracle moves to 0.28.0 (O2).
fn platforms_after_the_oracle() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../opentide-schema/tests/oracle/config_cases.toml");
    let cases: toml::Table = std::fs::read_to_string(path).unwrap().parse().unwrap();
    cases["difference"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|difference| difference["id"].as_str() == Some("platforms-after-0.23"))
        .flat_map(|difference| difference["fields"].as_array().unwrap().clone())
        .map(|field| field.as_str().unwrap().to_owned())
        .collect()
}

/// `rendered` without the lines that name one variable the bundled files of
/// `later` platforms reference: the header's `#   NAME` and a job's
/// `NAME: ${{ secrets.NAME }}`. 0.28.0 lists and maps them
/// (`platform_credential_names`); the 0.23.0 recordings could not.
fn without_later_variables(rendered: &str, later: &[String]) -> String {
    let texts: Vec<&str> = later
        .iter()
        .filter_map(|platform| {
            opentide_schema::configuration::bundled::text(&format!("platforms/{platform}.toml"))
        })
        .collect();
    let later_variable = |name: &str| {
        !name.is_empty()
            && name
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
            && texts.iter().any(|text| {
                text.contains(&format!("${name}")) || text.contains(&format!("${{{name}}}"))
            })
    };
    rendered
        .split_inclusive('\n')
        .filter(|line| {
            let body = line.trim_start().trim_start_matches('#').trim();
            let name = body.split(':').next().unwrap_or_default().trim();
            let rest = body.get(name.len()..).unwrap_or_default().trim();
            let only_names_it = rest.is_empty()
                || rest.trim_start_matches(':').trim() == format!("${{{{ secrets.{name} }}}}");
            !(only_names_it && later_variable(name))
        })
        .collect()
}

#[test]
fn pipelines_are_the_oracles() {
    let later = platforms_after_the_oracle();
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
            Ok(rendered) => without_later_variables(&rendered, &later),
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
