//! `setup ci`'s pipelines against the oracle's (UC-3.2c, #916): each case of
//! `tests/ci/` (recorded by `tests/ci/oracle.py` from the Python CLI) is
//! rendered from its inputs and compared with the oracle's file: first as
//! the YAML data it holds (the jobs, steps, commands and triggers), then as
//! text, line for line. GitLab's oracle wrote its pipeline with PyYAML's
//! dumper; the template writes the same layout, quoting a value only where
//! YAML would read it as something else. The oracle is retired (#1142): a
//! deliberate change to a pipeline updates its `.yml` here in the same
//! change (`OPENTIDE_CI_RENDERED=<dir>` writes what the templates render),
//! as the tenants' own credential variables did (#1655).

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
        sharing_credentials: Vec::new(),
        variable_groups: inputs.get("variable_groups").map(list).unwrap_or_default(),
        app_token: inputs.get("app_token").is_some_and(|value| value.as_bool().unwrap()),
        user_region: None,
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
            Ok(rendered) => rendered,
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

/// The major of each `actions/<name>` this repository's own workflows pin
/// (`uses: actions/<name>@<sha> # v7.0.1` or `@v7`), the newest of each.
fn repository_action_majors() -> IndexMap<String, u32> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut majors: IndexMap<String, u32> = IndexMap::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path
            .extension()
            .is_some_and(|ext| ext == "yml" || ext == "yaml")
        {
            continue;
        }
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            let Some((_, uses)) = line.split_once("uses: actions/") else {
                continue;
            };
            let (action, rest) = uses.split_once('@').unwrap();
            let (reference, comment) = rest.split_once('#').unwrap_or((rest, ""));
            let version = [reference, comment]
                .iter()
                .find_map(|text| text.trim().strip_prefix('v'));
            let major = version
                .and_then(|text| text.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|digits| digits.parse::<u32>().ok());
            if let Some(major) = major {
                let newest = majors.entry(action.to_owned()).or_insert(major);
                *newest = (*newest).max(major);
            }
        }
    }
    majors
}

/// Majors the generated workflow must pin at least, for actions this
/// repository's own workflows do not use: both still ran on Node 20 before.
const FIXED_MINIMUMS: [(&str, u32); 2] = [("upload-pages-artifact", 5), ("deploy-pages", 5)];

/// The generated GitHub workflow pins no `actions/*` major older than the one
/// this repository's own workflows pin for the same action, nor older than
/// [`FIXED_MINIMUMS`], so a generated pipeline does not run on a runtime
/// GitHub is retiring (Node 20).
#[test]
fn generated_actions_are_not_older_than_the_repositorys_own() {
    let mut minimums = repository_action_majors();
    for (action, major) in FIXED_MINIMUMS {
        let entry = minimums.entry(action.to_owned()).or_insert(major);
        *entry = (*entry).max(major);
    }
    let inputs: toml::Table = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ci/github-default.toml"),
    )
    .unwrap()
    .parse()
    .unwrap();
    let mut options = options(&inputs);
    options.explorer_pages = true;
    let written = render(&options).unwrap();
    let mut seen = 0;
    let mut stale = Vec::new();
    for line in written.lines() {
        let Some((_, uses)) = line.split_once("uses: actions/") else {
            continue;
        };
        let Some((action, version)) = uses.trim().split_once('@') else {
            continue;
        };
        let Some(newest) = minimums.get(action) else {
            continue;
        };
        let Ok(major) = version.trim_start_matches('v').parse::<u32>() else {
            continue;
        };
        seen += 1;
        if major < *newest {
            stale.push(format!("actions/{action}@v{major} (needs v{newest})"));
        }
    }
    assert!(
        stale.is_empty(),
        "the generated workflow pins older actions than this repository does: {}.\n\
         Bump them in crates/opentide-compile/src/ci/templates/github.yml.j2, regenerate \
         crates/opentide-compile/tests/ci/*.yml (OPENTIDE_CI_RENDERED=<dir> cargo test -p \
         opentide-compile --test setup_ci, then copy the files) and review the CLI snapshots \
         (INSTA_UPDATE=always cargo test -p opentide-cli --test cli_snapshots).",
        stale.join(", ")
    );
    assert!(seen >= 5, "only {seen} actions compared:\n{written}");
}
