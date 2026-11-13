//! The configuration checks against the oracle (UC-1.5, #811): every case of
//! `tests/oracle/config_cases.toml` run through `opentide_schema::configuration`
//! and compared with `tests/oracle/config_table.json`, what opentide 0.23.0
//! reports for it (`config_table.py`): each finding's code, severity, field
//! path, message, file and context; each workspace's resolved configuration
//! as JSON and its findings, or the error resolution stops on; each
//! `lint.toml`'s settings or error; each `sharing.toml`'s findings.
//!
//! A case whose result differs names the `[[difference]]` that explains it.
//! A difference lists the `fields` it may change (`message`, `resolved`, ...):
//! every other field of such a case (code, severity, field path, file, line,
//! column, context) is still compared with the oracle's. A case that names a
//! difference and does not differ fails, as does a difference no case names.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers: a fixture that does not parse fails the test"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use opentide_schema::configuration::checks::{self, Layers};
use opentide_schema::configuration::lint::{FilenameConfig, METADATA_KEYS, parse_lint_config};
use opentide_schema::configuration::merge::merge_layers;
use opentide_schema::configuration::resolve::{Folder, Instance, ResolveError, resolve};
use opentide_schema::configuration::{Finding, bundled, toml as config_toml};
use serde_json::{Map, Value as Json, json};

const TABLE: &str = include_str!("oracle/config_table.json");
const CASES: &str = include_str!("oracle/config_cases.toml");
const ROOT: &str = "<root>/parent/ws/.opentide/configurations";
const PARENT: &str = "<root>/parent/.opentide/configurations";

fn finding_json(finding: &Finding) -> Json {
    json!({
        "code": finding.code,
        "severity": finding.severity.as_str(),
        "field_path": finding.field_path,
        "message": finding.message,
        "file_path": finding.file_path,
        "context": finding.context,
    })
}

fn strings(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn folder(path: &str, files: Option<&toml::Value>) -> Folder {
    let mut folder = Folder {
        path: path.to_owned(),
        ..Folder::default()
    };
    if let Some(files) = files.and_then(toml::Value::as_table) {
        for (relative, text) in files {
            folder
                .files
                .push((relative.clone(), text.as_str().unwrap().to_owned()));
            if let Some((top, _)) = relative.split_once('/')
                && !folder.folders.iter().any(|seen| seen == top)
            {
                folder.folders.push(top.to_owned());
            }
        }
    }
    folder
}

fn text_case(case: &toml::Value) -> Json {
    let parse_all = |key: &str| -> Option<Vec<_>> {
        case.get(key).map(|_| {
            strings(case.get(key))
                .iter()
                .map(|text| config_toml::parse(text).unwrap())
                .collect()
        })
    };
    let earlier = parse_all("earlier");
    let later = parse_all("later").unwrap_or_default();
    let layers = Layers {
        earlier: earlier.as_ref().map(|nodes| nodes.iter().collect()),
        later: later.iter().collect(),
        status_names: case
            .get("status_names")
            .map(|_| strings(case.get("status_names"))),
        sharing_directory: case
            .get("sharing_directory")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false),
        partial: case
            .get("partial")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false),
    };
    let path = case["path"].as_str().unwrap();
    let text = case["text"].as_str().unwrap();
    Json::Array(
        checks::text_issues(path, text, &layers)
            .iter()
            .map(finding_json)
            .collect(),
    )
}

fn workspace_case(case: &toml::Value) -> Json {
    let workspace = folder(ROOT, case.get("files"));
    let parent = case.get("parent").map(|files| folder(PARENT, Some(files)));
    match resolve(&Instance {
        workspace: Some(&workspace),
        overlay: None,
        parent: parent.as_ref(),
        // The oracle runs without OPENTIDE_TIDE_WORKSPACE.
        skip_parent: false,
    }) {
        Ok(resolved) => json!({
            "resolved": resolved.to_json(),
            "issues": resolved.issues().iter().map(finding_json).collect::<Vec<_>>(),
        }),
        Err(ResolveError::Parse {
            path,
            message,
            line,
            column,
        }) => json!({"error": {
            "code": "config_parse", "path": path, "message": message, "line": line, "column": column,
        }}),
        Err(ResolveError::Retired { path, message }) => json!({"error": {
            "code": "retired_configuration_file", "path": path, "message": message,
            "line": null, "column": null,
        }}),
        Err(ResolveError::Proxy(message)) => json!({"error": {"code": null, "message": message}}),
    }
}

fn filenames_json(config: &FilenameConfig) -> Json {
    let kinds: Map<String, Json> = config
        .kinds
        .iter()
        .map(|(kind, own)| (kind.clone(), filenames_json(own)))
        .collect();
    json!({
        "style": config.style,
        "pattern": config.pattern,
        "pattern_key": config.pattern_key,
        "kinds": kinds,
    })
}

fn lint_case(case: &toml::Value) -> Json {
    let bundled = config_toml::parse(bundled::text("lint.toml").unwrap()).unwrap();
    let own = config_toml::parse(case["text"].as_str().unwrap()).unwrap();
    let merged = merge_layers([&bundled, &own]);
    match parse_lint_config(Some(&merged)) {
        Err(error) => json!({"error": error.0}),
        Ok(config) => {
            let checks: Map<String, Json> = config
                .checks
                .iter()
                .map(|(name, check)| {
                    (
                        name.clone(),
                        json!({"enabled": check.enabled, "severity": check.severity}),
                    )
                })
                .collect();
            json!({
                "checks": checks,
                "required_metadata": config.required_metadata,
                "filenames": filenames_json(&config.filenames),
            })
        }
    }
}

fn sharing_case(case: &toml::Value) -> Json {
    let workspace = folder(ROOT, case.get("files"));
    let parent = case.get("parent").map(|files| folder(PARENT, Some(files)));
    let resolved = resolve(&Instance {
        workspace: Some(&workspace),
        overlay: None,
        parent: parent.as_ref(),
        // The oracle runs without OPENTIDE_TIDE_WORKSPACE.
        skip_parent: false,
    })
    .unwrap();
    let statuses = resolved
        .get("deployment")
        .map(checks::status_names)
        .unwrap_or_default();
    let layer = |folder: &Folder| {
        (
            folder.path.clone(),
            folder
                .files
                .iter()
                .find(|(path, _)| path == "sharing.toml")
                .map(|(_, text)| text.clone()),
            folder.folders.iter().any(|name| name == "sharing"),
        )
    };
    let mut layers = vec![(
        "<bundled>".to_owned(),
        bundled::text("sharing.toml").map(str::to_owned),
        false,
    )];
    layers.push(layer(&workspace));
    if let Some(parent) = &parent {
        layers.push(layer(parent));
    }
    Json::Array(
        checks::sharing_config_issues(&layers, &statuses)
            .iter()
            .map(finding_json)
            .collect(),
    )
}

/// The paths at which `rust` differs from `oracle`, apart from the members
/// named in `allowed` (at any depth). An array of another length differs as
/// a whole.
fn differences_outside(
    oracle: &Json,
    rust: &Json,
    allowed: &BTreeSet<String>,
    path: &str,
    out: &mut Vec<String>,
) {
    match (oracle, rust) {
        (Json::Object(left), Json::Object(right)) => {
            let keys: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
            for key in keys {
                if allowed.contains(key.as_str()) {
                    continue;
                }
                let at = format!("{path}/{key}");
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => {
                        differences_outside(left, right, allowed, &at, out);
                    }
                    _ => out.push(at),
                }
            }
        }
        (Json::Array(left), Json::Array(right)) if left.len() == right.len() => {
            for (index, (left, right)) in left.iter().zip(right).enumerate() {
                differences_outside(left, right, allowed, &format!("{path}/{index}"), out);
            }
        }
        _ if oracle == rust => {}
        _ => out.push(if path.is_empty() {
            "/".to_owned()
        } else {
            path.to_owned()
        }),
    }
}

/// Checks one case against the oracle; a failure's description, if any.
fn compare(
    id: &str,
    oracle: &Json,
    rust: &Json,
    difference: Option<(&str, &BTreeSet<String>)>,
) -> Option<String> {
    let shown = || {
        format!(
            "\n  oracle: {}\n  rust:   {}",
            serde_json::to_string(oracle).unwrap(),
            serde_json::to_string(rust).unwrap()
        )
    };
    let Some((name, allowed)) = difference else {
        return (rust != oracle).then(|| format!("{id}:{}", shown()));
    };
    if rust == oracle {
        return Some(format!("{id}: names `{name}` but matches the oracle"));
    }
    let mut outside = Vec::new();
    differences_outside(oracle, rust, allowed, "", &mut outside);
    (!outside.is_empty()).then(|| {
        format!(
            "{id}: `{name}` may change {allowed:?}, but {} differ{}",
            outside.join(", "),
            shown()
        )
    })
}

#[test]
fn configuration_cases_match_the_oracle_or_name_their_difference() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    let cases: toml::Value = toml::from_str(CASES).unwrap();
    let differences: BTreeMap<String, BTreeSet<String>> = cases["difference"]
        .as_array()
        .unwrap()
        .iter()
        .map(|difference| {
            let fields: BTreeSet<String> = strings(difference.get("fields")).into_iter().collect();
            let id = difference["id"].as_str().unwrap().to_owned();
            assert!(!fields.is_empty(), "difference `{id}` lists no `fields`");
            (id, fields)
        })
        .collect();
    let mut used = BTreeSet::new();
    let mut failures = Vec::new();
    for case in cases["case"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let rust = match case["kind"].as_str().unwrap() {
            "text" => text_case(case),
            "workspace" => workspace_case(case),
            "lint" => lint_case(case),
            "sharing" => sharing_case(case),
            other => panic!("{id}: unknown kind {other}"),
        };
        let oracle = &table["cases"][id];
        // One difference's name, or a list of them: their fields together.
        let names: Vec<&str> = match case.get("difference") {
            Some(toml::Value::String(name)) => vec![name.as_str()],
            Some(toml::Value::Array(names)) => {
                names.iter().filter_map(toml::Value::as_str).collect()
            }
            _ => Vec::new(),
        };
        let mut fields = BTreeSet::new();
        for name in &names {
            fields.extend(
                differences
                    .get(*name)
                    .unwrap_or_else(|| panic!("{id}: unknown difference {name}"))
                    .iter()
                    .cloned(),
            );
            used.insert((*name).to_owned());
        }
        let joined = names.join(" + ");
        let difference = (!names.is_empty()).then_some((joined.as_str(), &fields));
        failures.extend(compare(id, oracle, &rust, difference));
    }
    for name in differences.keys() {
        if !used.contains(name) {
            failures.push(format!("difference `{name}` is named by no case"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_difference_still_compares_the_fields_it_does_not_name() {
    let allowed: BTreeSet<String> = ["message".to_owned()].into();
    let oracle = json!([{"code": "config_parse", "message": "a", "line": 1, "column": 5}]);
    let same_place = json!([{"code": "config_parse", "message": "b", "line": 1, "column": 5}]);
    assert_eq!(
        compare("c", &oracle, &same_place, Some(("d", &allowed))),
        None
    );
    for moved in [
        json!([{"code": "config_parse", "message": "b", "line": 1, "column": 6}]),
        json!([{"code": "unknown_key", "message": "b", "line": 1, "column": 5}]),
        json!([{"code": "config_parse", "message": "b", "line": 1}]),
        json!([]),
    ] {
        assert!(
            compare("c", &oracle, &moved, Some(("d", &allowed))).is_some(),
            "{moved}"
        );
    }
    assert!(compare("c", &oracle, &oracle, Some(("d", &allowed))).is_some());
    assert!(compare("c", &oracle, &same_place, None).is_some());
}

#[test]
fn configuration_bundled_files_are_the_folder_and_the_oracles() {
    let table: Json = serde_json::from_str(TABLE).unwrap();
    let compiled: Vec<&str> = bundled::FILES.iter().map(|(path, _)| *path).collect();
    let oracle: Vec<&str> = table["bundled"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect();
    assert_eq!(compiled, oracle);
    let folder =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src/opentide/data/configurations");
    let mut on_disk = Vec::new();
    for entry in std::fs::read_dir(&folder).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if entry.path().is_dir() {
            for nested in std::fs::read_dir(entry.path()).unwrap() {
                let nested = nested.unwrap().file_name().into_string().unwrap();
                if Path::new(&nested)
                    .extension()
                    .is_some_and(|ext| ext == "toml")
                {
                    on_disk.push(format!("{name}/{nested}"));
                }
            }
        } else if Path::new(&name)
            .extension()
            .is_some_and(|ext| ext == "toml")
        {
            on_disk.push(name);
        }
    }
    on_disk.sort();
    assert_eq!(compiled, on_disk);
    let keys: Vec<&str> = table["metadata_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().unwrap())
        .collect();
    assert_eq!(keys, METADATA_KEYS);
}

#[test]
fn configuration_bundled_files_are_valid_on_their_own() {
    for (path, text) in bundled::FILES {
        let found = checks::text_issues(
            &format!("/w/.opentide/configurations/{path}"),
            text,
            &Layers {
                earlier: Some(Vec::new()),
                ..Layers::default()
            },
        );
        let found: Vec<&Finding> = found
            .iter()
            .filter(|finding| finding.code != "not_a_configuration_file")
            .collect();
        assert!(found.is_empty(), "{path}: {found:?}");
    }
}

#[test]
fn configuration_buffer_takes_its_parent_layer_and_open_deployment() {
    let path = "/w/.opentide/configurations/sharing.toml";
    let text = "[[misp]]\nname = \"a\"\nurl = \"https://a\"\napi_key = \"${K}\"\nmax_tlp = \"red\"\nrule_statuses = [\"ONLY\"]\n";
    let unknown = checks::buffer_issues(path, text, &checks::BufferContext::default());
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert_eq!(unknown[0].code, "rule_status_unknown");
    let known = checks::buffer_issues(
        path,
        text,
        &checks::BufferContext {
            deployment: Some(
                "[[statuses]]\nname = \"ONLY\"\ndescription = \"d\"\nstrategy = \"RELEASE\"\n"
                    .to_owned(),
            ),
            sharing_directory: true,
            ..checks::BufferContext::default()
        },
    );
    assert_eq!(
        known.iter().map(|f| f.code.as_str()).collect::<Vec<_>>(),
        ["sharing_directory"]
    );
    let deployment = "/w/.opentide/configurations/deployment.toml";
    let target = "[promotion]\npromotion_target = \"NOPE\"\n";
    assert_eq!(
        checks::buffer_issues(deployment, target, &checks::BufferContext::default())[0].code,
        "promotion_target_unknown"
    );
    let fixed = checks::buffer_issues(
        deployment,
        target,
        &checks::BufferContext {
            parent: Some("\u{feff}[promotion]\npromotion_target = \"DESIGN\"\n".to_owned()),
            ..checks::BufferContext::default()
        },
    );
    assert!(fixed.is_empty(), "{fixed:?}");
    assert!(
        checks::buffer_issues(
            "/w/.opentide/configurations/colours.toml",
            "x = 1",
            &checks::BufferContext::default()
        )
        .is_empty()
    );
}

#[test]
fn configuration_file_keys_route_as_the_oracle_routes_them() {
    for (path, key) in [
        ("deployment.toml", Some("deployment.toml")),
        (
            "/w/.opentide/configurations/platforms/splunk.toml",
            Some("platforms/splunk.toml"),
        ),
        ("platforms/foo.toml", Some("platforms/*.toml")),
        ("/w/.opentide/schemas/paths.toml", None),
        ("/w/.opentide/configurations/sharing/x.toml", None),
        ("lint.toml", None),
        ("deployment.TOML", None),
    ] {
        assert_eq!(checks::file_key(path).as_deref(), key, "{path}");
    }
}

mod configuration_never_panics {
    use super::*;
    use proptest::prelude::*;

    const PATHS: [&str; 6] = [
        "/w/.opentide/configurations/deployment.toml",
        "/w/.opentide/configurations/documentation.toml",
        "/w/.opentide/configurations/visibility.toml",
        "/w/.opentide/configurations/sharing.toml",
        "/w/.opentide/configurations/platforms/splunk.toml",
        "/w/.opentide/configurations/platforms/any.toml",
    ];

    /// Text that is often TOML: keys the models know, tables, arrays.
    fn toml_text() -> impl Strategy<Value = String> {
        let key = prop::sample::select(vec![
            "name",
            "statuses",
            "strategy",
            "promotion",
            "tenants",
            "setup",
            "ssl",
            "misp",
            "url",
            "logsources",
            "columns",
            "system",
            "assets",
            "flavor",
            "x",
        ]);
        let value = prop::sample::select(vec![
            "1",
            "\"\"",
            "\"a\"",
            "true",
            "[]",
            "[1, \"b\"]",
            "{}",
            "{a = 1}",
            "1.5",
            "nan",
            "1979-05-27",
            "\"$X\"",
            "\"${K}\"",
        ]);
        prop::collection::vec(
            prop_oneof![
                (key.clone(), value).prop_map(|(k, v)| format!("{k} = {v}\n")),
                key.clone().prop_map(|k| format!("[{k}]\n")),
                key.prop_map(|k| format!("[[{k}]]\n")),
                "[ -~]{0,12}\n",
            ],
            0..12,
        )
        .prop_map(|lines| lines.concat())
    }

    proptest! {
        #[test]
        fn text_issues_never_panic(text in toml_text(), path in 0..PATHS.len()) {
            let _ = checks::text_issues(PATHS[path], &text, &Layers::default());
            let _ = checks::buffer_issues(PATHS[path], &text, &checks::BufferContext {
                parent: Some(text.clone()),
                deployment: Some(text.clone()),
                sharing_directory: true,
            });
        }

        #[test]
        fn resolution_never_panics(text in toml_text()) {
            let workspace = Folder {
                path: ROOT.to_owned(),
                files: vec![
                    ("deployment.toml".to_owned(), text.clone()),
                    ("platforms/splunk.toml".to_owned(), text.clone()),
                    ("lint.toml".to_owned(), text),
                ],
                folders: vec!["platforms".to_owned()],
            };
            if let Ok(resolved) = resolve(&Instance { workspace: Some(&workspace), ..Instance::default() }) {
                let _ = resolved.issues();
                let _ = parse_lint_config(resolved.get("lint"));
            }
        }
    }
}
