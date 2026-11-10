//! Every Sentinel and Elastic body of the compile corpus
//! (`tests/golden/payloads/corpus`) against what the oracle compiled from it
//! (`tests/golden/payloads/oracle.json`, written by `cargo xtask payloads diff
//! --against python --corpus payloads --record`): the dry run's body, each
//! tenant's, and the dry run's payload entry, byte for byte.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the corpus and the record are in the repository"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::json::Json;
use opentide_compile::preview::{self, Preview};
use opentide_compile::{CompileError, Owned, Rule, elastic, sentinel};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, Options, OsFs, RootOptions, Workspace};
use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn describe(outcome: &Value) -> String {
    if let Some(body) = outcome.get("body").and_then(Value::as_str) {
        return body.to_owned();
    }
    let error = &outcome["error"];
    format!(
        "error[{}] {}{}",
        error["code"].as_str().unwrap(),
        error["message"].as_str().unwrap(),
        error["help"]
            .as_str()
            .map(|help| format!(" (help: {help})"))
            .unwrap_or_default()
    )
}

fn candidate(result: Result<Json, CompileError>) -> String {
    match result {
        Ok(body) => body.to_compact(),
        Err(error) => format!(
            "error[{}] {}{}",
            error.code,
            error.reason,
            error
                .hint
                .map(|help| format!(" (help: {help})"))
                .unwrap_or_default()
        ),
    }
}

/// `text` (compact JSON) with the workspace `ws` written `<WS>` and the rest
/// of each path under it with `/` separators, as the oracle's record writes
/// it on every system.
fn in_workspace(text: &str, ws: &str) -> String {
    let escaped = ws.replace('\\', "\\\\");
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(&escaped) {
        out.push_str(&rest[..at]);
        out.push_str("<WS>");
        rest = &rest[at + escaped.len()..];
        let end = rest.find('"').unwrap_or(rest.len());
        out.push_str(&rest[..end].replace("\\\\", "/"));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[test]
fn a_windows_path_reads_as_the_record_writes_it() {
    let text = r#"{"file":"D:\\a\\corpus\\objects\\rules\\x.yaml","q":"a\\b"}"#;
    assert_eq!(
        in_workspace(text, r"D:\a\corpus"),
        r#"{"file":"<WS>/objects/rules/x.yaml","q":"a\\b"}"#
    );
    assert_eq!(
        in_workspace(r#"{"file":"/w/c/objects/x.yaml"}"#, "/w/c"),
        r#"{"file":"<WS>/objects/x.yaml"}"#
    );
}

#[test]
fn the_compile_corpus_compiles_as_the_oracle_compiles_it() {
    let corpus = dunce::canonicalize(repo().join("tests/golden/payloads/corpus")).unwrap();
    let record: Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("tests/golden/payloads/oracle.json")).unwrap(),
    )
    .unwrap();
    let workspace = Workspace::open(
        Arc::new(OsFs) as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(corpus.clone()),
                cwd: corpus.clone(),
                ..RootOptions::default()
            },
        },
    )
    .unwrap();
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let config = Json::from_node(&workspace.configuration().resolved.tree);
    let elastic_tenants = opentide_compile::plan::tenants(&config, "elastic");
    let ws = corpus.to_string_lossy().into_owned();
    let mut compared = 0;
    let mut differences = Vec::new();
    let rules = record["rules"].as_array().unwrap();
    assert!(
        rules.len() >= 15,
        "the record holds every rule of the corpus"
    );
    assert!(record["unloadable"].as_array().unwrap().is_empty());
    for entry in rules {
        let uuid = entry["uuid"].as_str().unwrap();
        let platform = entry["platform"].as_str().unwrap();
        let object = index.get("rule", uuid).unwrap();
        let rule = Rule::new(
            object.root().unwrap(),
            Some(object.path.to_string_lossy().into_owned()),
        );
        let mut check = |what: String, oracle: String, mine: String| {
            compared += 1;
            if oracle != in_workspace(&mine, &ws) {
                differences.push(format!(
                    "{uuid} {platform} {what}\n  oracle:    {oracle}\n  candidate: {mine}"
                ));
            }
        };
        let compiled = preview::compile_offline(&cx, platform, &rule).unwrap();
        check(
            "compile".into(),
            describe(&entry["compile"]),
            candidate(compiled),
        );
        for tenant in entry["tenants"].as_array().unwrap() {
            let name = tenant["tenant"].as_str().unwrap();
            let mine = if platform == "sentinel" {
                candidate(sentinel::compile(&cx, &rule, name))
            } else {
                let setup = elastic_tenants
                    .iter()
                    .find(|known| known.get("name").and_then(Json::as_str) == Some(name))
                    .map(|known| elastic::Setup::from_tenant(known))
                    .unwrap();
                candidate(elastic::compile(&cx, &rule, &setup))
            };
            check(format!("tenant {name}"), describe(tenant), mine);
        }
        match preview::preview(&cx, platform, &rule) {
            Preview::Entry(preview) => check(
                "preview".into(),
                entry["preview"].as_str().unwrap().to_owned(),
                preview.to_compact(),
            ),
            Preview::ConfigDump => differences.push(format!("{uuid} {platform}: no preview")),
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
    assert!(compared >= 60, "{compared} comparisons");
}
