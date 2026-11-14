//! Every body of the compile corpus (`tests/golden/payloads/corpus`): for
//! each rule and platform `tests/golden/payloads/oracle.json` lists (every
//! rule of the corpus, with the tenants it is compiled for), the dry run's
//! body, each tenant's (the writes a deployer sends, for the six platforms
//! whose body is built from the tenant) and the dry run's payload entry, held
//! to the reviewed snapshot `tests/snapshots/compile_corpus__bodies.snap`.
//! The corpus and its list were first written to hold the compiler to the
//! Python CLI's (opentide 0.23.0).
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the corpus and its list are in the repository"
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::json::Json;
use opentide_compile::preview::{self, Inputs};
use opentide_compile::{CompileError, Owned, Rule, splunk};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, Options, OsFs, RootOptions, Workspace};
use serde_json::Value;

/// The Splunk clock the corpus is compiled with: a random minute and hour
/// of 7, the time 03:04 UTC.
const CLOCK: splunk::Clock = splunk::Clock {
    random: (7, 7),
    now: (4, 3),
};

/// The Carbon Black report timestamp the corpus is compiled with.
const TIMESTAMP: i64 = 1_767_225_600;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus() -> (PathBuf, Value, Workspace) {
    let corpus = dunce::canonicalize(repo().join("tests/golden/payloads/corpus")).unwrap();
    let list: Value = serde_json::from_str(
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
    (corpus, list, workspace)
}

fn shown(result: Result<Json, CompileError>) -> String {
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

#[test]
fn the_compile_corpus_compiles_as_its_snapshot_says() {
    let (corpus, list, workspace) = corpus();
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let ws = corpus.to_string_lossy().into_owned();
    let rules = list["rules"].as_array().unwrap();
    assert!(rules.len() >= 40, "the list holds every rule of the corpus");
    let mut out = String::new();
    for entry in rules {
        let uuid = entry["uuid"].as_str().unwrap();
        let platform = entry["platform"].as_str().unwrap();
        let object = index.get("rule", uuid).unwrap();
        let rule = Rule::new(
            object.root().unwrap(),
            Some(object.path.to_string_lossy().into_owned()),
        );
        let _ = writeln!(out, "## {uuid} {platform}");
        if let Some(compiled) = preview::compile_offline(&cx, platform, &rule) {
            let _ = writeln!(out, "compile: {}", shown(compiled));
        }
        for tenant in entry["tenants"].as_array().unwrap() {
            let name = tenant["tenant"].as_str().unwrap();
            let inputs = Inputs {
                known: opentide_compile::plan::state_id(&OsFs, &corpus, uuid, platform, name),
                clock: CLOCK,
                timestamp: TIMESTAMP,
            };
            let body = preview::compile_tenant(&cx, platform, &rule, name, &inputs).unwrap();
            let _ = writeln!(out, "tenant {name}: {}", shown(body));
        }
        let preview = preview::preview(&cx, platform, &rule).to_compact();
        let _ = writeln!(out, "preview: {preview}\n");
    }
    insta::assert_snapshot!("bodies", in_workspace(&out, &ws));
}

/// `text` (compact JSON) with the workspace `ws` written `<WS>` and the rest
/// of each path under it with `/` separators, the same on
/// every system.
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
fn a_windows_path_reads_as_a_unix_one() {
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

/// The JSON pointers of every `null` in `value`, except the values of a
/// Splunk block's `advanced` table: there `null` is a value the rule writes
/// (the empty `savedsearches.conf` value), not a field it leaves unset.
fn nulls(value: &Json, at: &str, out: &mut Vec<String>) {
    match value {
        Json::Null => out.push(at.to_owned()),
        Json::Object(object) => {
            for (key, member) in object {
                if at.is_empty() && key == "advanced" {
                    continue;
                }
                nulls(member, &format!("{at}/{key}"), out);
            }
        }
        Json::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                nulls(item, &format!("{at}/{index}"), out);
            }
        }
        _ => {}
    }
}

/// One rule across platforms for a dry run's preview of a block it builds
/// no request body for (`deployers()`: Defender, Splunk, SentinelOne,
/// CrowdStrike, HarfangLab, Carbon Black Cloud): the block's model dump
/// leaves an unset field out, where the oracle printed it `null`
/// (#895). What the tenant receives is not the dump:
/// [`the_compile_corpus_compiles_as_its_snapshot_says`] holds each
/// tenant's requests, `null`s included where one is sent (Defender's
/// `organizationalScope`, for one).
#[test]
fn a_model_dump_preview_leaves_unset_fields_out_on_every_dump_platform() {
    let (_corpus, record, workspace) = corpus();
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let dumped = preview::deployers();
    let mut seen: Vec<&str> = Vec::new();
    let mut found = Vec::new();
    for entry in record["rules"].as_array().unwrap() {
        let platform = entry["platform"].as_str().unwrap();
        let Some(platform) = dumped.iter().copied().find(|known| *known == platform) else {
            continue;
        };
        let uuid = entry["uuid"].as_str().unwrap();
        let object = index.get("rule", uuid).unwrap();
        let rule = Rule::new(object.root().unwrap(), None);
        let shown = preview::preview(&cx, platform, &rule);
        let request = shown.get("api_request").unwrap();
        assert!(
            request.as_object().is_some(),
            "{uuid} {platform}: {shown:?}"
        );
        let mut at = Vec::new();
        nulls(request, "", &mut at);
        found.extend(at.into_iter().map(|at| format!("{uuid} {platform} {at}")));
        if !seen.contains(&platform) {
            seen.push(platform);
        }
    }
    assert!(
        found.is_empty(),
        "unset fields printed null:\n{}",
        found.join("\n")
    );
    seen.sort_unstable();
    let mut expected = dumped.clone();
    expected.sort_unstable();
    assert_eq!(
        seen, expected,
        "the corpus previews every model-dump platform"
    );
}
