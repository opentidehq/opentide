//! Every body of the compile corpus (`tests/golden/payloads/corpus`) against
//! what the oracle compiled from it (`tests/golden/payloads/oracle.json`,
//! written by `cargo xtask payloads diff --against python --corpus payloads
//! --record`): the dry run's body, each tenant's (the writes a deployer
//! sends, for the six platforms whose body is built from the tenant), and
//! the dry run's payload entry, byte for byte.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the corpus and the record are in the repository"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::json::Json;
use opentide_compile::preview::{self, Inputs, PROBE_CLOCK, PROBE_TIMESTAMP};
use opentide_compile::{CompileError, Owned, Rule};
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

/// The `[[dump]]` classes of `tests/golden/payloads/APPROVED.toml`: rule and
/// platforms.
fn dump_classes() -> Vec<(String, Vec<String>)> {
    let text = std::fs::read_to_string(repo().join("tests/golden/payloads/APPROVED.toml")).unwrap();
    let file: toml::Table = toml::from_str(&text).unwrap();
    file.get("dump")
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            (
                entry["rule"].as_str().unwrap().to_owned(),
                entry["platforms"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|platform| platform.as_str().unwrap().to_owned())
                    .collect(),
            )
        })
        .collect()
}

fn without_nulls(value: Json) -> Json {
    match value {
        Json::Object(object) => Json::Object(
            object
                .into_iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key, without_nulls(value)))
                .collect(),
        ),
        Json::Array(items) => Json::Array(items.into_iter().map(without_nulls).collect()),
        other => other,
    }
}

/// The class a model-dump preview that differs falls in: `nulls` (the
/// oracle's `null` members left out, it is the candidate) or `order` (the
/// same value, keys in another order); `None` for any other difference.
fn dump_class(oracle: &str, mine: &str) -> Option<&'static str> {
    let oracle: Json = serde_json::from_str(oracle).ok()?;
    if oracle.get("status").is_some() || oracle.get("api_request").is_none() {
        return None;
    }
    let trimmed = without_nulls(oracle).to_compact();
    if trimmed == mine {
        return Some("nulls");
    }
    let value = |text: &str| serde_json::from_str::<Value>(text).ok();
    (value(&trimmed)? == value(mine)?).then_some("order")
}

/// The approved differences of the compile corpus (`[[diff]]` entries of
/// `tests/golden/payloads/APPROVED.toml` for the corpus `payloads`): uuid,
/// platform, what, oracle and candidate.
fn approved() -> Vec<[String; 5]> {
    let text = std::fs::read_to_string(repo().join("tests/golden/payloads/APPROVED.toml")).unwrap();
    let file: toml::Table = toml::from_str(&text).unwrap();
    let field = |entry: &toml::Value, key: &str| entry[key].as_str().unwrap().to_owned();
    file.get("diff")
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|entry| entry["corpus"].as_str() == Some("payloads"))
        .map(|entry| {
            [
                field(entry, "uuid"),
                field(entry, "platform"),
                field(entry, "what"),
                field(entry, "oracle"),
                field(entry, "candidate"),
            ]
        })
        .collect()
}

/// The approved oracle faults (`[[fault]]` entries of
/// `tests/golden/payloads/APPROVED.toml`): platform and failure.
fn fault_approvals() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(repo().join("tests/golden/payloads/APPROVED.toml")).unwrap();
    let file: toml::Table = toml::from_str(&text).unwrap();
    file.get("fault")
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            (
                entry["platform"].as_str().unwrap().to_owned(),
                entry["error"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
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
    let ws = corpus.to_string_lossy().into_owned();
    let approved = approved();
    let classes = dump_classes();
    let faults = fault_approvals();
    let mut faulted = 0;
    let mut used = vec![false; approved.len()];
    let mut compared = 0;
    let mut differences = Vec::new();
    let rules = record["rules"].as_array().unwrap();
    assert!(
        rules.len() >= 40,
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
            let mine = in_workspace(&mine, &ws);
            if let Some(at) = approved.iter().position(|[u, p, w, o, c]| {
                u == uuid && p == platform && *w == what && *o == oracle && *c == mine
            }) {
                used[at] = true;
            } else if oracle != mine
                && !(what == "preview"
                    && dump_class(&oracle, &mine).is_some_and(|class| {
                        classes.iter().any(|(rule, platforms)| {
                            rule == class && platforms.iter().any(|known| known == platform)
                        })
                    }))
            {
                differences.push(format!(
                    "{uuid} {platform} {what}\n  oracle:    {oracle}\n  candidate: {mine}"
                ));
            }
        };
        if let Some(compiled) = preview::compile_offline(&cx, platform, &rule) {
            check(
                "compile".into(),
                describe(&entry["compile"]),
                candidate(compiled),
            );
        }
        for tenant in entry["tenants"].as_array().unwrap() {
            let name = tenant["tenant"].as_str().unwrap();
            // The oracle's own client failed and the probe worked around it:
            // the failure is an approved intended difference.
            if let Some(fault) = tenant.get("fault").and_then(Value::as_str) {
                faulted += 1;
                assert!(
                    faults
                        .iter()
                        .any(|(p, error)| p == platform && error == fault),
                    "{uuid} {platform} {name}: the oracle fails ({fault}) with no [[fault]] approval"
                );
            }
            let inputs = Inputs {
                known: opentide_compile::plan::state_id(&OsFs, &corpus, uuid, platform, name),
                clock: PROBE_CLOCK,
                timestamp: PROBE_TIMESTAMP,
            };
            let mine =
                candidate(preview::compile_tenant(&cx, platform, &rule, name, &inputs).unwrap());
            check(format!("tenant:{name}"), describe(tenant), mine);
        }
        check(
            "preview".into(),
            entry["preview"].as_str().unwrap().to_owned(),
            preview::preview(&cx, platform, &rule).to_compact(),
        );
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
    assert!(
        used.iter().all(|used| *used),
        "an approval of the compile corpus matches nothing (stale)"
    );
    assert!(compared >= 150, "{compared} comparisons");
    // Every HarfangLab body the corpus sends (four Sigma or YARA writes and
    // a delete) is one the 0.23.0 client never sent.
    assert!(faulted >= 5, "{faulted} oracle faults");
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
/// (`[[dump]]` `nulls`, #895). What the tenant receives is not the dump:
/// [`the_compile_corpus_compiles_as_the_oracle_compiles_it`] holds each
/// tenant's requests to the oracle's, `null`s included where the oracle
/// sent one (Defender's `organizationalScope`, for one).
#[test]
fn a_model_dump_preview_leaves_unset_fields_out_on_every_dump_platform() {
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
                cwd: corpus,
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
