//! Every body of the compile corpus (`tests/golden/payloads/corpus`) against
//! what the oracle compiled from it (`tests/golden/payloads/oracle.json`,
//! recorded by `cargo xtask payloads`, retired with the oracle in #1142): the dry run's body, each tenant's (the writes a deployer
//! sends, for the six platforms whose body is built from the tenant), and
//! the dry run's payload entry, byte for byte.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the corpus and the record are in the repository"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::json::Json;
use opentide_compile::preview::{self, Inputs};
use opentide_compile::{CompileError, Owned, Rule, splunk};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, Options, OsFs, RootOptions, Workspace};
use serde_json::Value;

/// The Splunk clock the oracle's probe pinned when it recorded:
/// a random minute and hour of 7, the time 03:04 UTC.
const PROBE_CLOCK: splunk::Clock = splunk::Clock {
    random: (7, 7),
    now: (4, 3),
};

/// The Carbon Black report timestamp the oracle's probe pins.
const PROBE_TIMESTAMP: i64 = 1_767_225_600;

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
    classes_of("dump")
}

/// The classes of `tests/golden/payloads/APPROVED.toml`'s `[[table]]`: rule
/// and platforms.
fn classes_of(table: &str) -> Vec<(String, Vec<String>)> {
    let text = std::fs::read_to_string(repo().join("tests/golden/payloads/APPROVED.toml")).unwrap();
    let file: toml::Table = toml::from_str(&text).unwrap();
    file.get(table)
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
/// oracle's `null` members left out, it is the candidate), `order` (the
/// same value, keys in another order) or `wrapped` (the oracle's request
/// as the candidate's `payload`, beside the block the candidate adds);
/// `None` for any other difference. The platforms whose dry run shows the
/// writes are the `request` class ([`request_problem`]).
fn dump_class(oracle: &str, mine: &str) -> Option<&'static str> {
    let oracle: Json = serde_json::from_str(oracle).ok()?;
    if oracle.get("status").is_some() || oracle.get("api_request").is_none() {
        return None;
    }
    // `wrapped`: the oracle's entry, byte for byte (key order kept), once
    // the candidate's `api_request` is replaced by its `payload`.
    let candidate: Json = serde_json::from_str(mine).ok()?;
    if let Json::Object(entry) = &candidate
        && let Some(Json::Object(request)) = entry.get("api_request")
        && request.len() == 2
        && matches!(request.get("block"), Some(Json::Object(_)))
        && let Some(payload) = request.get("payload")
    {
        let unwrapped: Json = Json::Object(
            entry
                .iter()
                .map(|(key, value)| {
                    let value = if key == "api_request" { payload } else { value };
                    (key.clone(), value.clone())
                })
                .collect(),
        );
        if unwrapped.to_compact() == oracle.to_compact() {
            return Some("wrapped");
        }
    }
    let trimmed = without_nulls(oracle).to_compact();
    if trimmed == mine {
        return Some("nulls");
    }
    let value = |text: &str| serde_json::from_str::<Value>(text).ok();
    (value(&trimmed)? == value(mine)?).then_some("order")
}

/// The `[[writes]] search` class: Splunk's writes as the oracle's probe
/// recorded them, without the `search` each update of the saved search
/// carries first, which must be the create's: the first update without it,
/// the last with it at its end. `None` when an update does not start with
/// it.
fn without_update_search(writes: &Json) -> Option<Json> {
    let Json::Array(writes) = writes else {
        return Some(writes.clone());
    };
    if writes.is_empty() {
        return Some(Json::Array(Vec::new()));
    }
    let search = writes.first()?.get("body")?.get("search")?.clone();
    let mut out = Vec::new();
    for (at, write) in writes.iter().enumerate() {
        let Json::Object(write) = write else {
            return None;
        };
        let mut write = write.clone();
        if at > 0 {
            let Some(Json::Object(body)) = write.get_mut("body") else {
                return None;
            };
            if body.first().map(|(key, value)| (key.as_str(), value)) != Some(("search", &search)) {
                return None;
            }
            body.shift_remove("search");
            // The probe's last update took the search at its end.
            if at + 1 == writes.len() {
                body.insert("search".into(), search.clone());
            }
        }
        out.push(Json::Object(write));
    }
    Some(Json::Array(out))
}

/// Whether `url`, a write's, names its host and every segment of its path:
/// it starts with `https://` or a `<tenant:KEY>` placeholder, then no
/// segment is empty (a trailing slash aside) and no host is.
fn whole_url(url: &str) -> bool {
    let rest = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if url.starts_with("<tenant:") {
        url
    } else {
        return false;
    };
    let path = rest.split('?').next().unwrap_or_default();
    let path = path.strip_suffix('/').unwrap_or(path);
    !path.starts_with([':', '/']) && path.split('/').all(|segment| !segment.is_empty())
}

#[test]
fn a_whole_url_has_its_host_and_every_segment() {
    assert!(whole_url(
        "https://h:8089/servicesNS/nobody/search/saved/searches/"
    ));
    assert!(whole_url("<tenant:url>/web/api/v2.1/cloud-detection/rules"));
    assert!(whole_url(
        "<tenant:api>/correlation-rules/entities/rules/v1?ids=1"
    ));
    assert!(!whole_url(
        "https://:8089/servicesNS/nobody/search/saved/searches/"
    ));
    assert!(!whole_url("/threathunter/watchlistmgr/v3/orgs/K/reports"));
    assert!(!whole_url(
        "<tenant:url>/threathunter/watchlistmgr/v3/orgs//reports"
    ));
    assert!(!whole_url(
        "https://h:8089/servicesNS/nobody//saved/searches/"
    ));
}

/// A rule's file name in the corpus, which names the rule in a message.
fn corpus_file(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The `[[writes]] url` class: Splunk's and Carbon Black's writes with each
/// `url` as the oracle's probe recorded it, the path under the tenant's app
/// namespace (`saved/searches`, `saved/searches/<name>`, decoded) or under
/// its `url` (`/threathunter/...`). The candidate's is the whole URL a
/// deploy sends to, which must start with the tenant's: `None` when one
/// does not.
fn recorded_urls(writes: &Json, platform: &str, tenant: &Json) -> Option<Json> {
    let Json::Array(writes) = writes else {
        return Some(writes.clone());
    };
    let mut out = Vec::new();
    for write in writes {
        let mut write = write.clone();
        let url = write.get("url").and_then(Json::as_str)?.to_owned();
        let recorded = if platform == "splunk" {
            let searches = splunk::saved_searches(tenant);
            let name = url.strip_prefix(&searches)?;
            let name = percent_encoding::percent_decode_str(name)
                .decode_utf8()
                .ok()?;
            if name.is_empty() {
                "saved/searches".to_owned()
            } else {
                format!("saved/searches/{name}")
            }
        } else {
            let server = opentide_compile::deploy::setup_text(tenant, "url");
            url.strip_prefix(server.trim_end_matches('/'))?.to_owned()
        };
        *write.get_mut("url")? = recorded.into();
        out.push(write);
    }
    Some(Json::Array(out))
}

/// The `[[writes]] watchlist` class: Carbon Black's writes without the
/// watchlist update that follows a new report, which the deploy reads from
/// the tenant (`PUT .../watchlists/<tenant-read:watchlist_id>`, its body
/// `<tenant-read:watchlist>`). `None` when a new report is not followed by
/// exactly that write.
fn without_watchlist_write(writes: &Json) -> Option<Json> {
    let Json::Array(writes) = writes else {
        return Some(writes.clone());
    };
    match writes.as_slice() {
        [] => Some(Json::Array(Vec::new())),
        [report, watchlist] => {
            let text = |write: &Json, key: &str| {
                write
                    .get(key)
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let reports = text(report, "url");
            let org = reports.strip_suffix("/reports")?;
            (text(report, "method") == "POST"
                && text(watchlist, "method") == "PUT"
                && text(watchlist, "url") == format!("{org}/watchlists/<tenant-read:watchlist_id>")
                && text(watchlist, "body") == "<tenant-read:watchlist>")
                .then(|| Json::Array(vec![report.clone()]))
        }
        _ => None,
    }
}

/// Whether `text`, where a `<send-time:NAME>` placeholder stands for a
/// number, reads as `actual`: each placeholder one or more ASCII digits,
/// every other character the same.
fn matches_send_time(text: &str, actual: &str) -> bool {
    let Some(at) = text.find("<send-time:") else {
        return text == actual;
    };
    let Some(end) = text[at..].find('>').map(|end| at + end + 1) else {
        return text == actual;
    };
    let Some(rest) = actual.strip_prefix(&text[..at]) else {
        return false;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    // The placeholder takes as many digits as leaves the rest matching.
    (1..=digits).any(|taken| matches_send_time(&text[end..], &rest[taken..]))
}

/// Whether the dry run's `shown` is `sent`, the request a deploy compiled
/// with a clock and a timestamp, but for `<send-time:NAME>` placeholders
/// where a number was sent: keys in the same order, every other value the
/// same. `placeholders` counts the placeholders met.
fn same_but_send_time(shown: &Json, sent: &Json, placeholders: &mut usize) -> bool {
    match (shown, sent) {
        (Json::Str(text), Json::Int(_)) if text.starts_with("<send-time:") => {
            *placeholders += 1;
            text == "<send-time:timestamp>"
        }
        (Json::Str(text), Json::Str(actual)) if text.contains("<send-time:") => {
            *placeholders += text.matches("<send-time:").count();
            matches_send_time(text, actual)
        }
        (Json::Array(shown), Json::Array(sent)) => {
            shown.len() == sent.len()
                && shown
                    .iter()
                    .zip(sent)
                    .all(|(shown, sent)| same_but_send_time(shown, sent, placeholders))
        }
        (Json::Object(shown), Json::Object(sent)) => {
            shown.len() == sent.len()
                && shown.iter().zip(sent).all(|((key, shown), (name, sent))| {
                    key == name && same_but_send_time(shown, sent, placeholders)
                })
        }
        _ => shown == sent,
    }
}

#[test]
fn a_send_time_placeholder_stands_for_a_number_only() {
    assert!(matches_send_time(
        "<send-time:minute> */2 * * *",
        "04 */2 * * *"
    ));
    assert!(matches_send_time(
        "<send-time:minute> <send-time:hour> */1 * *",
        "7 7 */1 * *"
    ));
    assert!(!matches_send_time(
        "<send-time:minute> */2 * * *",
        "x */2 * * *"
    ));
    assert!(!matches_send_time(
        "<send-time:minute> */2 * * *",
        "04 */3 * * *"
    ));
    let mut count = 0;
    let shown: Json = serde_json::from_str(r#"{"a":"<send-time:timestamp>","b":1}"#).unwrap();
    let sent: Json = serde_json::from_str(r#"{"a":1767225600,"b":1}"#).unwrap();
    assert!(same_but_send_time(&shown, &sent, &mut count));
    let reordered: Json = serde_json::from_str(r#"{"b":1,"a":1767225600}"#).unwrap();
    assert!(!same_but_send_time(&shown, &reordered, &mut count));
}

/// The `request` class (#1712): the dry run's entry for a rule on one of the
/// platforms whose deploy writes are built from the tenant
/// (`preview::deployers()`), checked against those writes as
/// [`preview::compile_tenant`] compiles them with the probe's clock and
/// timestamp, which `tenant:<name>` holds to the oracle. The entry is the
/// first tenant's writes, named by `tenant`, with `<send-time:NAME>` where a
/// number was sent; or, when a tenant cannot take the rule, the failure of
/// the first such tenant, naming it. `None` when it is; else the problem.
fn request_problem(
    shown: &Json,
    rule: &Rule,
    tenants: &[(String, Result<Json, CompileError>)],
    placeholders: &mut usize,
) -> Option<String> {
    let text = |key: &str| shown.get(key).and_then(Json::as_str).unwrap_or_default();
    if let Some((name, Err(error))) = tenants.iter().find(|(_, compiled)| compiled.is_err()) {
        let reason = format!("{} (tenant '{name}')", error.reason);
        return (text("status") != "failed"
            || text("code") != error.code
            || text("error") != reason)
            .then(|| format!("not the failure on tenant {name}: {reason}"));
    }
    let Some((name, Ok(sent))) = tenants.first() else {
        return Some("no tenant".into());
    };
    let keys: Vec<&str> = match shown {
        Json::Object(entry) => entry.keys().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    if keys != ["uuid", "name", "api_request", "tenant"]
        || text("uuid") != rule.uuid
        || text("name") != rule.name
        || text("tenant") != name
    {
        return Some(format!("not the entry of tenant {name}"));
    }
    let request = shown.get("api_request").unwrap_or(&Json::Null);
    (!same_but_send_time(request, sent, placeholders))
        .then(|| format!("not the writes to {name}: {}", sent.to_compact()))
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
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
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
    let writes_classes = classes_of("writes");
    let writes_preview = preview::deployers();
    let mut send_time = 0;
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
        // A message names the rule by its file in the corpus.
        let file = corpus_file(&object.path);
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
        let mut sent: Vec<(String, Result<Json, CompileError>)> = Vec::new();
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
                clock: Some(PROBE_CLOCK),
                timestamp: Some(PROBE_TIMESTAMP),
            };
            let compiled = preview::compile_tenant(&cx, platform, &rule, name, &inputs).unwrap();
            let mut mine = candidate(compiled.clone());
            // The `[[writes]]` classes: the writes as the oracle's probe
            // recorded them.
            if let Ok(writes) = &compiled {
                let class = |rule: &str| {
                    writes_classes.iter().any(|(class, platforms)| {
                        class == rule && platforms.iter().any(|known| known == platform)
                    })
                };
                let mut recorded = writes.clone();
                if class("url") {
                    let table = opentide_compile::deploy::tenant(&cx, platform, name).unwrap();
                    recorded = recorded_urls(&recorded, platform, table)
                        .unwrap_or_else(|| panic!("{file} {platform} {name}: {mine}"));
                }
                if class("search") {
                    recorded = without_update_search(&recorded)
                        .unwrap_or_else(|| panic!("{file} {platform} {name}: {mine}"));
                }
                if class("watchlist") {
                    recorded = without_watchlist_write(&recorded)
                        .unwrap_or_else(|| panic!("{file} {platform} {name}: {mine}"));
                }
                mine = recorded.to_compact();
            }
            check(format!("tenant:{name}"), describe(tenant), mine);
            // What a deploy at the probe's time sends: a drawn Splunk
            // schedule is the rule's own minute and hour (#1711), where the
            // probe pinned 7 and 7.
            let deployed = Inputs {
                clock: Some(splunk::Clock {
                    random: splunk::rule_minute_and_hour(uuid),
                    ..PROBE_CLOCK
                }),
                ..inputs
            };
            let compiled = preview::compile_tenant(&cx, platform, &rule, name, &deployed).unwrap();
            sent.push((name.to_owned(), compiled));
        }
        if writes_preview.contains(&platform) {
            // The oracle showed the block; the dry run shows the writes the
            // first tenant receives (#1712), held to them here, and they to
            // the oracle's above.
            compared += 1;
            assert!(
                classes.iter().any(|(class, platforms)| class == "request"
                    && platforms.iter().any(|known| known == platform)),
                "{platform}: no [[dump]] request approval"
            );
            let names: Vec<String> = sent.iter().map(|(name, _)| name.clone()).collect();
            let known = |tenant: &str| {
                opentide_compile::plan::state_id(&OsFs, &corpus, uuid, platform, tenant)
            };
            let shown = preview::preview_planned(&cx, platform, &rule, &names, &known);
            if let Some(problem) = request_problem(&shown, &rule, &sent, &mut send_time) {
                differences.push(format!(
                    "{uuid} {platform} preview: {problem}\n  candidate: {}",
                    shown.to_compact()
                ));
            }
            continue;
        }
        check(
            "preview".into(),
            entry["preview"].as_str().unwrap().to_owned(),
            preview::preview(&cx, platform, &rule).to_compact(),
        );
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
    // Splunk's schedule minute and Carbon Black's timestamp are met.
    assert!(send_time >= 2, "{send_time} send-time placeholders");
    assert!(
        used.iter().all(|used| *used),
        "an approval of the compile corpus matches nothing (stale)"
    );
    assert!(compared >= 150, "{compared} comparisons");
    // Every HarfangLab body the corpus sends (four Sigma or YARA writes and
    // a delete) is one the 0.23.0 client never sent.
    assert!(faulted >= 5, "{faulted} oracle faults");
}

/// Every `<tenant:KEY>` placeholder in `value`, by key.
fn tenant_placeholders(value: &Json, out: &mut Vec<String>) {
    match value {
        Json::Str(text) => {
            let mut rest = text.as_str();
            while let Some(at) = rest.find("<tenant:") {
                let Some(end) = rest[at..].find('>') else {
                    break;
                };
                let key = rest[at + "<tenant:".len()..at + end].to_owned();
                if !out.contains(&key) {
                    out.push(key);
                }
                rest = &rest[at + end..];
            }
        }
        Json::Object(object) => object
            .values()
            .for_each(|member| tenant_placeholders(member, out)),
        Json::Array(items) => items.iter().for_each(|item| tenant_placeholders(item, out)),
        _ => {}
    }
}

/// The `setup` keys the dry run's entry `shown` of a rule on `platform`
/// that reaches no tenant shows as `<tenant:KEY>`: the requests, each
/// `{"method", "url", "body"}`, hold exactly the placeholders
/// `unresolved.setup` lists, and its `reason` names the platform.
fn unreached_setup(file: &str, platform: &str, shown: &Json) -> Vec<String> {
    let Some(Json::Array(writes)) = shown.get("api_request") else {
        panic!("{file} {platform}: {}", shown.to_compact())
    };
    for write in writes {
        let Json::Object(write) = write else {
            panic!("{file} {platform}: {}", shown.to_compact())
        };
        assert_eq!(
            write.keys().map(String::as_str).collect::<Vec<_>>(),
            ["method", "url", "body"],
            "{file} {platform}"
        );
        // A setup key the requests carry that `tenant_keys` leaves out
        // would be empty here: no host, no segment.
        let url = write["url"].as_str().unwrap_or_default();
        assert!(whole_url(url), "{file} {platform}: {url}");
    }
    assert!(
        !shown.to_compact().contains("corpus-tenant"),
        "{file} {platform}: {}",
        shown.to_compact()
    );
    let mut found = Vec::new();
    tenant_placeholders(shown.get("api_request").unwrap(), &mut found);
    let unresolved = shown.get("unresolved").unwrap();
    let listed: Vec<String> = unresolved
        .get("setup")
        .and_then(Json::as_array)
        .map(|keys| {
            keys.iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    let mut sorted = listed.clone();
    sorted.sort();
    assert_eq!(found, sorted, "{file} {platform}: {}", shown.to_compact());
    assert!(
        unresolved
            .get("reason")
            .and_then(Json::as_str)
            .is_some_and(|reason| reason.contains(&format!("no {platform} tenant"))),
        "{file} {platform}"
    );
    listed
}

/// A dry run that reaches no tenant of a platform whose deploy writes are
/// built from the tenant (`deployers()`: Defender, Splunk, SentinelOne,
/// CrowdStrike, HarfangLab, Carbon Black Cloud) shows the writes compiled
/// for a tenant whose setup sets nothing (#1712), not the block: each
/// `{"method", "url", "body"}`, every value a tenant's setup gives written
/// `<tenant:KEY>` and named under `unresolved.setup`, and every send-time
/// value a `<send-time:NAME>` placeholder.
#[test]
fn a_dry_run_without_a_tenant_shows_the_writes_with_tenant_placeholders() {
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
    let deployers = preview::deployers();
    let mut seen: Vec<&str> = Vec::new();
    let mut shown_keys: Vec<String> = Vec::new();
    for entry in record["rules"].as_array().unwrap() {
        let platform = entry["platform"].as_str().unwrap();
        let Some(platform) = deployers.iter().copied().find(|known| *known == platform) else {
            continue;
        };
        let object = index.get("rule", entry["uuid"].as_str().unwrap()).unwrap();
        let rule = Rule::new(object.root().unwrap(), None);
        let shown = preview::preview(&cx, platform, &rule);
        if shown.get("status").and_then(Json::as_str) == Some("failed") {
            continue;
        }
        let listed = unreached_setup(&corpus_file(&object.path), platform, &shown);
        shown_keys.extend(listed.into_iter().map(|key| format!("{platform}:{key}")));
        if !seen.contains(&platform) {
            seen.push(platform);
        }
    }
    seen.sort_unstable();
    let mut expected = deployers.clone();
    expected.sort_unstable();
    assert_eq!(seen, expected, "the corpus previews every such platform");
    for key in [
        "sentinel_one:url",
        "sentinel_one:site_id",
        "crowdstrike:api",
        "crowdstrike:customer_id",
        "harfanglab:url",
        "harfanglab:source_id",
        "splunk:url",
        "splunk:port",
        "splunk:app",
        "carbon_black_cloud:url",
        "carbon_black_cloud:org_key",
    ] {
        assert!(
            shown_keys.iter().any(|shown| shown == key),
            "{key} is never a placeholder: {shown_keys:?}"
        );
    }
}

/// Every placeholder in `value`'s strings, whole (`<KIND:NAME>`), each
/// `NAME` held to the documented grammar (lowercase letters, digits, `_`).
fn placeholders_in(value: &Json, out: &mut std::collections::BTreeSet<String>) {
    match value {
        Json::Str(text) => {
            for kind in ["<send-time:", "<tenant-read:", "<tenant:"] {
                for (at, _) in text.match_indices(kind) {
                    let rest = &text[at + kind.len()..];
                    let name = rest.split('>').next().unwrap_or_default();
                    assert!(
                        !name.is_empty()
                            && rest.len() > name.len()
                            && name.bytes().all(|byte| byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || byte == b'_'),
                        "not a placeholder: {text}"
                    );
                    out.insert(format!("{kind}{name}>"));
                }
            }
        }
        Json::Object(object) => object
            .values()
            .for_each(|member| placeholders_in(member, out)),
        Json::Array(items) => items.iter().for_each(|item| placeholders_in(item, out)),
        _ => {}
    }
}

/// The placeholders `docs/cli/json-output.md`'s Placeholders table names, in
/// its first column, but for the row of `<tenant:KEY>`, any key whose value
/// names a variable, which it must hold.
fn documented_placeholders() -> std::collections::BTreeSet<String> {
    let text = std::fs::read_to_string(repo().join("docs/cli/json-output.md")).unwrap();
    let section = text.split("## Placeholders").nth(1).unwrap();
    let section = section.split("\n## ").next().unwrap();
    let mut out = std::collections::BTreeSet::new();
    let mut any_key = false;
    for row in section.lines().filter(|line| line.starts_with("| `<")) {
        let cell = row.split('|').nth(1).unwrap_or_default();
        if cell.contains("`<tenant:KEY>`") {
            any_key = true;
            continue;
        }
        placeholders_in(&Json::Str(cell.replace('`', "")), &mut out);
    }
    assert!(
        any_key,
        "the table has no row for a setup variable, <tenant:KEY>"
    );
    out
}

/// The placeholders a dry run writes are the ones `docs/cli/json-output.md`
/// lists, no more and no fewer (#1719): over the compile corpus, each
/// deployer's rule with no tenant (every `<tenant:KEY>` it can show:
/// `tenant_keys`), and with the tenants the oracle compiled for.
#[test]
fn the_documented_placeholders_are_those_a_dry_run_writes() {
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
    let deployers = preview::deployers();
    let mut written = std::collections::BTreeSet::new();
    for entry in record["rules"].as_array().unwrap() {
        let platform = entry["platform"].as_str().unwrap();
        if !deployers.contains(&platform) {
            continue;
        }
        let object = index.get("rule", entry["uuid"].as_str().unwrap()).unwrap();
        let rule = Rule::new(object.root().unwrap(), None);
        let tenants: Vec<String> = entry["tenants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tenant| tenant["tenant"].as_str().unwrap().to_owned())
            .collect();
        for shown in [
            preview::preview(&cx, platform, &rule),
            preview::preview_on(&cx, platform, &rule, &tenants),
        ] {
            placeholders_in(
                shown.get("api_request").unwrap_or(&Json::Null),
                &mut written,
            );
        }
    }
    // A daily Splunk schedule, which the corpus does not hold, shows the hour.
    let daily = splunk::cron_to_timeframe("1d", "random", None, None).unwrap();
    placeholders_in(&Json::Str(daily), &mut written);
    assert_eq!(written, documented_placeholders());
}
