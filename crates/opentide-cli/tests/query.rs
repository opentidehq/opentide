//! `opentide query` (UC-4.2c, #832) run in-process: the refusals of a call
//! that cannot run, and runs on Elastic tenants served by a stand-in
//! Elasticsearch on the loopback (one that answers, one that refuses the
//! query, one that is not listening, one that never answers). The recorded
//! tenants' runs are `command_goldens.rs`'s; two are replayed here with one
//! answer changed (a gateway's page in front of Splunk, Carbon Black Cloud
//! refusing the token).

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken stand-in is a failure"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// What a run printed.
struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Ran {
    fn document(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("{error}: not one JSON document:\n{}", self.stdout))
    }
}

/// Runs `opentide` with `words` in-process at `ws` (not a terminal), with
/// `env` besides `HOME`.
fn run_at(ws: &Path, words: &[&str], env: &[(&str, &str)]) -> Ran {
    let stderr = Buffer::default();
    let sink: Sink = Arc::new(Mutex::new(stderr.clone()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs(
        env.iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .chain([("HOME".to_owned(), home.display().to_string())]),
    );
    let mut out = Vec::new();
    let mut err = stderr.clone();
    let code = run(&argv, &env, &host, &mut out, &mut err);
    Ran {
        code,
        stdout: String::from_utf8(out).unwrap(),
        stderr: stderr.text(),
    }
}

/// A workspace whose `elastic.toml` holds `tenants` (`[[tenants]]` tables).
fn workspace(tenants: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    std::fs::write(
        platforms.join("elastic.toml"),
        format!("[platform]\nenabled = true\nname = \"Elastic Security\"\n\n{tenants}"),
    )
    .unwrap();
    (scratch, ws)
}

/// An Elastic tenant at `address`, its key given in the file.
fn tenant(name: &str, address: &str) -> String {
    format!(
        "[[tenants]]\nname = \"{name}\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\n\
         url = \"{address}\"\nelasticsearch_url = \"{address}\"\napi_key = \"key\"\n\n"
    )
}

/// A stand-in Elasticsearch: every request is read whole and answered with
/// `status` and the JSON `body`, the connection then closed. The requests'
/// first lines are kept.
fn elasticsearch(status: &str, body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&seen);
    let status = status.to_owned();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut payload = vec![0; length];
            reader.read_exact(&mut payload).unwrap();
            kept.lock().unwrap().push(format!(
                "{} {}",
                first.trim(),
                String::from_utf8_lossy(&payload)
            ));
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (address, seen)
}

/// An address nobody listens at.
fn nobody() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    address
}

const ANSWER: &str = r#"{"columns":[{"name":"host.name","type":"keyword"},{"name":"count","type":"long"}],"values":[["pc-1",3],["pc-2",null]],"is_partial":false}"#;
const REFUSAL: &str = r#"{"error":{"root_cause":[{"type":"verification_exception","reason":"Unknown column [nope]"}],"type":"verification_exception","reason":"Found 1 problem"},"status":400}"#;

const WINDOW: [&str; 4] = [
    "--from",
    "2099-01-01T00:00:00Z",
    "--to",
    "2099-01-01T01:00:00Z",
];

/// `--json query --platform elastic <WINDOW> <words>`.
fn elastic<'a>(words: &[&'a str]) -> Vec<&'a str> {
    let mut argv = vec!["--json", "query", "--platform", "elastic"];
    argv.extend(WINDOW);
    argv.extend(words);
    argv
}

#[test]
fn calls_that_cannot_run_are_refused_with_the_value_at_fault() {
    let (_scratch, ws) = workspace(&tenant("soc", "http://127.0.0.1:9"));
    let cases: &[(&[&str], &str, &str, &str)] = &[
        (
            &["--json", "query", "--platform", "elastic"],
            "usage_invalid_value",
            "QUERY",
            "give exactly one query: QUERY (or - for stdin), --query-file, --rule or --file",
        ),
        (
            &[
                "--json",
                "query",
                "--platform",
                "elastic",
                "--rule",
                "r",
                "FROM x",
            ],
            "usage_invalid_value",
            "--rule",
            "QUERY and --rule cannot be combined: give one query",
        ),
        (
            &[
                "--json",
                "query",
                "--platform",
                "elastic",
                "--file",
                "r.yaml",
            ],
            "usage_invalid_value",
            "--file",
            "no rule file at r.yaml",
        ),
        (
            &[
                "--json",
                "query",
                "--platform",
                "elastic",
                "--limit",
                "5001",
                "FROM x",
            ],
            "usage_invalid_value",
            "--limit",
            "--limit must be between 1 and 5000",
        ),
        (
            &[
                "--json",
                "query",
                "--platform",
                "elastic",
                "--timeout",
                "0",
                "FROM x",
            ],
            "usage_invalid_value",
            "--timeout",
            "--timeout must be positive",
        ),
        (
            &[
                "--json",
                "query",
                "--platform",
                "elastic",
                "--since",
                "1h",
                "--from",
                "2026-01-01",
                "FROM x",
            ],
            "usage_invalid_value",
            "--since",
            "--since cannot be combined with --from",
        ),
        (
            &[
                "--json",
                "query",
                "--platform",
                "elastic",
                "--to",
                "soon",
                "FROM x",
            ],
            "usage_invalid_value",
            "--to",
            "--to 'soon' is not an ISO-8601 time, such as 2026-10-27T08:00:00Z",
        ),
        (
            &[
                "--json",
                "query",
                "--platform",
                "elastic",
                "--since",
                "1 fortnight",
                "FROM x",
            ],
            "usage_invalid_value",
            "--since",
            "--since '1 fortnight' is not a duration, such as 15m, 24h, 7d or PT1H",
        ),
        (
            &["--json", "query", "--platform", "elastic", "  \n "],
            "usage_invalid_value",
            "QUERY",
            "the query is empty",
        ),
        (
            &[
                "--json",
                "query",
                "--platform",
                "elastic",
                "--tenant",
                "soc",
                "--tenant",
                "all",
                "FROM x",
            ],
            "usage_invalid_value",
            "--tenant",
            "--tenant all already selects every tenant; drop the other names",
        ),
    ];
    for (argv, code, argument, message) in cases {
        let ran = run_at(&ws, argv, &[]);
        assert_eq!(ran.code, 2, "{argv:?}: {}", ran.stdout);
        let document = ran.document();
        assert_eq!(document["status"], "failed", "{argv:?}");
        assert_eq!(document["command"], "query", "{argv:?}");
        assert_eq!(document["failure"]["code"], *code, "{argv:?}");
        assert_eq!(document["failure"]["argument"], *argument, "{argv:?}");
        assert_eq!(document["failure"]["message"], *message, "{argv:?}");
    }
    // Splunk, Carbon Black Cloud and Sentinel run here since UC-4.3 (#833):
    // a run on one of them is no longer refused as not ported, but goes on
    // to choose its tenants (none are configured for them here).
    for platform in ["splunk", "carbon_black_cloud", "sentinel"] {
        let ran = run_at(&ws, &["--json", "query", "--platform", platform, "q"], &[]);
        assert_eq!(ran.code, 2, "{platform}: {}", ran.stdout);
        let document = ran.document();
        assert_eq!(
            document["failure"]["code"], "usage_invalid_value",
            "{platform}"
        );
        assert_eq!(document["failure"]["argument"], "--tenant", "{platform}");
        let message = document["failure"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with(&format!("{platform} has no tenants configured: ")),
            "{platform}: {message}"
        );
    }
}

#[test]
fn a_language_the_platform_does_not_take_is_refused_with_the_closest() {
    let (_scratch, ws) = workspace(&tenant("soc", "http://127.0.0.1:9"));
    let ran = run_at(&ws, &elastic(&["--language", "esq", "FROM x"]), &[]);
    assert_eq!(ran.code, 2, "{}", ran.stdout);
    let document = ran.document();
    assert_eq!(
        document["failure"]["message"],
        "elastic queries are esql, eql, lucene, kuery, not 'esq'"
    );
    assert_eq!(document["failure"]["suggestion"], "esql");
    assert_eq!(document["platform"], "elastic");
    assert_eq!(
        document["choices"],
        serde_json::json!(["esql", "eql", "lucene", "kuery"])
    );
}

#[test]
fn tenants_are_chosen_among_those_configured() {
    // No tenant: the configuration file to add one to.
    let (_scratch, ws) = workspace("");
    let ran = run_at(&ws, &elastic(&["FROM x"]), &[]);
    assert_eq!(ran.code, 2, "{}", ran.stdout);
    assert_eq!(
        ran.document()["failure"]["message"],
        "elastic has no tenants configured: add a [[tenants]] entry in \
         .opentide/configurations/platforms/elastic.toml"
    );
    // Two tenants: name one; a near miss is suggested.
    let (_scratch, ws) = workspace(&format!(
        "{}{}",
        tenant("prod", "http://127.0.0.1:9"),
        tenant("lab", "http://127.0.0.1:9")
    ));
    let ran = run_at(&ws, &elastic(&["FROM x"]), &[]);
    let document = ran.document();
    assert_eq!(
        document["failure"]["message"],
        "elastic has 2 tenants (prod, lab): name one with --tenant, or pass --tenant all"
    );
    assert_eq!(
        document["choices"],
        serde_json::json!(["prod", "lab", "all"])
    );
    let ran = run_at(&ws, &elastic(&["--tenant", "prdo", "FROM x"]), &[]);
    let document = ran.document();
    assert_eq!(ran.code, 2);
    assert_eq!(
        document["failure"]["message"],
        "elastic has no tenant named 'prdo'; configured: prod, lab"
    );
    assert_eq!(document["failure"]["suggestion"], "prod");
}

/// A `$NAME` key left unset fails that tenant before any request, and the
/// configuration loader's log line names it once.
#[test]
fn an_unset_key_fails_its_tenant_without_a_request() {
    let (address, seen) = elasticsearch("200 OK", ANSWER);
    let (_scratch, ws) = workspace(&format!(
        "[[tenants]]\nname = \"soc\"\nstrategies = [\"PREVIEW\"]\n[tenants.setup]\n\
         url = \"{address}\"\nelasticsearch_url = \"{address}\"\napi_key = \"$GOLDEN_ES_KEY\"\n"
    ));
    let ran = run_at(&ws, &elastic(&["FROM x"]), &[]);
    assert_eq!(ran.code, 1, "{}", ran.stdout);
    let document = ran.document();
    assert_eq!(
        document["results"][0]["error"],
        "Elastic credentials are unset ($GOLDEN_ES_KEY). Set those environment variables \
         before a live check."
    );
    assert!(seen.lock().unwrap().is_empty());
    assert!(
        ran.stderr.contains("environment_variable_missing"),
        "{}",
        ran.stderr
    );
    assert!(ran.stderr.contains("$GOLDEN_ES_KEY"), "{}", ran.stderr);
}

/// Three tenants: one answers, one refuses the query, one cannot be
/// reached. The run fails on the first failure, with every tenant's
/// outcome in `results`.
#[test]
fn every_tenant_runs_and_a_failed_one_fails_the_run() {
    let (good, good_seen) = elasticsearch("200 OK", ANSWER);
    let (bad, _) = elasticsearch("400 Bad Request", REFUSAL);
    let down = nobody();
    let (_scratch, ws) = workspace(&format!(
        "{}{}{}",
        tenant("good", &good),
        tenant("bad", &bad),
        tenant("down", &down)
    ));
    let ran = run_at(
        &ws,
        &elastic(&[
            "--tenant",
            "all",
            "--limit",
            "5",
            "FROM logs-* | KEEP host.name",
        ]),
        &[],
    );
    assert_eq!(ran.code, 1, "{}", ran.stdout);
    let document = ran.document();
    assert_eq!(document["status"], "failed");
    assert_eq!(
        document["message"],
        "2 of 3 queries failed on 3 elastic tenants: bad: Elastic refused the ES|QL query on \
         bad (HTTP 400)"
    );
    assert_eq!(document["failure"]["code"], "command_failed");
    assert_eq!(document["detail"], "Unknown column [nope]");
    assert_eq!(
        document["tenants"],
        serde_json::json!(["good", "bad", "down"])
    );
    assert_eq!(document["row_count"], 2);
    assert_eq!(document["limit"], 5);
    assert_eq!(document["query"], "FROM logs-* | KEEP host.name");
    assert_eq!(
        document["window"],
        serde_json::json!({"from": "2099-01-01T00:00:00.000Z", "to": "2099-01-01T01:00:00.000Z"})
    );
    assert_eq!(
        document["summary"],
        serde_json::json!({"tenants": 3, "rows": 2, "failed": 2})
    );
    let results = document["results"].as_array().unwrap();
    assert_eq!(results[0]["status"], "ok");
    assert_eq!(
        results[0]["columns"],
        serde_json::json!([{"name": "host.name", "type": "keyword"}, {"name": "count", "type": "long"}])
    );
    assert_eq!(
        results[0]["rows"],
        serde_json::json!([{"host.name": "pc-1", "count": 3}, {"host.name": "pc-2", "count": null}])
    );
    assert_eq!(results[0]["language"], "esql");
    assert_eq!(
        results[0]["sent"],
        "FROM logs-* | KEEP host.name\n| LIMIT 6"
    );
    assert_eq!(results[1]["status"], "failed");
    assert_eq!(results[1]["detail"], "Unknown column [nope]");
    let unreachable = results[2]["error"].as_str().unwrap();
    assert!(
        unreachable.starts_with(&format!("Cannot reach elastic tenant 'down' at {down}")),
        "{unreachable}"
    );
    // The query went to `_query` with the limit and the window's filter.
    let seen = good_seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("POST /_query HTTP/1.1 "), "{}", seen[0]);
    assert!(seen[0].contains("2099-01-01T00:00:00.000Z"), "{}", seen[0]);
}

/// An Elastic ES|QL rule, its UUID in upper case.
const ES_RULE: &str = "name: Hosts\nmetadata:\n  uuid: 00000000-0000-4000-8000-0000000000EE\n  \
     schema: rule::1.0\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: \
     clear\ndescription: d\nconfigurations:\n  elastic:\n    status: STAGING\n    \
     type: esql\n    query: |\n      FROM logs-* | KEEP host.name\n";

#[test]
fn a_rules_query_runs_as_deploy_would_send_it() {
    // UC-4.4c (#834): --rule finds the rule whatever the case of its UUID,
    // --file reads it from the working directory, else the repository.
    let (good, seen) = elasticsearch("200 OK", ANSWER);
    let (_scratch, ws) = workspace(&tenant("good", &good));
    std::fs::create_dir_all(ws.join("objects/rules")).unwrap();
    std::fs::write(ws.join("objects/rules/hosts.yaml"), ES_RULE).unwrap();
    let by_uuid = run_at(
        &ws,
        &elastic(&["--rule", " 00000000-0000-4000-8000-0000000000ee "]),
        &[],
    );
    assert_eq!(by_uuid.code, 0, "{}", by_uuid.stdout);
    let document = by_uuid.document();
    assert_eq!(document["source"], "rule");
    assert!(document.get("query").is_none());
    assert_eq!(
        document["rule"],
        serde_json::json!({
            "uuid": "00000000-0000-4000-8000-0000000000ee",
            "name": "Hosts",
            "queries": ["FROM logs-* | KEEP host.name"],
        })
    );
    assert_eq!(document["results"][0]["language"], "esql");
    assert_eq!(document["row_count"], 2);
    let elsewhere = ws.with_file_name("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let by_file = run_at(
        &elsewhere,
        &{
            let mut argv = vec!["--repo", ws.to_str().unwrap()];
            argv.extend(elastic(&["--file", "objects/rules/hosts.yaml"]));
            argv
        },
        &[],
    );
    assert_eq!(by_file.code, 0, "{}", by_file.stdout);
    assert_eq!(by_file.document()["rule"], document["rule"]);
    assert_eq!(seen.lock().unwrap().len(), 2);
    // A file that is no valid rule is refused with the model's errors.
    std::fs::write(
        ws.join("objects/rules/bad.yaml"),
        ES_RULE.replace("  tlp: clear\n", ""),
    )
    .unwrap();
    let invalid = run_at(&ws, &elastic(&["--file", "objects/rules/bad.yaml"]), &[]);
    assert_eq!(invalid.code, 2);
    assert_eq!(
        invalid.document()["message"],
        "cannot read the rule in objects/rules/bad.yaml: 1 validation error for DetectionRule\n\
         metadata.tlp\n  Field required [type=missing]"
    );
    assert_eq!(invalid.document()["failure"]["argument"], "--file");
    // A UUID no rule has, with the closest; a rule without the platform.
    let unknown = run_at(
        &ws,
        &elastic(&["--rule", "00000000-0000-4000-8000-0000000000ef"]),
        &[],
    );
    assert_eq!(unknown.code, 2);
    let failure = &unknown.document()["failure"];
    assert_eq!(failure["code"], "usage_invalid_value");
    assert_eq!(failure["argument"], "--rule");
    assert_eq!(
        failure["message"],
        "no rule with UUID 00000000-0000-4000-8000-0000000000ef"
    );
    assert_eq!(
        failure["suggestion"],
        "00000000-0000-4000-8000-0000000000EE"
    );
    let mut argv = vec!["--json", "query", "--platform", "splunk"];
    argv.extend(["--rule", "00000000-0000-4000-8000-0000000000ee"]);
    let missing = run_at(&ws, &argv, &[]);
    assert_eq!(missing.code, 2);
    assert_eq!(
        missing.document()["message"],
        "rule 'Hosts' has no splunk configuration"
    );
    assert_eq!(missing.document()["failure"]["argument"], "--rule");
}

#[test]
fn rows_are_printed_as_a_table_json_lines_or_csv() {
    let (good, _) = elasticsearch("200 OK", ANSWER);
    let (bad, _) = elasticsearch("400 Bad Request", REFUSAL);
    let (_scratch, ws) = workspace(&format!("{}{}", tenant("good", &good), tenant("bad", &bad)));
    let argv = |format: &'static str| -> Vec<&'static str> {
        let mut argv = vec!["query", "--platform", "elastic", "--tenant", "all"];
        argv.extend(WINDOW);
        argv.extend(["--format", format, "FROM logs-*"]);
        argv
    };
    let table = run_at(&ws, &argv("table"), &[]);
    assert_eq!(table.code, 1);
    assert!(
        table.stdout.starts_with(
            "good  2 rows\n\
             host.name ┃ count\n\
             ━━━━━━━━━━╇━━━━━━\n\
             pc-1      │ 3    \n\
             pc-2      │      \n\
             \n"
        ),
        "{}",
        table.stdout
    );
    assert!(
        table
            .stderr
            .contains("bad  failed: Elastic refused the ES|QL query on bad (HTTP 400)\n"),
        "{}",
        table.stderr
    );
    let lines = run_at(&ws, &argv("jsonl"), &[]);
    assert_eq!(lines.code, 1);
    assert!(
        lines.stdout.starts_with(
            "{\"_tenant\": \"good\", \"host.name\": \"pc-1\", \"count\": 3}\n\
             {\"_tenant\": \"good\", \"host.name\": \"pc-2\", \"count\": null}\n"
        ),
        "{}",
        lines.stdout
    );
    let csv = run_at(&ws, &argv("csv"), &[]);
    assert_eq!(csv.code, 1);
    assert!(
        csv.stdout
            .starts_with("_tenant,host.name,count\ngood,pc-1,3\ngood,pc-2,\n"),
        "{}",
        csv.stdout
    );
    // One tenant that answers: the rows are the whole of stdout.
    let mut only_good = argv("csv");
    only_good[4] = "good";
    let csv = run_at(&ws, &only_good, &[]);
    assert_eq!(csv.code, 0, "{}", csv.stderr);
    assert_eq!(
        csv.stdout,
        "_tenant,host.name,count\ngood,pc-1,3\ngood,pc-2,\n"
    );
    let mut only_good = argv("jsonl");
    only_good[4] = "good";
    let lines = run_at(&ws, &only_good, &[]);
    assert_eq!(lines.code, 0, "{}", lines.stderr);
    assert_eq!(
        lines.stdout,
        "{\"_tenant\": \"good\", \"host.name\": \"pc-1\", \"count\": 3}\n\
         {\"_tenant\": \"good\", \"host.name\": \"pc-2\", \"count\": null}\n"
    );
}

/// A tenant that takes the query and never answers: the read timeout, named
/// as requests names it, and what to do about it.
#[test]
fn a_tenant_that_does_not_answer_in_time_fails_with_advice() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    let (_scratch, ws) = workspace(&tenant("slow", &address));
    let ran = run_at(&ws, &elastic(&["--timeout", "1", "FROM x"]), &[]);
    assert_eq!(ran.code, 1, "{}", ran.stdout);
    let document = ran.document();
    assert_eq!(
        document["results"][0]["error"],
        "elastic tenant 'slow' did not answer the query within 1s: \
         HTTPSConnectionPool(host='127.0.0.1', port=443): Read timed out. (read timeout=1)"
    );
    assert_eq!(document["detail"], "narrow the window or raise --timeout");
}

/// The repository's root.
fn repo() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Replays the recorded run `golden/<scenario>` (`tests/cassettes/`) with
/// its first `keep` interactions as recorded and the next one answered with
/// `status`, `content_type` and `body`, on the golden `tenants` fixture's
/// configuration of `platform`; `argv` is the recorded case's, so the
/// requests are the cassette's. The run, and every difference between what
/// was sent and the cassette.
fn replay_answering(
    scenario: &str,
    platform: &str,
    keep: usize,
    (status, content_type, body): (u16, &str, &str),
    argv: &[&str],
    credential: (&str, &str),
) -> (Ran, Vec<String>) {
    use opentide_cassette::{Body, Cassette, Mode, Proxy, Redaction};
    let text =
        std::fs::read_to_string(repo().join(format!("tests/cassettes/golden/{scenario}.json")))
            .unwrap();
    let recorded = Cassette::parse(&text).unwrap();
    let mut interactions = recorded.interactions[..=keep].to_vec();
    let answer = &mut interactions[keep].response;
    answer.status = status;
    answer.headers = vec![("content-type".into(), content_type.into())];
    answer.body = Body::Text(body.into());
    let cassette = Cassette::new(
        &recorded.scenario,
        recorded.recorded_from.clone(),
        interactions,
    );
    let proxy = Proxy::start(Mode::Replay { cassette }, Redaction::default()).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::create_dir_all(&platforms).unwrap();
    let config = format!("{platform}.toml");
    std::fs::copy(
        repo()
            .join("tests/golden/fixtures/tenants/.opentide/configurations/platforms")
            .join(&config),
        platforms.join(&config),
    )
    .unwrap();
    let ca = scratch.path().join("cassette-ca.pem");
    std::fs::write(&ca, proxy.ca_pem()).unwrap();
    let env = proxy.client_env(&ca.display().to_string());
    let mut pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    pairs.push(credential);
    let ran = run_at(&ws, argv, &pairs);
    let mismatches = proxy.verify().iter().map(|m| format!("{m:?}")).collect();
    (ran, mismatches)
}

/// The one tenant's error and advice in a run's JSON document.
fn tenant_failure(ran: &Ran) -> (String, Option<String>) {
    assert_eq!(ran.code, 1, "{}", ran.stdout);
    let document = ran.document();
    let result = &document["results"][0];
    assert_eq!(result["status"], "failed", "{result}");
    (
        result["error"].as_str().unwrap().to_owned(),
        result["detail"].as_str().map(str::to_owned),
    )
}

/// A gateway in front of Splunk answers the search with its own HTML page
/// (UC-4.3, #833): the tenant did not answer in time, with the advice to
/// narrow the window, and the page names the proxy the request went
/// through.
#[test]
fn a_splunk_search_a_gateway_answers_is_a_timeout_with_advice() {
    let (ran, mismatches) = replay_answering(
        "query-splunk",
        "splunk",
        2,
        (
            504,
            "text/html",
            "<html><head><title>504 Gateway Time-out</title></head><body></body></html>",
        ),
        &[
            "--json",
            "query",
            "--platform",
            "splunk",
            "--from",
            "2099-01-01T00:00:00Z",
            "--to",
            "2099-01-01T01:00:00Z",
            "--limit",
            "2",
            "index=main EventCode=4688",
        ],
        ("SPLUNK_TOKEN", "golden-stand-in-credential"),
    );
    assert_eq!(mismatches, Vec::<String>::new());
    let (error, detail) = tenant_failure(&ran);
    assert!(
        error.starts_with(
            "splunk tenant 'lab' did not answer the query within 120s: Splunk at \
             https://splunk.invalid:8089 answered with an HTML page (HTTP 504), not its REST API \
             (page title: '504 Gateway Time-out'). HTTP 504 Gateway Timeout is what a gateway"
        ),
        "{error}"
    );
    assert!(
        error.contains(" The request went through the proxy http://127.0.0.1:"),
        "{error}"
    );
    assert_eq!(
        detail.as_deref(),
        Some("narrow the window or raise --timeout")
    );
}

/// Carbon Black Cloud answers the query's validation with 401: the tenant
/// cannot be signed in to, and no search starts.
#[test]
fn a_carbon_black_tenant_that_refuses_the_token_fails_authentication() {
    let (ran, mismatches) = replay_answering(
        "query-carbon-black",
        "carbon_black_cloud",
        0,
        (401, "application/json", ""),
        &[
            "--json",
            "query",
            "--platform",
            "carbon_black_cloud",
            "--from",
            "2099-01-01T00:00:00Z",
            "--to",
            "2099-01-01T01:00:00Z",
            "--limit",
            "2",
            "process_name:cmd.exe",
        ],
        ("CBC_TOKEN", "golden-stand-in-credential"),
    );
    assert_eq!(mismatches, Vec::<String>::new());
    let (error, detail) = tenant_failure(&ran);
    assert_eq!(
        error,
        "cannot authenticate to carbon_black_cloud tenant 'lab': Unauthorized (Check API \
         creds): attempted to POST \
         https://cbc.invalid/api/investigate/v2/orgs/ORGKEY01/processes/search_validation"
    );
    assert_eq!(detail, None);
}
