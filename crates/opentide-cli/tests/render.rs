//! The renderers against the oracle (UC-3.4, #826): code frames, outcome lines,
//! SARIF, Code Quality, CI sinks and progress, byte for byte.
//!
//! `tests/render/*.input.json` are what the oracle's commands build in memory
//! (the fault workspace's diagnostics as `validate` and `lint` hand them to
//! their report writer, one synthetic diagnostic per code with a page, the
//! catalogue of explain pages, outcome, CI and progress cases), and
//! `tests/render/snapshots/render__*.snap` what the oracle prints for them.
//! Both are written by `scripts/golden/render_oracle.py`, run with the oracle's
//! interpreter; never edited. Each test renders the same input with the Rust
//! renderers and compares: exactly, and as an insta snapshot for review.
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions"
)]

use opentide_cli::env::Env;
use opentide_cli::envelope::NextAction;
use opentide_cli::json::{Json, document_text};
use opentide_cli::mode::Mode;
use opentide_cli::render::ci::{self, Provider};
use opentide_cli::render::codeframe::Frames;
use opentide_cli::render::diagnostic::{Diagnostic, MemorySources};
use opentide_cli::render::outcome::{Console, OutcomeKind};
use opentide_cli::render::progress::{self, Progress, Step, StepStatus, Ticker};
use opentide_cli::render::report::{RuleCatalogue, RulePage, codequality_report, sarif_report};
use opentide_cli::render::summary::{self, MAX_SUMMARY_BYTES};
use opentide_cli::render::text::Colour;
use regex::Regex;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Where `<WS>` lives while rendering: absolute, so links are built as for a real file.
const ROOT: &str = "/ws-root";

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/render")
}

fn input(name: &str) -> Value {
    let text = std::fs::read_to_string(dir().join(name)).expect("read an input");
    serde_json::from_str(&text).expect("parse an input")
}

/// The oracle's output: the snapshot's body, exactly.
fn oracle(name: &str) -> String {
    let path = dir().join(format!("snapshots/render__{name}.snap"));
    let text = std::fs::read_to_string(&path).expect("read a snapshot");
    let body = text
        .splitn(3, "---\n")
        .nth(2)
        .expect("an insta header between two `---` lines");
    body.strip_suffix('\n')
        .expect("a body ends in a newline")
        .to_owned()
}

/// `candidate` equals the oracle's `name` byte for byte, and its insta snapshot.
fn check(name: &str, candidate: &str) {
    let expected = oracle(name);
    if candidate != expected {
        let line = candidate
            .split('\n')
            .zip(expected.split('\n'))
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| {
                candidate
                    .split('\n')
                    .count()
                    .min(expected.split('\n').count())
            });
        panic!(
            "{name}: the Rust renderer differs from the oracle at line {}\n  oracle: {:?}\n  rust:   {:?}",
            line + 1,
            expected.split('\n').nth(line).unwrap_or("<end>"),
            candidate.split('\n').nth(line).unwrap_or("<end>"),
        );
    }
    insta::with_settings!({snapshot_path => dir().join("snapshots"), prepend_module_to_snapshot => true}, {
        insta::assert_snapshot!(name, candidate);
    });
}

/// The workspace back as `<WS>`, and terminal hyperlink ids as `<ID>`.
fn normalised(text: &str) -> String {
    let link = Regex::new("\u{1b}\\]8;id=[^;]*;").unwrap();
    let text = text
        .replace(&format!("file://{ROOT}"), "file://<WS>")
        .replace(ROOT, "<WS>");
    link.replace_all(&text, "\u{1b}]8;id=<ID>;").into_owned()
}

fn at_root(path: &str) -> PathBuf {
    PathBuf::from(path.replacen("<WS>", ROOT, 1))
}

fn diagnostics(value: &Value) -> Vec<Diagnostic> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            let mut diagnostic: Diagnostic =
                serde_json::from_value(item.clone()).expect("a diagnostic");
            diagnostic.file_path = diagnostic
                .file_path
                .map(|path| at_root(&path.to_string_lossy()));
            diagnostic
        })
        .collect()
}

fn sources(value: &Value) -> MemorySources {
    let mut sources = MemorySources::default();
    for (path, text) in value.as_object().unwrap() {
        sources
            .texts
            .insert(at_root(path), text.as_str().unwrap().to_owned());
    }
    sources
}

fn frames(mode: &str) -> Frames {
    let human = mode == "human";
    Frames {
        colour: if human { Colour::Full } else { Colour::None },
        links: human,
        columns: human.then_some(100),
        highlight: human,
        cwd: PathBuf::from(ROOT),
        env: Env::from_pairs([("OPENTIDE_LINKS", "file")]),
    }
}

fn catalogue() -> RuleCatalogue {
    RuleCatalogue {
        rules: serde_json::from_value::<Vec<RulePage>>(input("rules.input.json"))
            .expect("rule pages"),
    }
}

fn fault(command: &str) {
    let data = input(&format!("{command}-fault.input.json"));
    let items = diagnostics(&data["diagnostics"]);
    let mut texts = sources(&data["sources"]);
    for mode in ["human", "plain"] {
        let rendered = frames(mode).render(&items, &mut texts, false);
        check(
            &format!("{command}_fault_frames_{mode}"),
            &normalised(&rendered),
        );
    }
    let root = PathBuf::from(ROOT);
    let path_for = |item: &Diagnostic| ci::repository_path(item, Some(&root));
    let version = data["version"].as_str().unwrap();
    let sarif = sarif_report(&items, command, version, &catalogue(), &path_for);
    check(
        &format!("{command}_fault_sarif"),
        document_text(&sarif, true).trim_end_matches('\n'),
    );
    let quality = codequality_report(&items, &path_for);
    check(
        &format!("{command}_fault_codequality"),
        document_text(&quality, true).trim_end_matches('\n'),
    );
    for (name, provider) in [
        ("github", Provider::Github),
        ("gitlab", Provider::Gitlab),
        ("azure", Provider::Azure),
    ] {
        let lines = ci::annotation_lines(&items, Some(provider), Some(&root));
        check(
            &format!("{command}_fault_ci_{name}"),
            &normalised(&lines.join("\n")),
        );
    }
    let markdown = summary::diagnostics_summary(
        &format!("opentide {command}"),
        "101 errors in 89 files",
        &items,
        "failed",
        Some(&path_for),
    );
    check(
        &format!("{command}_fault_summary"),
        &summary::fit(&markdown, MAX_SUMMARY_BYTES),
    );
}

#[test]
fn render_validate_fault_workspace_frames_reports_and_sinks() {
    fault("validate");
}

#[test]
fn render_lint_fault_workspace_frames_reports_and_sinks() {
    fault("lint");
}

#[test]
fn render_every_code_frame_human_and_plain() {
    let data = input("codes.input.json");
    let items = diagnostics(&data["diagnostics"]);
    let mut texts = sources(&data["sources"]);
    for mode in ["human", "plain"] {
        let mut out = String::new();
        for item in &items {
            out.push_str(&format!("== {}\n", item.code));
            out.push_str(&frames(mode).render(std::slice::from_ref(item), &mut texts, false));
        }
        check(&format!("codes_frames_{mode}"), &normalised(&out));
    }
}

fn outcome_kind(name: &str) -> OutcomeKind {
    match name {
        "ok" => OutcomeKind::Ok,
        "warning" => OutcomeKind::Warning,
        "skipped" => OutcomeKind::Skipped,
        "failed" => OutcomeKind::Failed,
        _ => OutcomeKind::Plan,
    }
}

fn pairs(value: &Value) -> Vec<(String, String)> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_owned(),
                pair[1].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn step(spec: &Value) -> Step {
    let mut step = Step::new(spec["name"].as_str().unwrap());
    spec.get("unit")
        .and_then(Value::as_str)
        .unwrap_or("file")
        .clone_into(&mut step.unit);
    step.seconds = 1.25;
    if let Some(count) = spec.get("count").and_then(Value::as_u64) {
        step.count = Some(usize::try_from(count).unwrap());
    }
    step.place = spec.get("where").and_then(Value::as_str).map(str::to_owned);
    step.outcome = spec
        .get("outcome")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(plural) = spec.get("plural").and_then(Value::as_str) {
        step.outcome = Some(progress::plural(
            step.count.unwrap(),
            &step.unit,
            Some(plural),
        ));
    }
    match spec["status"].as_str().unwrap() {
        "skipped" => {
            step.status = StepStatus::Skipped;
            spec["detail"]
                .as_str()
                .unwrap()
                .clone_into(&mut step.detail);
        }
        "ok" => step.status = StepStatus::Ok,
        "failed" => step.status = StepStatus::Failed,
        _ => step.status = StepStatus::Running,
    }
    step
}

#[test]
fn render_every_outcome_line_variant() {
    let data = input("outcome.input.json");
    for case in data["cases"].as_array().unwrap() {
        for (mode, console, output_mode) in [
            (
                "human",
                Console {
                    colour: Colour::Full,
                    width: Some(100),
                },
                Mode::Human,
            ),
            (
                "plain",
                Console {
                    colour: Colour::None,
                    width: None,
                },
                Mode::Plain,
            ),
            (
                "narrow",
                Console {
                    colour: Colour::Full,
                    width: Some(40),
                },
                Mode::Human,
            ),
        ] {
            let rendered = match case["kind"].as_str().unwrap() {
                "outcome" => console.outcome(
                    outcome_kind(case["outcome"].as_str().unwrap()),
                    case["message"].as_str().unwrap(),
                ),
                "warnings" => console.warnings(
                    &case["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|message| message.as_str().unwrap().to_owned())
                        .collect::<Vec<_>>(),
                ),
                "notes" => console.notes(&pairs(&case["notes"])),
                "error" => console.error(
                    case["message"].as_str().unwrap(),
                    &pairs(&case["notes"]),
                    Mode::Agent,
                    true,
                ),
                "next" => console.next_actions(
                    &pairs(&case["actions"])
                        .into_iter()
                        .map(|(command, reason)| NextAction::new(command, reason))
                        .collect::<Vec<_>>(),
                ),
                "tip" => console.agent_tip(Mode::Agent) + &console.agent_tip(output_mode),
                "steps" => case["steps"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|spec| console.line(&progress::step_line(&step(spec))))
                    .collect(),
                other => panic!("unknown case kind {other}"),
            };
            assert_eq!(
                rendered,
                case["rendered"][mode].as_str().unwrap(),
                "{case} in {mode}"
            );
        }
    }
    for entry in data["words"]["plural"].as_array().unwrap() {
        let count = usize::try_from(entry[0].as_u64().unwrap()).unwrap();
        assert_eq!(
            progress::plural(count, entry[1].as_str().unwrap(), None),
            entry[2].as_str().unwrap()
        );
    }
    for entry in data["words"]["seconds"].as_array().unwrap() {
        assert_eq!(
            progress::seconds_text(entry[0].as_f64().unwrap()),
            entry[1].as_str().unwrap()
        );
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn render_ci_sinks_escaping_caps_and_summaries() {
    let data = input("ci.input.json");
    for case in data["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let items = diagnostics(&case["diagnostics"]);
        assert_eq!(
            ci::annotation_lines(&items, Some(Provider::Github), None),
            strings(&case["github"]),
            "{name}"
        );
        assert_eq!(
            ci::annotation_lines(&items, Some(Provider::Azure), None),
            strings(&case["azure"]),
            "{name}"
        );
        assert_eq!(
            ci::annotation_lines(&items, Some(Provider::Gitlab), None),
            strings(&case["gitlab"]),
            "{name}"
        );
        assert_eq!(
            summary::diagnostics_summary(
                "opentide validate",
                "3 errors · <b>x</b> | y",
                &items,
                "failed",
                None
            ),
            case["summary"].as_str().unwrap(),
            "{name}"
        );
    }
    for fit in data["fits"].as_array().unwrap() {
        let limit = fit[1]
            .as_u64()
            .map_or(MAX_SUMMARY_BYTES, |limit| usize::try_from(limit).unwrap());
        assert_eq!(
            summary::fit(fit[0].as_str().unwrap(), limit),
            fit[2].as_str().unwrap()
        );
    }
    let escapes = &data["escapes"];
    for pair in escapes["cell"].as_array().unwrap() {
        assert_eq!(
            summary::cell(pair[0].as_str().unwrap()),
            pair[1].as_str().unwrap()
        );
    }
    for pair in escapes["code"].as_array().unwrap() {
        assert_eq!(
            summary::code(pair[0].as_str().unwrap()),
            pair[1].as_str().unwrap()
        );
    }
    for pair in escapes["heading"].as_array().unwrap() {
        assert_eq!(
            summary::heading(pair[0].as_str().unwrap(), "opentide x"),
            pair[1].as_str().unwrap()
        );
    }
    for pair in escapes["file_names"].as_array().unwrap() {
        assert_eq!(
            ci::summary_file_name(pair[0].as_str().unwrap()),
            pair[1].as_str().unwrap()
        );
    }
    let warnings = strings(&escapes["warning"]);
    assert_eq!(
        [
            ci::warning_line(
                Some(Provider::Github),
                "the run: 50%, done",
                Some("opentide")
            )
            .unwrap(),
            ci::github_command("warning", "no title", &[("title", None)]),
            ci::azure_command(
                "task.logissue",
                "the run; done]",
                &[
                    ("type", Some("warning".to_owned())),
                    ("code", Some("x;y".to_owned()))
                ]
            ),
            ci::azure_command("task.uploadsummary", "/tmp/a b.md", &[]),
        ]
        .as_slice(),
        warnings.as_slice()
    );
    // The results keep their keys in order: read them through the order-keeping tree.
    let text = std::fs::read_to_string(dir().join("ci.input.json")).unwrap();
    let all = Json::parse(&text).unwrap();
    let results = all.get("results").unwrap();
    let Some(Json::Array(deploys)) = results.get("deploy") else {
        panic!("no deploy results");
    };
    for entry in deploys {
        let dry_run = match entry.get("dry_run") {
            Some(Json::Bool(flag)) => Some(*flag),
            _ => None,
        };
        let Some(Json::Str(markdown)) = entry.get("markdown") else {
            panic!("no markdown");
        };
        assert_eq!(
            &summary::deploy_summary(entry.get("result").unwrap(), None, dry_run),
            markdown
        );
    }
    let Some(Json::Array(queries)) = results.get("query") else {
        panic!("no query results");
    };
    for entry in queries {
        let Some(Json::Str(markdown)) = entry.get("markdown") else {
            panic!("no markdown");
        };
        assert_eq!(
            &summary::query_summary(entry.get("result").unwrap(), None),
            markdown
        );
    }
}

#[test]
fn render_progress_events_and_tickers() {
    let text = std::fs::read_to_string(dir().join("progress.input.json")).unwrap();
    let data = Json::parse(&text).unwrap();
    let Some(Json::Array(tickers)) = data.get("tickers") else {
        panic!("no tickers");
    };
    for case in tickers {
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&events);
        let sink = Progress::to_sink(Arc::new(move |event| seen.lock().unwrap().push(event)));
        let Some(Json::Int(total)) = case.get("total") else {
            panic!("no total");
        };
        let ticker = Ticker::new(&sink, "schemas", usize::try_from(*total).unwrap());
        let Some(Json::Array(advances)) = case.get("advances") else {
            panic!("no advances");
        };
        for advance in advances {
            let Json::Int(count) = advance else {
                panic!("a count")
            };
            ticker.advance(usize::try_from(*count).unwrap());
        }
        assert_eq!(
            Json::Array(events.lock().unwrap().clone()),
            case.get("events").unwrap().clone(),
            "total {total}"
        );
    }
    let lines = [
        progress::event_line(&progress::progress_event("objects", 3, None)),
        progress::event_line(
            &progress::TenantEvent {
                platform: "sentinel",
                tenant: "prod 🔥",
                ok: false,
                rows: 0,
                elapsed_ms: 12,
                label: None,
            }
            .to_json(),
        ),
        progress::event_line(
            &progress::TenantEvent {
                platform: "elastic",
                tenant: "dev",
                ok: true,
                rows: 4,
                elapsed_ms: 5,
                label: Some("query 2"),
            }
            .to_json(),
        ),
    ]
    .concat();
    let Some(Json::Str(stderr)) = data.get("stderr") else {
        panic!("no stderr");
    };
    assert_eq!(&lines, stderr);
}
