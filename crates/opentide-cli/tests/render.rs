//! The renderers (UC-3.4, #826): code frames, outcome lines, SARIF, Code
//! Quality, CI sinks and progress.
//!
//! `tests/render/*.input.json` are what the commands build in memory (the
//! fault workspace's diagnostics as `validate` and `lint` hand them to their
//! report writer, one synthetic diagnostic per code with a page, the
//! catalogue of explain pages, outcome, CI and progress cases), recorded once
//! from the Python implementation and never edited. Each test renders an input
//! with the Rust renderers and holds the result to its reviewed insta snapshot
//! in `tests/render/snapshots/`, or, for the CI sinks and the progress
//! events, to the values the input records.
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

#[path = "common/sarif.rs"]
mod sarif;

/// Where `<WS>` lives while rendering: absolute, so links are built as for a real file.
const ROOT: &str = "/ws-root";

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/render")
}

fn input(name: &str) -> Value {
    let text = std::fs::read_to_string(dir().join(name)).expect("read an input");
    serde_json::from_str(&text).expect("parse an input")
}

/// `candidate` is the reviewed insta snapshot `name`.
fn check(name: &str, candidate: &str) {
    insta::with_settings!({snapshot_path => dir().join("snapshots"), prepend_module_to_snapshot => true, omit_expression => true}, {
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

/// A SARIF report as the snapshot holds it: every rule of the catalogue
/// carries its full shape (its names, `helpUri`, and for a code with a page
/// its summary as the short and full description, the page's Markdown and its
/// plain text as the help), which is asserted here against the page; the
/// snapshot then holds the report without that help text, as the CLI
/// snapshots do ([`sarif::stable_sarif`]: the rules the results name, each as
/// one line, and each result's `ruleIndex` checked against its `ruleId`). The
/// catalogue's help is about 1 MB a report, and the pages are held by the
/// `explain` cases.
fn held_sarif(text: &str) -> String {
    let mut value: Value = serde_json::from_str(text).expect("a SARIF document");
    let pages = catalogue().rules;
    let rules = value
        .pointer("/runs/0/tool/driver/rules")
        .and_then(Value::as_array)
        .expect("the report's rules");
    assert_eq!(rules.len(), pages.len(), "one rule for each page");
    for (rule, page) in rules.iter().zip(&pages) {
        let at = |pointer: &str| rule.pointer(pointer).and_then(Value::as_str);
        assert_eq!(at("/id"), Some(page.code.as_str()));
        assert!(at("/name").is_some_and(|name| !name.is_empty()), "{page:?}");
        assert!(
            at("/helpUri").is_some_and(|uri| uri.ends_with(&format!("#{}", page.code))),
            "{}",
            page.code
        );
        if let (Some(summary), Some(markdown)) = (&page.summary, &page.markdown) {
            assert_eq!(at("/shortDescription/text"), Some(summary.as_str()));
            assert_eq!(at("/fullDescription/text"), Some(summary.as_str()));
            assert_eq!(at("/help/markdown"), Some(markdown.as_str()));
            assert_eq!(
                at("/help/text"),
                Some(opentide_cli::render::report::plain_text(markdown).as_str())
            );
        }
        let retired = rule
            .pointer("/properties/tags")
            .and_then(Value::as_array)
            .is_some_and(|tags| tags.iter().any(|tag| tag == "retired"));
        assert_eq!(retired, page.retired, "{}", page.code);
    }
    sarif::stable_sarif(&mut value);
    serde_json::to_string_pretty(&value).expect("a document")
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
        &held_sarif(&document_text(&sarif, false)),
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
    let mut rendered_lines = String::new();
    for (number, case) in data["cases"].as_array().unwrap().iter().enumerate() {
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
            rendered_lines.push_str(&format!(
                "{number} {} {mode}: {rendered:?}\n",
                case["kind"].as_str().unwrap()
            ));
        }
    }
    check("outcome_lines", &rendered_lines);
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
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
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
