//! Public Falco rules converted into opentide rules (`configurations.sysdig`,
//! sysdig-1.0), in `crates/testdata/workspaces/falco/`: the injected condition,
//! macro conditions, and output are checked as Falco, with the block's own
//! macros and lists and its event source; hover and completion work inside
//! them; a fault in any of them is reported on the source text that holds it.
//!
//! Each file names the public rule it is converted from. The Tide checks of
//! the object itself come from opentide's field catalog, which knows
//! `configurations.sysdig`: every converted rule is clean end to end.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_analysis::{
    AnalyzeRequest, LanguageId, MemoryWorkspace, Position, analyze, analyze_blocks,
    analyze_queries, codes, completions, hover,
};
use std::fs;
use std::path::PathBuf;

fn rules() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/workspaces/falco/objects/rules");
    let mut out: Vec<(String, String)> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .map(|p| {
            (
                format!("objects/rules/{}", p.file_name().unwrap().to_string_lossy()),
                fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

fn rule(name: &str) -> String {
    rules()
        .into_iter()
        .find(|(path, _)| path.ends_with(name))
        .unwrap_or_else(|| panic!("no fixture {name}"))
        .1
}

/// Every `falco_*` finding of the object: its condition's, and the Sysdig
/// block's own ([`analyze_blocks`], which `lint` reports and the editor
/// leaves to it: UC-2.6, #821).
fn falco_codes(path: &str, text: &str) -> Vec<(String, String)> {
    let host = MemoryWorkspace {
        files: vec![(path.into(), text.into())],
    };
    analyze(
        &host,
        AnalyzeRequest {
            uri: path.into(),
            language: LanguageId::TideYaml,
            text: text.into(),
        },
    )
    .diagnostics
    .into_iter()
    .chain(analyze_blocks(&host, text))
    .filter(|d| d.code.starts_with("falco_"))
    .map(|d| {
        let line = text.lines().nth(d.range.start.line as usize).unwrap_or("");
        let at: String = line
            .chars()
            .skip(d.range.start.character as usize)
            .take((d.range.end.character - d.range.start.character) as usize)
            .collect();
        (d.code, at)
    })
    .collect()
}

#[test]
fn the_converted_rules_have_no_finding_of_any_kind() {
    for (path, text) in rules() {
        let host = MemoryWorkspace {
            files: vec![(path.clone(), text.clone())],
        };
        let found: Vec<String> = analyze(
            &host,
            AnalyzeRequest {
                uri: path.clone(),
                language: LanguageId::TideYaml,
                text,
            },
        )
        .diagnostics
        .into_iter()
        .map(|d| format!("{}: {}", d.code, d.message))
        .collect();
        assert!(found.is_empty(), "{path}: {found:?}");
    }
}

fn position_of(text: &str, needle: &str) -> (usize, Position) {
    let offset = text.find(needle).unwrap_or_else(|| panic!("{needle}")) + 1;
    (offset, opentide_core::offset_to_position(text, offset))
}

#[test]
fn the_converted_rules_cover_the_sources_and_a_tuning() {
    let all = rules();
    assert!(all.len() >= 9, "{}", all.len());
    for needle in [
        "source: k8s_audit",
        "source: aws_cloudtrail",
        "append_to_rule:",
        "macros:",
        "lists:",
        "exceptions:",
    ] {
        assert!(
            all.iter().any(|(_, text)| text.contains(needle)),
            "no fixture with {needle}"
        );
    }
}

#[test]
fn every_converted_rule_is_clean() {
    let host = MemoryWorkspace::default();
    for (path, text) in rules() {
        let queries = analyze_queries(&host, &text);
        let falco: Vec<_> = queries
            .iter()
            .filter(|q| q.language == LanguageId::Falco)
            .collect();
        assert!(
            falco
                .iter()
                .any(|q| q.field_path == ["configurations", "sysdig", "condition"]),
            "{path}: the condition is not checked"
        );
        for q in &falco {
            assert_eq!(q.platform, "sysdig");
            assert!(
                q.diagnostics.is_empty(),
                "{path} {}: {:?}",
                q.field_path.join("."),
                q.diagnostics
                    .iter()
                    .map(|d| (&d.code, &d.message))
                    .collect::<Vec<_>>()
            );
        }
        assert_eq!(falco_codes(&path, &text), vec![], "{path}");
    }
}

/// UC-2.6 (#821): an exception value the field's type cannot hold is a
/// fault of the condition Falco appends it to, so the condition's analysis
/// carries it: `opentide validate`'s queries check ([`analyze_queries`], as
/// an error) and the editor ([`analyze`]) report it, once each, and the
/// block's own findings ([`analyze_blocks`], `lint`'s) do not repeat it.
#[test]
fn an_exception_value_the_field_cannot_hold_is_the_conditions_fault() {
    let text = rule("terminal-shell-in-container.yaml").replacen(
        "fields: [proc.pname, container.image.repository]",
        "fields: [proc.pid, container.image.repository]",
        1,
    );
    let host = MemoryWorkspace::default();
    let condition = analyze_queries(&host, &text)
        .into_iter()
        .find(|q| q.field_path == ["configurations", "sysdig", "condition"])
        .unwrap_or_else(|| panic!("no condition query"));
    let errors: Vec<&str> = condition
        .diagnostics
        .iter()
        .filter(|d| d.severity == opentide_analysis::Severity::Error)
        .map(|d| d.code.as_str())
        .collect();
    assert_eq!(
        errors,
        [codes::FALCO_EXCEPTION],
        "{:?}",
        condition.diagnostics
    );
    let editor = analyze(
        &host,
        AnalyzeRequest {
            uri: "objects/rules/terminal-shell-in-container.yaml".into(),
            language: LanguageId::TideYaml,
            text: text.clone(),
        },
    )
    .diagnostics;
    let exceptions = |found: &[opentide_analysis::Diagnostic]| {
        found
            .iter()
            .filter(|d| d.code == codes::FALCO_EXCEPTION)
            .count()
    };
    assert_eq!(exceptions(&editor), 1, "{editor:?}");
    assert_eq!(exceptions(&analyze_blocks(&host, &text)), 0);
}

/// An exception whose shape the model refuses is `validate`'s
/// `sysdig_exception_shape` alone: the condition's analysis does not report
/// Falco's finding on it too (UC-2.6, #821). The fault corpus's two
/// exception kinds, the misaligned comps and a block list in a value.
#[test]
fn an_exception_the_model_refuses_is_not_reported_twice() {
    let rule = |block: &str| {
        format!(
            "name: Shape\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000085\n  \
             schema: rule::1.0\nconfigurations:\n  sysdig:\n    status: STAGING\n{block}"
        )
    };
    let errors = |text: &str| -> Vec<String> {
        analyze_queries(&MemoryWorkspace::default(), text)
            .into_iter()
            .flat_map(|q| q.diagnostics)
            .filter(|d| d.severity == opentide_analysis::Severity::Error)
            .map(|d| d.code)
            .collect()
    };
    let misaligned = rule(
        "    condition: spawned_process and proc.name = bash\n    exceptions:\n    \
         - name: e\n      fields: [proc.pname, proc.name]\n      comps: ['=']\n      \
         values: [[a, b]]\n",
    );
    assert_eq!(errors(&misaligned), Vec::<String>::new());
    let list_in_value = rule(
        "    condition: spawned_process and proc.pname in (corpus_parents)\n    lists:\n    \
         - name: corpus_parents\n      items: [sshd]\n    exceptions:\n    - name: e\n      \
         fields: [proc.name]\n      comps: ['=']\n      values: [[x corpus_parents]]\n",
    );
    assert_eq!(errors(&list_in_value), Vec::<String>::new());
    // An exception the model accepts keeps Falco's checks.
    let value_type = rule(
        "    condition: spawned_process and proc.name = bash\n    exceptions:\n    \
         - name: e\n      fields: [proc.pid]\n      comps: ['=']\n      values: [[abc]]\n",
    );
    assert_eq!(errors(&value_type), [codes::FALCO_EXCEPTION]);
}

/// A tuning that appends exceptions alone has no condition to carry them:
/// the block's own findings report them, and the editor does not.
#[test]
fn exceptions_without_a_condition_are_the_blocks() {
    let text = "name: Tuning\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000083\n  \
                schema: rule::1.0\nconfigurations:\n  sysdig:\n    status: STAGING\n    \
                append_to_rule: Terminal shell in container\n    exceptions:\n    - name: e\n      \
                fields: [proc.pname]\n      values: [[x]]\n    - name: e\n      \
                fields: [proc.pname]\n      values: [[y]]\n";
    let host = MemoryWorkspace::default();
    let codes_of = |found: Vec<opentide_analysis::Diagnostic>| -> Vec<String> {
        found.into_iter().map(|d| d.code).collect()
    };
    let blocks = codes_of(analyze_blocks(&host, text));
    assert!(
        blocks.iter().any(|c| c == codes::FALCO_EXCEPTION),
        "{blocks:?}"
    );
    let editor = codes_of(
        analyze(
            &host,
            AnalyzeRequest {
                uri: "objects/rules/tuning.yaml".into(),
                language: LanguageId::TideYaml,
                text: text.into(),
            },
        )
        .diagnostics,
    );
    assert!(
        !editor.iter().any(|c| c == codes::FALCO_EXCEPTION),
        "{editor:?}"
    );
}

#[test]
fn macro_conditions_and_outputs_are_checked_too() {
    let text = rule("read-sensitive-file-untrusted.yaml");
    let paths: Vec<String> = analyze_queries(&MemoryWorkspace::default(), &text)
        .into_iter()
        .filter(|q| q.language == LanguageId::Falco)
        .map(|q| q.field_path.join("."))
        .collect();
    assert_eq!(
        paths,
        vec![
            "configurations.sysdig.condition",
            "configurations.sysdig.output",
            "configurations.sysdig.macros.0.condition",
        ]
    );
}

#[test]
fn faults_are_reported_where_they_are_written() {
    let cases = [
        // A misspelt field in a folded condition.
        (
            "terminal-shell-in-container.yaml",
            "proc.tty != 0",
            "proc.ttty != 0",
            codes::FALCO_UNKNOWN_FIELD,
            "proc.ttty",
        ),
        // A syscall field in a k8s_audit rule.
        (
            "create-privileged-pod.yaml",
            "kevt and pod",
            "kevt and proc.name = x and pod",
            codes::FALCO_UNKNOWN_FIELD,
            "proc.name",
        ),
        // An output field that does not exist.
        (
            "console-login-without-mfa.yaml",
            "%ct.srcip",
            "%ct.sourceip",
            codes::FALCO_UNKNOWN_FIELD,
            "ct.sourceip",
        ),
        // The block's own macro, broken.
        (
            "read-sensitive-file-untrusted.yaml",
            "fd.name startswith /etc/vault",
            "fd.name startswith",
            codes::FALCO_PARSE_ERROR,
            "",
        ),
        // A misspelt macro of the default rules, in a literal block.
        (
            "netcat-remote-code-execution-in-container.yaml",
            "spawned_process and container and",
            "spawned_proces and container and",
            codes::FALCO_UNKNOWN_MACRO,
            "spawned_proces",
        ),
        // The block's list used as a macro.
        (
            "drop-and-execute-new-binary-in-container.yaml",
            "and not known_drop_and_execute_activities",
            "and not known_drop_and_execute_containers",
            codes::FALCO_MISPLACED_LIST,
            "known_drop_and_execute_containers",
        ),
        // A tuning that does not append.
        (
            "terminal-shell-in-container-ci-runners-excluded.yaml",
            "condition: and not proc.pname",
            "condition: not proc.pname",
            codes::FALCO_APPEND_CONDITION,
            "not proc.pname in (ci_runners)",
        ),
        // An unknown event type.
        (
            "contact-k8s-api-server-from-container.yaml",
            "evt.type=connect",
            "evt.type=conect",
            codes::FALCO_UNKNOWN_EVENT,
            "conect",
        ),
        // Two exceptions with one name (Falco's LOAD_EXCEPTION_NAME_NOT_UNIQUE).
        // A misaligned exception is the model's `sysdig_exception_shape`, not
        // Falco's here: `an_exception_the_model_refuses_is_not_reported_twice`.
        (
            "terminal-shell-in-container.yaml",
            "      - [kubectl, registry.example.com/ops/]\n",
            "      - [kubectl, registry.example.com/ops/]\n    - name: known_shell_parents\n      \
             fields: [proc.pname]\n      values: [[sudo]]\n",
            codes::FALCO_EXCEPTION,
            "name",
        ),
        // An exception value the field's type cannot hold, compiled as Falco
        // writes it into the condition.
        (
            "terminal-shell-in-container.yaml",
            "fields: [proc.pname, container.image.repository]",
            "fields: [proc.pid, container.image.repository]",
            codes::FALCO_EXCEPTION,
            "values",
        ),
        // A value the field's type cannot hold, in the condition.
        (
            "contact-k8s-api-server-from-container.yaml",
            "evt.type=connect",
            "evt.type=connect and proc.pid = abc",
            codes::FALCO_VALUE_TYPE,
            "abc",
        ),
        // An event source no plugin defines.
        (
            "attach-or-exec-into-a-pod.yaml",
            "source: k8s_audit",
            "source: k8s_audits",
            codes::FALCO_UNKNOWN_SOURCE,
            "source",
        ),
    ];
    for (file, from, to, code, at) in cases {
        let text = rule(file).replacen(from, to, 1);
        let found = falco_codes(&format!("objects/rules/{file}"), &text);
        assert!(
            found
                .iter()
                .any(|(c, a)| c == code && (at.is_empty() || a == at)),
            "{file}: expected {code} on `{at}`, got {found:?}"
        );
    }
}

#[test]
fn hover_and_completion_inside_the_injected_condition() {
    let host = MemoryWorkspace::default();
    let text = rule("read-sensitive-file-untrusted.yaml");
    let (at, _) = position_of(&text, "proc_name_exists");
    let h = hover(&host, LanguageId::TideYaml, &text, at).unwrap();
    assert!(h.contains("Falco default rules"), "{h}");
    let (at, _) = position_of(&text, "and not user_known_read_sensitive_files_activities");
    let h = hover(&host, LanguageId::TideYaml, &text, at + 9).unwrap();
    assert!(h.contains("this block"), "{h}");
    assert!(h.contains("vault"), "{h}");
    let (at, _) = position_of(&text, "fd.name startswith /etc/vault");
    let h = hover(&host, LanguageId::TideYaml, &text, at).unwrap();
    assert!(h.contains("CHARBUF") || h.contains("FSPATH"), "{h}");

    let k8s = rule("create-privileged-pod.yaml");
    let offset = k8s.find("kevt and pod").unwrap();
    let labels: Vec<String> = completions(&host, LanguageId::TideYaml, &k8s, offset)
        .into_iter()
        .map(|i| i.label)
        .collect();
    assert!(labels.iter().any(|l| l == "ka.verb"), "k8s_audit fields");
    assert!(
        !labels.iter().any(|l| l == "proc.name"),
        "no syscall fields"
    );
}

#[test]
fn the_condition_is_highlighted_in_the_object() {
    let (path, text) = (
        "objects/rules/terminal-shell-in-container.yaml",
        rule("terminal-shell-in-container.yaml"),
    );
    let host = MemoryWorkspace::default();
    let tokens = analyze(
        &host,
        AnalyzeRequest {
            uri: path.into(),
            language: LanguageId::TideYaml,
            text: text.clone(),
        },
    )
    .tokens;
    let start = text.find("spawned_process").unwrap();
    let macro_token = tokens
        .iter()
        .find(|t| t.span.start == start)
        .expect("token on the macro");
    assert_eq!(macro_token.capture, "macro");
    let list = text.find("allowed_debug_images)").unwrap();
    let list_token = tokens.iter().find(|t| t.span.start == list).expect("list");
    assert_eq!(list_token.capture, "variable");
}
