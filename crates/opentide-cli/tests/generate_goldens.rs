//! `generate` against the oracle's recordings (UC-3.2, #824): every recorded
//! case of the ported generate commands, run in-process through
//! [`opentide_cli::run`] on a fresh copy of its fixture, with the goldens'
//! normalisation (`opentide-compare`), compared with the recording by the
//! goldens' comparator (`opentide_compare::compare`, as `cargo xtask golden
//! check --engine compare` compares them) under `APPROVED_DIFFS.toml`: exit
//! code, stdout, stderr, and every file written.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken recording is a failure"
)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};

#[path = "common/replay.rs"]
mod replay;
use replay::{Buffer, fixture};

/// The commands whose recordings this test replays.
const COMMANDS: &[&str] = &[
    "generate.exports",
    "generate.exports.navigator",
    "generate.exports.objects",
    "generate.exports.revisions",
    "generate.docs",
    "generate.docs.rules",
    "generate.docs.objectives",
    "generate.docs.threats",
    "generate.docs.index",
];

#[test]
fn generate_cases_are_the_oracles() {
    let (problems, ran) = replay::replay_commands(COMMANDS, true);
    assert!(ran >= 32, "only {ran} cases found");
    assert!(problems.is_empty(), "{}", problems.join("\n\n"));
}

/// The exports that rendered before one failed are on disk, as the oracle,
/// which writes them one after another, leaves them: a threat without
/// `metadata.version` fails the objects table after the Navigator layer.
#[test]
fn exports_before_a_failure_are_written() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let threat = ws.join("Objects/Threat Vectors/threat-0001-simulated-actor.yaml");
    let text = std::fs::read_to_string(&threat).unwrap();
    assert!(text.contains("  version: 1\n"));
    std::fs::write(&threat, text.replace("  version: 1\n", "")).unwrap();
    let sink: Sink = Arc::new(Mutex::new(Buffer::default()));
    let host = Host {
        version: "0.23.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: sink,
        cwd: Some(ws.clone()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = ["--json", "generate", "exports"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let home = ws.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), Buffer::default());
    let exit_code = run(&argv, &env, &host, &mut out, &mut err);
    let stdout = String::from_utf8(out).unwrap();
    assert_eq!(exit_code, 1, "{stdout}");
    assert!(
        stdout.contains("\"message\":\"exports: KeyError: 'version' while rendering 00000000-0000-4000-8001-000000000001\""),
        "{stdout}"
    );
    let exports = ws.join(".opentide/exports");
    assert!(exports.join("attack-navigator.json").is_file());
    assert!(!exports.join("objects.export.json").exists());
    assert!(!exports.join("revisions.export.json").exists());
}

/// Runs the CLI in-process at `ws`; the exit code and stdout.
fn run_at(ws: &Path, words: &[&str]) -> (i32, String) {
    let sink: Sink = Arc::new(Mutex::new(Buffer::default()));
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
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), Buffer::default());
    let exit_code = run(&argv, &env, &host, &mut out, &mut err);
    (exit_code, String::from_utf8(out).unwrap())
}

fn git(ws: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(ws)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        // No automatic maintenance or gc: either works in `.git` in the
        // background after a commit, while the test reads the repository (#934).
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "maintenance.auto")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_CONFIG_KEY_1", "gc.auto")
        .env("GIT_CONFIG_VALUE_1", "0")
        .env("HOME", ws)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// `generate docs --changed` after a rule is renamed: its page moves (the old
/// one is removed), and the pages of the objective and threat above it are
/// rewritten; nothing else is.
#[test]
fn changed_docs_rewrite_a_renamed_rule_and_its_parents() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    git(&ws, &["init", "-q", "-b", "main"]);
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-q", "-m", "base"]);
    let rule = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&rule).unwrap();
    std::fs::write(
        &rule,
        text.replacen("name: Sentinel KQL Rule", "name: Renamed Sentinel Rule", 1),
    )
    .unwrap();
    let docs = ws.join("docs");
    let before_defender = std::fs::metadata(docs.join("rules/defender-kql-rule.md"))
        .unwrap()
        .modified()
        .unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--changed"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["changed_paths"],
        serde_json::json!(["Objects/Detection Rules/rule-0001-sentinel-kql.yaml"])
    );
    assert_eq!(
        document["changed_uuids"],
        serde_json::json!(["00000000-0000-4000-8003-000000000001"])
    );
    assert_eq!(
        document["targets"],
        serde_json::json!([
            "00000000-0000-4000-8001-000000000001",
            "00000000-0000-4000-8002-000000000001",
            "00000000-0000-4000-8003-000000000001"
        ])
    );
    assert_eq!(
        document["scopes"],
        serde_json::json!(["objective", "rule", "threat"])
    );
    assert_eq!(
        document["counts"],
        serde_json::json!({"rules": 1, "objectives": 1, "threats": 1})
    );
    assert_eq!(document["removed"], 1);
    assert!(docs.join("rules/renamed-sentinel-rule.md").is_file());
    assert!(!docs.join("rules/sentinel-kql-rule.md").exists());
    let objective =
        std::fs::read_to_string(docs.join("objectives/credential-access-objective.md")).unwrap();
    assert!(objective.contains("[Renamed Sentinel Rule](../rules/renamed-sentinel-rule.md)"));
    let after_defender = std::fs::metadata(docs.join("rules/defender-kql-rule.md"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        before_defender, after_defender,
        "an unrelated page was rewritten"
    );
    // Nothing changed against HEAD once it is committed: nothing is written.
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-q", "-m", "renamed"]);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--changed"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["message"],
        "No changed object documentation detected"
    );
    assert_eq!(document["changed_paths"], serde_json::json!([]));
}

/// A scoped run with `--changed` is a usage error, and two flags write both
/// families (`--rules --threats` used to write rules only).
#[test]
fn docs_scopes() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--rules", "--changed"]);
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.contains("\"code\":\"usage_error\""), "{stdout}");
    assert!(stdout.contains("\"argument\":\"--changed\""), "{stdout}");
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--rules", "--threats"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["scopes"], serde_json::json!(["rules", "threats"]));
    assert_eq!(
        document["counts"],
        serde_json::json!({"rules": 10, "objectives": 0, "threats": 1})
    );
    assert!(ws.join("docs/threats/simulated-actor.md").is_file());
    assert!(!ws.join("docs/objectives").exists());
}

/// Documentation previews open pull requests: a shard of a newer version
/// replaces the object for the run, a shard of a new object adds its page,
/// and a raw shard of the same version does not replace the file's object.
#[test]
fn docs_preview_the_inflight_shards() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let threat_file = ws.join("Objects/Threat Vectors/threat-0001-simulated-actor.yaml");
    let rule_file = ws.join("Objects/Detection Rules/rule-0002-defender-kql.yaml");
    let yaml = |path: &Path| -> serde_json::Value {
        let text = std::fs::read_to_string(path).unwrap();
        let document = opentide_schema::node::load(&text).unwrap();
        let json = opentide_compile::json::Json::from_node(document.root().unwrap());
        serde_json::from_str(&json.to_compact()).unwrap()
    };
    let mut threat = yaml(&threat_file);
    threat["name"] = "Previewed Actor".into();
    threat["metadata"]["version"] = 2.into();
    let mut added = yaml(&rule_file);
    added["name"] = "Pull Request Rule".into();
    added["metadata"]["uuid"] = "00000000-0000-4000-8003-00000000aaaa".into();
    let mut same = yaml(&rule_file);
    same["name"] = "Not Replaced".into();
    let inflight = ws.join(".opentide/inflight");
    std::fs::create_dir_all(&inflight).unwrap();
    let wrap = |object: serde_json::Value| {
        serde_json::json!({"schema": "inflight.shard::1.0", "object": object}).to_string()
    };
    std::fs::write(inflight.join("a.json"), wrap(threat)).unwrap();
    std::fs::write(inflight.join("b.json"), wrap(added)).unwrap();
    std::fs::write(inflight.join("c.json"), same.to_string()).unwrap();
    std::fs::write(inflight.join("d.json"), "not json").unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let docs = ws.join("docs");
    assert!(docs.join("threats/previewed-actor.md").is_file());
    assert!(!docs.join("threats/simulated-actor.md").exists());
    assert!(docs.join("rules/pull-request-rule.md").is_file());
    assert!(docs.join("rules/defender-kql-rule.md").is_file());
    assert!(!docs.join("rules/not-replaced.md").exists());
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["counts"],
        serde_json::json!({"rules": 11, "objectives": 1, "threats": 1})
    );
}

/// `generate docs --changed` after an objective is renamed: its page moves,
/// the threat above it is rewritten (a parent shows its children), and so is
/// every rule below it (their pages link to the objective by its name).
#[test]
fn changed_docs_rewrite_the_pages_below_a_renamed_objective() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    git(&ws, &["init", "-q", "-b", "main"]);
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-q", "-m", "base"]);
    let objective = ws.join("Objects/Detection Objectives/objective-0001-credential-access.yaml");
    let text = std::fs::read_to_string(&objective).unwrap();
    std::fs::write(
        &objective,
        text.replacen(
            "name: Credential Access Objective",
            "name: Renamed Objective",
            1,
        ),
    )
    .unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--changed"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        document["changed_uuids"],
        serde_json::json!(["00000000-0000-4000-8002-000000000001"])
    );
    // The upstream walk alone reaches the threat; the rules come from the
    // rename's downstream walk.
    assert_eq!(
        document["targets"],
        serde_json::json!([
            "00000000-0000-4000-8001-000000000001",
            "00000000-0000-4000-8002-000000000001",
            "00000000-0000-4000-8003-000000000001",
            "00000000-0000-4000-8003-000000000002",
            "00000000-0000-4000-8003-000000000003",
            "00000000-0000-4000-8003-000000000004",
            "00000000-0000-4000-8003-000000000005",
            "00000000-0000-4000-8003-000000000006",
            "00000000-0000-4000-8003-000000000007",
            "00000000-0000-4000-8003-000000000008",
            "00000000-0000-4000-8003-000000000009",
            "00000000-0000-4000-8003-0000005d1a90"
        ])
    );
    assert_eq!(
        document["counts"],
        serde_json::json!({"rules": 10, "objectives": 1, "threats": 1})
    );
    assert_eq!(document["removed"], 1);
    let docs = ws.join("docs");
    assert!(docs.join("objectives/renamed-objective.md").is_file());
    assert!(
        !docs
            .join("objectives/credential-access-objective.md")
            .exists()
    );
    for rule in ["sentinel-kql-rule.md", "sysdig-falco-rule.md"] {
        let page = std::fs::read_to_string(docs.join("rules").join(rule)).unwrap();
        assert!(
            page.contains("[Renamed Objective](../objectives/renamed-objective.md)"),
            "{rule}: {page}"
        );
        assert!(
            !page.contains("credential-access-objective"),
            "{rule}: {page}"
        );
    }
    let threat = std::fs::read_to_string(docs.join("threats/simulated-actor.md")).unwrap();
    assert!(
        threat.contains("[Renamed Objective](../objectives/renamed-objective.md)"),
        "{threat}"
    );
}

/// A run removes the generated pages no object writes any more, and leaves
/// the files it did not write: hand-written notes (even one with a Metadata
/// heading), README.md, and pages in subfolders.
#[test]
fn docs_remove_stale_pages_and_keep_hand_written_files() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let rules = ws.join("docs/rules");
    let generated = std::fs::read_to_string(rules.join("sentinel-kql-rule.md")).unwrap();
    std::fs::write(rules.join("old-rule.md"), &generated).unwrap();
    let notes = "# Notes\n\nHand-written.\n";
    let metadata_notes = "# Review\n\n## Metadata\n\n| UUID | to be assigned |\n";
    std::fs::write(rules.join("notes.md"), notes).unwrap();
    std::fs::write(rules.join("review.md"), metadata_notes).unwrap();
    std::fs::create_dir_all(rules.join("archive")).unwrap();
    std::fs::write(rules.join("archive/older-rule.md"), &generated).unwrap();
    std::fs::write(ws.join("docs/objectives/notes.md"), notes).unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["removed"], 1, "{stdout}");
    assert!(!rules.join("old-rule.md").exists());
    assert_eq!(
        std::fs::read_to_string(rules.join("notes.md")).unwrap(),
        notes
    );
    assert_eq!(
        std::fs::read_to_string(rules.join("review.md")).unwrap(),
        metadata_notes
    );
    assert!(rules.join("archive/older-rule.md").is_file());
    assert_eq!(
        std::fs::read_to_string(ws.join("docs/objectives/notes.md")).unwrap(),
        notes
    );
    assert!(rules.join("sentinel-kql-rule.md").is_file());
}

/// The inflight preview re-reads what the shards change: an objective's
/// shard renames a signal and adds one, a new rule's shard names the new
/// signal as its detection model, and another's names the objective; the
/// objective's page shows both rules and the signals as the shard has them.
/// A new threat's shard chains to the committed threat, whose page draws
/// the chain.
#[test]
fn docs_preview_shards_refresh_signals_and_references() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let yaml = |path: &Path| -> serde_json::Value {
        let text = std::fs::read_to_string(path).unwrap();
        let document = opentide_schema::node::load(&text).unwrap();
        let json = opentide_compile::json::Json::from_node(document.root().unwrap());
        serde_json::from_str(&json.to_compact()).unwrap()
    };
    let mut objective =
        yaml(&ws.join("Objects/Detection Objectives/objective-0001-credential-access.yaml"));
    objective["metadata"]["version"] = 2.into();
    objective["objective"]["signals"][0]["name"] = "Renamed logon signal".into();
    let mut signal = objective["objective"]["signals"][0].clone();
    signal["name"] = "Pull request signal".into();
    signal["uuid"] = "00000000-0000-4000-8099-000000000002".into();
    objective["objective"]["signals"]
        .as_array_mut()
        .unwrap()
        .push(signal);
    let rule = yaml(&ws.join("Objects/Detection Rules/rule-0002-defender-kql.yaml"));
    let mut on_signal = rule.clone();
    on_signal["name"] = "Signal Rule".into();
    on_signal["metadata"]["uuid"] = "00000000-0000-4000-8003-00000000aaaa".into();
    on_signal["detection_model"] = "00000000-0000-4000-8099-000000000002".into();
    let mut on_objective = rule;
    on_objective["name"] = "Objective Rule".into();
    on_objective["metadata"]["uuid"] = "00000000-0000-4000-8003-00000000bbbb".into();
    let mut chained = yaml(&ws.join("Objects/Threat Vectors/threat-0001-simulated-actor.yaml"));
    chained["name"] = "Chained Actor".into();
    chained["metadata"]["uuid"] = "00000000-0000-4000-8001-00000000cccc".into();
    chained["threat"]["chaining"] = serde_json::json!([{
        "relation": "preceeds",
        "vector": "00000000-0000-4000-8001-000000000001",
        "description": "Then the actor"
    }]);
    let inflight = ws.join(".opentide/inflight");
    std::fs::create_dir_all(&inflight).unwrap();
    for (name, object) in [
        ("a", objective),
        ("b", on_signal),
        ("c", on_objective),
        ("d", chained),
    ] {
        let shard = serde_json::json!({"schema": "inflight.shard::1.0", "object": object});
        std::fs::write(inflight.join(format!("{name}.json")), shard.to_string()).unwrap();
    }
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let page =
        std::fs::read_to_string(ws.join("docs/objectives/credential-access-objective.md")).unwrap();
    for line in [
        "### Renamed logon signal\n",
        "### Pull request signal\n",
        "| Renamed logon signal | _None_ |\n",
        "| Pull request signal | [Signal Rule](../rules/signal-rule.md) \
         (`00000000-0000-4000-8003-00000000aaaa`) |\n",
        "| Signal | [Pull request signal](credential-access-objective.md#pull-request-signal) \
         (`00000000-0000-4000-8099-000000000002`) | Downstream | signal |\n",
        "| Rule | [Signal Rule](../rules/signal-rule.md) \
         (`00000000-0000-4000-8003-00000000aaaa`) | Downstream | rule |\n",
        "| Rule | [Objective Rule](../rules/objective-rule.md) \
         (`00000000-0000-4000-8003-00000000bbbb`) | Downstream | rule |\n",
    ] {
        assert!(page.contains(line), "{line}: {page}");
    }
    assert!(!page.contains("Suspicious logon signal"), "{page}");
    let threat = std::fs::read_to_string(ws.join("docs/threats/simulated-actor.md")).unwrap();
    assert!(
        threat.contains(
            "00000000_0000_4000_8001_00000000cccc -->|preceeds| \
             00000000_0000_4000_8001_000000000001\n"
        ),
        "{threat}"
    );
}

/// A threat that lists CVEs, with `[cve] retrieve_details` on (the default):
/// its page needs each record's details, which only the Python engine
/// fetches, so every run that writes it is refused with `engine_not_ported`
/// before any page is written (`OPENTIDE_ENGINE=compare` then runs Python
/// alone); a run that does not write it, and every run with the setting off,
/// writes as before, the CVEs as links.
#[test]
fn docs_with_cve_details_are_left_to_python() {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    fixture("tide-corpus", &ws);
    let threat = ws.join("Objects/Threat Vectors/threat-0001-simulated-actor.yaml");
    let mut text = std::fs::read_to_string(&threat).unwrap();
    text.push_str("  cve:\n    - CVE-2024-3094\n");
    std::fs::write(&threat, text).unwrap();
    for words in [
        &["--json", "generate", "docs"][..],
        &["--json", "generate", "docs", "--threats"],
        &["--json", "generate", "docs", "--rules", "--threats"],
        &["--json", "generate", "docs", "threats"],
    ] {
        let (code, stdout) = run_at(&ws, words);
        assert_eq!(code, 2, "{words:?}: {stdout}");
        let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            document["failure"]["code"], "engine_not_ported",
            "{words:?}: {stdout}"
        );
        assert_eq!(document["failure"]["argument"], "OPENTIDE_ENGINE");
        let message = document["failure"]["message"].as_str().unwrap();
        assert!(
            message.starts_with("The CVE details of Simulated Actor ([cve] retrieve_details)"),
            "{message}"
        );
        assert!(!ws.join("docs").exists(), "{words:?} wrote pages");
    }
    // Rules and the index carry no CVE section.
    for words in [
        &["--json", "generate", "docs", "rules"][..],
        &["--json", "generate", "docs", "index"],
    ] {
        let (code, stdout) = run_at(&ws, words);
        assert_eq!(code, 0, "{words:?}: {stdout}");
    }
    assert!(!ws.join("docs/threats/simulated-actor.md").exists());
    // --changed: refused when a changed object's pages include the threat's.
    git(&ws, &["init", "-q", "-b", "main"]);
    git(&ws, &["add", "-A"]);
    git(&ws, &["commit", "-q", "-m", "base"]);
    let rule = ws.join("Objects/Detection Rules/rule-0001-sentinel-kql.yaml");
    let text = std::fs::read_to_string(&rule).unwrap();
    std::fs::write(
        &rule,
        text.replacen("name: Sentinel KQL Rule", "name: Renamed Sentinel Rule", 1),
    )
    .unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs", "--changed"]);
    assert_eq!(code, 2, "{stdout}");
    assert!(
        stdout.contains("\"code\":\"engine_not_ported\""),
        "{stdout}"
    );
    assert!(!ws.join("docs/rules/renamed-sentinel-rule.md").exists());
    // With the setting off, the page lists the CVE as a link.
    std::fs::write(
        ws.join(".opentide/configurations/documentation.toml"),
        "[cve]\nretrieve_details = false\n",
    )
    .unwrap();
    let (code, stdout) = run_at(&ws, &["--json", "generate", "docs"]);
    assert_eq!(code, 0, "{stdout}");
    let page = std::fs::read_to_string(ws.join("docs/threats/simulated-actor.md")).unwrap();
    assert!(
        page.contains("- [CVE-2024-3094](https://vulnerability.circl.lu/vuln/CVE-2024-3094)\n"),
        "{page}"
    );
}
