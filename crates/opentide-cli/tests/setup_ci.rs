//! `opentide setup ci` with a provider it does not know (0.24.1, #882): the
//! value and the three providers are named, the closest one is suggested,
//! the run exits 2 and writes nothing. `none` is the wizard's choice
//! (`setup --ci none`), not a provider of this argument (0.28.0's
//! `test_setup_ci_none_is_rejected`).

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a test helper: a broken fixture is a failure"
)]

#[path = "common/replay.rs"]
mod replay;

use std::path::Path;
use std::sync::{Arc, Mutex};

use opentide_cli::env::Env;
use opentide_cli::logging::Sink;
use opentide_cli::{Host, run};

/// `opentide <words>` in plain mode from `cwd`: the exit code, stdout and
/// stderr.
fn opentide(cwd: &Path, words: &[&str]) -> (i32, String, String) {
    let host = Host {
        version: "0.28.1".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: Arc::new(Mutex::new(replay::Buffer::default())) as Sink,
        cwd: Some(cwd.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let argv: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
    let home = cwd.with_file_name("home");
    std::fs::create_dir_all(&home).unwrap();
    let env = Env::from_pairs([("HOME".to_owned(), home.display().to_string())]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&argv, &env, &host, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn tide_corpus() -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = tempfile::tempdir().unwrap();
    let ws = std::fs::canonicalize(scratch.path()).unwrap().join("ws");
    replay::fixture("tide-corpus", &ws);
    (scratch, ws)
}

#[test]
fn none_is_not_a_provider() {
    let (_scratch, ws) = tide_corpus();
    let before = replay::files(&ws);
    let (code, stdout, stderr) = opentide(&ws, &["setup", "ci", "none", "--yes"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(
        stderr.contains("error: invalid value 'none' for '<ci_platform>'")
            && stderr.contains("[possible values: github, gitlab, azure]"),
        "{stderr}"
    );
    assert_eq!(replay::files(&ws), before, "setup ci wrote a file");
    assert!(!ws.join(".github").exists());
}

#[test]
fn a_misspelled_provider_suggests_the_closest() {
    let (_scratch, ws) = tide_corpus();
    let (code, stdout, stderr) = opentide(&ws, &["setup", "ci", "gitlb", "--yes"]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(
        stderr.contains("error: invalid value 'gitlb' for '<ci_platform>'"),
        "{stderr}"
    );
    assert!(
        stderr.contains("tip: a similar value exists: 'gitlab'"),
        "{stderr}"
    );
    assert!(!ws.join(".gitlab-ci.yml").exists());
}

/// Every enabled platform's tenants reach the jobs, not only the platforms
/// with a live query check (#1655): a CrowdStrike tenant's own `$FALCON_SECRET`
/// is listed and mapped into GitHub's deploy jobs and Azure's deploy steps,
/// `sharing.toml`'s `$MISP_API_KEY` into the share job, and `$PATH`, which
/// the runner sets itself, is never mapped but warned about.
#[test]
fn the_tenants_own_variables_are_mapped() {
    let (_scratch, ws) = tide_corpus();
    let platforms = ws.join(".opentide/configurations/platforms");
    std::fs::write(
        platforms.join("crowdstrike.toml"),
        "[platform]\nenabled = true\n\n[[tenants]]\nname = \"falcon\"\n[tenants.setup]\napi = \"https://api.crowdstrike.invalid\"\ncustomer_id = \"$PATH\"\nclient_id = \"$FALCON_ID\"\nclient_secret = \"$FALCON_SECRET\"\n",
    )
    .unwrap();
    std::fs::write(
        ws.join(".opentide/configurations/sharing.toml"),
        "[[misp]]\nname = \"misp\"\nurl = \"https://misp.invalid\"\napi_key = \"${MISP_API_KEY}\"\n",
    )
    .unwrap();
    let words = ["--default-branch", "main", "--sharing", "--yes"];

    let (code, stdout, stderr) = opentide(&ws, &[&["setup", "ci", "github"][..], &words].concat());
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains(".opentide/configurations/platforms/crowdstrike.toml reads $PATH, a variable the CI runner sets itself"),
        "{stderr}"
    );
    let github = std::fs::read_to_string(ws.join(".github/workflows/opentide.yml")).unwrap();
    assert!(github.contains("#   FALCON_SECRET\n"), "{github}");
    // validate, deploy_staging and deploy_production
    for name in ["FALCON_ID", "FALCON_SECRET"] {
        let mapped = format!("      {name}: ${{{{ secrets.{name} }}}}\n");
        assert_eq!(github.matches(&mapped).count(), 3, "{github}");
    }
    let share = &github[github.find("\n  share:\n").unwrap()..];
    assert!(
        share.contains("      MISP_API_KEY: ${{ secrets.MISP_API_KEY }}\n"),
        "{share}"
    );
    assert!(!github.contains(" PATH:"), "{github}");

    let (code, stdout, stderr) = opentide(&ws, &[&["setup", "ci", "azure"][..], &words].concat());
    assert_eq!(code, 0, "{stdout}{stderr}");
    let azure = std::fs::read_to_string(ws.join("azure-pipelines.yml")).unwrap();
    assert!(azure.contains("#   FALCON_SECRET\n"), "{azure}");
    let production = &azure[azure.find("- job: deploy_production").unwrap()..];
    assert!(
        production.contains("            FALCON_SECRET: $(FALCON_SECRET)\n"),
        "{production}"
    );
    let share = &azure[azure.find("- job: share").unwrap()..];
    assert!(
        share.contains("            MISP_API_KEY: $(MISP_API_KEY)\n"),
        "{share}"
    );
    assert!(!azure.contains(" PATH:"), "{azure}");
}
