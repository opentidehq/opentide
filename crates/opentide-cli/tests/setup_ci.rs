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

/// `--python-version` is written into the pipeline as it is (#1656): a value
/// no provider reads as a supported Python exits 2 and writes nothing, from
/// `setup ci` and from `setup --ci`.
#[test]
fn a_python_version_the_pipeline_cannot_hold_is_refused() {
    let (_scratch, ws) = tide_corpus();
    let before = replay::files(&ws);
    for version in ["2.7", "abc\"; x", "3.12\nevil: true"] {
        let (code, stdout, stderr) = opentide(
            &ws,
            &[
                "setup",
                "ci",
                "gitlab",
                "--python-version",
                version,
                "--yes",
            ],
        );
        assert_eq!(code, 2, "{version:?}: {stdout}{stderr}");
        assert!(stderr.contains("--python-version"), "{stderr}");
        assert!(stderr.contains("use 3.10 or later"), "{stderr}");
    }
    let (code, stdout, stderr) = opentide(
        &ws,
        &[
            "setup",
            "--ci",
            "github",
            "--python-version",
            "3.9",
            "--yes",
        ],
    );
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert_eq!(replay::files(&ws), before, "a refused run wrote a file");
    let (code, stdout, stderr) = opentide(
        &ws,
        &[
            "setup",
            "ci",
            "gitlab",
            "--python-version",
            "3.13.1",
            "--yes",
        ],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    let pipeline = std::fs::read_to_string(ws.join(".gitlab-ci.yml")).unwrap();
    assert!(
        pipeline.contains("image: python:3.13.1-slim\n"),
        "{pipeline}"
    );
    // 3.x, the latest 3, as 0.28.1 took it: setup-python and
    // UsePythonVersion read it; GitLab has no `python:3.x-slim` image.
    let (code, stdout, stderr) = opentide(
        &ws,
        &["setup", "ci", "gitlab", "--python-version", "3.x", "--yes"],
    );
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stderr.contains("needs a version, not 3.x"), "{stderr}");
    for provider in ["github", "azure"] {
        let (code, stdout, stderr) = opentide(
            &ws,
            &[
                "setup",
                "ci",
                provider,
                "--default-branch",
                "main",
                "--python-version",
                "3.x",
                "--yes",
            ],
        );
        assert_eq!(code, 0, "{provider}: {stdout}{stderr}");
    }
    let github = std::fs::read_to_string(ws.join(".github/workflows/opentide.yml")).unwrap();
    assert!(github.contains("python-version: \"3.x\"\n"), "{github}");
}

/// A pipeline an older opentide wrote is regenerated whatever the case of
/// its first line (`# Generated by OpenTide` through 0.16.0), and a file that
/// is not UTF-8 text is kept, by `setup ci` and by `setup --ci`, in a plan
/// and in a run (#1656).
#[test]
fn an_older_pipeline_is_regenerated_and_an_unreadable_one_is_kept() {
    let (_scratch, ws) = tide_corpus();
    let path = ws.join(".gitlab-ci.yml");
    std::fs::write(
        &path,
        "# Generated by OpenTide — regenerate with `opentide setup ci gitlab`\nstages: [old]\n",
    )
    .unwrap();
    let (code, stdout, stderr) = opentide(&ws, &["setup", "ci", "gitlab", "--yes"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains(".gitlab-ci.yml differs from what this run generates"),
        "{stderr}"
    );
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.starts_with("# Generated by opentide"), "{written}");

    let latin1 = b"# Pipeline de l'\xe9quipe\nstages: [test]\n".to_vec();
    std::fs::write(&path, &latin1).unwrap();
    for words in [
        &["--json", "setup", "ci", "gitlab", "--plan"][..],
        &["--json", "setup", "--ci", "gitlab", "--plan"][..],
    ] {
        let (code, stdout, stderr) = opentide(&ws, words);
        assert_eq!(code, 0, "{words:?}: {stdout}{stderr}");
        let plan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let files: Vec<&serde_json::Value> = plan["steps"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|step| step["files"].as_array().unwrap())
            .filter(|file| file["path"] == ".gitlab-ci.yml")
            .collect();
        assert_eq!(files.len(), 1, "{words:?}: {stdout}");
        assert_eq!(files[0]["action"], "skip", "{words:?}: {stdout}");
        assert!(
            stdout.contains(".gitlab-ci.yml is not UTF-8 text, or cannot be read"),
            "{stdout}"
        );
    }
    let (code, stdout, stderr) = opentide(&ws, &["setup", "ci", "gitlab", "--yes"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains("move or delete it and run the command again"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), latin1);
    // `setup ci` and the group's step report the kept file alike.
    let (code, stdout, stderr) = opentide(&ws, &["--json", "setup", "ci", "gitlab", "--yes"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let run: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        run["skipped"],
        serde_json::json!([".gitlab-ci.yml"]),
        "{stdout}"
    );
    assert_eq!(run["files"], serde_json::json!([]), "{stdout}");
    let (code, stdout, stderr) = opentide(&ws, &["--json", "setup", "--ci", "gitlab", "--yes"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stdout.contains("CI pipeline kept: the file there is not opentide's"),
        "{stdout}"
    );
    assert!(
        stdout.contains(".gitlab-ci.yml is not UTF-8 text, or cannot be read"),
        "{stdout}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), latin1);
}

/// `setup ci` never writes over a pipeline it did not write, and says so
/// when it replaces one that was edited (#1656).
#[test]
fn a_pipeline_the_user_wrote_is_kept_and_an_edited_one_is_replaced_with_a_warning() {
    let (_scratch, ws) = tide_corpus();
    let own = "stages: [test]\ntest:\n  script: [make test]\n";
    std::fs::write(ws.join(".gitlab-ci.yml"), own).unwrap();

    let (code, stdout, stderr) = opentide(&ws, &["--json", "setup", "ci", "gitlab", "--plan"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let plan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(plan["steps"][0]["files"][0]["action"], "skip", "{stdout}");
    assert!(stdout.contains("was not written by opentide"), "{stdout}");

    let (code, stdout, stderr) = opentide(&ws, &["setup", "ci", "gitlab", "--yes"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains(".gitlab-ci.yml was not written by opentide"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(ws.join(".gitlab-ci.yml")).unwrap(),
        own
    );

    let (code, stdout, stderr) = opentide(
        &ws,
        &["setup", "ci", "github", "--default-branch", "main", "--yes"],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(!stderr.contains("is replaced"), "{stderr}");
    let path = ws.join(".github/workflows/opentide.yml");
    let generated = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{generated}# my custom edit\n")).unwrap();
    let (code, stdout, stderr) = opentide(
        &ws,
        &["setup", "ci", "github", "--default-branch", "main", "--yes"],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains(".github/workflows/opentide.yml differs from what this run generates; it is replaced, and any hand edits in it are replaced too"),
        "{stderr}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), generated);
}

/// Every enabled platform's tenants reach the jobs, not only the platforms
/// with a live query check (#1655): a CrowdStrike tenant's own `$FALCON_SECRET`
/// is listed and mapped into GitHub's deploy jobs and Azure's deploy steps
/// (and, since #1689, into no other platform's step),
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
    // deploy_staging and deploy_production: CrowdStrike has no live query
    // check, so no validate step maps its variables (#1689).
    for name in ["FALCON_ID", "FALCON_SECRET"] {
        let mapped = format!("      {name}: ${{{{ secrets.{name} }}}}\n");
        assert_eq!(github.matches(&mapped).count(), 2, "{github}");
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

/// `--variable-group` links an Azure Library group, in list-form
/// `variables:`, and the header's regenerate line keeps it; the other
/// providers ignore it with a warning (OT-9).
#[test]
fn a_variable_group_is_linked_on_azure_and_ignored_elsewhere() {
    let (_scratch, ws) = tide_corpus();
    let (code, stdout, stderr) = opentide(
        &ws,
        &[
            "setup",
            "ci",
            "azure",
            "--variable-group",
            "opentide-tenants",
            "--variable-group",
            "Shared secrets",
            "--default-branch",
            "main",
            "--yes",
        ],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    let written = std::fs::read_to_string(ws.join("azure-pipelines.yml")).unwrap();
    assert!(
        written.contains("variables:\n  - group: opentide-tenants\n  - group: Shared secrets\n  - name: OPENTIDE_REPO_ROOT\n"),
        "{written}"
    );
    assert!(
        written.starts_with("# Generated by opentide — regenerate with `opentide setup ci azure --variable-group opentide-tenants --variable-group 'Shared secrets'`\n"),
        "{written}"
    );
    assert!(!stderr.contains("--variable-group was ignored"), "{stderr}");

    let (code, stdout, stderr) = opentide(
        &ws,
        &[
            "setup",
            "ci",
            "github",
            "--variable-group",
            "x",
            "--default-branch",
            "main",
            "--yes",
        ],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(
        stderr.contains("--variable-group was ignored: only Azure Pipelines links Library variable groups, not github"),
        "{stderr}"
    );
    let github = std::fs::read_to_string(ws.join(".github/workflows/opentide.yml")).unwrap();
    assert!(!github.contains("group"), "{github}");

    let (code, _stdout, stderr) = opentide(
        &ws,
        &["setup", "ci", "azure", "--variable-group", " ", "--yes"],
    );
    assert_eq!(code, 2, "{stderr}");
}

/// A regenerate names the jobs a hand-edited pipeline holds that the new one
/// lacks, on each provider, in the text and in `--json`.
#[test]
fn a_regenerate_names_the_jobs_it_drops() {
    let (_scratch, ws) = tide_corpus();
    let cases = [
        (
            "azure",
            "azure-pipelines.yml",
            "\n  - stage: Intel\n    jobs:\n      - job: intel_sources\n        steps:\n          - script: echo hi\n",
            "replacing azure-pipelines.yml drops stage Intel (job intel_sources) that this run does not generate",
        ),
        (
            "github",
            ".github/workflows/opentide.yml",
            "  intel_sources:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
            "replacing .github/workflows/opentide.yml drops job intel_sources that this run does not generate",
        ),
        (
            "gitlab",
            ".gitlab-ci.yml",
            "\nintel_sources:\n  script:\n    - echo hi\n",
            "replacing .gitlab-ci.yml drops job intel_sources that this run does not generate",
        ),
    ];
    for (provider, file, extra, warning) in cases {
        let args = ["setup", "ci", provider, "--default-branch", "main", "--yes"];
        let (code, stdout, stderr) = opentide(&ws, &args);
        assert_eq!(code, 0, "{provider}: {stdout}{stderr}");
        assert!(!stderr.contains("drops job"), "{provider}: {stderr}");
        let path = ws.join(file);
        let generated = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{generated}{extra}")).unwrap();
        let (code, stdout, stderr) = opentide(&ws, &args);
        assert_eq!(code, 0, "{provider}: {stdout}{stderr}");
        assert!(stderr.contains(warning), "{provider}: {stderr}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), generated);

        std::fs::write(&path, format!("{generated}{extra}")).unwrap();
        let (code, stdout, stderr) = opentide(
            &ws,
            &[
                "--json",
                "setup",
                "ci",
                provider,
                "--default-branch",
                "main",
                "--yes",
            ],
        );
        assert_eq!(code, 0, "{provider}: {stdout}{stderr}");
        assert!(stdout.contains(warning), "{provider}: {stdout}");
    }
}

/// The Azure pipeline `ws` holds, regenerated with `words` after the file's
/// text went through `edit`: the exit code, stderr and the file now.
fn regenerate_azure(
    ws: &Path,
    words: &[&str],
    edit: impl FnOnce(&str) -> String,
) -> (i32, String, String) {
    let path = ws.join("azure-pipelines.yml");
    let before = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, edit(&before)).unwrap();
    let mut argv = vec!["setup", "ci", "azure", "--default-branch", "main", "--yes"];
    argv.extend_from_slice(words);
    let (code, stdout, stderr) = opentide(ws, &argv);
    assert_eq!(code, 0, "{stdout}{stderr}");
    (code, stderr, std::fs::read_to_string(&path).unwrap())
}

const MAP_VARIABLES: &str =
    "variables:\n  OPENTIDE_REPO_ROOT: $(Build.SourcesDirectory)\n  OPENTIDE_VERSION: \"0.28.1\"\n";

/// A plain `setup ci azure` keeps the Library groups the old pipeline links,
/// whether someone added them by hand or an earlier run wrote them, and says
/// so; an explicit `--variable-group` replaces them (OT-9).
#[test]
fn a_regenerate_keeps_the_variable_groups_of_an_azure_pipeline() {
    let (_scratch, ws) = tide_corpus();
    let (code, stdout, stderr) = opentide(
        &ws,
        &["setup", "ci", "azure", "--default-branch", "main", "--yes"],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");

    // A group added by hand to the map-form file the previous release wrote.
    let (_, stderr, written) = regenerate_azure(&ws, &[], |text| {
        let at = text.find("variables:\n").unwrap();
        let end = text[at..].find("\n\n").unwrap() + at + 1;
        format!(
            "{}variables:\n  - group: tenants\n  - name: OPENTIDE_REPO_ROOT\n    value: $(Build.SourcesDirectory)\n{}",
            &text[..at],
            &text[end..]
        )
    });
    assert!(
        stderr.contains("keeping variable group tenants from azure-pipelines.yml; pass --variable-group to replace it"),
        "{stderr}"
    );
    assert!(
        written.contains("variables:\n  - group: tenants\n  - name: OPENTIDE_REPO_ROOT\n"),
        "{written}"
    );
    assert!(written.starts_with("# Generated by opentide — regenerate with `opentide setup ci azure --variable-group tenants`\n"), "{written}");

    // Generated with groups, then regenerated without the flag.
    let (_, stderr, _) = regenerate_azure(
        &ws,
        &["--variable-group", "a", "--variable-group", "b"],
        str::to_owned,
    );
    assert!(!stderr.contains("keeping variable"), "{stderr}");
    let (_, stderr, written) = regenerate_azure(&ws, &[], str::to_owned);
    assert!(stderr.contains("keeping variable groups a, b from azure-pipelines.yml; pass --variable-group to replace them"), "{stderr}");
    assert!(
        written.contains("variables:\n  - group: a\n  - group: b\n  - name:"),
        "{written}"
    );

    // An explicit option replaces them.
    let (_, stderr, written) = regenerate_azure(&ws, &["--variable-group", "c"], str::to_owned);
    assert!(!stderr.contains("keeping variable"), "{stderr}");
    assert!(
        written.contains("variables:\n  - group: c\n  - name:"),
        "{written}"
    );
    assert!(!written.contains("group: a"), "{written}");

    // A file with no group stays in map form.
    let (_, _, written) = regenerate_azure(&ws, &[], |text| {
        let at = text.find("variables:\n").unwrap();
        let end = text[at..].find("\n\n").unwrap() + at + 1;
        format!("{}{MAP_VARIABLES}{}", &text[..at], &text[end..])
    });
    assert!(
        written.contains("variables:\n  OPENTIDE_REPO_ROOT: $(Build.SourcesDirectory)\n"),
        "{written}"
    );
    assert!(!written.contains("- group:"), "{written}");
}

/// Group names are trimmed and each is written once, in the order given.
#[test]
fn variable_group_names_are_trimmed_and_unique() {
    let (_scratch, ws) = tide_corpus();
    let (code, stdout, stderr) = opentide(
        &ws,
        &["setup", "ci", "azure", "--default-branch", "main", "--yes"],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    let (_, _, written) = regenerate_azure(
        &ws,
        &[
            "--variable-group",
            " b ",
            "--variable-group",
            "a",
            "--variable-group",
            "b",
        ],
        str::to_owned,
    );
    assert!(
        written.contains("variables:\n  - group: b\n  - group: a\n  - name:"),
        "{written}"
    );
}

/// A stage or job a flag turned off is named without calling it hand-added,
/// and Azure's `deployment:` and `template:` entries are compared as
/// (stage, name) pairs, so a job added to a kept stage is named with it.
#[test]
fn the_drop_warning_names_what_the_run_does_not_generate() {
    let (_scratch, ws) = tide_corpus();
    let (code, stdout, stderr) = opentide(
        &ws,
        &["setup", "ci", "azure", "--default-branch", "main", "--yes"],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    let (_, stderr, written) = regenerate_azure(&ws, &["--sharing"], str::to_owned);
    assert!(!stderr.contains("drops"), "{stderr}");
    assert!(written.contains("- stage: Share"), "{written}");

    let (_, stderr, _) = regenerate_azure(&ws, &["--no-sharing"], str::to_owned);
    assert!(
        stderr.contains("drops stage Share (job share) that this run does not generate"),
        "{stderr}"
    );
    assert!(!stderr.contains("opentide does not generate"), "{stderr}");

    let (_, stderr, _) = regenerate_azure(&ws, &[], |text| {
        text.replacen(
            "  - stage: Deploy\n    displayName: Deploy\n    dependsOn: Generate\n    jobs:\n",
            "  - stage: Deploy\n    displayName: Deploy\n    dependsOn: Generate\n    jobs:\n      - deployment: approve_prod\n        environment: prod\n      - template: extra.yml\n",
            1,
        )
    });
    assert!(
        stderr.contains("drops deployment Deploy/approve_prod; template Deploy/extra.yml that this run does not generate"),
        "{stderr}"
    );
}
