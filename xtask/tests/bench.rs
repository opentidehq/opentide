//! `cargo xtask bench` end to end: a measured run, its JSON, and the budget
//! check on it. An injected slowdown (`XTASK_BENCH_INJECT_SLEEP_MS`, a sleep
//! inside every measured run's timed window) must make the check fail, and
//! the same run without it must pass: issue #806's acceptance criterion.
//!
//! The command measured is `explain`, on a stand-in `opentide` (a shell
//! script that prints what `opentide --json explain vocab_unknown` prints), so
//! that the test needs neither the oracle nor the heavy workspace.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("xtask-bench-{name}-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fake_opentide(dir: &Path) -> PathBuf {
    let path = dir.join("opentide");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         printf '%s\\n' '{\"code\":\"vocab_unknown\",\"ok\":true,\"exit_code\":0}'\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn xtask(args: &[&str], inject_ms: Option<u64>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    command.args(args).env_remove("XTASK_BENCH_INJECT_SLEEP_MS");
    if let Some(ms) = inject_ms {
        command.env("XTASK_BENCH_INJECT_SLEEP_MS", ms.to_string());
    }
    command.output().expect("run xtask")
}

fn bench(opentide: &Path, out: &Path, inject_ms: Option<u64>) -> serde_json::Value {
    let output = xtask(
        &[
            "bench",
            "--only",
            "explain",
            "--opentide",
            opentide.to_str().unwrap(),
            "--runs",
            "3",
            "--warmup",
            "0",
            "--json",
            "--out",
            out.to_str().unwrap(),
        ],
        inject_ms,
    );
    assert!(
        output.status.success(),
        "bench failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out).unwrap()).unwrap();
    assert_eq!(printed, written, "--json and --out disagree");
    written
}

/// Budgets whose only command is `explain`, with the given run as the
/// oracle baseline.
fn budgets_from(report: &serde_json::Value, path: &Path) {
    let explain = &report["results"][0];
    assert_eq!(explain["id"], "explain");
    assert_eq!(explain["status"], "measured");
    let median = explain["median_s"].as_f64().unwrap();
    #[expect(clippy::cast_precision_loss, reason = "a test RSS")]
    let rss_mib = explain["peak_rss_bytes"].as_u64().unwrap() as f64 / (1024.0 * 1024.0);
    std::fs::write(
        path,
        format!(
            "schema_version = 1\n\n\
             [policy]\nregression = 0.10\nnoise_floor_s = 0.03\nnoise_floor_rss_mib = 2.0\n\n\
             [baseline]\nengine = \"python\"\noracle = \"stand-in\"\nscale = 1\nseed = 20261107\n\
             runner = \"this machine\"\nsource = \"tests/bench.rs\"\n\n\
             [commands.explain]\nlabel = \"explain\"\nbaseline_s = {median}\n\
             baseline_rss_mib = {rss_mib}\ntarget_s = 0.03\n"
        ),
    )
    .unwrap();
}

#[test]
fn an_injected_slowdown_fails_the_budget_check_and_the_same_run_without_it_passes() {
    let dir = scratch("slowdown");
    let opentide = fake_opentide(&dir);

    let normal = dir.join("normal.json");
    let report = bench(&opentide, &normal, None);
    assert_eq!(report["engine"], "python");
    assert_eq!(report["runs"], 3);
    assert_eq!(
        report["results"][0]["samples_s"].as_array().unwrap().len(),
        3
    );
    assert!(report["results"][0]["peak_rss_bytes"].as_u64().unwrap() > 0);
    let budgets = dir.join("budgets.toml");
    budgets_from(&report, &budgets);

    // The run the budgets were taken from passes them.
    let output = xtask(
        &[
            "bench",
            "--check",
            budgets.to_str().unwrap(),
            normal.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // 300 ms more on a command of a few milliseconds: far over 10% and the
    // 30 ms noise floor.
    let slowed = dir.join("slowed.json");
    let report = bench(&opentide, &slowed, Some(300));
    let median = report["results"][0]["median_s"].as_f64().unwrap();
    assert!(
        median >= 0.3,
        "the injected sleep is not in the timed window: {median}"
    );
    assert!(
        report["results"][0]["note"]
            .as_str()
            .unwrap()
            .contains("XTASK_BENCH_INJECT_SLEEP_MS"),
        "{report}"
    );

    let summary = dir.join("summary.md");
    let output = xtask(
        &[
            "bench",
            "--check",
            budgets.to_str().unwrap(),
            slowed.to_str().unwrap(),
            "--previous",
            normal.to_str().unwrap(),
            "--summary",
            summary.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "the slowdown passed the check"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("explain: median"), "{stderr}");
    assert!(stderr.contains("against the oracle baseline"), "{stderr}");
    assert!(
        stderr.contains("against the last development result"),
        "{stderr}"
    );
    let summary = std::fs::read_to_string(summary).unwrap();
    assert!(summary.contains("FAILED"), "{summary}");
    assert!(summary.contains("| explain (`explain`) |"), "{summary}");

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_command_that_fails_is_not_measured() {
    // A stand-in that exits 1: a benchmark of a command that failed early
    // would measure nothing, so the run stops with exit status 2.
    let dir = scratch("failure");
    let opentide = dir.join("opentide");
    std::fs::write(&opentide, "#!/bin/sh\necho '{\"exit_code\":1}'\nexit 1\n").unwrap();
    std::fs::set_permissions(&opentide, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = xtask(
        &[
            "bench",
            "--only",
            "explain",
            "--opentide",
            opentide.to_str().unwrap(),
            "--runs",
            "1",
            "--warmup",
            "0",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("exited 1, not [0]"), "{stderr}");
    std::fs::remove_dir_all(dir).unwrap();
}
