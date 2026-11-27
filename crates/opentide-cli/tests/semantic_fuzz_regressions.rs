//! The `semantic` fuzz target's seeds and saved crashes
//! (`fuzz/seeds/semantic`, `fuzz/regressions/semantic`), replayed on stable
//! Rust (#1946): each is a rule file, written into a workspace in memory that
//! enables every built-in platform, then validated (the compile check and the
//! queries included) and dry-run for both strategies. None may panic. The
//! harness is a copy of `fuzz/src/lib.rs::semantic_run`.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: an unreadable seed is a failure"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use opentide_compile::dry_run::{self, Outcome, Request};
use opentide_compile::plan::Scope;
use opentide_compile::validate::Compilers;
use opentide_core::json::Json;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::validate::{Options as ValidateOptions, Validation};
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

/// `fuzz/src/lib.rs::SEMANTIC_MAX_INPUT`.
const MAX_INPUT: usize = 16 * 1024;

/// The template workspace in memory, `rule` its one rule file.
fn workspace(rule: &[u8]) -> Option<Workspace> {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    for platform in opentide_schema::platforms::PLATFORMS {
        fs.write(
            format!(
                "/ws/.opentide/configurations/platforms/{}.toml",
                platform.id
            ),
            "[platform]\nenabled = true\n",
        );
    }
    fs.write("/ws/objects/rules/fuzz.yaml", rule);
    Workspace::open(
        fs as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )
    .ok()
}

/// `fuzz/src/lib.rs::semantic_run`, then `semantic`'s checks.
fn run(data: &[u8]) -> Option<(Validation, Outcome)> {
    if data.len() > MAX_INPUT {
        return None;
    }
    if let Ok(document) = opentide_schema::node::load_bytes(data)
        && let Some(root) = document.root()
    {
        let _ = Json::from_node(root).to_compact();
    }
    let workspace = workspace(data)?;
    let validation = workspace.validate(&ValidateOptions {
        query_check: Some(&opentide_analysis::queries::EngineQueries),
        compile_check: Some(&Compilers),
        ..ValidateOptions::default()
    });
    let owned = opentide_compile::Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let request = Request {
        strategies: vec!["PREVIEW".to_owned(), "RELEASE".to_owned()],
        all: true,
        cwd: PathBuf::from("/ws"),
        ..Request::default()
    };
    let changed = |_: &Path, _: &str| -> Result<(Scope, Option<String>), dry_run::ScopeError> {
        Err("no git here".to_owned().into())
    };
    let outcome = dry_run::run(&workspace, &owned, &request, &changed, &|_| true);
    assert!(
        matches!(outcome.exit_code, 0..=2),
        "exit {}",
        outcome.exit_code
    );
    let _ = Json::Object(outcome.payload.clone()).to_compact();
    for issue in &validation.report.issues {
        assert!(!issue.code.is_empty(), "{issue:?}");
    }
    Some((validation, outcome))
}

fn seed(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/seeds/semantic")
            .join(name),
    )
    .unwrap()
}

/// Each issue's code and field path (`code at a.b.c`).
fn issues(validation: &Validation) -> Vec<String> {
    validation
        .report
        .issues
        .iter()
        .map(|issue| format!("{} at {}", issue.code, issue.field_path.join(".")))
        .collect()
}

/// The platforms the dry run compiled a payload for.
fn compiled(outcome: &Outcome) -> Vec<String> {
    match outcome.payload.get("payloads") {
        Some(Json::Object(payloads)) => payloads.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

#[test]
fn every_seed_and_saved_input_runs_without_a_panic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let mut replayed = 0;
    for dir in ["seeds/semantic", "regressions/semantic"] {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let data = std::fs::read(&path).unwrap();
            let started = Instant::now();
            let outcome = std::panic::catch_unwind(|| run(&data).is_some());
            assert!(outcome.is_ok(), "{} panicked", path.display());
            // The fuzzer's `-timeout` is 10 s per input; a debug build gets more.
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "{} took {:?}",
                path.display(),
                started.elapsed()
            );
            replayed += 1;
        }
    }
    assert!(replayed >= 6, "only {replayed} inputs replayed");
}

/// The seed every mutation starts from validates and compiles a payload for
/// every built-in platform: the fuzzer reaches each platform's compile.
#[test]
fn the_template_validates_and_compiles_a_payload_for_every_platform() {
    let (validation, outcome) = run(&seed("template.yaml")).unwrap();
    assert!(
        validation.report.issues.is_empty(),
        "{:?}",
        issues(&validation)
    );
    assert_eq!(outcome.exit_code, 0);
    let platforms: Vec<String> = opentide_schema::platforms::PLATFORMS
        .iter()
        .map(|platform| platform.id.to_owned())
        .collect();
    assert_eq!(compiled(&outcome), platforms);
}

/// #1926: a Defender frequency whose last character is multi-byte is a
/// finding on the field, and the dry run fails that block, not the run.
#[test]
fn a_multi_byte_defender_frequency_is_a_finding_not_a_panic() {
    for name in [
        "defender-frequency-multibyte.yaml",
        "defender-frequency-emoji.yaml",
    ] {
        let (validation, outcome) = run(&seed(name)).unwrap();
        assert_eq!(
            issues(&validation),
            [
                "microsoft_defender_frequency at configurations.microsoft_defender.schedule.frequency"
            ],
            "{name}"
        );
        assert_eq!(outcome.exit_code, 1, "{name}");
    }
}

/// #1928: a Splunk lookback whose minutes overflow is a finding, and the dry
/// run writes no wrapped earliest time.
#[test]
fn an_overflowing_splunk_lookback_is_a_finding_not_a_wrapped_time() {
    let (validation, outcome) = run(&seed("splunk-lookback-overflow.yaml")).unwrap();
    assert_eq!(
        issues(&validation),
        ["schema_validation at configurations.splunk.scheduling.timerange.lookback"]
    );
    let payload = Json::Object(outcome.payload.clone()).to_compact();
    assert!(!payload.contains("\"--"), "{payload}");
}

/// #1927: nested aliases past the loader's budget are a YAML error for
/// validate and for the dry run; within it, the dry run copies them out and
/// compiles every block.
#[test]
fn nested_aliases_past_the_budget_are_refused_and_within_it_compile() {
    let (validation, outcome) = run(&seed("nested-alias-expansion.yaml")).unwrap();
    assert_eq!(issues(&validation), ["yaml_parse at "]);
    assert_eq!(outcome.exit_code, 1);
    assert!(compiled(&outcome).is_empty());

    let (validation, outcome) = run(&seed("nested-alias-within-budget.yaml")).unwrap();
    assert!(
        !issues(&validation)
            .iter()
            .any(|issue| issue.starts_with("yaml_parse")),
        "{:?}",
        issues(&validation)
    );
    assert_eq!(
        compiled(&outcome).len(),
        opentide_schema::platforms::PLATFORMS.len()
    );
}
