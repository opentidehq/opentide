//! Every input the `config` fuzz target saved (`fuzz/regressions/config/`,
//! #843), and its seeds, run through the engine on stable Rust as
//! `fuzz/src/lib.rs::configuration` runs them: the input's field paths placed
//! as findings, the schemas installed, then hover and completion. The
//! schemas are process-wide, so this file is its own test binary.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

use opentide_analysis::{
    CONFIGURATIONS_DIRECTORY, ConfigIssue, Severity, configuration_completions,
    configuration_hover, install_configuration_schemas,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The fuzzer's `-timeout` in CI is 10 s per input; a debug build gets more.
const BUDGET: Duration = Duration::from_secs(30);

/// `fuzz/src/lib.rs::CONFIGURATION_FILES`, in its order: an input's first
/// byte picks one.
const FILES: &[&str] = &[
    "paths.toml",
    "global.toml",
    "deployment.toml",
    "schema.toml",
    "visibility.toml",
    "documentation.toml",
    "sharing.toml",
    "platforms/sentinel.toml",
    "platforms/splunk.toml",
    "platforms/carbon_black_cloud.toml",
    "platforms/sentinel_one.toml",
    "platforms/defender_for_endpoint.toml",
    "platforms/crowdstrike.toml",
    "platforms/harfanglab.toml",
    "platforms/elastic.toml",
    "platforms/other.toml",
];

fn install_schemas() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/config/schemas");
    let mut router = None;
    let mut schemas = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("crates/testdata/config/schemas") {
        let path = entry.expect("entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let text = std::fs::read_to_string(&path).expect("schema");
        if name == "configurations.router.json" {
            router = Some(text);
        } else {
            schemas.push((name, text));
        }
    }
    install_configuration_schemas(router.as_deref(), &schemas).expect("schemas");
}

fn boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

/// `fuzz/src/lib.rs::configuration`, with the same input format.
fn exercise(data: &[u8]) {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let mut parts = rest.split(|b| *b == 0);
    let Some(Ok(text)) = parts.next().map(std::str::from_utf8) else {
        return;
    };
    let mut issues = Vec::new();
    for part in parts {
        let Ok(path) = std::str::from_utf8(part) else {
            continue;
        };
        // `!` made a host's checker fail; the checks are native now and
        // cannot (UC-2.6): the saved inputs that hold it place nothing for it.
        if path == "!" {
            continue;
        }
        let severity = match path.len() % 4 {
            0 => Severity::Error,
            1 => Severity::Warning,
            2 => Severity::Information,
            _ => Severity::Hint,
        };
        issues.push(ConfigIssue {
            code: "fuzz_finding".to_string(),
            field_path: if path.is_empty() {
                Vec::new()
            } else {
                path.split('.').map(str::to_string).collect()
            },
            severity,
            message: path.to_string(),
        });
    }
    let file = FILES[usize::from(pick) % FILES.len()];
    let path = format!("/w/{CONFIGURATIONS_DIRECTORY}{file}");
    let diagnostics = opentide_analysis::place_configuration_issues(text, issues);
    let lines = u32::try_from(text.split('\n').count()).unwrap();
    for d in &diagnostics {
        assert!(d.range.start.line < lines.max(1), "{d:?}");
        assert!(d.range.end.line < lines.max(1), "{d:?}");
        assert!(
            (d.range.start.line, d.range.start.character)
                <= (d.range.end.line, d.range.end.character),
            "{d:?}"
        );
    }
    for offset in [0, text.len() / 3, text.len() / 2, text.len()] {
        let offset = boundary(text, offset);
        let _ = configuration_hover(&path, text, offset);
        let _ = configuration_completions(&path, text, offset);
    }
}

#[test]
fn saved_configuration_inputs_do_not_crash_or_hang() {
    install_schemas();
    let fuzz = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let mut ran = 0;
    for dir in ["seeds/config", "regressions/config"] {
        let Ok(entries) = std::fs::read_dir(fuzz.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let bytes = std::fs::read(entry.path()).unwrap();
            let start = Instant::now();
            exercise(&bytes);
            let took = start.elapsed();
            assert!(took < BUDGET, "{}: {took:?}", entry.path().display());
            ran += 1;
        }
    }
    assert!(ran >= 10, "the seeds ran ({ran})");
}

/// `fuzz/src/lib.rs` compiles in the schemas by name; this replay reads the
/// directory. A schema added to one and not the other would fuzz a host the
/// replay does not reproduce.
#[test]
fn the_fuzz_target_installs_every_schema_the_replay_does() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/config/schemas");
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| {
            name != "configurations.router.json"
                && std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext == "json")
        })
        .collect();
    on_disk.sort();
    let harness = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/src/lib.rs"),
    )
    .unwrap();
    let mut compiled: Vec<String> = harness
        .split("schema!(\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(name, _)| name.to_string()))
        .collect();
    compiled.sort();
    assert_eq!(compiled, on_disk);
    // The first byte of an input picks a file by its index: the same list.
    let files = harness
        .split_once("pub const CONFIGURATION_FILES: &[&str] = &[")
        .and_then(|(_, rest)| rest.split_once("];"))
        .map(|(list, _)| list)
        .unwrap();
    let listed: Vec<&str> = files.split('"').skip(1).step_by(2).collect();
    assert_eq!(listed, FILES);
}
