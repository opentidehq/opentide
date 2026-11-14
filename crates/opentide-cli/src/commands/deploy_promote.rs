//! The status promotion of `opentide deploy` (UC-4.6c, #979): a RELEASE run
//! on a push in CI, without `--skip-promotion`, moves the platform blocks of
//! the rule files the push changed to the promotion target before it plans
//! (`cli/services/deploy.py` `_deploy`, `mutation/promotion.py`
//! `PromoteMDR.promote`).
//!
//! The run shows one step, `status promotion`, counting the changed rule
//! files, as its own checklist. Every file is read and planned before any is
//! written, so a file that cannot be promoted fails the run with nothing
//! half-promoted; a status the promotion cannot rewrite safely (an anchor, an
//! alias, a merge key) leaves its file as it is, with a warning. The text
//! edit is [`opentide_compile::promotion`].
//!
//! A target that is not a configured status (none set, or not a string) ends
//! the run as the oracle's `sys.exit(1)` does; a promoted block whose key is
//! not a string, and promoted text that does not read back, fail it with the
//! exception the oracle raises.

use std::path::{Path, PathBuf};
use std::time::Instant;

use opentide_compile::Json as Setting;
use opentide_compile::promotion::{self, Error, LOGGER, NOT_PROMOTED_ADVICE, Settings};
use opentide_schema::node;

use super::deploy_send::Lines;
use crate::json::Json;
use crate::render::progress::{Step, StepStatus};

/// The step's name.
pub const STEP: &str = "status promotion";
/// The result key of a run the oracle ends with `sys.exit`: no document, no
/// outcome line, only its exit code.
pub const BARE_EXIT: &str = "_bare_exit";

/// What the promotion needs from the run.
#[derive(Debug)]
pub struct Promotion<'a> {
    /// `[promotion]` and the statuses.
    pub settings: &'a Settings,
    /// The rule files the push changed (`modified_mdr_files`).
    pub changed: &'a [PathBuf],
    /// Every rule file directly in the rules folder (`local_rule_files`),
    /// promoted instead in debug mode.
    pub local: &'a [PathBuf],
    /// Debug mode: `--debug`, or the environment asking for it
    /// ([`crate::env::Env::debug_requested`]); never the terminal the run starts in.
    pub debug: bool,
}

/// How a promotion ended, when the run does not go on to plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The run fails with this message (an exception `_deploy` reports).
    Failed(String),
    /// The oracle exits 1 without a result (an invalid target).
    Exit,
}

/// One thing the promotion logs, in the order the oracle logs it.
enum Event {
    Info(&'static str, Vec<(&'static str, String)>),
    NotPromoted { path: String, detail: String },
    InvalidTarget { target: Setting, detail: String },
}

fn emit(event: &Event) {
    match event {
        Event::InvalidTarget { target, detail } => invalid_target(target, detail),
        Event::NotPromoted { path, detail } => tracing::warn!(
            path = path.as_str(),
            detail = detail.as_str(),
            advice = NOT_PROMOTED_ADVICE,
            logger = LOGGER,
            "rule_not_promoted"
        ),
        Event::Info(name, fields) => {
            let detail = fields
                .iter()
                .find(|(key, _)| *key == "detail")
                .map(|(_, value)| value.as_str());
            let path = fields
                .iter()
                .find(|(key, _)| *key == "path")
                .map(|(_, value)| value.as_str());
            let target = fields
                .iter()
                .find(|(key, _)| *key == "target")
                .map(|(_, value)| value.as_str());
            match (path, target, detail) {
                (Some(path), Some(target), _) => {
                    tracing::info!(path, target, logger = LOGGER, "{name}");
                }
                (_, _, Some(detail)) => tracing::info!(detail, logger = LOGGER, "{name}"),
                _ => tracing::info!(logger = LOGGER, "{name}"),
            }
        }
    }
}

/// Logs `invalid_promotion_target` with the target as the oracle's
/// structlog line holds it: a number as one, anything else as Python's `str`
/// writes it (`None` when no target is set, `True`). A JSON log line holds
/// a boolean, an array or a table as that text where the oracle's holds the
/// value.
fn invalid_target(target: &Setting, detail: &str) {
    let event = "invalid_promotion_target";
    match target {
        Setting::Int(number) => {
            tracing::error!(target = number, detail, logger = LOGGER, "{event}");
        }
        Setting::Float(number) => {
            tracing::error!(target = number, detail, logger = LOGGER, "{event}");
        }
        other => {
            let text = setting_text(other);
            tracing::error!(target = text.as_str(), detail, logger = LOGGER, "{event}");
        }
    }
}

/// A TOML value as the log shows it: a string as is, anything else as its
/// JSON.
fn setting_text(value: &Setting) -> String {
    match value {
        Setting::Str(text) => text.clone(),
        other => other.to_compact(),
    }
}

/// Runs the promotion: plans every file, then logs, writes and draws the
/// step. `Ok` when the run goes on to plan.
///
/// # Errors
///
/// [`Stop`]: how the run ends instead.
pub fn run(promotion: &Promotion<'_>, lines: &Lines) -> Result<(), Stop> {
    let started = Instant::now();
    let (events, planned, mut ended) = plan(promotion);
    for event in &events {
        emit(event);
    }
    if ended.is_none() {
        for (path, bytes) in &planned {
            if let Err(error) = write_atomically(path, bytes) {
                ended = Some(Stop::Failed(super::deploy_state::os_error_text(
                    &error, path,
                )));
                break;
            }
            emit(&Event::Info(
                "rule_promoted",
                vec![
                    ("path", path.display().to_string()),
                    (
                        "target",
                        promotion.settings.target.clone().unwrap_or_default(),
                    ),
                ],
            ));
        }
    }
    let mut step = Step::new(STEP);
    step.unit = "rule".into();
    step.count = Some(promotion.changed.len());
    step.status = if ended.is_some() {
        StepStatus::Failed
    } else {
        StepStatus::Ok
    };
    step.seconds = started.elapsed().as_secs_f64();
    lines.step(&step, 1, 1);
    lines.checklist(std::slice::from_ref(&step));
    ended.map_or(Ok(()), Err)
}

type Planned = (Vec<Event>, Vec<(PathBuf, Vec<u8>)>, Option<Stop>);

/// Every file read and planned (`PromoteMDR.promote` up to its writes): the
/// events to log, the bytes to write, and how the run stops, if it does.
fn plan(promotion: &Promotion<'_>) -> Planned {
    let settings = promotion.settings;
    let mut events = vec![Event::Info(
        "rule_promotion_started",
        vec![(
            "detail",
            "Promotes the status of modified rule files according to configuration".into(),
        )],
    )];
    if !settings.enabled {
        events.push(Event::Info(
            "rule_promotion_disabled_in_config",
            vec![(
                "detail",
                "Enable status promotion under [promotion] in deployment.toml".into(),
            )],
        ));
        return (events, Vec::new(), None);
    }
    // `PROMOTION_TARGET not in VALID_STATUSES`: a target that is not set, or
    // not a string, names no status either.
    let Some(target) = settings.valid_target() else {
        events.push(Event::InvalidTarget {
            target: settings.target_value.clone(),
            detail: format!("Valid statuses: {}", settings.valid.join(", ")),
        });
        return (events, Vec::new(), Some(Stop::Exit));
    };
    let files = if promotion.debug {
        promotion.local
    } else {
        if promotion.changed.is_empty() {
            events.push(Event::Info(
                "found_nothing_to_deploy_in_pre_deployment_environment_variable",
                Vec::new(),
            ));
            return (events, Vec::new(), None);
        }
        promotion.changed
    };
    let mut planned = Vec::new();
    for path in files {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                let failed = Stop::Failed(os_error(&error, path));
                return (events, Vec::new(), Some(failed));
            }
        };
        // A file that does not read as YAML fails the run, as the oracle's
        // parser's exception does; the words are this loader's (UC-6.0d).
        let document = match node::load_bytes(&bytes) {
            Ok(document) => document,
            Err(error) => {
                let failed = Stop::Failed(unreadable(path, &error));
                return (events, Vec::new(), Some(failed));
            }
        };
        let root = document.root().map(AsRef::as_ref);
        if let Err(message) = promotion::name_error(root) {
            return (events, Vec::new(), Some(Stop::Failed(message)));
        }
        let name = root
            .and_then(|root| root.get("name"))
            .map(|name| match &name.value {
                node::Value::Str(text) => text.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        let blocks = root
            .map(|root| promotion::promotable(root, &settings.non_promotable))
            .unwrap_or_default();
        if blocks.is_empty() {
            events.push(Event::Info(
                "nothing_to_promote_rule_already_in_production_status",
                vec![("detail", name)],
            ));
            continue;
        }
        events.push(Event::Info(
            "detected_statuses_needing_promotion_for_the_following_rule",
            vec![("detail", name)],
        ));
        let listed: Vec<String> = blocks
            .iter()
            .map(|(platform, status)| format!("{platform} : {status}"))
            .collect();
        events.push(Event::Info(
            "promoting_the_following_systems_statuses",
            vec![("detail", listed.join(", "))],
        ));
        let statuses: Vec<String> = blocks.into_iter().map(|(_, status)| status).collect();
        match promotion::promote_block_statuses(&document, &statuses, target) {
            Ok(None) => {}
            Ok(Some(text)) => {
                let mut out = Vec::with_capacity(text.len() + 3);
                if bytes.starts_with("\u{feff}".as_bytes()) {
                    out.extend_from_slice("\u{feff}".as_bytes());
                }
                out.extend_from_slice(text.as_bytes());
                planned.push((path.clone(), out));
            }
            Err(Error::Refused(detail)) => events.push(Event::NotPromoted {
                path: path.display().to_string(),
                detail,
            }),
            // `planned_statuses`' `ValueError`, the parser's words this
            // loader's.
            Err(Error::Unreadable(words)) => {
                let message = format!("{}: cannot promote its statuses: {words}", path.display());
                return (events, Vec::new(), Some(Stop::Failed(message)));
            }
            // `expected["configurations"][platform]`'s `KeyError`.
            Err(Error::KeyError(key)) => {
                let message = format!("{key:?}");
                return (events, Vec::new(), Some(Stop::Failed(message)));
            }
        }
    }
    (events, planned, None)
}

/// The message of a rule file this loader cannot read as YAML: the oracle
/// fails the run with its parser's exception, which names the problem and
/// where it is (`in "<file>", line N, column M`).
fn unreadable(path: &Path, error: &node::LoadError) -> String {
    match &error.mark {
        Some(mark) => format!(
            "{}\n  in \"{}\", line {}, column {}",
            error.problem,
            path.display(),
            mark.line,
            mark.column
        ),
        None => format!("{}\n  in \"{}\"", error.problem, path.display()),
    }
}

/// An I/O error as Python words an `OSError` on `path`
/// (`[Errno 2] No such file or directory: 'x.yaml'`).
fn os_error(error: &std::io::Error, path: &Path) -> String {
    let text = error.to_string();
    match error.raw_os_error() {
        Some(code) => {
            let words = text
                .strip_suffix(&format!(" (os error {code})"))
                .unwrap_or(&text);
            format!("[Errno {code}] {words}: {:?}", path.display().to_string())
        }
        None => text,
    }
}

/// Replaces `path` with `bytes` through a temporary file beside it
/// (`_write_atomically`): the file is created owner-only, as `mkstemp`
/// creates it, takes `path`'s permission bits, so a rule committed as 0644
/// stays 0644 (#987), and takes `path`'s place. Windows has no such bits to
/// keep.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let written = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        drop(file);
        #[cfg(unix)]
        std::fs::set_permissions(&temporary, std::fs::metadata(path)?.permissions())?;
        std::fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// The result of a run the promotion stopped.
pub fn stopped(stop: &Stop) -> Vec<(String, Json)> {
    match stop {
        Stop::Failed(message) => vec![
            ("status".to_owned(), Json::str("failed")),
            ("message".to_owned(), Json::str(message)),
            ("_exit_code".to_owned(), Json::Int(1)),
        ],
        Stop::Exit => vec![
            ("status".to_owned(), Json::str("failed")),
            ("message".to_owned(), Json::str("Invalid promotion target")),
            ("_exit_code".to_owned(), Json::Int(1)),
            (BARE_EXIT.to_owned(), Json::Bool(true)),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::outcome::Console;
    use crate::render::text::Colour;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn lines(buffer: &Buffer, progress: bool) -> Lines {
        Lines {
            sink: Arc::new(Mutex::new(buffer.clone())),
            console: Console {
                colour: Colour::None,
                width: None,
            },
            silent: false,
            quiet: false,
            progress,
            terminal: false,
            live: None,
        }
    }

    fn settings(enabled: bool, target: &str) -> Settings {
        Settings {
            enabled,
            target: Some(target.to_owned()),
            target_value: Setting::Str(target.to_owned()),
            valid: vec!["STAGING".into(), "PRODUCTION".into(), "REMOVED".into()],
            non_promotable: vec!["PRODUCTION".into(), "REMOVED".into()],
        }
    }

    const RULE: &str = "name: R\nconfigurations:\n  splunk:\n    status: STAGING\n    query: x\n";

    /// Runs a promotion of `files` (name, bytes) in a fresh folder: the
    /// outcome, what it drew, and each file's bytes afterwards.
    fn promote(
        settings: &Settings,
        files: &[(&str, &[u8])],
        debug: bool,
        progress: bool,
    ) -> (Result<(), Stop>, String, Vec<Vec<u8>>) {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<PathBuf> = files
            .iter()
            .map(|(name, bytes)| {
                let path = dir.path().join(name);
                std::fs::write(&path, bytes).unwrap();
                path
            })
            .collect();
        let changed = if debug { Vec::new() } else { paths.clone() };
        let buffer = Buffer::default();
        let outcome = run(
            &Promotion {
                settings,
                changed: &changed,
                local: &paths,
                debug,
            },
            &lines(&buffer, progress),
        );
        let drawn = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        let after = paths
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect();
        (outcome, drawn, after)
    }

    #[test]
    fn a_changed_rule_is_promoted_in_place() {
        let bom = format!("\u{feff}{}", RULE.replace('\n', "\r\n"));
        let done = "name: D\nconfigurations:\n  splunk:\n    status: PRODUCTION\n";
        let (outcome, drawn, after) = promote(
            &settings(true, "PRODUCTION"),
            &[("a.yaml", bom.as_bytes()), ("b.yaml", done.as_bytes())],
            false,
            true,
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(after[0], bom.replace("STAGING", "PRODUCTION").into_bytes());
        assert_eq!(after[1], done.as_bytes());
        assert!(drawn.contains("\"step\":\"status promotion\""), "{drawn}");
        assert!(drawn.contains("status promotion · 2 rules"), "{drawn}");
    }

    /// The temporary file is created 0600, as `mkstemp` creates it: a rule
    /// committed as 0644 came back owner-only (#987).
    #[cfg(unix)]
    #[test]
    fn the_promoted_file_keeps_its_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        for kept in [0o644, 0o640, 0o755] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("r.yaml");
            std::fs::write(&path, "x").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(kept)).unwrap();
            write_atomically(&path, b"y").unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, kept, "{kept:o}");
            assert_eq!(std::fs::read(&path).unwrap(), b"y");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn disabled_or_nothing_changed_writes_nothing() {
        let (outcome, drawn, after) = promote(
            &settings(false, "PRODUCTION"),
            &[("a.yaml", RULE.as_bytes())],
            false,
            false,
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(after[0], RULE.as_bytes());
        assert!(drawn.contains("✓ status promotion · 1 rule"), "{drawn}");
        let (outcome, drawn, _) = promote(&settings(true, "PRODUCTION"), &[], false, false);
        assert_eq!(outcome, Ok(()));
        assert!(drawn.contains("status promotion · 0 rules"), "{drawn}");
    }

    #[test]
    fn debug_promotes_every_rule_file() {
        let (outcome, drawn, after) = promote(
            &settings(true, "PRODUCTION"),
            &[("a.yaml", RULE.as_bytes())],
            true,
            false,
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(after[0], RULE.replace("STAGING", "PRODUCTION").into_bytes());
        // The step counts the changed files, none here.
        assert!(drawn.contains("status promotion · 0 rules"), "{drawn}");
    }

    #[test]
    fn an_invalid_target_ends_the_run_with_a_failed_step() {
        let (outcome, drawn, after) = promote(
            &settings(true, "LIVE"),
            &[("a.yaml", RULE.as_bytes())],
            false,
            false,
        );
        assert_eq!(outcome, Err(Stop::Exit));
        assert_eq!(after[0], RULE.as_bytes());
        assert!(drawn.contains("✗ status promotion · 1 rule"), "{drawn}");
        let result = stopped(&Stop::Exit);
        assert!(result.iter().any(|(key, _)| key == BARE_EXIT));
    }

    #[test]
    fn a_rule_without_a_name_fails_the_run_and_nothing_is_written() {
        let (outcome, _, after) = promote(
            &settings(true, "PRODUCTION"),
            &[("a.yaml", RULE.as_bytes()), ("b.yaml", b"title: x\n")],
            false,
            false,
        );
        assert_eq!(outcome, Err(Stop::Failed("\"name\"".into())));
        assert_eq!(after[0], RULE.as_bytes());
        let (outcome, _, _) = promote(
            &settings(true, "PRODUCTION"),
            &[("a.yaml", b"")],
            false,
            false,
        );
        assert_eq!(
            outcome,
            Err(Stop::Failed(
                "'NoneType' object is not subscriptable".into()
            ))
        );
        let result = stopped(&Stop::Failed("\"name\"".into()));
        assert_eq!(result[1].1, Json::str("\"name\""));
    }

    /// A rule file that is not YAML, or whose root is no mapping, fails the
    /// run as the oracle's exception does, and nothing is written (UC-6.0d).
    #[test]
    fn a_file_that_does_not_read_or_is_no_mapping_fails_the_run() {
        for (bytes, expected) in [
            (&b"name: [\n"[..], None),
            (b"\xff\n", None),
            (
                b"just text\n",
                Some("string indices must be integers, not 'str'"),
            ),
            (b"42\n", Some("'int' object is not subscriptable")),
        ] {
            let (outcome, drawn, after) = promote(
                &settings(true, "PRODUCTION"),
                &[("a.yaml", RULE.as_bytes()), ("b.yaml", bytes)],
                false,
                false,
            );
            let Err(Stop::Failed(message)) = outcome else {
                panic!("{bytes:?}: {outcome:?}");
            };
            match expected {
                Some(expected) => assert_eq!(message, expected),
                None => assert!(message.contains("b.yaml\""), "{bytes:?}: {message}"),
            }
            assert!(drawn.contains("status promotion"), "{drawn}");
            assert_eq!(after, [RULE.as_bytes(), bytes]);
        }
    }

    /// No target, or one that is not a string, names no status: the
    /// oracle's `PROMOTION_TARGET not in VALID_STATUSES` exits 1 as an
    /// invalid target does, nothing written.
    #[test]
    fn a_target_unset_or_not_a_string_is_an_invalid_target() {
        for target in [Setting::Null, Setting::Int(1), Setting::Bool(true)] {
            let settings = Settings {
                target: None,
                target_value: target.clone(),
                ..settings(true, "PRODUCTION")
            };
            let (outcome, drawn, after) =
                promote(&settings, &[("a.yaml", RULE.as_bytes())], false, false);
            assert_eq!(outcome, Err(Stop::Exit), "{target:?}");
            assert_eq!(after[0], RULE.as_bytes());
            assert!(drawn.contains("✗ status promotion · 1 rule"), "{drawn}");
        }
        assert_eq!(setting_text(&Setting::Null), "null");
        assert_eq!(setting_text(&Setting::Str("A".into())), "A");
        assert_eq!(
            setting_text(&Setting::Array(vec![
                Setting::Str("A".into()),
                Setting::Float(1.5),
                Setting::Bool(false),
            ])),
            r#"["A",1.5,false]"#
        );
    }

    /// A promoted block whose key is not a string fails the run with the
    /// oracle's `KeyError`, nothing written; the other file is not promoted.
    #[test]
    fn a_promoted_block_whose_key_is_not_a_string_fails_the_run() {
        let keyed = RULE.replace("  splunk:\n", "  1:\n");
        let (outcome, _, after) = promote(
            &settings(true, "PRODUCTION"),
            &[("a.yaml", RULE.as_bytes()), ("b.yaml", keyed.as_bytes())],
            false,
            false,
        );
        assert_eq!(outcome, Err(Stop::Failed("\"1\"".into())));
        assert_eq!(after, [RULE.as_bytes(), keyed.as_bytes()]);
    }

    /// Promoted text that does not read back fails the run with the
    /// oracle's `ValueError`, naming the file; nothing is written.
    #[test]
    fn promoted_text_that_does_not_read_back_fails_the_run() {
        let flow = "name: R\nconfigurations:\n  splunk: {status: STAGING, query: x}\n";
        let settings = Settings {
            target: Some("LIVE}".into()),
            target_value: Setting::Str("LIVE}".into()),
            valid: vec!["STAGING".into(), "LIVE}".into()],
            non_promotable: vec!["LIVE}".into()],
            enabled: true,
        };
        let (outcome, _, after) = promote(&settings, &[("a.yaml", flow.as_bytes())], false, false);
        let Err(Stop::Failed(message)) = outcome else {
            panic!("{outcome:?}");
        };
        assert!(
            message.contains("a.yaml: cannot promote its statuses: "),
            "{message}"
        );
        assert_eq!(after[0], flow.as_bytes());
    }

    #[test]
    fn an_anchored_status_is_left_as_it_is() {
        let anchored = RULE.replace("status: STAGING", "status: &s STAGING");
        let (outcome, _, after) = promote(
            &settings(true, "PRODUCTION"),
            &[("a.yaml", anchored.as_bytes())],
            false,
            false,
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(after[0], anchored.as_bytes());
    }
}
