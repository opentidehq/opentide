//! The status promotion of `opentide deploy` (UC-4.6c, #979): a RELEASE run
//! on a push in CI, without `--skip-promotion`, moves the platform blocks of
//! the rule files the push changed to the promotion target before it plans.
//!
//! The run shows one step, `status promotion`, counting the changed rule
//! files, as its own checklist. Every file is read and planned before any is
//! written, so a file that cannot be promoted fails the run with nothing
//! half-promoted; a status the promotion cannot rewrite safely (an anchor, an
//! alias, a merge key) leaves its file as it is, with a warning. The text
//! edit is [`opentide_compile::promotion`].
//!
//! A target that is not a configured status (none set, or not a string) ends
//! the run with exit 1 and no result document ([`CommandResult::bare_exit`]); a promoted
//! block whose key is not a string, and promoted text that does not read
//! back, fail it with a message ([`Stop::Failed`]).

use std::path::PathBuf;
use std::time::Instant;

use opentide_compile::Json as Setting;
use opentide_compile::promotion::{self, Error, NOT_PROMOTED_ADVICE, Settings};
use opentide_schema::node;

use super::deploy_send::Lines;
use super::result::{CommandResult, ExitCode};
use crate::render::progress::{Step, StepStatus};

/// The step's name.
pub const STEP: &str = "status promotion";

/// What the promotion needs from the run.
#[derive(Debug)]
pub struct Promotion<'a> {
    /// `[promotion]` and the statuses.
    pub settings: &'a Settings,
    /// The rule files the push changed.
    pub changed: &'a [PathBuf],
    /// Every rule file directly in the rules folder (`local_rule_files`),
    /// promoted instead in debug mode.
    pub local: &'a [PathBuf],
    /// Debug mode: `--debug` or `OPENTIDE_DEBUG`
    /// ([`crate::env::Env::opentide_debug`]); never a bare `DEBUG`, nor the
    /// terminal the run starts in.
    pub debug: bool,
}

/// A rule file the promotion rewrote: what it held before and after, so a
/// deploy that sends the rule nowhere can put it back (#1653).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Promoted {
    /// The file.
    pub path: PathBuf,
    /// Its bytes before the promotion.
    pub original: Vec<u8>,
    /// The bytes the promotion wrote.
    pub promoted: Vec<u8>,
    /// The rule's `metadata.uuid`, canonical, when it has one.
    pub uuid: Option<String>,
}

/// What putting a promoted file back did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Restored {
    /// The file holds its bytes from before the promotion again.
    Done,
    /// The file is gone: it is not made again.
    Missing,
    /// The file no longer holds what the promotion wrote (someone edited
    /// it): it is left as it is.
    Edited,
}

impl Promoted {
    /// Writes the file's bytes from before the promotion back, as the
    /// promotion wrote it (through a temporary file, its mode kept), when
    /// the file still holds exactly what the promotion wrote. A file that
    /// holds its bytes from before the promotion is left as it is (`Done`).
    ///
    /// # Errors
    ///
    /// The file cannot be read or written: the message names it.
    pub fn restore(&self) -> Result<Restored, String> {
        let now = match std::fs::read(&self.path) {
            Ok(now) => now,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Restored::Missing);
            }
            Err(error) => return Err(format!("{}: {error}", self.path.display())),
        };
        if now == self.original {
            return Ok(Restored::Done);
        }
        if now != self.promoted {
            return Ok(Restored::Edited);
        }
        opentide_workspace::fs::write_atomically(&self.path, &self.original)
            .map(|()| Restored::Done)
            .map_err(|error| format!("{}: {error}", self.path.display()))
    }
}

/// The promoted files a run has not settled yet: put back before the
/// process ends at once (a second Ctrl-C, a run still stopping after the
/// grace period, SIGTERM), where no destructor runs. Every change to a
/// file it holds, the promotion's write and each restore, happens under
/// its lock, so a signal waits for a write or a restore in progress and
/// then finds the file settled or still pending, never half done.
static PENDING: std::sync::Mutex<Vec<Promoted>> = std::sync::Mutex::new(Vec::new());

/// The pending files, locked.
pub fn pending() -> std::sync::MutexGuard<'static, Vec<Promoted>> {
    PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Takes *files* off the pending list: the run settled them.
pub fn settle(files: &[Promoted]) {
    pending().retain(|held| !files.iter().any(|file| file.path == held.path));
}

/// A tenant received the rule *uuid* (canonical): its file stays
/// promoted, and a forced exit no longer puts it back.
pub fn received(uuid: &str) {
    pending().retain(|held| held.uuid.as_deref() != Some(uuid));
}

/// Set by [`restore_pending`]: the process is ending, and the promotion
/// writes nothing more (it checks this under the pending lock, before each
/// write).
static ENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Puts back every pending file before the process ends at once, and stops
/// the promotion from writing another: under the pending lock, which it
/// releases before it writes on stderr, so a thread that holds stderr and
/// waits for the pending files (or the reverse) never blocks it. Called
/// from a signal's thread, where nothing logs: what it did is written on
/// stderr.
pub fn restore_pending() {
    use std::io::Write as _;
    let lines: Vec<String> = {
        let mut held = pending();
        ENDING.store(true, std::sync::atomic::Ordering::SeqCst);
        held.drain(..)
            .map(|file| {
                let path = file.path.display();
                match file.restore() {
                    Ok(Restored::Done) => format!(
                        "warning: {path}: status promotion undone, as no tenant received the rule"
                    ),
                    Ok(Restored::Missing) => format!(
                        "warning: {path} was deleted during the deploy, so its status promotion \
                         was not undone"
                    ),
                    Ok(Restored::Edited) => format!(
                        "error: {path} changed during the deploy, so its status promotion was \
                         not undone: no tenant received the rule; set its status back before \
                         committing"
                    ),
                    Err(error) => format!(
                        "error: could not undo the status promotion of {path}, which no tenant \
                         received: {error}"
                    ),
                }
            })
            .collect()
    };
    let mut err = std::io::stderr().lock();
    for line in lines {
        let _ignored = writeln!(err, "{line}");
    }
}

/// While a promotion is pending, SIGTERM (and SIGHUP) put the pending
/// files back ([`restore_pending`]), then end the process as their default
/// does. A signal is taken only while it still has its default action when
/// the first promotion starts: one that is ignored (`nohup`) or already
/// handled (`opentide serve`, a host program's own handler) is left alone.
/// On Linux `/proc/self/status` says which; elsewhere only SIGTERM is taken,
/// and only where opentide is the whole process ([`crate::app::exit`]) and
/// no `serve` handles it. The handler stays installed once taken, since
/// signal-hook never gives a signal back to its default (an unregistered
/// SIGTERM would be ignored): with nothing pending it ends the process at
/// once, as the default does.
pub fn guard_termination() {
    #[cfg(unix)]
    {
        static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INSTALLED.get_or_init(|| {
            use signal_hook::consts::{SIGHUP, SIGTERM};
            let taken: Vec<i32> = [SIGTERM, SIGHUP]
                .into_iter()
                .filter(|&signal| match default_action(signal) {
                    Some(default) => default,
                    None => {
                        signal == SIGTERM
                            && crate::app::process_ends()
                            && !crate::serve::handles_termination()
                    }
                })
                .collect();
            if taken.is_empty() {
                return;
            }
            if let Err(error) = install_termination(&taken) {
                tracing::warn!(detail = %error, "promotion_signal_not_handled");
            }
        });
    }
}

/// Whether *signal* has its default action (neither ignored nor caught),
/// read from `/proc/self/status`; `None` where that cannot be read.
#[cfg(unix)]
fn default_action(signal: i32) -> Option<bool> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let mask = |name: &str| -> Option<u64> {
        let value = status.lines().find_map(|line| line.strip_prefix(name))?;
        u64::from_str_radix(value.trim(), 16).ok()
    };
    let bit = 1_u64 << (signal - 1);
    Some(mask("SigIgn:")? & bit == 0 && mask("SigCgt:")? & bit == 0)
}

#[cfg(unix)]
fn install_termination(signals: &[i32]) -> std::io::Result<()> {
    let mut signals = signal_hook::iterator::Signals::new(signals)?;
    std::thread::Builder::new()
        .name("opentide-promotion-stop".into())
        .spawn(move || {
            if let Some(signal) = signals.forever().next() {
                restore_pending();
                let _ignored = signal_hook::low_level::emulate_default_handler(signal);
            }
        })?;
    Ok(())
}

#[cfg(all(test, unix))]
mod signal_tests {
    /// SIGTERM has its default action in a test process; SIGPIPE, which
    /// Rust's runtime ignores, does not.
    #[test]
    fn the_status_file_says_which_signals_keep_their_default() {
        if !std::path::Path::new("/proc/self/status").exists() {
            return;
        }
        assert_eq!(
            super::default_action(signal_hook::consts::SIGPIPE),
            Some(false)
        );
        assert_eq!(
            super::default_action(signal_hook::consts::SIGUSR2),
            Some(true)
        );
    }
}

/// How a promotion ended, when the run does not go on to plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The run fails with this message.
    Failed(String),
    /// The run exits 1 without a result (an invalid target).
    Exit,
}

/// One thing the promotion logs, in the order it happens.
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
                    tracing::info!(path, target, "{name}");
                }
                (_, _, Some(detail)) => tracing::info!(detail, "{name}"),
                _ => tracing::info!("{name}"),
            }
        }
    }
}

/// Logs `invalid_promotion_target` with the target: a number as one, a
/// string as it is, anything else as its JSON (`null` when no target is
/// set, `true`).
fn invalid_target(target: &Setting, detail: &str) {
    let event = "invalid_promotion_target";
    match target {
        Setting::Int(number) => {
            tracing::error!(target = number, detail, "{event}");
        }
        Setting::Float(number) => {
            tracing::error!(target = number, detail, "{event}");
        }
        other => {
            let text = setting_text(other);
            tracing::error!(target = text.as_str(), detail, "{event}");
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
/// step: the files it rewrote, held pending ([`pending`]), and `Ok` when the
/// run goes on to plan. A write that fails stops the run, and the files
/// written before it are among those returned, to put back.
pub fn run(promotion: &Promotion<'_>, lines: &Lines) -> (Vec<Promoted>, Result<(), Stop>) {
    let started = Instant::now();
    let (events, planned, mut ended) = plan(promotion);
    for event in &events {
        emit(event);
    }
    let mut promoted = Vec::new();
    if ended.is_none() {
        for (path, bytes, before) in planned {
            let (path, bytes) = (&path, &bytes);
            let written = Promoted {
                path: path.clone(),
                original: before.0,
                promoted: bytes.clone(),
                uuid: before.1,
            };
            // Pending before it is written, under the lock: a signal waits
            // for the write, then puts the file back.
            let mut held = pending();
            // The process is ending ([`restore_pending`] ran): nothing more
            // is written, and what was is back.
            if ENDING.load(std::sync::atomic::Ordering::SeqCst) {
                ended = Some(Stop::Failed("interrupted".to_owned()));
                break;
            }
            held.push(written.clone());
            // Through a temporary file beside it, the
            // rule's permission bits kept (#987).
            if let Err(error) = opentide_workspace::fs::write_atomically(path, bytes) {
                held.pop();
                ended = Some(Stop::Failed(format!("{}: {error}", path.display())));
                break;
            }
            drop(held);
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
            promoted.push(written);
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
    (promoted, ended.map_or(Ok(()), Err))
}

/// A file the promotion would rewrite: its path, its promoted bytes, and
/// its rule's canonical UUID.
pub type Previewed = (PathBuf, Vec<u8>, Option<String>);

/// What the promotion would write, without writing it or drawing its step
/// (the dry run's and the live gate's preview, #1653): each file's promoted
/// bytes. Its events are not logged: the run that promotes logs them.
///
/// # Errors
///
/// [`Stop`]: how a real run would end instead.
pub fn preview(promotion: &Promotion<'_>) -> Result<Vec<Previewed>, Stop> {
    let (_, planned, ended) = plan(promotion);
    match ended {
        Some(stop) => Err(stop),
        None => Ok(planned
            .into_iter()
            .map(|(path, bytes, (_, uuid))| (path, bytes, uuid))
            .collect()),
    }
}

/// What a [`Stop`] says, as a preview warns of it.
pub fn stop_text(stop: &Stop) -> String {
    match stop {
        Stop::Failed(message) => message.clone(),
        Stop::Exit => "Invalid promotion target".to_owned(),
    }
}

/// A file's original bytes and its rule's UUID.
type Before = (Vec<u8>, Option<String>);

type Planned = (Vec<Event>, Vec<(PathBuf, Vec<u8>, Before)>, Option<Stop>);

/// Every file read and planned, nothing written yet: the events to log, the
/// bytes to write, and how the run stops, if it does.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
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
    // A target must be a configured status: one that is not set, or not a
    // string, names no status either.
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
                let failed = Stop::Failed(format!("{}: {error}", path.display()));
                return (events, Vec::new(), Some(failed));
            }
        };
        // A file that does not read as YAML fails the run (UC-6.0d).
        let document = match node::load_bytes(&bytes) {
            Ok(document) => document,
            Err(error) => {
                let message = format!("{}: {}", path.display(), promotion::placed(&error));
                let failed = Stop::Failed(message);
                return (events, Vec::new(), Some(failed));
            }
        };
        let root = document.root().map(AsRef::as_ref);
        if let Err(message) = promotion::name_error(root) {
            let message = format!("{}: {message}", path.display());
            return (events, Vec::new(), Some(Stop::Failed(message)));
        }
        let name = root
            .and_then(|root| root.get("name"))
            .map(|name| match &name.value {
                node::Value::Str(text) => text.to_string(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        let blocks = root
            .map(|root| promotion::promotable(root, &settings.non_promotable))
            .unwrap_or_default();
        if blocks.is_empty() {
            events.push(Event::Info(
                "nothing_to_promote_rule_already_in_production_status",
                vec![("detail", name.clone())],
            ));
            continue;
        }
        events.push(Event::Info(
            "detected_statuses_needing_promotion_for_the_following_rule",
            vec![("detail", name.clone())],
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
                let uuid = root
                    .and_then(|root| root.get("metadata"))
                    .and_then(|metadata| metadata.get("uuid"))
                    .and_then(|uuid| match &uuid.value {
                        node::Value::Str(text) => {
                            Some(opentide_compile::rule::canonical_uuid(text.as_ref()))
                        }
                        _ => None,
                    });
                planned.push((path.clone(), out, (bytes.clone(), uuid)));
            }
            Err(Error::Refused(detail)) => events.push(Event::NotPromoted {
                path: path.display().to_string(),
                detail,
            }),
            Err(error @ (Error::Unreadable(_) | Error::NonStringKey(_))) => {
                let message = format!("{}: cannot promote its statuses: {error}", path.display());
                return (events, Vec::new(), Some(Stop::Failed(message)));
            }
        }
    }
    (events, planned, None)
}

/// The result of a run the promotion stopped: failed, exit 1; an invalid
/// target ends the run with its exit code alone.
pub fn stopped(stop: &Stop) -> CommandResult {
    match stop {
        Stop::Failed(message) => CommandResult::failed(message, ExitCode::Failure),
        Stop::Exit => CommandResult {
            bare_exit: true,
            ..CommandResult::failed("Invalid promotion target", ExitCode::Failure)
        },
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
        (outcome.1, drawn, after)
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
        assert!(outcome.is_ok(), "{outcome:?}");
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
            opentide_workspace::fs::write_atomically(&path, b"y").unwrap();
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
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(after[0], RULE.as_bytes());
        assert!(drawn.contains("✓ status promotion · 1 rule"), "{drawn}");
        let (outcome, drawn, _) = promote(&settings(true, "PRODUCTION"), &[], false, false);
        assert!(outcome.is_ok(), "{outcome:?}");
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
        assert!(outcome.is_ok(), "{outcome:?}");
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
        assert!(result.bare_exit);
        let report = result.report("deploy");
        assert!(report.bare_exit);
        assert_eq!(report.outcome.exit_code, 1);
    }

    #[test]
    fn a_rule_without_a_name_fails_the_run_and_nothing_is_written() {
        let (outcome, _, after) = promote(
            &settings(true, "PRODUCTION"),
            &[("a.yaml", RULE.as_bytes()), ("b.yaml", b"title: x\n")],
            false,
            false,
        );
        let Err(Stop::Failed(message)) = outcome else {
            panic!("{outcome:?}");
        };
        assert!(message.ends_with("b.yaml: rule has no name"), "{message}");
        assert_eq!(after[0], RULE.as_bytes());
        let (outcome, _, _) = promote(
            &settings(true, "PRODUCTION"),
            &[("a.yaml", b"")],
            false,
            false,
        );
        let Err(Stop::Failed(message)) = outcome else {
            panic!("{outcome:?}");
        };
        assert!(
            message.ends_with("a.yaml: rule file is empty, not a mapping with a name"),
            "{message}"
        );
        let result = stopped(&Stop::Failed("b.yaml: rule has no name".into()));
        assert_eq!(result.message.as_deref(), Some("b.yaml: rule has no name"));
        assert!(!result.bare_exit);
    }

    /// A rule file that is not YAML, or whose root is no mapping, fails the
    /// run naming the file, and nothing is written (UC-6.0d).
    #[test]
    fn a_file_that_does_not_read_or_is_no_mapping_fails_the_run() {
        for (bytes, expected) in [
            (&b"name: [\n"[..], None),
            (b"\xff\n", None),
            (
                b"just text\n",
                Some("b.yaml: rule file holds a string, not a mapping with a name"),
            ),
            (
                b"42\n",
                Some("b.yaml: rule file holds an integer, not a mapping with a name"),
            ),
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
                Some(expected) => assert!(message.ends_with(expected), "{message}"),
                None => assert!(message.contains("b.yaml: "), "{bytes:?}: {message}"),
            }
            assert!(drawn.contains("status promotion"), "{drawn}");
            assert_eq!(after, [RULE.as_bytes(), bytes]);
        }
    }

    /// No target, or one that is not a string, names no status: the run
    /// exits 1 as for any invalid target, nothing written.
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

    /// A promoted block whose key is not a string fails the run, naming the
    /// file and the key, nothing written; the other file is not promoted.
    #[test]
    fn a_promoted_block_whose_key_is_not_a_string_fails_the_run() {
        let keyed = RULE.replace("  splunk:\n", "  1:\n");
        let (outcome, _, after) = promote(
            &settings(true, "PRODUCTION"),
            &[("a.yaml", RULE.as_bytes()), ("b.yaml", keyed.as_bytes())],
            false,
            false,
        );
        let Err(Stop::Failed(message)) = outcome else {
            panic!("{outcome:?}");
        };
        assert!(
            message.ends_with(
                "b.yaml: cannot promote its statuses: configurations.1 is not a string key \
                 (quote the platform name)"
            ),
            "{message}"
        );
        assert_eq!(after, [RULE.as_bytes(), keyed.as_bytes()]);
    }

    /// Promoted text that does not read back fails the run, naming the
    /// file; nothing is written.
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
        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(after[0], anchored.as_bytes());
    }

    /// A promoted file is put back only while it holds what the promotion
    /// wrote: a file edited since is left as it is, and a deleted one is not
    /// made again (#1653).
    #[test]
    fn a_restore_puts_back_only_what_the_promotion_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.yaml");
        std::fs::write(&path, "promoted").unwrap();
        let file = Promoted {
            path: path.clone(),
            original: b"original".to_vec(),
            promoted: b"promoted".to_vec(),
            uuid: None,
        };
        assert_eq!(file.restore(), Ok(Restored::Done));
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        // Put back already (a signal's restore, then the run's).
        assert_eq!(file.restore(), Ok(Restored::Done));
        std::fs::write(&path, "edited").unwrap();
        assert_eq!(file.restore(), Ok(Restored::Edited));
        assert_eq!(std::fs::read(&path).unwrap(), b"edited");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(file.restore(), Ok(Restored::Missing));
        assert!(!path.exists());
    }

    /// A write that fails part-way stops the run and returns the files
    /// written before it, so the deploy puts them back (#1653). A folder the
    /// user cannot write refuses the temporary file; a privileged user
    /// writes there all the same, and the test then has nothing to show.
    #[cfg(unix)]
    #[test]
    fn a_write_that_fails_part_way_returns_the_files_written_before_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (open, shut) = (dir.path().join("1"), dir.path().join("2"));
        let paths = vec![open.join("a.yaml"), shut.join("b.yaml")];
        for path in &paths {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, RULE).unwrap();
        }
        let mode = |bits| std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(bits));
        mode(0o555).unwrap();
        if std::fs::write(shut.join("probe"), "").is_ok() {
            mode(0o755).unwrap();
            eprintln!("skipped: this user writes a read-only folder");
            return;
        }
        let (written, outcome) = run(
            &Promotion {
                settings: &settings(true, "PRODUCTION"),
                changed: &paths,
                local: &paths,
                debug: false,
            },
            &lines(&Buffer::default(), false),
        );
        mode(0o755).unwrap();
        settle(&written);
        let Err(Stop::Failed(message)) = outcome else {
            panic!("{outcome:?}");
        };
        assert!(message.contains("b.yaml"), "{message}");
        assert_eq!(written.len(), 1, "{written:?}");
        assert_eq!(written[0].path, paths[0]);
        assert_eq!(written[0].original, RULE.as_bytes());
        assert_eq!(
            std::fs::read(&paths[0]).unwrap(),
            RULE.replace("STAGING", "PRODUCTION").into_bytes()
        );
    }
}
