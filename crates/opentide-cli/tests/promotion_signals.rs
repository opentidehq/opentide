//! A deploy's pending promoted files when the process ends at once (#1653):
//! a second Ctrl-C puts them back, never blocks against a run that holds
//! them, and stops the promotion from writing another. A test binary of its
//! own: the pending files and the process's ending are the process's.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use opentide_cli::app::{Interrupt, on_ctrl_c};
use opentide_cli::commands::deploy_promote::{self, Promoted, Promotion, Stop};
use opentide_cli::commands::deploy_send::Lines;
use opentide_cli::render::outcome::Console;
use opentide_cli::render::text::Colour;
use opentide_compile::json::Json;
use opentide_compile::promotion::Settings;

const STAGING: &str = "name: R\nconfigurations:\n  splunk:\n    status: STAGING\n    query: x\n";

/// One test at a time: they share the pending files and the ending.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A promoted file, pending, in *dir*.
fn pending_file(dir: &std::path::Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let promoted = STAGING.replace("STAGING", "PRODUCTION");
    std::fs::write(&path, &promoted).unwrap();
    deploy_promote::pending().push(Promoted {
        path: path.clone(),
        original: STAGING.as_bytes().to_vec(),
        promoted: promoted.into_bytes(),
        uuid: None,
    });
    path
}

/// A second Ctrl-C puts the pending files back before the process ends.
#[test]
fn a_second_ctrl_c_puts_the_pending_promotions_back() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    let path = pending_file(dir.path(), "a.yaml");
    let interrupt = Interrupt::default();
    assert_eq!(
        on_ctrl_c(&interrupt),
        None,
        "the first only asks the run to stop"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        STAGING.replace("STAGING", "PRODUCTION")
    );
    assert_eq!(on_ctrl_c(&interrupt), Some(130));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), STAGING);
}

/// A second Ctrl-C while the run holds the pending files (putting them
/// back, about to log) never blocks the run from logging: the handler
/// releases stderr before it waits for them.
#[test]
fn a_second_ctrl_c_never_blocks_a_run_that_holds_the_pending_files() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    let path = pending_file(dir.path(), "b.yaml");
    let interrupt = Interrupt::default();
    interrupt.request();
    // The run holds the pending files...
    let held = deploy_promote::pending();
    let handler = {
        let interrupt = interrupt.clone();
        std::thread::spawn(move || on_ctrl_c(&interrupt))
    };
    std::thread::sleep(Duration::from_millis(200));
    // ... and logs, which takes stderr.
    let (done, wrote) = mpsc::channel();
    let logger = std::thread::spawn(move || {
        let _err = std::io::stderr().lock();
        let _ = done.send(());
    });
    let in_time = wrote.recv_timeout(Duration::from_secs(5));
    drop(held);
    logger.join().unwrap();
    assert_eq!(handler.join().unwrap(), Some(130));
    assert!(
        in_time.is_ok(),
        "the run could not log while the handler waited"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), STAGING);
}

/// Once the pending files are put back for the process's end, the
/// promotion writes nothing more.
#[test]
fn a_promotion_writes_nothing_once_the_process_is_ending() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.yaml");
    std::fs::write(&path, STAGING).unwrap();
    deploy_promote::restore_pending();
    let settings = Settings {
        enabled: true,
        target: Some("PRODUCTION".into()),
        target_value: Json::Str("PRODUCTION".into()),
        valid: vec!["STAGING".into(), "PRODUCTION".into()],
        non_promotable: vec!["PRODUCTION".into()],
    };
    let paths = vec![path.clone()];
    let lines = Lines {
        sink: std::sync::Arc::new(std::sync::Mutex::new(std::io::sink())),
        console: Console {
            colour: Colour::None,
            width: None,
        },
        silent: true,
        quiet: true,
        progress: false,
        terminal: false,
        live: None,
    };
    let (written, outcome) = deploy_promote::run(
        &Promotion {
            settings: &settings,
            changed: &paths,
            local: &paths,
            debug: false,
        },
        &lines,
    );
    assert!(written.is_empty(), "{written:?}");
    assert!(matches!(outcome, Err(Stop::Failed(_))), "{outcome:?}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), STAGING);
}
