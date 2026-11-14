//! The `cli` fuzz target's seeds and saved crashes (`fuzz/seeds/cli`,
//! `fuzz/regressions/cli`), replayed on stable Rust: each is `\0`-separated
//! arguments, and none may crash the run (`error[internal]`) or exit with
//! anything but 0, 1 or 2. The loop is `fuzz/src/lib.rs::cli`'s.
//!
//! Each test runs its command lines in a temporary folder of its own: a line
//! such as `generate docs` writes files where it runs, and never in the source
//! tree (#931). The tests that replay arbitrary lines run them in a child of
//! the test binary whose stdin is closed, within a time limit: a line can be a
//! server on stdio (`with_stdin_closed`).

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: an unreadable seed is a failure"
)]

use opentide_cli::env::Env;
use opentide_cli::{Host, run};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;

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

/// The folder a test's command lines run in.
fn scratch() -> TempDir {
    tempfile::tempdir().unwrap()
}

/// Runs `data` as `opentide`'s arguments with `cwd` as the working directory.
fn replay(data: &[u8], cwd: &Path) -> (i32, String) {
    let argv: Vec<String> = data
        .split(|b| *b == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let err = Buffer::default();
    let host = Host {
        version: "0.0.0".into(),
        stdout_tty: false,
        stderr_tty: false,
        log_sink: Arc::new(Mutex::new(err.clone())),
        cwd: Some(cwd.to_path_buf()),
        width: None,
        interrupt: opentide_cli::app::Interrupt::default(),
    };
    let mut out = Vec::new();
    let code = run(&argv, &Env::default(), &host, &mut out, &mut err.clone());
    let stderr = String::from_utf8(err.0.lock().unwrap().clone()).unwrap();
    (code, stderr)
}

/// Set in the child [`with_stdin_closed`] starts: the test runs its body.
const CHILD: &str = "OPENTIDE_FUZZ_REGRESSIONS_CHILD";

/// How long a test of arbitrary command lines may take, in a debug build.
const LIMIT: Duration = Duration::from_secs(600);

/// Runs `body`, the test `name`, in a child of this test binary whose stdin
/// is closed, and fails if it has not finished within [`LIMIT`].
///
/// An arbitrary command line can be a server on stdio (`serve`, `mcp start`,
/// `lsp start`), which serves the process's own stdin until it closes.
/// nextest and the fuzzer give a test `/dev/null`, but `cargo test` passes on
/// the shell's stdin, and an open pipe (an agent's shell, a CI step) never
/// closes: the test hung for good. In the child, stdin ends at once.
fn with_stdin_closed(name: &str, body: impl FnOnce()) {
    if std::env::var_os(CHILD).is_some() {
        body();
        return;
    }
    let output = tempfile::tempfile().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .stdin(Stdio::null())
        .stdout(output.try_clone().unwrap())
        .stderr(output.try_clone().unwrap())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if started.elapsed() > LIMIT {
            let _ignored = child.kill();
            let _ignored = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let printed = {
        use std::io::{Read, Seek};
        let mut output = output;
        let mut printed = String::new();
        output.rewind().unwrap();
        let _ignored = output.read_to_string(&mut printed);
        printed
    };
    match status {
        Some(status) => assert!(status.success(), "{name} failed:\n{printed}"),
        None => panic!("{name} did not finish within {LIMIT:?}:\n{printed}"),
    }
}

#[test]
fn framework_fuzz_seeds_and_regressions_do_not_crash() {
    with_stdin_closed(
        "framework_fuzz_seeds_and_regressions_do_not_crash",
        seeds_and_regressions,
    );
}

fn seeds_and_regressions() {
    let fuzz = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let cwd = scratch();
    let mut ran = 0;
    for dir in ["seeds/cli", "regressions/cli"] {
        let Ok(entries) = std::fs::read_dir(fuzz.join(dir)) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let (code, stderr) = replay(&std::fs::read(&path).unwrap(), cwd.path());
            assert!(
                !stderr.contains("error[internal]"),
                "{}: {stderr}",
                path.display()
            );
            assert!(matches!(code, 0..=2), "{}: exit {code}", path.display());
            ran += 1;
        }
    }
    assert!(ran >= 10, "the seeds ran");
}

#[test]
fn framework_fuzz_odd_arguments_do_not_crash() {
    let cwd = scratch();
    for data in [
        &b""[..],
        b"\0",
        b"--\0--",
        b"--repo",
        b"--repo=",
        b"-",
        b"--json\0--json\0commands\0--json",
        b"\xff\xfe",
        b"setup\0ci\0GITHUB\0--plan",
        b"query\0--platform=\0x",
        b"--proxy\0http://u:p@h\0commands",
    ] {
        let (code, stderr) = replay(data, cwd.path());
        assert!(!stderr.contains("error[internal]"), "{data:?}: {stderr}");
        assert!(matches!(code, 0..=2), "{data:?}: exit {code}");
    }
}

/// Every word the tree knows, and a few it does not, in random order: a
/// deterministic sweep on stable Rust beside the fuzz target.
#[test]
fn framework_fuzz_random_command_lines_do_not_crash() {
    with_stdin_closed(
        "framework_fuzz_random_command_lines_do_not_crash",
        random_command_lines,
    );
}

fn random_command_lines() {
    let root = opentide_cli::catalog::root();
    let mut words: Vec<String> = vec![
        "--".into(),
        "-".into(),
        "x".into(),
        "=".into(),
        "--json".into(),
        "-V".into(),
        "--help".into(),
        "7".into(),
        "sentinel".into(),
    ];
    for entry in opentide_cli::catalog::entries(&root) {
        words.push(entry.command.get_name().to_owned());
        for arg in entry.command.get_arguments() {
            words.extend(opentide_cli::catalog::flags(arg));
            words.extend(
                arg.get_possible_values()
                    .iter()
                    .map(|value| value.get_name().to_owned()),
            );
        }
    }
    words.sort();
    words.dedup();
    // xorshift64*: the same lines on every run.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let cwd = scratch();
    for _ in 0..3000 {
        let count = usize::try_from(next() % 7).unwrap();
        let line: Vec<u8> = (0..count)
            .map(|_| words[usize::try_from(next()).unwrap() % words.len()].clone())
            .collect::<Vec<_>>()
            .join("\0")
            .into_bytes();
        let (code, stderr) = replay(&line, cwd.path());
        assert!(!stderr.contains("error[internal]"), "{line:?}: {stderr}");
        assert!(matches!(code, 0..=2), "{line:?}: exit {code}");
    }
}

/// A replayed line writes under its test's temporary folder: `generate docs`
/// once wrote `crates/opentide-cli/docs/` from the crate folder, where cargo
/// runs the tests (#931).
#[test]
fn framework_fuzz_lines_write_in_their_temporary_folder() {
    let cwd = scratch();
    let (code, stderr) = replay(b"generate\0docs", cwd.path());
    assert_eq!(code, 0, "{stderr}");
    assert!(cwd.path().join("docs/README.md").is_file(), "{stderr}");
}
