//! The `cli` fuzz target's seeds and saved crashes (`fuzz/seeds/cli`,
//! `fuzz/regressions/cli`), replayed on stable Rust: each is `\0`-separated
//! arguments, and none may crash the run (`error[internal]`) or exit with
//! anything but 0, 1 or 2. The loop is `fuzz/src/lib.rs::cli`'s.

#![expect(
    clippy::unwrap_used,
    reason = "a test helper: an unreadable seed is a failure"
)]

use opentide_cli::env::Env;
use opentide_cli::{Host, run};
use std::path::Path;
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

fn replay(data: &[u8]) -> (i32, String) {
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
        cwd: None,
        width: None,
    };
    let mut out = Vec::new();
    let code = run(&argv, &Env::default(), &host, &mut out, &mut err.clone());
    let stderr = String::from_utf8(err.0.lock().unwrap().clone()).unwrap();
    (code, stderr)
}

#[test]
fn framework_fuzz_seeds_and_regressions_do_not_crash() {
    let fuzz = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let mut ran = 0;
    for dir in ["seeds/cli", "regressions/cli"] {
        let Ok(entries) = std::fs::read_dir(fuzz.join(dir)) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let (code, stderr) = replay(&std::fs::read(&path).unwrap());
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
        let (code, stderr) = replay(data);
        assert!(!stderr.contains("error[internal]"), "{data:?}: {stderr}");
        assert!(matches!(code, 0..=2), "{data:?}: exit {code}");
    }
}

/// Every word the tree knows, and a few it does not, in random order: a
/// deterministic sweep on stable Rust beside the fuzz target.
#[test]
fn framework_fuzz_random_command_lines_do_not_crash() {
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
    for _ in 0..3000 {
        let count = usize::try_from(next() % 7).unwrap();
        let line: Vec<u8> = (0..count)
            .map(|_| words[usize::try_from(next()).unwrap() % words.len()].clone())
            .collect::<Vec<_>>()
            .join("\0")
            .into_bytes();
        let (code, stderr) = replay(&line);
        assert!(!stderr.contains("error[internal]"), "{line:?}: {stderr}");
        assert!(matches!(code, 0..=2), "{line:?}: exit {code}");
    }
}
