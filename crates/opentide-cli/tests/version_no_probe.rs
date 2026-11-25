//! `opentide --version` checks nothing (#1072): it prints the version and
//! touches no file and no network on the way. Held by tracing the binary's
//! file and network system calls with Linux's `strace` where it is installed
//! (elsewhere the test says it was skipped: Git for Windows ships a Cygwin
//! `strace` of the same name, which traces Win32 debug events and takes none
//! of these options).

use std::process::Command;

/// The paths the dynamic loader and the C runtime read before `main`, which
/// no opentide code chooses.
fn runtime_path(path: &str) -> bool {
    [
        "/etc/ld.so",
        "/lib",
        "/usr/lib",
        "/lib64",
        "/usr/lib64",
        "/proc/self/",
        "/sys/",
        "/dev/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
        // glibc's malloc reads it when it trims a heap (`malloc/arena.c`,
        // `check_may_shrink_heap`, glibc 2.39): the allocator on a `free`,
        // not a file opentide reads (seen on CI's runners, #1591).
        || path == "/proc/sys/vm/overcommit_memory"
}

/// The LLVM profile a coverage build (`-C instrument-coverage`, which
/// `cargo llvm-cov` sets with `LLVM_PROFILE_FILE`) writes when it exits:
/// the profiler runtime's file, not one opentide reads. The child's
/// environment is cleared, so the runtime falls back to its default name,
/// `default_<signature>_<n>_<pid>.profraw` in the working directory.
fn profile_output(path: &str, instrumented: bool) -> bool {
    instrumented
        && std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("default_") && name.ends_with(".profraw"))
}

/// Whether `strace` is Linux's: its version line is `strace -- version N`.
fn linux_strace() -> bool {
    Command::new("strace").arg("-V").output().is_ok_and(|out| {
        out.status.success()
            && String::from_utf8_lossy(&out.stdout).starts_with("strace -- version")
    })
}

/// Each call in `probes` with its stack, from `strace -k` (where strace has
/// it), so that a failure names the component that made the call.
fn stacks(binary: &str, flag: &str, dir: &std::path::Path, probes: &[&str]) -> String {
    let log = dir.join("stacks.log");
    let ran = Command::new("strace")
        .args([
            "-f",
            "-qq",
            "-k",
            "-s",
            "4096",
            "-e",
            "trace=%file,%network,getcwd",
            "-o",
        ])
        .arg(&log)
        .arg(binary)
        .arg(flag)
        .current_dir(dir)
        .env_clear()
        .env("HOME", dir)
        .env("PWD", dir)
        .output();
    let Ok(trace) = ran.and_then(|_| std::fs::read_to_string(&log)) else {
        return "(no stacks: strace -k did not run)".to_owned();
    };
    // A call's line, then its frames (` > ...`).
    let mut out = String::new();
    let mut keep = false;
    for line in trace.lines() {
        if line.starts_with(" > ") {
            if keep {
                out.push_str(line);
                out.push('\n');
            }
        } else {
            keep = probes.iter().any(|probe| {
                let call = probe.split_once(' ').map_or(*probe, |(_, call)| call);
                line.contains(call.split(" = ").next().unwrap_or(call))
            });
            if keep {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

#[test]
fn the_version_touches_no_file_and_no_network() {
    if !linux_strace() {
        eprintln!("skipped: Linux's strace is not installed");
        return;
    }
    let instrumented = std::env::var_os("LLVM_PROFILE_FILE").is_some();
    let binary = env!("CARGO_BIN_EXE_opentide-cli");
    let dir = tempfile::tempdir().unwrap();
    // A workspace a probe would find, and a home it could read.
    std::fs::create_dir_all(dir.path().join(".opentide/configurations")).unwrap();
    let log = dir.path().join("trace.log");
    for flag in ["--version", "-V"] {
        let out = Command::new("strace")
            // Whole strings (strace cuts them at 32 bytes), and the working
            // directory's lookup, which is no `%file` call.
            .args([
                "-f",
                "-qq",
                "-s",
                "4096",
                "-e",
                "trace=%file,%network,getcwd",
                "-o",
            ])
            .arg(&log)
            .arg(binary)
            .arg(flag)
            .current_dir(dir.path())
            .env_clear()
            .env("HOME", dir.path())
            .env("PWD", dir.path())
            .output()
            .unwrap();
        if !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("ptrace") {
            eprintln!("skipped: strace may not trace here (ptrace is denied)");
            return;
        }
        assert!(out.status.success(), "{out:?}");
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(
            stdout.starts_with("opentide ") && stdout.ends_with('\n'),
            "{stdout}"
        );
        let trace = std::fs::read_to_string(&log).unwrap();
        // The trace is the binary's: its start, at least, is in it.
        assert!(trace.contains("execve("), "an empty trace: {trace:?}");
        let probes: Vec<&str> = trace
            .lines()
            .filter(|line| !line.contains("execve("))
            .filter(|line| {
                let quoted = line.split('"').nth(1).unwrap_or_default();
                let network = ["socket(", "connect(", "bind(", "sendto(", "getcwd("]
                    .iter()
                    .any(|call| line.contains(call));
                network
                    || !(quoted.is_empty()
                        || runtime_path(quoted)
                        || profile_output(quoted, instrumented)
                        || quoted == binary)
            })
            .collect();
        assert!(
            probes.is_empty(),
            "{flag}: {probes:#?}\n{}",
            stacks(binary, flag, dir.path(), &probes)
        );
    }
}

#[test]
fn only_an_instrumented_runs_default_profile_is_the_profilers() {
    // The file a coverage run's `--version` opened (#1751).
    let profile = "default_4551761045566378340_0_31847.profraw";
    assert!(profile_output(profile, true));
    assert!(profile_output(&format!("/tmp/x/{profile}"), true));
    assert!(!profile_output(profile, false));
    assert!(!profile_output(
        ".opentide/configurations/default.toml",
        true
    ));
    assert!(!profile_output("custom.profraw", true));
}
