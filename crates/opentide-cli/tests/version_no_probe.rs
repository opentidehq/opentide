//! `opentide --version` checks nothing (#1072): it prints the version and
//! touches no file and no network on the way. Held by tracing the binary's
//! file and network system calls with `strace` where it is installed (Linux;
//! elsewhere the test says it was skipped).

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
    let strace = Command::new("strace").arg("-V").output();
    if !strace.is_ok_and(|out| out.status.success()) {
        eprintln!("skipped: strace is not installed");
        return;
    }
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
                network || !(quoted.is_empty() || runtime_path(quoted) || quoted == binary)
            })
            .collect();
        assert!(
            probes.is_empty(),
            "{flag}: {probes:#?}\n{}",
            stacks(binary, flag, dir.path(), &probes)
        );
    }
}
