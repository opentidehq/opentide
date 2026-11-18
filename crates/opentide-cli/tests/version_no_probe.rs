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
            .args(["-f", "-qq", "-e", "trace=%file,%network", "-o"])
            .arg(&log)
            .arg(binary)
            .arg(flag)
            .current_dir(dir.path())
            .env_clear()
            .env("HOME", dir.path())
            .env("PWD", dir.path())
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(
            stdout.starts_with("opentide ") && stdout.ends_with('\n'),
            "{stdout}"
        );
        let trace = std::fs::read_to_string(&log).unwrap();
        let probes: Vec<&str> = trace
            .lines()
            .filter(|line| !line.contains("execve("))
            .filter(|line| {
                let quoted = line.split('"').nth(1).unwrap_or_default();
                let network = ["socket(", "connect(", "bind(", "sendto("]
                    .iter()
                    .any(|call| line.contains(call));
                network || !(quoted.is_empty() || runtime_path(quoted) || quoted == binary)
            })
            .collect();
        assert!(probes.is_empty(), "{flag}: {probes:#?}");
    }
}
