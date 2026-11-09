//! Running a command as a fresh process and measuring it: wall time around
//! the spawn and the wait, and the peak RSS `wait4(2)` reports.
//!
//! Every run is a new process with an environment of its own (an empty
//! `HOME`, no inherited variables but `PATH`, proxies that lead nowhere), in a
//! fresh copy of the workspace: nothing a previous run wrote (caches,
//! generated files, `.opentide/` state) can make the next one faster. The
//! operating system's file cache is the one thing a run inherits; dropping it
//! needs root, so a warm-up run first gives every measured run the same cache.

use crate::bench::report::Sample;
use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use wait4::Wait4;

/// `XTASK_BENCH_INJECT_SLEEP_MS`: a test-only slowdown. When set, every
/// measured run's wall time includes this many more milliseconds (a sleep
/// after the process exits, inside the timed window), as a slower command
/// would. The tests use it to
/// prove that a slowdown fails the budget check; nothing else sets it, and a
/// report of a run with it set says so in its notes.
pub const INJECT_SLEEP_ENV: &str = "XTASK_BENCH_INJECT_SLEEP_MS";

/// An address no proxy listens on: a command that tries the network fails
/// at once instead of reaching a tenant (`deploy --dry-run` must not).
pub const DEAD_PROXY: &str = "http://127.0.0.1:9";

/// The injected sleep, if `XTASK_BENCH_INJECT_SLEEP_MS` asks for one.
pub fn injected_sleep() -> Result<Option<Duration>> {
    match std::env::var(INJECT_SLEEP_ENV) {
        Ok(text) if text.trim().is_empty() => Ok(None),
        Ok(text) => {
            let ms: u64 = text
                .trim()
                .parse()
                .with_context(|| format!("{INJECT_SLEEP_ENV}={text} is not milliseconds"))?;
            Ok((ms > 0).then(|| Duration::from_millis(ms)))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => bail!("{INJECT_SLEEP_ENV}: {err}"),
    }
}

/// Where one run happens: a fresh directory holding the workspace copy, the
/// empty home and the captured output.
#[derive(Debug)]
pub struct RunDir {
    /// The run's root.
    pub root: PathBuf,
    /// The workspace copy the command runs in.
    pub workspace: PathBuf,
    /// The command's `HOME`.
    pub home: PathBuf,
    /// Its captured standard output.
    pub stdout: PathBuf,
    /// Its captured standard error.
    pub stderr: PathBuf,
}

impl RunDir {
    /// Clears `root` and copies `workspace` (if any) into it.
    pub fn prepare(root: &Path, workspace: Option<&Path>) -> Result<Self> {
        if root.exists() {
            std::fs::remove_dir_all(root).with_context(|| format!("remove {}", root.display()))?;
        }
        let run = Self {
            root: root.to_owned(),
            workspace: root.join("workspace"),
            home: root.join("home"),
            stdout: root.join("stdout.txt"),
            stderr: root.join("stderr.txt"),
        };
        std::fs::create_dir_all(&run.home)
            .with_context(|| format!("create {}", run.home.display()))?;
        match workspace {
            Some(source) => copy_tree(source, &run.workspace)?,
            None => std::fs::create_dir_all(&run.workspace)
                .with_context(|| format!("create {}", run.workspace.display()))?,
        }
        Ok(run)
    }

    /// The command's captured standard output.
    pub fn read_stdout(&self) -> Result<String> {
        std::fs::read_to_string(&self.stdout)
            .with_context(|| format!("read {}", self.stdout.display()))
    }

    /// The last lines of its standard error, for an error message.
    pub fn stderr_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.stderr).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(20)..].join("\n")
    }
}

/// Copies a directory tree: directories and regular files (symbolic links
/// are copied as the files they point to).
pub fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    std::fs::create_dir_all(target).with_context(|| format!("create {}", target.display()))?;
    for entry in std::fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry?;
        let from = entry.path();
        let to = target.join(entry.file_name());
        if std::fs::metadata(&from)?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)
                .with_context(|| format!("copy {} to {}", from.display(), to.display()))?;
        }
    }
    Ok(())
}

/// A command in the benchmark's environment: run in `run.workspace`, with
/// `HOME` and the XDG directories in `run.home`, `PATH` from this process and
/// nothing else inherited, every proxy at [`DEAD_PROXY`], stdin empty and the
/// output captured to files (a pipe nobody reads could block it).
pub fn command(program: &Path, args: &[OsString], run: &RunDir) -> Result<Command> {
    let mut command = Command::new(program);
    command.args(args).current_dir(&run.workspace).env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("HOME", &run.home)
        .env("XDG_CONFIG_HOME", run.home.join(".config"))
        .env("XDG_CACHE_HOME", run.home.join(".cache"))
        .env("XDG_DATA_HOME", run.home.join(".local/share"))
        .env("XDG_STATE_HOME", run.home.join(".local/state"))
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
        // The bytecode the oracle's install compiled is what runs; a run
        // must not write more for the next one.
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONHASHSEED", "0");
    for proxy in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "OPENTIDE_PROXY",
    ] {
        command.env(proxy, DEAD_PROXY);
    }
    command.env("NO_PROXY", "").env("no_proxy", "");
    command.stdin(Stdio::null());
    command.stdout(
        std::fs::File::create(&run.stdout)
            .with_context(|| format!("create {}", run.stdout.display()))?,
    );
    command.stderr(
        std::fs::File::create(&run.stderr)
            .with_context(|| format!("create {}", run.stderr.display()))?,
    );
    Ok(command)
}

/// What one measured process did.
#[derive(Clone, Copy, Debug)]
pub struct Measured {
    /// Its wall time and peak RSS.
    pub sample: Sample,
    /// Its exit code; `None` when a signal ended it.
    pub exit_code: Option<i32>,
    /// xtask's own peak RSS at the spawn: the floor under the measured one
    /// ([`own_peak_rss`], [`distinct_from_own`]).
    pub own_peak_rss: Option<u64>,
}

/// Spawns `command`, waits for it with `wait4(2)`, and measures it: the wall
/// time from before the spawn to after the wait, and the peak RSS of the
/// process and the children it waited for. `inject` sleeps inside the timed
/// window ([`INJECT_SLEEP_ENV`]).
pub fn run(command: &mut Command, inject: Option<Duration>) -> Result<Measured> {
    let own_peak_rss = own_peak_rss();
    let start = Instant::now();
    let child = command
        .spawn()
        .with_context(|| format!("spawn {:?}", command.get_program()))?;
    let usage = child.wait4().context("wait4")?;
    // After the wait, not during it: a sleep that overlapped the child would
    // add nothing to a command that runs longer than the sleep.
    if let Some(sleep) = inject {
        std::thread::sleep(sleep);
    }
    let wall = start.elapsed();
    Ok(Measured {
        sample: Sample {
            wall_s: wall.as_secs_f64(),
            peak_rss_bytes: usage.rusage.maxrss,
        },
        exit_code: usage.status.code(),
        own_peak_rss,
    })
}

/// This process's own peak RSS (`VmHWM` in `/proc/self/status`), in bytes;
/// `None` where there is no `/proc`.
///
/// On Linux a child's `ru_maxrss` is the larger of its own peak and the
/// spawning process's peak at the spawn: `exec` records the high-water mark
/// of the memory the child shared with its parent until then. A measured
/// peak at or under xtask's own is that floor, not the command's.
pub fn own_peak_rss() -> Option<u64> {
    // Reset the high-water mark to the current RSS first (`clear_refs` 5):
    // what xtask held earlier (the generated corpus, at scale 10 about
    // 110 MiB) is gone and must not raise the floor of every later run.
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<u64>()
        .ok()?;
    Some(kb * 1024)
}

/// Refuses a measured peak RSS that does not exceed xtask's own: it could be
/// the floor [`own_peak_rss`] describes, and the command's own peak unknown.
pub fn distinct_from_own(measured: u64, own: Option<u64>) -> Result<()> {
    match own {
        Some(own) if measured <= own => bail!(
            "the measured peak RSS ({} KiB) does not exceed xtask's own ({} KiB), so it may \
             be xtask's, not the command's",
            measured / 1024,
            own / 1024
        ),
        _ => Ok(()),
    }
}

/// Waits for a child that was spawned elsewhere (the language server, whose
/// time ends at its first diagnostics, not at its exit) and returns its peak
/// RSS and exit code.
pub fn reap(child: Child) -> Result<(u64, Option<i32>)> {
    let usage = child.wait4().context("wait4")?;
    Ok((usage.rusage.maxrss, usage.status.code()))
}

/// [`reap`] with a deadline: a child still running at `deadline` is killed
/// (and reaped), and the result is an error rather than a wait forever.
pub fn reap_by(mut child: Child, deadline: Instant) -> Result<(u64, Option<i32>)> {
    loop {
        if let Some(usage) = child.try_wait4().context("wait4")? {
            return Ok((usage.rusage.maxrss, usage.status.code()));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = reap(child);
            bail!("the process did not exit in time and was killed");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("xtask-bench-measure-{name}-{}", std::process::id()))
    }

    #[test]
    fn a_run_reports_its_exit_code_wall_time_and_rss() {
        let root = scratch("exit");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let mut command = command(
            Path::new("sh"),
            &["-c".into(), "echo hi; exit 3".into()],
            &run_dir,
        )
        .unwrap();
        let measured = run(&mut command, None).unwrap();
        assert_eq!(measured.exit_code, Some(3));
        assert!(measured.sample.wall_s > 0.0);
        assert!(measured.sample.peak_rss_bytes > 0, "wait4 reported no RSS");
        assert_eq!(run_dir.read_stdout().unwrap(), "hi\n");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_peak_rss_is_the_child_not_this_process() {
        // A child that touches 64 MiB more than this process holds has a
        // peak RSS above that; wait4 counts the grandchild `sh` waits for.
        let root = scratch("rss");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let own = own_peak_rss().unwrap();
        let mib = own / (1024 * 1024) + 64;
        let mut big = command(
            Path::new("sh"),
            &[
                "-c".into(),
                format!("dd if=/dev/zero of=/dev/null bs={mib}M count=1 2>/dev/null; true").into(),
            ],
            &run_dir,
        )
        .unwrap();
        let big = run(&mut big, None).unwrap().sample.peak_rss_bytes;
        assert!(big > mib * 1024 * 1024, "big child: {big} bytes, own {own}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_peak_rss_under_xtasks_own_is_reported_as_such() {
        // `sh -c true` peaks far below this test process: what wait4 reports
        // is this process's high-water mark, and the guard says so.
        let root = scratch("floor");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let ballast = vec![1u8; 48 << 20];
        std::hint::black_box(&ballast);
        let mut small = command(Path::new("sh"), &["-c".into(), "true".into()], &run_dir).unwrap();
        let measured = run(&mut small, None).unwrap();
        let own = measured.own_peak_rss.unwrap();
        assert!(own >= 48 << 20, "{own}");
        let error = distinct_from_own(measured.sample.peak_rss_bytes, measured.own_peak_rss)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not exceed xtask's own"), "{error}");
        assert!(distinct_from_own(10, Some(5)).is_ok());
        assert!(distinct_from_own(5, Some(5)).is_err());
        assert!(distinct_from_own(5, None).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_environment_is_the_benchmarks_not_this_process() {
        let root = scratch("env");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let mut command = command(Path::new("sh"), &["-c".into(), "env".into()], &run_dir).unwrap();
        run(&mut command, None).unwrap();
        let env = run_dir.read_stdout().unwrap();
        assert!(
            env.contains(&format!("HOME={}", run_dir.home.display())),
            "{env}"
        );
        assert!(env.contains(&format!("HTTPS_PROXY={DEAD_PROXY}")), "{env}");
        assert!(!env.contains("CARGO_"), "{env}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_injected_sleep_adds_to_the_commands_own_time() {
        // A 0.3 s command with 0.3 s injected measures at least 0.6 s: the
        // sleep adds to the command's time, it does not overlap it.
        let root = scratch("inject");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let mut command = command(
            Path::new("sh"),
            &["-c".into(), "sleep 0.3".into()],
            &run_dir,
        )
        .unwrap();
        let measured = run(&mut command, Some(Duration::from_millis(300))).unwrap();
        assert!(measured.sample.wall_s >= 0.6, "{}", measured.sample.wall_s);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn memory_xtask_freed_before_the_spawn_does_not_raise_the_floor() {
        // 256 MiB touched and freed: without the reset of VmHWM before the
        // spawn, a 64 MiB child would report this process's 256 MiB peak,
        // and the guard would refuse it.
        let root = scratch("freed");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let buffer = vec![1u8; 256 << 20];
        std::hint::black_box(&buffer);
        drop(buffer);
        let mut child = command(
            Path::new("sh"),
            &[
                "-c".into(),
                "dd if=/dev/zero of=/dev/null bs=64M count=1 2>/dev/null".into(),
            ],
            &run_dir,
        )
        .unwrap();
        let measured = run(&mut child, None).unwrap();
        let peak = measured.sample.peak_rss_bytes;
        assert!(
            peak < 200 << 20,
            "the child reported {peak} bytes: the parent's freed peak"
        );
        distinct_from_own(peak, measured.own_peak_rss).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_child_that_outlives_its_deadline_is_killed_not_awaited() {
        let root = scratch("deadline");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let mut command =
            command(Path::new("sh"), &["-c".into(), "sleep 30".into()], &run_dir).unwrap();
        let child = command.spawn().unwrap();
        let started = Instant::now();
        let outcome = reap_by(child, started + Duration::from_millis(200));
        assert!(outcome.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_run_directory_starts_from_a_fresh_copy() {
        let root = scratch("copy");
        let source = root.join("source");
        std::fs::create_dir_all(source.join("objects/rules")).unwrap();
        std::fs::write(source.join("objects/rules/a.yaml"), "a: 1\n").unwrap();
        let run_root = root.join("run");
        let first = RunDir::prepare(&run_root, Some(&source)).unwrap();
        std::fs::write(first.workspace.join("left-over"), "x").unwrap();
        let second = RunDir::prepare(&run_root, Some(&source)).unwrap();
        assert!(!second.workspace.join("left-over").exists());
        assert_eq!(
            std::fs::read_to_string(second.workspace.join("objects/rules/a.yaml")).unwrap(),
            "a: 1\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
