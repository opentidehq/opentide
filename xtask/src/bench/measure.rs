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

/// `XTASK_BENCH_TEST_BALLAST_MIB`: test-only. xtask holds this many MiB,
/// touched, for the whole run, which sets its own resident memory (and so
/// the floor [`distinct_from_own`] guards) to a known size whatever the
/// runner's memory layout. The tests use it to prove that a command peaking
/// below xtask's own memory is refused; nothing else sets it.
pub const TEST_BALLAST_ENV: &str = "XTASK_BENCH_TEST_BALLAST_MIB";

/// The ballast [`TEST_BALLAST_ENV`] asks for, allocated and touched.
pub fn test_ballast() -> Result<Option<Vec<u8>>> {
    match std::env::var(TEST_BALLAST_ENV) {
        Ok(text) if !text.trim().is_empty() => {
            let mib: usize = text
                .trim()
                .parse()
                .with_context(|| format!("{TEST_BALLAST_ENV}={text} is not MiB"))?;
            Ok(Some(vec![1u8; mib << 20]))
        }
        _ => Ok(None),
    }
}

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
    /// xtask's own peak RSS from just before the spawn to its return: the
    /// floor under the measured one ([`spawn`], [`distinct_from_own`]).
    pub own_peak_rss: Option<u64>,
}

/// Spawns `command`, waits for it with `wait4(2)`, and measures it: the wall
/// time from before the spawn to after the wait, and the peak RSS of the
/// process and the children it waited for. `inject` sleeps inside the timed
/// window ([`INJECT_SLEEP_ENV`]).
pub fn run(command: &mut Command, inject: Option<Duration>) -> Result<Measured> {
    run_with(command, inject, || {})
}

/// [`run`], calling `before_spawn` between the reset of xtask's high-water
/// mark and the spawn (the tests fault memory there).
fn run_with(
    command: &mut Command,
    inject: Option<Duration>,
    before_spawn: impl FnOnce(),
) -> Result<Measured> {
    let Spawned {
        child,
        start,
        own_peak_rss,
    } = spawn(command, before_spawn)?;
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

/// The hidden mode in which xtask measures one command for its parent
/// ([`run_isolated`], [`measure_here`]).
pub const INTERNAL_MEASURE: &str = "--internal-measure";

/// [`run`], through a fresh xtask process that spawns `command`, waits for
/// it and writes what it measured to a file in `run`: the command's floor
/// ([`own_peak_rss`]) is that small process's memory, not the benchmark's.
/// A Rust command can peak below a running xtask (`rules unreviewed`, about
/// 14 MiB, against 18 to 32 MiB by xtask's profile) and would be refused
/// ([`distinct_from_own`]). The command keeps `command`'s program,
/// arguments, directory and environment (`command` clears the inherited
/// one, as [`command`] does); its output goes to `run`'s files. The time is
/// the trampoline's, spawn to reap, so its own start is not counted.
pub fn run_isolated(command: &Command, run: &RunDir, inject: Option<Duration>) -> Result<Measured> {
    let result = run.root.join("measured.txt");
    let xtask = std::env::current_exe().context("find xtask's own executable")?;
    let mut trampoline = Command::new(xtask);
    trampoline
        .arg("bench")
        .arg(INTERNAL_MEASURE)
        .arg(&result)
        .arg(command.get_program())
        .args(command.get_args())
        .env_clear();
    if let Some(dir) = command.get_current_dir() {
        trampoline.current_dir(dir);
    }
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            trampoline.env(key, value);
        }
    }
    trampoline.stdin(Stdio::null());
    trampoline.stdout(
        std::fs::File::create(&run.stdout)
            .with_context(|| format!("create {}", run.stdout.display()))?,
    );
    trampoline.stderr(
        std::fs::File::create(&run.stderr)
            .with_context(|| format!("create {}", run.stderr.display()))?,
    );
    let status = trampoline
        .status()
        .context("run xtask's measuring process")?;
    if !status.success() {
        bail!(
            "xtask's measuring process failed ({status}): {}",
            run.stderr_tail()
        );
    }
    let text =
        std::fs::read_to_string(&result).with_context(|| format!("read {}", result.display()))?;
    let mut measured = parse_measured(&text).with_context(|| {
        format!(
            "{}: not what {INTERNAL_MEASURE} writes: {text:?}",
            result.display()
        )
    })?;
    // After the wait, as in `run`.
    if let Some(sleep) = inject {
        std::thread::sleep(sleep);
        measured.sample.wall_s += sleep.as_secs_f64();
    }
    Ok(measured)
}

/// What [`measure_here`] writes: `wall_s peak_rss_bytes exit_code
/// own_peak_rss`, `-` for a value it has not.
fn format_measured(measured: &Measured) -> String {
    let or_dash = |value: Option<String>| value.unwrap_or_else(|| "-".to_owned());
    format!(
        "{} {} {} {}\n",
        measured.sample.wall_s,
        measured.sample.peak_rss_bytes,
        or_dash(measured.exit_code.map(|code| code.to_string())),
        or_dash(measured.own_peak_rss.map(|rss| rss.to_string())),
    )
}

fn parse_measured(text: &str) -> Option<Measured> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    let [wall, rss, code, own] = fields.as_slice() else {
        return None;
    };
    Some(Measured {
        sample: Sample {
            wall_s: wall
                .parse()
                .ok()
                .filter(|s: &f64| s.is_finite() && *s >= 0.0)?,
            peak_rss_bytes: rss.parse().ok()?,
        },
        exit_code: optional(code).ok()?,
        own_peak_rss: optional(own).ok()?,
    })
}

/// A field of [`format_measured`]: `-` for none.
fn optional<T: std::str::FromStr>(field: &str) -> Result<Option<T>, T::Err> {
    if field == "-" {
        Ok(None)
    } else {
        field.parse().map(Some)
    }
}

/// `xtask bench --internal-measure RESULT PROGRAM ARGS...`: runs PROGRAM in
/// this process's directory, environment and standard streams, measures it
/// as [`run`] does, and writes the result to RESULT ([`run_isolated`]).
///
/// # Errors
///
/// The command cannot be spawned or waited for, or RESULT not written.
pub fn measure_here(result: &Path, program: &str, args: &[String]) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args);
    let measured = run(&mut command, None)?;
    std::fs::write(result, format_measured(&measured))
        .with_context(|| format!("write {}", result.display()))
}

/// A child [`spawn`] started for measuring.
#[derive(Debug)]
pub struct Spawned {
    /// The child, running.
    pub child: Child,
    /// When the clock started: just before the spawn.
    pub start: Instant,
    /// xtask's own peak RSS from the reset to the spawn's return: the floor
    /// under the child's ([`own_peak_rss`], [`distinct_from_own`]).
    pub own_peak_rss: Option<u64>,
}

/// Spawns `command` for measuring, the one way both the commands and the
/// language server are started: resets xtask's high-water mark
/// ([`reset_own_peak_rss`]), calls `before_spawn` (the tests fault memory
/// there; nothing otherwise), starts the clock, spawns, and reads xtask's
/// own peak RSS as soon as the spawn returns.
///
/// That read bounds the floor the child inherited, and nothing more: on
/// Linux std's `Command::spawn` returns only once the child has exec'd
/// (`posix_spawn` suspends the parent until then; the fork path waits for
/// the close-on-exec error pipe). It counts every page xtask touched between
/// the reset and the exec, the spawn's own allocations (the environment it
/// builds, the `posix_spawn` stack) included, and nothing xtask touches
/// after the exec, which the child never shared (the language server's
/// reader thread, the JSON-RPC messages). On the fork path (a program looked
/// up in a `PATH` the command sets) the child inherits only part of it, and
/// the floor is conservative.
pub fn spawn(command: &mut Command, before_spawn: impl FnOnce()) -> Result<Spawned> {
    reset_own_peak_rss();
    before_spawn();
    let start = Instant::now();
    let child = command
        .spawn()
        .with_context(|| format!("spawn {}", Path::new(command.get_program()).display()))?;
    let own_peak_rss = own_peak_rss();
    Ok(Spawned {
        child,
        start,
        own_peak_rss,
    })
}

/// Resets this process's high-water mark to its current RSS (`clear_refs`
/// 5), before a spawn: what xtask held earlier (the generated corpus, at
/// scale 10 about 110 MiB) is gone and must not raise the floor of every
/// later run. Nothing where there is no `/proc`.
pub fn reset_own_peak_rss() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

/// This process's own peak RSS (`VmHWM` in `/proc/self/status`), in bytes;
/// `None` where there is no `/proc`.
///
/// On Linux a child's `ru_maxrss` is the larger of its own peak and the
/// spawning process's peak at the spawn: `exec` records the high-water mark
/// of the memory the child shared with its parent until then. A measured
/// peak at or under xtask's own is that floor, not the command's. [`spawn`]
/// resets it before the spawn and reads it once the spawn returns: a page
/// xtask touches between the two (the spawn's own allocations) raises the
/// floor the child inherits, and a floor read before the spawn would miss
/// it and let xtask's peak pass for the command's.
pub fn own_peak_rss() -> Option<u64> {
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
    fn what_the_measuring_process_writes_reads_back() {
        for measured in [
            Measured {
                sample: Sample {
                    wall_s: 0.012_345_678_9,
                    peak_rss_bytes: 14 << 20,
                },
                exit_code: Some(0),
                own_peak_rss: Some(3 << 20),
            },
            Measured {
                sample: Sample {
                    wall_s: 1.5,
                    peak_rss_bytes: 1,
                },
                exit_code: None,
                own_peak_rss: None,
            },
        ] {
            let read = parse_measured(&format_measured(&measured)).unwrap();
            assert_eq!(read.sample.wall_s, measured.sample.wall_s);
            assert_eq!(read.sample.peak_rss_bytes, measured.sample.peak_rss_bytes);
            assert_eq!(read.exit_code, measured.exit_code);
            assert_eq!(read.own_peak_rss, measured.own_peak_rss);
        }
        for bad in [
            "",
            "1 2 3",
            "x 1 0 1",
            "-1 1 0 1",
            "1 1 zero 1",
            "1 1 0 1 extra",
        ] {
            assert!(parse_measured(bad).is_none(), "{bad:?}");
        }
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

    // Reads /proc (VmHWM, clear_refs) and Linux's ru_maxrss semantics.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_peak_rss_is_the_child_not_this_process() {
        // A child that touches 64 MiB more than this process holds has a
        // peak RSS above that; wait4 counts the grandchild `sh` waits for.
        let root = scratch("rss");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        reset_own_peak_rss();
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

    // Reads /proc (VmHWM, clear_refs) and Linux's ru_maxrss semantics.
    #[cfg(target_os = "linux")]
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

    // Reads /proc (VmHWM, clear_refs) and Linux's ru_maxrss semantics.
    #[cfg(target_os = "linux")]
    #[test]
    fn memory_xtask_touches_after_the_reset_is_part_of_the_floor() {
        if !crate::bench::measured_alone(
            module_path!(),
            "memory_xtask_touches_after_the_reset_is_part_of_the_floor",
        ) {
            return;
        }
        // 16 MiB touched between the reset and the spawn is in the floor the
        // child inherits: a floor read before it would let `sh -c true`
        // pass for a command that peaks above xtask.
        let root = scratch("late");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let mut late = Vec::new();
        let mut small = command(Path::new("sh"), &["-c".into(), "true".into()], &run_dir).unwrap();
        let measured = run_with(&mut small, None, || {
            late = vec![1u8; 16 << 20];
            std::hint::black_box(&late);
        })
        .unwrap();
        let error = distinct_from_own(measured.sample.peak_rss_bytes, measured.own_peak_rss)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not exceed xtask's own"), "{error}");
        drop(late);
        std::fs::remove_dir_all(root).unwrap();
    }

    // Reads /proc (VmHWM, clear_refs) and Linux's ru_maxrss semantics.
    #[cfg(target_os = "linux")]
    #[test]
    fn memory_the_spawn_itself_touches_is_part_of_the_floor() {
        if !crate::bench::measured_alone(
            module_path!(),
            "memory_the_spawn_itself_touches_is_part_of_the_floor",
        ) {
            return;
        }
        // No fault before the spawn: `Command::spawn` alone copies this
        // 1.5 MiB environment (into the map it captures, then into the
        // C strings `execve` gets) before `posix_spawn`, and those pages are
        // in the floor the child inherits. A floor read before
        // `Command::spawn` misses them and lets `sh -c true` pass for a
        // command that peaks above xtask. `/bin/sh`, an absolute path as the
        // bench's programs are: std takes the `posix_spawn` path, whose child
        // inherits the parent's whole mark (the fork path's inherits less).
        let root = scratch("spawn");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let mut small = command(
            Path::new("/bin/sh"),
            &["-c".into(), "true".into()],
            &run_dir,
        )
        .unwrap();
        for index in 0..15 {
            small.env(format!("XTASK_BENCH_PAD_{index}"), "x".repeat(100 << 10));
        }
        let mut before = None;
        let measured = run_with(&mut small, None, || before = own_peak_rss()).unwrap();
        // The spawn did raise the floor: the child's peak is above xtask's
        // mark just before `Command::spawn`, so only a floor read after it
        // tells the two apart.
        let before = before.unwrap();
        assert!(
            measured.sample.peak_rss_bytes > before,
            "child {} <= xtask before the spawn {before}",
            measured.sample.peak_rss_bytes
        );
        let error = distinct_from_own(measured.sample.peak_rss_bytes, measured.own_peak_rss)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not exceed xtask's own"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    // Reads /proc (VmHWM, clear_refs) and Linux's ru_maxrss semantics.
    #[cfg(target_os = "linux")]
    #[test]
    fn memory_xtask_touches_after_the_exec_is_not_part_of_the_floor() {
        if !crate::bench::measured_alone(
            module_path!(),
            "memory_xtask_touches_after_the_exec_is_not_part_of_the_floor",
        ) {
            return;
        }
        // 128 MiB touched once the spawn has returned (as the language
        // server's session allocates while the server runs) was never the
        // child's: the floor `spawn` reads leaves it out, and a 64 MiB child
        // is measured. A floor read after the reap would hold it and refuse
        // the child.
        let root = scratch("after");
        let run_dir = RunDir::prepare(&root, None).unwrap();
        let mut child = command(
            Path::new("/bin/sh"),
            &[
                "-c".into(),
                "dd if=/dev/zero of=/dev/null bs=64M count=1 2>/dev/null".into(),
            ],
            &run_dir,
        )
        .unwrap();
        let spawned = spawn(&mut child, || {}).unwrap();
        let after = vec![1u8; 128 << 20];
        std::hint::black_box(&after);
        let (peak, exit_code) = reap(spawned.child).unwrap();
        assert!(own_peak_rss().unwrap() >= 128 << 20);
        drop(after);
        assert_eq!(exit_code, Some(0));
        assert!(
            (64 << 20..128 << 20).contains(&peak),
            "the child reported {peak} bytes"
        );
        distinct_from_own(peak, spawned.own_peak_rss).unwrap();
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

    // Reads /proc (VmHWM, clear_refs) and Linux's ru_maxrss semantics.
    #[cfg(target_os = "linux")]
    #[test]
    fn memory_xtask_freed_before_the_spawn_does_not_raise_the_floor() {
        if !crate::bench::measured_alone(
            module_path!(),
            "memory_xtask_freed_before_the_spawn_does_not_raise_the_floor",
        ) {
            return;
        }
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
