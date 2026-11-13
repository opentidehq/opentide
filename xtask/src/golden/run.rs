//! Runs one case through an engine in a private directory and returns its
//! normalised [`Recording`].
//!
//! Each case gets a fresh root, `<temp>/golden-XXXXXX/`, holding `ws/` (the
//! fixture, and the working directory), `home/` (`HOME`) and `tmp/`
//! (`TMPDIR`). The environment is exactly the case's: nothing is inherited.
//! On Linux the program runs in a session of its own (`setsid`), so it never
//! reaches the terminal `cargo xtask` runs in; in human mode its stdin
//! pseudo-terminal is its controlling terminal.

use crate::golden::case::{self, Case, Mode, StdinKind};
use crate::golden::fixture::FixtureSpec;
use crate::golden::normalise::{Normaliser, Volatile, utc_date};
use crate::golden::recording::Recording;
use crate::golden::snapshot::Snapshot;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

/// An implementation of the CLI that cases run against.
#[derive(Clone, Debug)]
pub struct Engine {
    /// `python` (the oracle), `rust` (this repository's console script) or
    /// `node` (the npm package's bin).
    pub name: String,
    /// The directory that holds its `opentide` executable (`<ENGINE_BIN>` in `PATH`).
    pub bin_dir: PathBuf,
    /// Its installation directory, normalised to `<ENGINE>` in outputs.
    pub install_dir: PathBuf,
    /// Other directories of the host it reads from, with their placeholders:
    /// the Python a virtual environment links to (`<PYTHON>`), whose standard
    /// library shows in a traceback.
    pub host_paths: Vec<(PathBuf, String)>,
    /// The UUIDs in its own installed files (bundled vocabularies, data):
    /// deterministic, never fresh.
    pub known_uuids: std::sync::Arc<std::collections::BTreeSet<String>>,
}

/// What every case of a run shares.
#[derive(Clone, Debug)]
pub struct RunContext {
    /// The repository root (fixture sources are relative to it).
    pub repo: PathBuf,
    /// The fixtures of `cases.toml`.
    pub fixtures: BTreeMap<String, FixtureSpec>,
    /// The engine.
    pub engine: Engine,
    /// `git --version`'s number on this host.
    pub git_version: Option<String>,
    /// The kernel release (`uname -r`) on this host.
    pub kernel_release: Option<String>,
    /// Where case roots are created.
    pub temp_parent: PathBuf,
}

/// The `setsid` that puts a case in a session of its own, when the host has one.
const SETSID: &str = "/usr/bin/setsid";

/// Runs `case` and returns its normalised recording.
pub fn run_case(case: &Case, ctx: &RunContext) -> Result<Recording> {
    let root = tempfile::Builder::new()
        .prefix("golden-")
        .rand_bytes(6)
        .tempdir_in(&ctx.temp_parent)
        .with_context(|| format!("create a case directory in {}", ctx.temp_parent.display()))?;
    let root_path = root.path().to_path_buf();
    let (ws, home, tmp) = (
        root_path.join("ws"),
        root_path.join("home"),
        root_path.join("tmp"),
    );
    for dir in [&ws, &home, &tmp] {
        fs::create_dir(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let fixture = ctx
        .fixtures
        .get(&case.fixture)
        .with_context(|| format!("unknown fixture `{}`", case.fixture))?;
    fixture
        .materialise(&ctx.repo, &ws)
        .with_context(|| format!("materialise fixture `{}`", case.fixture))?;

    // A cassette case's network traffic: the replaying proxy, and its CA
    // where the case's CA bundle variables point.
    let proxy = match &case.cassette {
        Some(name) => Some(cassette_proxy(&ctx.repo, name, &root_path)?),
        None => None,
    };
    let proxy_url = proxy.as_ref().map(opentide_cassette::Proxy::url);

    let before = Snapshot::take(&root_path)?;
    let started = SystemTime::now();
    let (stdout, stderr, exit_code) = execute(case, ctx, &root_path, proxy_url.as_deref())
        .with_context(|| format!("run case {}", case.id))?;
    if let (Some(proxy), Some(name)) = (&proxy, &case.cassette) {
        let mismatches = proxy.verify();
        let listed: Vec<String> = mismatches.iter().map(ToString::to_string).collect();
        if let Some(report) = cassette_mismatch(&ctx.repo, &case.id, name, &listed)? {
            eprintln!("{report}");
        }
    }
    let finished = SystemTime::now();
    let after = Snapshot::take(&root_path)?;
    let changes = before.changes(&after);

    let mut dates = vec![utc_date(started), utc_date(finished)];
    dates.dedup();
    let mut paths = vec![
        (&ws, case::WS),
        (&home, case::HOME),
        (&root_path, case::TMP),
        (&ctx.engine.bin_dir, case::ENGINE_BIN),
        (&ctx.engine.install_dir, "<ENGINE>"),
    ];
    paths.extend(
        ctx.engine
            .host_paths
            .iter()
            .map(|(p, name)| (p, name.as_str())),
    );
    let mut literals = path_literals(&paths);
    if let Some(url) = &proxy_url {
        literals.push((url.clone(), case::CASSETTE_PROXY.to_owned()));
    }
    if let Some(release) = &ctx.kernel_release {
        literals.extend(kernel_literals(release));
    }
    let volatile = Volatile {
        literals,
        dates,
        recent_dates: (1..=7)
            .map(|days| utc_date(started - Duration::from_secs(days * 86_400)))
            .collect(),
        git_version: ctx.git_version.clone(),
        known_uuids: case_uuids(case)
            .chain(ctx.engine.known_uuids.iter().cloned())
            .collect(),
    };
    let mut normaliser = Normaliser::new(&volatile, &case.normalise, before.texts());
    Ok(Recording::new(
        case.clone(),
        &stdout,
        &stderr,
        exit_code,
        &changes,
        &mut normaliser,
    ))
}

/// Each path, and its canonical form when that differs (`/tmp` behind a link).
pub(crate) fn path_literals(paths: &[(&PathBuf, &str)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (path, placeholder) in paths {
        out.push((
            path.to_string_lossy().into_owned(),
            (*placeholder).to_owned(),
        ));
        if let Ok(real) = path.canonicalize()
            && &real != *path
        {
            out.push((
                real.to_string_lossy().into_owned(),
                (*placeholder).to_owned(),
            ));
        }
    }
    out
}

/// Starts the proxy that replays cassette `name` for a case under `root`,
/// its CA written where [`case::CASSETTE_CA`] points.
pub fn cassette_proxy(repo: &Path, name: &str, root: &Path) -> Result<opentide_cassette::Proxy> {
    let path = repo.join("tests/cassettes").join(format!("{name}.json"));
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let cassette = opentide_cassette::Cassette::parse(&text)
        .map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))?;
    let proxy = opentide_cassette::Proxy::start(
        opentide_cassette::Mode::Replay { cassette },
        opentide_cassette::Redaction::default(),
    )
    .map_err(|error| anyhow::anyhow!("start the replaying proxy: {error}"))?;
    let ca = case::CASSETTE_CA.replace(case::TMP, &root.to_string_lossy());
    fs::write(&ca, proxy.ca_pem()).with_context(|| format!("write {ca}"))?;
    Ok(proxy)
}

/// The case's environment with its placeholders filled in.
fn environment(
    case: &Case,
    ctx: &RunContext,
    root: &Path,
    proxy: Option<&str>,
) -> BTreeMap<String, String> {
    let fill = |value: &str| {
        value
            .replace(case::CASSETTE_PROXY, proxy.unwrap_or(case::REFUSING_PROXY))
            .replace(case::ENGINE_BIN, &ctx.engine.bin_dir.to_string_lossy())
            .replace(case::WS, &root.join("ws").to_string_lossy())
            .replace(case::HOME, &root.join("home").to_string_lossy())
            .replace(case::TMP, &root.to_string_lossy())
    };
    case.env.iter().map(|(k, v)| (k.clone(), fill(v))).collect()
}

fn execute(
    case: &Case,
    ctx: &RunContext,
    root: &Path,
    proxy: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>, i32)> {
    let Some((program, args)) = case.argv.split_first() else {
        bail!("empty argv");
    };
    let env = environment(case, ctx, root, proxy);
    let mut command = if Path::new(SETSID).is_file() {
        let mut c = Command::new(SETSID);
        if case.mode == Mode::Human {
            c.arg("--ctty");
        }
        c.arg("--wait").arg(program);
        c
    } else {
        Command::new(program)
    };
    command
        .args(args)
        .env_clear()
        .envs(&env)
        .current_dir(root.join("ws").join(&case.cwd));

    let mut streams: Vec<Stream> = Vec::new();
    let mut keep_open: Vec<fs::File> = Vec::new();
    let mut child = if case.mode == Mode::Human {
        spawn_on_terminals(
            &mut command,
            &case.stdin.input,
            &mut streams,
            &mut keep_open,
        )?
    } else {
        spawn_on_pipes(&mut command, case, &mut streams)?
    };
    let status = wait(&mut child, Duration::from_secs(case.timeout_secs));
    // Whatever the program left running in its session goes with it, so the
    // readers see the end of their streams.
    kill_session(&child);
    let status = status?;
    let mut outputs = Vec::new();
    for stream in streams {
        outputs.push(stream.finish()?);
    }
    let mut outputs = outputs.into_iter();
    let stdout = outputs.next().unwrap_or_default();
    let stderr = outputs.next().unwrap_or_default();
    drop(keep_open);
    let Some(code) = status.code() else {
        bail!("ended by a signal ({status})");
    };
    Ok((stdout, stderr, code))
}

/// A stream of the program's output being read.
enum Stream {
    /// A pipe, read to its end.
    Pipe(JoinHandle<Vec<u8>>),
    /// A pseudo-terminal (human mode).
    #[cfg(unix)]
    Terminal(crate::golden::pty::Capture),
}

impl Stream {
    /// Everything the program wrote; call it once the program is over.
    fn finish(self) -> Result<Vec<u8>> {
        match self {
            Self::Pipe(reader) => reader
                .join()
                .map_err(|_| anyhow::anyhow!("a stream reader panicked")),
            #[cfg(unix)]
            Self::Terminal(capture) => capture.finish(),
        }
    }
}

fn spawn_on_pipes(command: &mut Command, case: &Case, streams: &mut Vec<Stream>) -> Result<Child> {
    let stdin = match case.stdin.kind {
        StdinKind::Pipe => Stdio::piped(),
        StdinKind::Null | StdinKind::Tty => Stdio::null(),
    };
    let mut child = command
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start the engine")?;
    if let Some(mut pipe) = child.stdin.take() {
        let input = case.stdin.input.clone().into_bytes();
        std::thread::spawn(move || {
            let _ = pipe.write_all(&input);
        });
    }
    let stdout = child.stdout.take().context("no stdout pipe")?;
    let stderr = child.stderr.take().context("no stderr pipe")?;
    streams.push(Stream::Pipe(spawn_reader(stdout)));
    streams.push(Stream::Pipe(spawn_reader(stderr)));
    Ok(child)
}

fn spawn_reader<R: Read + Send + 'static>(mut stream: R) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        buf
    })
}

#[cfg(unix)]
fn spawn_on_terminals(
    command: &mut Command,
    input: &str,
    streams: &mut Vec<Stream>,
    keep_open: &mut Vec<fs::File>,
) -> Result<Child> {
    use crate::golden::pty::{self, Capture, Role};
    let stdin = pty::open(Role::Input)?;
    let (stdout, stdout_slave) = Capture::start(pty::open(Role::Output)?)?;
    let (stderr, stderr_slave) = Capture::start(pty::open(Role::Output)?)?;
    let child = command
        .stdin(Stdio::from(stdin.slave))
        .stdout(Stdio::from(stdout_slave))
        .stderr(Stdio::from(stderr_slave))
        .spawn()
        .context("start the engine")?;
    // The command holds the slaves until it is dropped: only the program and
    // the captures may hold them while it runs.
    *command = Command::new("true");
    streams.push(Stream::Terminal(stdout));
    streams.push(Stream::Terminal(stderr));
    // The input, then the end-of-file character. The input master stays open
    // until the case is over: closing it hangs the terminal up.
    // Written on a thread of its own: a program that never reads would block
    // a long input before the timeout starts.
    let writer = stdin.master;
    let mut input_side = writer.try_clone().context("clone the input terminal")?;
    let bytes: Vec<u8> = input.bytes().chain([0x04]).collect();
    std::thread::spawn(move || {
        let _ = input_side.write_all(&bytes);
    });
    let drain = writer.try_clone().context("clone the input terminal")?;
    std::thread::spawn(move || read_terminal(drain));
    keep_open.push(writer);
    Ok(child)
}

#[cfg(not(unix))]
fn spawn_on_terminals(
    _command: &mut Command,
    _input: &str,
    _streams: &mut Vec<Stream>,
    _keep_open: &mut Vec<fs::File>,
) -> Result<Child> {
    bail!("human mode needs a pseudo-terminal: record the goldens on Linux")
}

/// Reads a terminal's master until the last slave closes (`EIO` on Linux);
/// the input terminal's echo-free drain.
#[cfg(unix)]
fn read_terminal(mut master: fs::File) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    out
}

fn wait(child: &mut Child, timeout: Duration) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context("wait for the engine")? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            kill_session(child);
            let _ = child.kill();
            let _ = child.wait();
            bail!("timed out after {}s", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn kill_session(child: &Child) {
    if Path::new(SETSID).is_file() {
        let pid = rustix::process::Pid::from_child(child);
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

#[cfg(not(unix))]
fn kill_session(_child: &Child) {}

/// The UUIDs a case passes in: argv, environment and stdin.
fn case_uuids(case: &Case) -> impl Iterator<Item = String> + '_ {
    case.argv
        .iter()
        .chain(case.env.values())
        .chain(std::iter::once(&case.stdin.input))
        .flat_map(|text| crate::golden::normalise::uuids_in(text).collect::<Vec<_>>())
}

/// The kernel release of this host (`uname -r`), on Linux.
pub fn kernel_release() -> Option<String> {
    let text = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let release = text.trim();
    (!release.is_empty()).then(|| release.to_owned())
}

/// The crash handler's `os` fact, `Linux <release> (<machine>)`, as it
/// prints it and as its pre-filled issue link encodes it: only in that
/// context, so a short release (`6.1.0`) never replaces a version elsewhere.
pub fn kernel_literals(release: &str) -> Vec<(String, String)> {
    let encoded = release.replace('+', "%2B");
    let mut out = Vec::new();
    for (space, paren, rel) in [
        (" ", "(", release),
        ("+", "%28", encoded.as_str()),
        ("%20", "%28", encoded.as_str()),
    ] {
        out.push((
            format!("Linux{space}{rel}{space}{paren}"),
            format!("Linux{space}<KERNEL>{space}{paren}"),
        ));
    }
    out
}

/// Where case directories go: `/tmp` on Unix whatever `TMPDIR` says, so an
/// absolute path in an output has the same length on every host (Rich wraps
/// lines by length); the system's temporary directory elsewhere.
pub fn temp_parent() -> PathBuf {
    if cfg!(unix) && Path::new("/tmp").is_dir() {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    }
}

/// The number in `git --version` (`2.43.0`), when git is on `PATH`.
pub fn git_version() -> Option<String> {
    let output = Command::new("git").arg("--version").output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    text.split_whitespace().nth(2).map(str::to_owned)
}

/// What a case whose requests are not its cassette's (`listed`, one line
/// each) does to the run. With none, nothing. Otherwise the run stops with
/// an error, except on the catch-up train (`report_only`): a cassette
/// recorded from the 0.23.0 oracle may not hold the requests a port sends
/// now (0.28.1's `setup skills` downloads the catalogue's
/// detection-engineering), so the case is compared, and the returned report
/// names the cassette O2 must record again from the new oracle.
///
/// # Errors
///
/// `listed` is not empty and `repo` is not report-only.
fn cassette_mismatch(
    repo: &Path,
    case: &str,
    cassette: &str,
    listed: &[String],
) -> Result<Option<String>> {
    if listed.is_empty() {
        return Ok(None);
    }
    if !super::report_only::enabled(repo) {
        bail!(
            "case {case}: the requests are not cassette {cassette}'s (record it again, or fix the client):\n{}",
            listed.join("\n")
        );
    }
    Ok(Some(format!(
        "case {case}: request mismatch with cassette {cassette}: reported, not failed ({} is \
         present); O2 records {cassette} again from the new oracle:\n{}",
        super::report_only::MARKER,
        listed.join("\n")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A case whose requests are not its cassette's stops the run, unless
    /// the repository carries the report-only marker: then it is reported
    /// as a request mismatch naming the cassette O2 records again.
    #[test]
    fn a_cassette_request_mismatch_fails_unless_the_train_is_report_only() {
        let repo = tempfile::tempdir().unwrap();
        let listed = vec!["request 2: URL a was recorded, b sent".to_owned()];
        assert_eq!(
            cassette_mismatch(
                repo.path(),
                "setup/json/none/skills",
                "skills/manifest",
                &[]
            )
            .unwrap(),
            None
        );
        let error = cassette_mismatch(
            repo.path(),
            "setup/json/none/skills",
            "skills/manifest",
            &listed,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.starts_with(
                "case setup/json/none/skills: the requests are not cassette skills/manifest's"
            ),
            "{error}"
        );
        let marker = super::super::report_only::marker_path(repo.path());
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, "train\n").unwrap();
        let report = cassette_mismatch(
            repo.path(),
            "setup/json/none/skills",
            "skills/manifest",
            &listed,
        )
        .unwrap()
        .unwrap();
        assert!(
            report.starts_with(
                "case setup/json/none/skills: request mismatch with cassette skills/manifest"
            ),
            "{report}"
        );
        assert!(
            report.contains("O2 records skills/manifest again"),
            "{report}"
        );
        assert!(report.ends_with("URL a was recorded, b sent"), "{report}");
    }

    #[test]
    fn kernel_release_only_in_its_context() {
        let literals = kernel_literals("6.1.0+x");
        let mut normaliser = Normaliser::new(
            &Volatile {
                literals,
                ..Volatile::default()
            },
            &[],
            [],
        );
        assert_eq!(
            normaliser.text("os: Linux 6.1.0+x (x86_64)\nhttps://i?os=Linux+6.1.0%2Bx+%28x86_64%29 rule version 6.1.0+x"),
            "os: Linux <KERNEL> (x86_64)\nhttps://i?os=Linux+<KERNEL>+%28x86_64%29 rule version 6.1.0+x"
        );
    }
}
