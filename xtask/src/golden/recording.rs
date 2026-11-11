//! A recording: one case's normalised outputs, as they are stored under
//! `tests/golden/cases/<command>/<mode>/<fixture>/<variant>/`:
//!
//! | File | Holds |
//! |------|-------|
//! | `case.toml` | the [`Case`]: argv, environment, stdin, mode, fixture |
//! | `stdout`, `stderr` | the streams, normalised |
//! | `outcome.toml` | the exit code and every file created, changed or deleted |
//! | `files/<path>` | the bytes of each created or changed regular file, normalised |
//!
//! A file of [`blob::THRESHOLD`] bytes or more is kept once in
//! `tests/golden/blobs/` instead, and `outcome.toml` names its SHA-256.
//!
//! A path component that starts with `.git` or `~` is stored with a `~`
//! before it, so a recorded `.gitignore` or `.git/` cannot change what git
//! does with the recordings themselves.

use crate::golden::blob;
use crate::golden::case::Case;
use crate::golden::normalise::Normaliser;
use crate::golden::snapshot::{Change, ChangeKind, Kind};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// One file system change, normalised.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    /// The path under the case's root: `ws/…`, `home/…` or `tmp/…`.
    pub path: String,
    /// Created, modified or deleted.
    pub change: ChangeKind,
    /// File, directory or symbolic link.
    pub kind: Kind,
    /// Permission bits in octal (`"0644"`); absent for links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// A file's size after normalisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Whether the bytes are not UTF-8 (and so were not normalised).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub binary: bool,
    /// A link's target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The SHA-256 of a large file's bytes, kept in the blob store instead of `files/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    /// The bytes of a created or changed file (stored in `files/`).
    #[serde(skip)]
    pub contents: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct Outcome {
    exit_code: i32,
    #[serde(default)]
    files: Vec<FileRecord>,
}

/// A case and what it did, normalised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recording {
    /// The case that ran.
    pub case: Case,
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
    /// The exit code.
    pub exit_code: i32,
    /// File system changes, in path order.
    pub files: Vec<FileRecord>,
}

/// A part of two recordings that differs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    /// `stdout`, `stderr`, `exit_code`, `case.toml`, `files` or `files/<path>`.
    pub part: String,
    /// A unified diff, or a description when there is none.
    pub detail: String,
}

impl Recording {
    /// Normalises a run's outputs: stdout, stderr, then each change in path order.
    pub fn new(
        case: Case,
        stdout: &[u8],
        stderr: &[u8],
        exit_code: i32,
        changes: &[Change],
        normaliser: &mut Normaliser,
    ) -> Recording {
        let stdout = normaliser.bytes(stdout);
        let stderr = normaliser.bytes(stderr);
        // Fresh UUIDs are numbered by first appearance, so the changes are
        // visited in an order that does not depend on them: by path, then
        // bytes, with every fresh UUID masked (an inflight shard is named by
        // its object's UUID).
        let mut ordered: Vec<&Change> = changes.iter().collect();
        ordered.sort_by_cached_key(|change| {
            (
                normaliser.mask_fresh(&change.path),
                normaliser.mask_fresh(&String::from_utf8_lossy(&change.entry.bytes)),
            )
        });
        let mut files: Vec<FileRecord> = ordered
            .into_iter()
            .map(|change| {
                let entry = &change.entry;
                let path = normaliser.text(&change.path);
                let mut record = FileRecord {
                    path,
                    change: change.change,
                    kind: entry.kind,
                    mode: (entry.kind != Kind::Symlink).then(|| format!("{:04o}", entry.mode)),
                    size: None,
                    binary: false,
                    target: None,
                    blob: None,
                    contents: None,
                };
                match entry.kind {
                    Kind::Symlink => {
                        record.target =
                            Some(normaliser.text(&String::from_utf8_lossy(&entry.bytes)));
                    }
                    Kind::File if change.change != ChangeKind::Deleted => {
                        record.binary = std::str::from_utf8(&entry.bytes).is_err();
                        let bytes = normaliser.bytes(&entry.bytes);
                        record.size = Some(bytes.len() as u64);
                        if bytes.len() >= blob::THRESHOLD {
                            record.blob = Some(blob::sha256_hex(&bytes));
                        }
                        record.contents = Some(bytes);
                    }
                    Kind::File | Kind::Dir => {}
                }
                record
            })
            .collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Recording {
            case,
            stdout,
            stderr,
            exit_code,
            files,
        }
    }

    /// Writes the recording into `dir`, replacing whatever was there; large
    /// files go to the blob store `blobs`.
    pub fn write(&self, dir: &Path, blobs: &Path) -> Result<()> {
        if dir.exists() {
            fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
        }
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        write(&dir.join("case.toml"), self.case.render()?.as_bytes())?;
        write(&dir.join("stdout"), &self.stdout)?;
        write(&dir.join("stderr"), &self.stderr)?;
        write(&dir.join("outcome.toml"), self.render_outcome()?.as_bytes())?;
        for file in &self.files {
            if let (Some(bytes), Some(_)) = (&file.contents, &file.blob) {
                blob::put(blobs, bytes)?;
            } else if let Some(bytes) = &file.contents {
                let path = dir.join("files").join(escape(&file.path));
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("create {}", parent.display()))?;
                }
                write(&path, bytes)?;
            }
        }
        Ok(())
    }

    fn render_outcome(&self) -> Result<String> {
        let outcome = Outcome {
            exit_code: self.exit_code,
            files: self.files.clone(),
        };
        let body = toml::to_string(&outcome).context("serialise outcome.toml")?;
        Ok(format!(
            "# Generated by `cargo xtask golden record`: never edit.\n{body}"
        ))
    }

    /// Reads the recording in `dir`, and its large files from `blobs`.
    pub fn read(dir: &Path, blobs: &Path) -> Result<Recording> {
        let case = Case::parse(&read_string(&dir.join("case.toml"))?)
            .with_context(|| format!("in {}", dir.display()))?;
        let outcome: Outcome = toml::from_str(&read_string(&dir.join("outcome.toml"))?)
            .with_context(|| format!("parse {}", dir.join("outcome.toml").display()))?;
        let mut files = outcome.files;
        for file in &mut files {
            if let Some(hash) = &file.blob {
                file.contents = Some(blob::get(blobs, hash)?);
            } else if file.kind == Kind::File && file.change != ChangeKind::Deleted {
                let path = dir.join("files").join(escape(&file.path));
                file.contents =
                    Some(fs::read(&path).with_context(|| format!("read {}", path.display()))?);
            }
        }
        Ok(Recording {
            case,
            stdout: read(&dir.join("stdout"))?,
            stderr: read(&dir.join("stderr"))?,
            exit_code: outcome.exit_code,
            files,
        })
    }

    /// Where `self` (recorded) and `actual` differ, part by part.
    pub fn differences(&self, actual: &Recording) -> Vec<Difference> {
        let mut out = Vec::new();
        if self.case != actual.case {
            let expected = self.case.render().unwrap_or_default();
            let got = actual.case.render().unwrap_or_default();
            out.push(Difference {
                part: "case.toml".into(),
                detail: unified(&expected, &got),
            });
        }
        if self.exit_code != actual.exit_code {
            out.push(Difference {
                part: "exit_code".into(),
                detail: format!("recorded {}, got {}", self.exit_code, actual.exit_code),
            });
        }
        for (part, expected, got) in [
            ("stdout", &self.stdout, &actual.stdout),
            ("stderr", &self.stderr, &actual.stderr),
        ] {
            if expected != got {
                out.push(Difference {
                    part: part.into(),
                    detail: bytes_diff(expected, got),
                });
            }
        }
        let manifest = |files: &[FileRecord]| {
            files
                .iter()
                .map(|f| toml::to_string(f).unwrap_or_default() + "\n")
                .collect::<String>()
        };
        if self
            .files
            .iter()
            .map(strip)
            .ne(actual.files.iter().map(strip))
        {
            out.push(Difference {
                part: "files".into(),
                detail: unified(&manifest(&self.files), &manifest(&actual.files)),
            });
        }
        for expected in &self.files {
            let Some(got) = actual.files.iter().find(|f| f.path == expected.path) else {
                continue;
            };
            if let (Some(a), Some(b)) = (&expected.contents, &got.contents)
                && a != b
            {
                out.push(Difference {
                    part: format!("files/{}", expected.path),
                    detail: bytes_diff(a, b),
                });
            }
        }
        out
    }
}

fn strip(file: &FileRecord) -> FileRecord {
    FileRecord {
        contents: None,
        ..file.clone()
    }
}

/// A unified diff of two texts, or a note for bytes that are not UTF-8.
fn bytes_diff(expected: &[u8], got: &[u8]) -> String {
    match (std::str::from_utf8(expected), std::str::from_utf8(got)) {
        (Ok(a), Ok(b)) => unified(a, b),
        _ => format!(
            "binary contents differ ({} bytes recorded, {} bytes now)",
            expected.len(),
            got.len()
        ),
    }
}

/// A unified diff with escape characters made visible.
pub fn unified(expected: &str, got: &str) -> String {
    let visible = |s: &str| s.replace('\x1b', "␛").replace('\r', "␍");
    let (a, b) = (visible(expected), visible(got));
    similar::TextDiff::from_lines(&a, &b)
        .unified_diff()
        .context_radius(3)
        .header("recorded", "now")
        .to_string()
}

/// The stored path of a recorded file path, safe to commit and to check out
/// on every platform:
///
/// - `%` and the characters Windows forbids in a name (`<>:"|?*\\` and
///   control characters) become `%XX`: a normalised name such as
///   `crash-<TIMESTAMP>-<PID>.log` holds `<` and `>`;
/// - a component that starts with `.git` or `~`, or is a name Windows
///   reserves (`CON`, `NUL`, `COM1`, … with any extension), or ends in `.` or
///   a space, gets a `~` before it, so a recorded `.gitignore` or `.git/`
///   cannot change what git does with the recordings themselves.
pub fn escape(path: &str) -> PathBuf {
    path.split('/').map(escape_part).collect()
}

fn escape_part(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    for c in part.chars() {
        if matches!(c, '%' | '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\\') || c.is_ascii_control()
        {
            out.push_str(&format!("%{:02X}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    let stem = out.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit());
    if out.starts_with(".git")
        || out.starts_with('~')
        || reserved
        || out.ends_with('.')
        || out.ends_with(' ')
    {
        out.insert(0, '~');
    }
    out
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn read_string(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

/// Every recording directory under `cases`: the ones that hold a `case.toml`,
/// as ids relative to `cases`, sorted.
pub fn recorded_ids(cases: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if cases.is_dir() {
        find(cases, cases, &mut out)?;
    }
    out.sort();
    Ok(out)
}

fn find(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    if dir.join("case.toml").is_file() {
        let rel = dir
            .strip_prefix(root)
            .context("a recording outside the cases directory")?;
        let id: Vec<String> = rel
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        ensure!(
            id.len() == 4,
            "{}: a recording sits at <command>/<mode>/<fixture>/<variant>",
            dir.display()
        );
        out.push(id.join("/"));
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            find(root, &entry.path(), out)?;
        } else if dir == root {
            bail!(
                "{}: only recordings belong under cases/",
                entry.path().display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden::case::{Mode, Stdin, StdinKind};
    use crate::golden::normalise::Volatile;
    use crate::golden::snapshot::Entry;
    use std::collections::BTreeMap;

    fn case() -> Case {
        Case {
            id: "new.threat/plain/none/example".into(),
            command: "new threat".into(),
            variant: "example".into(),
            mode: Mode::Plain,
            fixture: "none".into(),
            argv: vec!["opentide".into(), "new".into(), "threat".into()],
            cwd: ".".into(),
            env: BTreeMap::from([("HOME".into(), "<HOME>".into())]),
            stdin: Stdin {
                kind: StdinKind::Null,
                input: String::new(),
            },
            timeout_secs: 60,
            normalise: Vec::new(),
            cassette: None,
        }
    }

    fn sample() -> Recording {
        let volatile = Volatile {
            literals: vec![("/tmp/g/ws".into(), "<WS>".into())],
            dates: vec![],
            recent_dates: vec![],
            known_uuids: std::collections::BTreeSet::new(),
            git_version: None,
        };
        let mut normaliser = Normaliser::new(&volatile, &[], []);
        let changes = vec![
            Change {
                path: "ws/.gitignore".into(),
                change: ChangeKind::Created,
                entry: Entry {
                    kind: Kind::File,
                    mode: 0o644,
                    bytes: b"*.log\n".to_vec(),
                },
            },
            Change {
                path: "ws/a.yaml".into(),
                change: ChangeKind::Modified,
                entry: Entry {
                    kind: Kind::File,
                    mode: 0o600,
                    bytes: b"path: /tmp/g/ws/x\n".to_vec(),
                },
            },
            Change {
                path: "ws/big.json".into(),
                change: ChangeKind::Created,
                entry: Entry {
                    kind: Kind::File,
                    mode: 0o644,
                    bytes: vec![b'x'; blob::THRESHOLD],
                },
            },
            Change {
                path: "ws/bin".into(),
                change: ChangeKind::Created,
                entry: Entry {
                    kind: Kind::File,
                    mode: 0o755,
                    bytes: vec![0xff, 0x00],
                },
            },
            Change {
                path: "ws/gone".into(),
                change: ChangeKind::Deleted,
                entry: Entry {
                    kind: Kind::File,
                    mode: 0o644,
                    bytes: b"x".to_vec(),
                },
            },
            Change {
                path: "ws/link".into(),
                change: ChangeKind::Created,
                entry: Entry {
                    kind: Kind::Symlink,
                    mode: 0,
                    bytes: b"/tmp/g/ws/a.yaml".to_vec(),
                },
            },
        ];
        Recording::new(case(), b"ok /tmp/g/ws\n", b"", 3, &changes, &mut normaliser)
    }

    #[test]
    fn writes_and_reads_back() {
        let rec = sample();
        assert_eq!(rec.stdout, b"ok <WS>\n");
        assert_eq!(
            rec.files[1].contents.as_deref(),
            Some(&b"path: <WS>/x\n"[..])
        );
        assert_eq!(rec.files[5].target.as_deref(), Some("<WS>/a.yaml"));
        assert!(rec.files[3].binary);
        assert!(rec.files[2].blob.is_some() && rec.files[1].blob.is_none());
        let dir = tempfile::tempdir().unwrap();
        let at = dir.path().join("r");
        let blobs = dir.path().join("blobs");
        rec.write(&at, &blobs).unwrap();
        assert!(at.join("files/ws/~.gitignore").is_file());
        assert!(!at.join("files/ws/gone").exists());
        let big = rec.files.iter().find(|f| f.path == "ws/big.json").unwrap();
        let hash = big.blob.clone().unwrap();
        assert!(blobs.join(&hash).is_file());
        assert!(!at.join("files/ws/big.json").exists());
        let back = Recording::read(&at, &blobs).unwrap();
        assert_eq!(back, rec);
        assert!(rec.differences(&back).is_empty());
        let outcome = fs::read_to_string(at.join("outcome.toml")).unwrap();
        assert!(outcome.contains("exit_code = 3"), "{outcome}");
        assert!(outcome.contains("mode = \"0755\""), "{outcome}");
    }

    #[test]
    fn differences_name_each_part() {
        let rec = sample();
        let mut other = rec.clone();
        other.stdout = b"ok elsewhere\n".to_vec();
        other.stderr = b"warning: elsewhere\n".to_vec();
        other.exit_code = 0;
        other.files[1].contents = Some(b"path: y\n".to_vec());
        other.files[1].size = Some(8);
        let parts: Vec<String> = rec
            .differences(&other)
            .into_iter()
            .map(|d| d.part)
            .collect();
        assert_eq!(
            parts,
            ["exit_code", "stdout", "stderr", "files", "files/ws/a.yaml"]
        );
        let differences = rec.differences(&other);
        let diff = &differences[1].detail;
        assert!(
            diff.contains("-ok <WS>") && diff.contains("+ok elsewhere"),
            "{diff}"
        );
        assert!(
            differences[2].detail.contains("+warning: elsewhere"),
            "{}",
            differences[2].detail
        );
    }

    #[test]
    fn fresh_uuid_numbers_do_not_depend_on_the_minted_values() {
        use crate::golden::case::Rule;
        // Two shards named by fresh UUIDs, one per object; which UUID sorts
        // first is chance. The recording must not depend on it.
        let shard = |uuid: &str, name: &str| Change {
            path: format!("ws/.opentide/inflight/{uuid}.json"),
            change: ChangeKind::Created,
            entry: Entry {
                kind: Kind::File,
                mode: 0o644,
                bytes: format!("{{\"uuid\": \"{uuid}\", \"name\": \"{name}\"}}\n").into_bytes(),
            },
        };
        let record = |a: &str, b: &str| {
            let mut n = Normaliser::new(&Volatile::default(), &[Rule::FreshUuids], []);
            Recording::new(
                case(),
                b"",
                b"",
                0,
                &[shard(a, "alpha"), shard(b, "beta")],
                &mut n,
            )
        };
        let low = "11111111-1111-4111-8111-111111111111";
        let high = "ffffffff-ffff-4fff-8fff-ffffffffffff";
        let first = record(low, high);
        let second = record(high, low);
        assert_eq!(first, second);
        assert_eq!(
            first.files[0].contents.as_deref(),
            Some(&b"{\"uuid\": \"<UUID-1>\", \"name\": \"alpha\"}\n"[..])
        );
    }

    #[test]
    fn stored_paths_are_portable() {
        assert_eq!(
            escape("home/.local/state/opentide/crash-<TIMESTAMP>-<PID>.log"),
            PathBuf::from("home/.local/state/opentide/crash-%3CTIMESTAMP%3E-%3CPID%3E.log")
        );
        assert_eq!(
            escape("ws/.opentide/inflight/<UUID-1>.json"),
            PathBuf::from("ws/.opentide/inflight/%3CUUID-1%3E.json")
        );
        assert_eq!(escape("ws/a%3C"), PathBuf::from("ws/a%253C"));
        assert_eq!(
            escape("ws/nul.txt/COM1/con"),
            PathBuf::from("ws/~nul.txt/~COM1/~con")
        );
        assert_eq!(
            escape("ws/COM10/console/x."),
            PathBuf::from("ws/COM10/console/~x.")
        );
        // Each stored name, not the joined path: Windows joins with `\\`.
        for path in ["a/b:c", "x|y?z*", "q\"r\\s"] {
            for part in &escape(path) {
                let part = part.to_string_lossy();
                assert!(
                    !part.contains(['<', '>', ':', '"', '|', '?', '*', '\\']),
                    "{part}"
                );
            }
        }
    }

    #[test]
    fn escapes_git_names() {
        assert_eq!(escape("ws/.git/HEAD"), PathBuf::from("ws/~.git/HEAD"));
        assert_eq!(
            escape("ws/~x/.gitattributes"),
            PathBuf::from("ws/~~x/~.gitattributes")
        );
        assert_eq!(escape("ws/a.git"), PathBuf::from("ws/a.git"));
    }

    #[test]
    fn finds_recordings() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = tempfile::tempdir().unwrap();
        sample()
            .write(
                &dir.path().join("new.threat/plain/none/example"),
                blobs.path(),
            )
            .unwrap();
        assert_eq!(
            recorded_ids(dir.path()).unwrap(),
            ["new.threat/plain/none/example"]
        );
        sample()
            .write(&dir.path().join("too/shallow"), blobs.path())
            .unwrap();
        assert!(recorded_ids(dir.path()).is_err());
    }
}
