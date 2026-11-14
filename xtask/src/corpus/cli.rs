//! The `corpus` subcommands: argument parsing, files and processes.

use super::coverage;
use super::faults::{self, Catalogue};
use super::generate::{self, Counts, Layout, Options};
use super::workspace::Workspace;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// The usage of `cargo xtask corpus`.
pub const USAGE: &str = "\
usage: cargo xtask corpus <command> [options]

commands:
  generate --seed N [--scale F | --threats N --objectives N --rules N]
           [--layout standard|explicit|custom] --out DIR
                 write the heavy workspace for seed N (default counts
                 300/300/500, --scale multiplies them); DIR must not exist
                 or be empty. --digest prints the digest instead of writing
  faults --out DIR [--catalogue FILE]
                 write one workspace ([combined] counts) with every fault
                 kind not marked isolated applied once (twice if cross-file)
                 to files of its own, and DIR.faults.json beside it listing
                 each kind's files, command and expected codes
  coverage [--check | --write] [--dir DIR]
                 map every code in tests/corpora/codes.toml to the fault
                 kinds that produce it; --write records tests/corpora/COVERAGE.md,
                 --check fails when a code has no kind or the file is stale;
                 --dir reads faults.toml, codes.toml and COVERAGE.md from DIR
";

/// Runs `corpus <args>`; the process exit status.
pub fn run(args: &[String]) -> Result<u8> {
    let Some((command, rest)) = args.split_first() else {
        bail!("missing command\n\n{USAGE}");
    };
    match command.as_str() {
        "generate" => generate_command(rest),
        "faults" => faults_command(rest),
        "coverage" => coverage_command(rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(0)
        }
        other => bail!("unknown command `{other}`\n\n{USAGE}"),
    }
}

fn value<'a>(args: &mut impl Iterator<Item = &'a String>, flag: &str) -> Result<&'a str> {
    args.next()
        .map(String::as_str)
        .with_context(|| format!("{flag} needs a value"))
}

fn number(text: &str, flag: &str) -> Result<usize> {
    text.parse()
        .with_context(|| format!("{flag}: `{text}` is not a whole number"))
}

/// Parses the generator's options.
pub fn parse_options(args: &[String]) -> Result<(Options, Option<String>, bool)> {
    let mut seed = None;
    let mut scale = None;
    let mut counts = [None, None, None];
    let mut layout = Layout::Explicit;
    let mut out = None;
    let mut digest = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                let text = value(&mut args, arg)?;
                seed = Some(
                    text.parse::<u64>()
                        .with_context(|| format!("--seed: `{text}` is not a whole number"))?,
                );
            }
            "--scale" => {
                let text = value(&mut args, arg)?;
                let factor: f64 = text
                    .parse()
                    .with_context(|| format!("--scale: `{text}` is not a number"))?;
                scale = Some(
                    Counts::scaled(factor)
                        .with_context(|| format!("--scale: `{text}` is not in (0, 1000]"))?,
                );
            }
            "--threats" => counts[0] = Some(number(value(&mut args, arg)?, arg)?),
            "--objectives" => counts[1] = Some(number(value(&mut args, arg)?, arg)?),
            "--rules" => counts[2] = Some(number(value(&mut args, arg)?, arg)?),
            "--layout" => {
                let text = value(&mut args, arg)?;
                layout = Layout::parse(text).with_context(|| {
                    format!("--layout: `{text}` is not standard, explicit or custom")
                })?;
            }
            "--out" => out = Some(value(&mut args, arg)?.to_string()),
            "--digest" => digest = true,
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    let seed = seed.context("--seed is required")?;
    if scale.is_some() && counts.iter().any(Option::is_some) {
        bail!("--scale and --threats/--objectives/--rules exclude each other");
    }
    let base = scale.unwrap_or(generate::DEFAULT_COUNTS);
    let counts = Counts {
        threats: counts[0].unwrap_or(base.threats),
        objectives: counts[1].unwrap_or(base.objectives),
        rules: counts[2].unwrap_or(base.rules),
    };
    Ok((
        Options {
            platforms: crate::corpus::vocab::PLATFORMS,
            seed,
            counts,
            layout,
        },
        out,
        digest,
    ))
}

fn generate_command(args: &[String]) -> Result<u8> {
    let (options, out, digest) = parse_options(args)?;
    let started = Instant::now();
    let workspace = generate::generate(&options);
    if digest {
        println!("{}", workspace.digest());
        return Ok(0);
    }
    let out = out.context("--out is required (or --digest)")?;
    write_workspace(&workspace, Path::new(&out))?;
    eprintln!(
        "corpus generate: seed {} ({}) into {out} in {} ms; digest {}",
        options.seed,
        workspace.summary(),
        started.elapsed().as_millis(),
        workspace.digest()
    );
    Ok(0)
}

/// Writes `workspace` under `root`, which must not exist or be empty: the
/// generator never overwrites a file it did not write.
pub fn write_workspace(workspace: &Workspace, root: &Path) -> Result<()> {
    if root.exists() {
        let mut entries =
            std::fs::read_dir(root).with_context(|| format!("cannot read {}", root.display()))?;
        if entries.next().is_some() {
            bail!("{} exists and is not empty", root.display());
        }
    }
    for (path, text) in workspace.rendered() {
        if !super::faults::is_relative_inside(&path) {
            bail!("{path} is not a path inside the workspace");
        }
        let target = root.join(&path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .with_context(|| format!("cannot create {}", target.display()))?;
        std::io::Write::write_all(&mut file, text.as_bytes())
            .with_context(|| format!("cannot write {}", target.display()))?;
    }
    Ok(())
}

/// The repository root: `CARGO_MANIFEST_DIR`'s parent as `cargo run` sets
/// it at run time, else the working directory (never compiled in:
/// xtask/AGENTS.md).
pub fn repo_root() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .and_then(|dir| dir.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `tests/corpora/` under the repository root.
pub fn corpora_dir() -> PathBuf {
    repo_root().join("tests").join("corpora")
}

/// Removes the scratch directory however the run ends, unless `--keep`.
pub(crate) struct Scratch {
    pub(crate) path: PathBuf,
    pub(crate) keep: bool,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

struct FaultArgs {
    out: Option<PathBuf>,
    catalogue: PathBuf,
}

fn parse_fault_args(args: &[String]) -> Result<FaultArgs> {
    let mut parsed = FaultArgs {
        out: None,
        catalogue: corpora_dir().join("faults.toml"),
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => parsed.out = Some(PathBuf::from(value(&mut args, arg)?)),
            "--catalogue" => parsed.catalogue = PathBuf::from(value(&mut args, arg)?),
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    Ok(parsed)
}

pub(crate) fn load_catalogue(path: &Path) -> Result<Catalogue> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Catalogue::parse(&text).with_context(|| format!("in {}", path.display()))
}

fn faults_command(args: &[String]) -> Result<u8> {
    let parsed = parse_fault_args(args)?;
    let catalogue = load_catalogue(&parsed.catalogue)?;
    let Some(out) = &parsed.out else {
        bail!("faults needs --out\n\n{USAGE}");
    };
    materialise(&catalogue, out)
}

/// `DIR.faults.json` beside `DIR` (also for `DIR/`), never inside it.
fn manifest_path(out: &Path) -> Result<PathBuf> {
    let name = out
        .file_name()
        .with_context(|| format!("--out {} names no directory", out.display()))?;
    let mut manifest_name = name.to_os_string();
    manifest_name.push(".faults.json");
    Ok(out.with_file_name(manifest_name))
}

/// Writes the combined fault workspace and its manifest.
pub(crate) fn materialise(catalogue: &Catalogue, out: &Path) -> Result<u8> {
    let options = catalogue.combined_options()?;
    let mut workspace = generate::generate(&options);
    let mut taken = BTreeSet::new();
    let mut manifest = Vec::new();
    for kind in catalogue.kinds.iter().filter(|k| !k.isolated) {
        let mut once = kind.clone();
        once.count = kind.combined_count();
        let kind = &once;
        let targets = faults::select(&workspace, kind, &taken)?;
        taken.extend(targets.iter().copied());
        let before = workspace.files.len();
        faults::apply(&mut workspace, kind, &targets)?;
        if workspace.files.len() < before {
            bail!("fault kind `{}` deletes files; mark it isolated", kind.id);
        }
        // The files the kind changed, and those it added (a state shard, a
        // configuration file), where its findings are.
        let files: Vec<String> = targets
            .iter()
            .copied()
            .chain(before..workspace.files.len())
            .map(|i| workspace.files[i].path.clone())
            .collect();
        // Files a kind adds are its own, never another kind's target.
        taken.extend(before..workspace.files.len());
        let severities: BTreeMap<&str, &str> = kind
            .codes
            .iter()
            .filter_map(|c| kind.severity_of(c).ok().map(|s| (c.as_str(), s)))
            .collect();
        manifest.push(serde_json::json!({
            "id": kind.id,
            "class": kind.class,
            "command": kind.command,
            "env": kind.env,
            "codes": severities,
            "files": files,
        }));
    }
    let manifest_path = manifest_path(out)?;
    if manifest_path.exists() {
        bail!(
            "{} exists; the manifest is never overwritten",
            manifest_path.display()
        );
    }
    write_workspace(&workspace, out)?;
    let document = serde_json::json!({
        "oracle": catalogue.oracle,
        "base": {
            "seed": options.seed,
            "threats": options.counts.threats,
            "objectives": options.counts.objectives,
            "rules": options.counts.rules,
            "layout": options.layout.name(),
        },
        "note": "each kind is applied to files no other kind touches, once (twice for a \
                 cross-file kind); kinds marked isolated are left out. The expectations are \
                 checked per kind in isolation (faults --check), not on this workspace.",
        "digest": workspace.digest(),
        "kinds": manifest,
    });
    let mut manifest_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .with_context(|| format!("cannot create {}", manifest_path.display()))?;
    std::io::Write::write_all(
        &mut manifest_file,
        (serde_json::to_string_pretty(&document)? + "\n").as_bytes(),
    )
    .with_context(|| format!("cannot write {}", manifest_path.display()))?;
    eprintln!(
        "corpus faults: {} kinds into {} (digest {}); manifest {}",
        manifest.len(),
        out.display(),
        workspace.digest(),
        manifest_path.display()
    );
    Ok(0)
}

fn coverage_command(args: &[String]) -> Result<u8> {
    let mut mode = "print";
    let mut dir = corpora_dir();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--check" => mode = "check",
            "--write" => mode = "write",
            "--dir" => dir = PathBuf::from(value(&mut iter, arg)?),
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    let catalogue = load_catalogue(&dir.join("faults.toml"))?;
    let codes_path = dir.join("codes.toml");
    let codes_text = std::fs::read_to_string(&codes_path)
        .with_context(|| format!("cannot read {}", codes_path.display()))?;
    let codes = coverage::Codes::parse(&codes_text)?;
    let report = coverage::report(&codes, &catalogue);
    let rendered = coverage::render(&report, &catalogue);
    let path = dir.join("COVERAGE.md");
    match mode {
        "write" => {
            std::fs::write(&path, &rendered)
                .with_context(|| format!("cannot write {}", path.display()))?;
            eprintln!("corpus coverage: wrote {}", path.display());
        }
        "check" => {
            let recorded = std::fs::read_to_string(&path).unwrap_or_default();
            if recorded != rendered {
                eprintln!(
                    "corpus coverage: {} is stale; run `cargo xtask corpus coverage --write`",
                    path.display()
                );
                return Ok(1);
            }
        }
        _ => print!("{rendered}"),
    }
    println!("{}", report.summary());
    Ok(u8::from(
        !report.missing.is_empty() || !report.problems.is_empty(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{Scratch, manifest_path};
    use std::path::Path;

    #[test]
    fn scratch_is_removed_unless_kept() {
        let base = std::env::temp_dir().join(format!("xtask-scratch-test-{}", std::process::id()));
        for keep in [false, true] {
            std::fs::create_dir_all(base.join("_base")).unwrap();
            drop(Scratch {
                path: base.clone(),
                keep,
            });
            assert_eq!(base.exists(), keep);
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_manifest_sits_beside_the_workspace() {
        assert_eq!(
            manifest_path(Path::new("/tmp/x/faults/")).unwrap(),
            Path::new("/tmp/x/faults.faults.json")
        );
        assert_eq!(
            manifest_path(Path::new("ws")).unwrap(),
            Path::new("ws.faults.json")
        );
        assert!(manifest_path(Path::new("/")).is_err());
    }
}
