//! The `corpus` subcommands: argument parsing, files and processes.

use super::generate::{self, Counts, Layout, Options};
use super::workspace::Workspace;
use anyhow::{Context, Result, bail};
use std::path::Path;
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
";

/// Runs `corpus <args>`; the process exit status.
pub fn run(args: &[String]) -> Result<u8> {
    let Some((command, rest)) = args.split_first() else {
        bail!("missing command\n\n{USAGE}");
    };
    match command.as_str() {
        "generate" => generate_command(rest),
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
        let target = root.join(&path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        std::fs::write(&target, text)
            .with_context(|| format!("cannot write {}", target.display()))?;
    }
    Ok(())
}
