//! The oracle: the Python CLI of a frozen release, installed from PyPI into
//! an isolated virtual environment, never from the working tree.
//!
//! `tests/golden/ORACLE` names the release, its wheel and the wheel's
//! SHA-256, and the Python it runs on. `tests/golden/oracle-requirements.txt`
//! pins every package of the environment with its hashes (`cargo xtask golden
//! lock` writes it); the opentide line carries exactly the ORACLE wheel's hash,
//! so the install fails unless PyPI serves that very file. uv installs with
//! `--require-hashes` into a uv-managed Python of the recorded version.

use crate::golden::run::Engine;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// How `uv pip install` installs the oracle: by hash only, wheels only, no
/// configuration file of the host, and byte-compiled, since cases run with
/// `PYTHONDONTWRITEBYTECODE=1` and would otherwise compile every module on
/// every run.
const INSTALL_FLAGS: [&str; 7] = [
    "--require-hashes",
    "--no-deps",
    "--only-binary",
    ":all:",
    "--no-config",
    "--compile-bytecode",
    "--no-progress",
];

/// `tests/golden/ORACLE`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oracle {
    /// The release tag (`v0.23.0`).
    pub tag: String,
    /// The commit the tag points at.
    pub commit: String,
    /// The PyPI distribution.
    pub package: String,
    /// Its version.
    pub version: String,
    /// The wheel installed (the platform below).
    pub wheel: String,
    /// The wheel's SHA-256, as PyPI lists it.
    pub wheel_sha256: String,
    /// The CPython version (uv-managed) the oracle runs on.
    pub python: String,
    /// The platform the goldens are recorded on.
    pub platform: String,
    /// `uv pip compile`'s `--exclude-newer`: the resolution of the lock.
    pub exclude_newer: String,
    /// The pinned requirements file, relative to `tests/golden`.
    pub requirements: String,
}

impl Oracle {
    /// Parses `ORACLE`.
    pub fn parse(text: &str) -> Result<Oracle> {
        let oracle: Oracle = toml::from_str(text).context("parse tests/golden/ORACLE")?;
        ensure!(
            oracle.wheel_sha256.len() == 64
                && oracle.wheel_sha256.chars().all(|c| c.is_ascii_hexdigit()),
            "ORACLE: wheel_sha256 is not a SHA-256"
        );
        ensure!(
            oracle
                .wheel
                .starts_with(&format!("{}-{}-", oracle.package, oracle.version)),
            "ORACLE: the wheel `{}` is not {} {}",
            oracle.wheel,
            oracle.package,
            oracle.version
        );
        Ok(oracle)
    }

    /// Checks that the requirements pin this release by this wheel's hash alone.
    pub fn check_requirements(&self, text: &str) -> Result<()> {
        let pin = format!("{}=={}", self.package, self.version);
        let mut lines = text
            .lines()
            .map(str::trim)
            .skip_while(|line| !line.starts_with(&pin));
        ensure!(lines.next().is_some(), "the requirements do not pin {pin}");
        let hashes: Vec<&str> = lines
            .take_while(|line| line.starts_with("--hash="))
            .map(|line| {
                line.trim_start_matches("--hash=sha256:")
                    .trim_end_matches(" \\")
                    .trim()
            })
            .collect();
        ensure!(
            hashes == [self.wheel_sha256.as_str()],
            "the requirements pin {pin} by {hashes:?}, not by the ORACLE wheel's hash {} alone: \
             run `cargo xtask golden lock`",
            self.wheel_sha256
        );
        Ok(())
    }

    /// Installs the oracle under `cache` (once per requirements) and returns it as an engine.
    pub fn provision(&self, golden: &Path, cache: &Path) -> Result<Engine> {
        let requirements = golden.join(&self.requirements);
        let text = fs::read_to_string(&requirements)
            .with_context(|| format!("read {}", requirements.display()))?;
        self.check_requirements(&text)?;
        let dir = cache.join(format!(
            "oracle-{}-{}",
            self.version,
            &self.wheel_sha256[..12]
        ));
        let stamp = dir.join("golden-stamp.txt");
        // Everything the installation depends on: a change installs afresh.
        let wanted = format!("python {}\ninstall {INSTALL_FLAGS:?}\n{text}", self.python);
        if fs::read_to_string(&stamp).ok().as_deref() != Some(wanted.as_str()) {
            if dir.exists() {
                fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
            }
            fs::create_dir_all(cache).with_context(|| format!("create {}", cache.display()))?;
            let dir_arg = dir.to_string_lossy().into_owned();
            uv(&[
                "venv",
                "--quiet",
                "--no-project",
                "--managed-python",
                "--python",
                &self.python,
                &dir_arg,
            ])?;
            let python = dir.join("bin").join("python");
            let python = python.to_string_lossy().into_owned();
            let requirements = requirements.to_string_lossy().into_owned();
            let mut args = vec!["pip", "install", "--quiet", "--python", &python];
            args.extend(INSTALL_FLAGS);
            args.extend(["-r", &requirements]);
            uv(&args)?;
            fs::write(&stamp, &wanted).with_context(|| format!("write {}", stamp.display()))?;
        }
        let bin_dir = dir.join("bin");
        let version = Command::new(bin_dir.join(&self.package))
            .arg("--version")
            .env_clear()
            .env("PATH", &bin_dir)
            .output()
            .context("run the oracle's --version")?;
        let printed = String::from_utf8_lossy(&version.stdout).trim().to_owned();
        let expected = format!("{} {}", self.package, self.version);
        ensure!(
            printed == expected,
            "the oracle prints `{printed}`, not `{expected}`"
        );
        Ok(Engine {
            name: "python".into(),
            bin_dir,
            install_dir: dir,
        })
    }

    /// Writes the requirements with `uv pip compile`: every dependency pinned
    /// with its hashes, and the opentide line narrowed to the ORACLE wheel.
    pub fn lock(&self, golden: &Path) -> Result<()> {
        let scratch = tempfile::tempdir().context("create a scratch directory")?;
        let input = scratch.path().join("requirements.in");
        fs::write(&input, format!("{}=={}\n", self.package, self.version))
            .context("write requirements.in")?;
        let output = scratch.path().join("requirements.txt");
        let (arch, os) = self
            .platform
            .split_once('-')
            .map(|(os, arch)| (arch, os))
            .unwrap_or(("", ""));
        ensure!(
            os == "linux" && arch == "x86_64",
            "`golden lock` knows the linux-x86_64 platform only"
        );
        let minor: String = self.python.split('.').take(2).collect::<Vec<_>>().join(".");
        uv(&[
            "pip",
            "compile",
            "--quiet",
            "--no-config",
            "--generate-hashes",
            "--no-header",
            "--python-version",
            &minor,
            "--python-platform",
            "x86_64-manylinux_2_28",
            "--exclude-newer",
            &self.exclude_newer,
            &input.to_string_lossy(),
            "-o",
            &output.to_string_lossy(),
        ])?;
        let compiled = fs::read_to_string(&output).context("read the compiled requirements")?;
        let narrowed = narrow(
            &compiled,
            &format!("{}=={}", self.package, self.version),
            &self.wheel_sha256,
        )?;
        let text = format!(
            "# Generated by `cargo xtask golden lock` from tests/golden/ORACLE: never edit.\n{}",
            narrowed.replace(&input.to_string_lossy().into_owned(), "ORACLE")
        );
        self.check_requirements(&text)?;
        let path = golden.join(&self.requirements);
        fs::write(&path, text).with_context(|| format!("write {}", path.display()))
    }
}

/// Keeps only `sha` among the hashes of the `pin` block.
fn narrow(text: &str, pin: &str, sha: &str) -> Result<String> {
    let mut out = String::new();
    let mut in_pin = false;
    let mut found = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(pin) {
            in_pin = true;
            out.push_str(&format!("{pin} \\\n    --hash=sha256:{sha}\n"));
            continue;
        }
        if in_pin && trimmed.starts_with("--hash=") {
            found |= trimmed.contains(sha);
            continue;
        }
        in_pin = false;
        out.push_str(line);
        out.push('\n');
    }
    ensure!(
        found,
        "PyPI does not list the ORACLE wheel's hash for {pin}"
    );
    Ok(out)
}

fn uv(args: &[&str]) -> Result<()> {
    let status = Command::new("uv")
        .args(args)
        .status()
        .context("run uv (https://docs.astral.sh/uv/): it installs the oracle")?;
    if !status.success() {
        bail!("uv {} failed ({status})", args.join(" "));
    }
    Ok(())
}

/// Where the oracle is installed: `$OPENTIDE_GOLDEN_CACHE`, or `golden/` in the target directory.
pub fn cache_dir(target_dir: &Path) -> PathBuf {
    std::env::var_os("OPENTIDE_GOLDEN_CACHE")
        .map_or_else(|| target_dir.join("golden"), PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "de12c30f53327c4790fff5996c20b7d14508b4fd96ac73c81db20a02993211bc";

    fn oracle() -> Oracle {
        Oracle::parse(&format!(
            r#"
tag = "v0.23.0"
commit = "f41fe5e5c5a8631b3cc3ab5f80aba39b4e65f2d7"
package = "opentide"
version = "0.23.0"
wheel = "opentide-0.23.0-cp310-abi3-manylinux_2_28_x86_64.whl"
wheel_sha256 = "{SHA}"
python = "3.13.14"
platform = "linux-x86_64"
exclude_newer = "2026-11-08T00:00:00Z"
requirements = "oracle-requirements.txt"
"#
        ))
        .unwrap()
    }

    #[test]
    fn narrows_the_pin_to_the_oracle_wheel() {
        let compiled = format!(
            "a==1 \\\n    --hash=sha256:aa\nopentide==0.23.0 \\\n    --hash=sha256:4df4 \\\n    --hash=sha256:{SHA}\n    # via -r in\nz==2 \\\n    --hash=sha256:zz\n"
        );
        let narrowed = narrow(&compiled, "opentide==0.23.0", SHA).unwrap();
        assert_eq!(
            narrowed,
            format!(
                "a==1 \\\n    --hash=sha256:aa\nopentide==0.23.0 \\\n    --hash=sha256:{SHA}\n    # via -r in\nz==2 \\\n    --hash=sha256:zz\n"
            )
        );
        oracle().check_requirements(&narrowed).unwrap();
        assert!(narrow(&compiled, "opentide==0.23.0", &"0".repeat(64)).is_err());
    }

    #[test]
    fn rejects_requirements_that_allow_another_file() {
        let o = oracle();
        let two =
            format!("opentide==0.23.0 \\\n    --hash=sha256:4df4 \\\n    --hash=sha256:{SHA}\n");
        assert!(o.check_requirements(&two).is_err());
        assert!(o.check_requirements("other==1\n").is_err());
        let one = format!("opentide==0.23.0 \\\n    --hash=sha256:{SHA}\n");
        o.check_requirements(&one).unwrap();
    }

    #[test]
    fn rejects_a_bad_oracle() {
        let text = toml::to_string(&Oracle {
            wheel_sha256: "abc".into(),
            ..oracle()
        })
        .unwrap();
        assert!(Oracle::parse(&text).is_err());
        let text = toml::to_string(&Oracle {
            wheel: "other-1.whl".into(),
            ..oracle()
        })
        .unwrap();
        assert!(Oracle::parse(&text).is_err());
    }
}
