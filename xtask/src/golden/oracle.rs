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
        // The version names a directory of the cache, which is replaced on reinstall.
        ensure!(
            !oracle.version.is_empty()
                && oracle
                    .version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-')),
            "ORACLE: version `{}` is not a release number",
            oracle.version
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
        let host_paths = python_home(&dir)
            .map(|home| vec![(home, "<PYTHON>".to_owned())])
            .unwrap_or_default();
        let known_uuids = std::sync::Arc::new(installed_uuids(&dir, &self.package)?);
        Ok(Engine {
            name: "python".into(),
            bin_dir,
            install_dir: dir,
            host_paths,
            known_uuids,
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

/// Every UUID in the text files of the installed `package` under `venv`
/// (`lib/python*/site-packages/<package>/`): its bundled vocabularies and
/// data, which a case's output may quote and which are not fresh.
fn installed_uuids(venv: &Path, package: &str) -> Result<std::collections::BTreeSet<String>> {
    let mut out = std::collections::BTreeSet::new();
    let lib = venv.join("lib");
    let Ok(pythons) = fs::read_dir(&lib) else {
        return Ok(out);
    };
    for python in pythons {
        let root = python
            .with_context(|| format!("read {}", lib.display()))?
            .path()
            .join("site-packages")
            .join(package);
        if root.is_dir() {
            collect_uuids(&root, &mut out)?;
        }
    }
    Ok(out)
}

fn collect_uuids(dir: &Path, out: &mut std::collections::BTreeSet<String>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let kind = entry
            .file_type()
            .with_context(|| format!("stat {}", entry.path().display()))?;
        if kind.is_dir() {
            collect_uuids(&entry.path(), out)?;
        } else if kind.is_file()
            && let Ok(text) = fs::read_to_string(entry.path())
        {
            out.extend(crate::golden::normalise::uuids_in(&text));
        }
    }
    Ok(())
}

/// The installation the virtual environment `venv` links to: the parent of
/// `home` in its `pyvenv.cfg` (`…/cpython-3.13.14-linux-x86_64-gnu`).
fn python_home(venv: &Path) -> Option<PathBuf> {
    let cfg = fs::read_to_string(venv.join("pyvenv.cfg")).ok()?;
    let home = cfg
        .lines()
        .find_map(|line| line.strip_prefix("home").map(str::trim))?
        .strip_prefix('=')?
        .trim();
    // A uv-managed Python lives in `…/cpython-<version>-<platform>/bin`; any
    // other home (`/usr/bin`) is left alone rather than replace `/usr`.
    let install = Path::new(home).parent()?;
    let name = install.file_name()?.to_string_lossy();
    name.starts_with("cpython-").then(|| install.to_path_buf())
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
    fn finds_the_python_a_venv_links_to() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pyvenv.cfg"),
            "home = /root/.local/share/uv/python/cpython-3.13.14-linux-x86_64-gnu/bin\nversion_info = 3.13.14\n",
        )
        .unwrap();
        assert_eq!(
            python_home(dir.path()).unwrap(),
            Path::new("/root/.local/share/uv/python/cpython-3.13.14-linux-x86_64-gnu")
        );
        assert!(python_home(&dir.path().join("none")).is_none());
        fs::write(dir.path().join("pyvenv.cfg"), "home = /usr/bin\n").unwrap();
        assert!(python_home(dir.path()).is_none());
    }

    #[test]
    fn rejects_a_version_that_is_a_path() {
        let text = toml::to_string(&Oracle {
            version: "../../x".into(),
            wheel: "opentide-../../x-a.whl".into(),
            ..oracle()
        })
        .unwrap();
        assert!(
            Oracle::parse(&text)
                .unwrap_err()
                .to_string()
                .contains("release number")
        );
    }

    #[test]
    fn collects_the_uuids_of_the_installed_package_only() {
        let venv = tempfile::tempdir().unwrap();
        let data = venv
            .path()
            .join("lib/python3.13/site-packages/opentide/data");
        fs::create_dir_all(&data).unwrap();
        fs::write(
            data.join("vocab.toml"),
            "id = \"4D3C2B1A-0F9E-4D8C-B7A6-958473625140\"\n",
        )
        .unwrap();
        fs::write(data.join("blob.bin"), [0xff, 0xfe]).unwrap();
        let other = venv.path().join("lib/python3.13/site-packages/rich");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("x.py"), "11111111-2222-4333-8444-555566667777").unwrap();
        let found = installed_uuids(venv.path(), "opentide").unwrap();
        assert_eq!(
            found.into_iter().collect::<Vec<_>>(),
            ["4d3c2b1a-0f9e-4d8c-b7a6-958473625140"]
        );
        assert!(
            installed_uuids(&venv.path().join("none"), "opentide")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn installs_by_hash_only_wheels_and_no_host_configuration() {
        // V857-S-6: the flags that make the install the ORACLE wheel and nothing else.
        for flag in ["--require-hashes", "--no-deps", "--no-config"] {
            assert!(INSTALL_FLAGS.contains(&flag), "{flag}");
        }
        let only = INSTALL_FLAGS
            .iter()
            .position(|f| *f == "--only-binary")
            .unwrap();
        assert_eq!(INSTALL_FLAGS[only + 1], ":all:");
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
