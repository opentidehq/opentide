//! The engines the benchmark runs: the oracle (opentide at the frozen tag,
//! installed from its PyPI wheel into a virtual environment of its own) and
//! the Rust language server built from this workspace.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The Python the oracle runs on: a uv-managed CPython (python-build-standalone),
/// the same build on a laptop and on CI, at one exact release so that a new
/// patch release cannot move the numbers unannounced.
pub const ORACLE_PYTHON: &str = "3.14.6";

/// The oracle's pinned requirements, relative to the workspace root: every
/// package at one version with its SHA-256 (`uv pip compile --generate-hashes`).
pub const ORACLE_REQUIREMENTS: &str = "tests/bench/oracle-requirements.txt";

/// Compiles the interpreter's standard library (`compileall`, every CPU),
/// failing when a module does not compile.
const COMPILE_STDLIB: &str = "import compileall, sys, sysconfig; \
    sys.exit(0 if compileall.compile_dir(sysconfig.get_path('stdlib'), quiet=1, workers=0) else 1)";

/// Exits 1 when a standard library module the CLI imports has no bytecode.
const STDLIB_IS_COMPILED: &str = "import importlib.util, os, sys, sysconfig; \
    stdlib = sysconfig.get_path('stdlib'); \
    sources = [os.path.join(stdlib, m) for m in ('json/decoder.py', 'typing.py', 'pathlib/__init__.py', 'argparse.py')]; \
    sys.exit(0 if all(os.path.exists(importlib.util.cache_from_source(s)) for s in sources if os.path.exists(s)) else 1)";

/// The opentide version a requirements file pins: its `opentide==X` line.
pub fn pinned_version(requirements: &str) -> Result<String> {
    requirements
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("opentide==")?;
            let version: String = rest
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '\\' && *c != ';')
                .collect();
            (!version.is_empty()).then_some(version)
        })
        .context("no `opentide==<version>` line")
}

/// Whether every line of the requirements that pins a package carries a hash
/// (what `--require-hashes` needs, checked here for a clearer message).
pub fn every_pin_is_hashed(requirements: &str) -> Result<()> {
    // A checkout with CRLF line endings (Windows) must read the same.
    let joined = requirements.replace("\r\n", "\n").replace("\\\n", " ");
    for line in joined.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.contains("==") || !line.contains("--hash=sha256:") {
            bail!("an unpinned or unhashed requirement: {line}");
        }
    }
    Ok(())
}

/// Installs the oracle into `dir` (once: a stamp holding the requirements it
/// was installed from is checked first) and returns its `opentide`.
///
/// uv verifies every wheel against the SHA-256 the requirements pin, opentide
/// comes only as a wheel (`--only-binary opentide`), and the bytecode is
/// compiled at install time so that no measured run pays for it.
pub fn ensure_oracle(root: &Path, dir: &Path) -> Result<(PathBuf, String)> {
    let requirements_path = root.join(ORACLE_REQUIREMENTS);
    let requirements = std::fs::read_to_string(&requirements_path)
        .with_context(|| format!("read {}", requirements_path.display()))?;
    let version = pinned_version(&requirements)
        .with_context(|| format!("parse {}", requirements_path.display()))?;
    every_pin_is_hashed(&requirements)
        .with_context(|| format!("check {}", requirements_path.display()))?;
    let stamp = dir.join("xtask-bench-requirements.txt");
    let opentide = dir.join("bin").join("opentide");
    // The stamp names every install step, so that an install made before a
    // step existed is redone.
    let stamp_text = format!("python {ORACLE_PYTHON}\nstdlib bytecode\n{requirements}");
    let installed = std::fs::read_to_string(&stamp).is_ok_and(|text| text == stamp_text);
    if !installed || !opentide.exists() {
        eprintln!(
            "bench: installing the oracle, opentide {version}, into {}",
            dir.display()
        );
        run(Command::new("uv")
            .args([
                "venv",
                "--no-config",
                "--quiet",
                "--clear",
                "--python",
                ORACLE_PYTHON,
            ])
            .arg(dir)
            .env("UV_PYTHON_PREFERENCE", "only-managed"))?;
        run(Command::new("uv")
            .args([
                "pip",
                "install",
                "--no-config",
                "--quiet",
                "--require-hashes",
                "--only-binary",
                "opentide",
                "--compile-bytecode",
                "--python",
            ])
            .arg(dir.join("bin").join("python"))
            .arg("-r")
            .arg(&requirements_path))?;
        // uv's managed CPython ships its standard library without bytecode
        // (49 .pyc for 655 modules in 3.14.6): with PYTHONDONTWRITEBYTECODE
        // (measure.rs) every run would compile what it imports again. Compile
        // it once here, as the first run of an interpreter would.
        run(Command::new(dir.join("bin").join("python"))
            .args(["-c", COMPILE_STDLIB])
            .env("PYTHONDONTWRITEBYTECODE", ""))?;
        std::fs::write(&stamp, &stamp_text)
            .with_context(|| format!("write {}", stamp.display()))?;
    }
    // Every run must find the standard library compiled; one that does not
    // measures the compiler (see COMPILE_STDLIB).
    let python = dir.join("bin").join("python");
    if run(Command::new(&python).args(["-c", STDLIB_IS_COMPILED])).is_err() {
        // uv may have reinstalled the interpreter since the stamp: compile
        // its standard library again, then insist.
        run(Command::new(&python)
            .args(["-c", COMPILE_STDLIB])
            .env("PYTHONDONTWRITEBYTECODE", ""))?;
        run(Command::new(&python).args(["-c", STDLIB_IS_COMPILED]))
            .context("the oracle's standard library has no bytecode")?;
    }
    let output = Command::new(&opentide)
        .arg("--version")
        .output()
        .with_context(|| format!("run {} --version", opentide.display()))?;
    let printed = String::from_utf8_lossy(&output.stdout);
    if printed.trim() != format!("opentide {version}") {
        bail!(
            "{} --version printed {:?}, not `opentide {version}`",
            opentide.display(),
            printed.trim()
        );
    }
    Ok((opentide, format!("opentide {version}")))
}

/// Builds opentide-workspace's `load` example (release): the Rust engine's
/// `load` command.
pub fn build_load(root: &Path) -> Result<PathBuf> {
    build_example(root, "load")
}

/// Builds opentide-workspace's `validate` example (`--release`): the Rust
/// engine's `validate_*` commands (UC-2.2, #817).
///
/// # Errors
///
/// The build fails, or names no executable.
pub fn build_validate(root: &Path) -> Result<PathBuf> {
    build_example(root, "validate")
}

/// Builds the opentide-workspace example `name` (`--release`); its path.
fn build_example(root: &Path, name: &str) -> Result<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    eprintln!("bench: building opentide-workspace's {name} example (release)");
    let output = Command::new(cargo)
        .current_dir(root)
        .args([
            "build",
            "--release",
            "--locked",
            "--package",
            "opentide-workspace",
            "--example",
            name,
            "--message-format=json-render-diagnostics",
        ])
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("run cargo build")?;
    if !output.status.success() {
        bail!(
            "cargo build -p opentide-workspace --example {name} failed ({})",
            output.status
        );
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == name)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .with_context(|| format!("cargo built no {name} executable"))
}

/// Builds the Rust CLI (opentide-cli's `opentide`, release): the Rust
/// engine of the commands it runs.
pub fn build_cli(root: &Path) -> Result<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    eprintln!("bench: building opentide-cli (release)");
    let output = Command::new(cargo)
        .current_dir(root)
        .args([
            "build",
            "--release",
            "--locked",
            "--package",
            "opentide-cli",
            "--bin",
            "opentide",
            "--message-format=json-render-diagnostics",
        ])
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("run cargo build")?;
    if !output.status.success() {
        bail!("cargo build -p opentide-cli failed ({})", output.status);
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == "opentide")
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .context("cargo built no opentide executable")
}

/// Builds the language server from this workspace (release profile, the
/// lock file as it is) and returns the binary.
pub fn build_lsp(root: &Path) -> Result<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    eprintln!("bench: building opentide-lsp (release)");
    let output = Command::new(cargo)
        .current_dir(root)
        .args([
            "build",
            "--release",
            "--locked",
            "--package",
            "opentide-lsp",
            "--bin",
            "opentide-lsp",
            "--message-format=json-render-diagnostics",
        ])
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("run cargo build")?;
    if !output.status.success() {
        bail!("cargo build -p opentide-lsp failed ({})", output.status);
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == "opentide-lsp")
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .context("cargo built no opentide-lsp executable")
}

fn run(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("run {}", command.get_program().display()))?;
    if !status.success() {
        bail!("{command:?} failed ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIREMENTS: &str = "\
annotated-types==0.7.0 \\
    --hash=sha256:aaaa
opentide==0.23.0 \\
    --hash=sha256:bbbb \\
    --hash=sha256:cccc
    # via -r oracle.in
";

    #[test]
    fn the_pinned_version_is_read_from_the_requirements() {
        assert_eq!(pinned_version(REQUIREMENTS).unwrap(), "0.23.0");
        assert!(pinned_version("annotated-types==0.7.0\n").is_err());
    }

    #[test]
    fn crlf_line_endings_read_the_same() {
        let crlf = REQUIREMENTS.replace('\n', "\r\n");
        assert_eq!(pinned_version(&crlf).unwrap(), "0.23.0");
        every_pin_is_hashed(&crlf).unwrap();
    }

    #[test]
    fn an_unhashed_pin_is_refused() {
        every_pin_is_hashed(REQUIREMENTS).unwrap();
        assert!(every_pin_is_hashed("opentide==0.23.0\n").is_err());
        assert!(every_pin_is_hashed("opentide>=0.23 --hash=sha256:x\n").is_err());
    }

    #[test]
    fn the_repository_pins_the_frozen_oracle_with_hashes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join(ORACLE_REQUIREMENTS)).unwrap();
        assert_eq!(pinned_version(&text).unwrap(), "0.23.0");
        every_pin_is_hashed(&text).unwrap();
        // The manylinux x86_64 wheel PyPI publishes for 0.23.0.
        assert!(text.contains(
            "--hash=sha256:de12c30f53327c4790fff5996c20b7d14508b4fd96ac73c81db20a02993211bc"
        ));
    }
}
