//! `cargo xtask check-layers` checks the workspace it runs in, not the one its
//! binary was built from.
//!
//! Worktrees that share a `CARGO_TARGET_DIR` can run a binary another worktree
//! built (cargo judges freshness by modification times), so a path compiled in
//! with `env!("CARGO_MANIFEST_DIR")` would name that other worktree and check
//! the wrong tree. Each case below runs the real binary in a small workspace of
//! its own whose table is broken; a binary that read the repository it was
//! built from would pass it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A workspace of two crates where `low` depends on `high`, and a table that
/// places `low` in the bottom layer and `high` in the top one: an upward edge.
struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("xtask-{name}-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        let files = [
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"low\", \"high\"]\nresolver = \"2\"\n",
            ),
            (
                "low/Cargo.toml",
                "[package]\nname = \"low\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
                 [dependencies]\nhigh = { path = \"../high\" }\n",
            ),
            ("low/src/lib.rs", ""),
            (
                "high/Cargo.toml",
                "[package]\nname = \"high\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            ("high/src/lib.rs", ""),
            (
                "xtask/layers.toml",
                "[[layer]]\nname = \"bottom\"\ntiers = [[\"low\"]]\n\n\
                 [[layer]]\nname = \"top\"\ntiers = [[\"high\"]]\n",
            ),
        ];
        for (path, text) in files {
            let path = root.join(path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, text)?;
        }
        Ok(Self { root })
    }

    /// `xtask check-layers` started from `cwd`, with `manifest_dir` as the
    /// `CARGO_MANIFEST_DIR` that `cargo run` (the `cargo xtask` alias) sets,
    /// or none, as when the binary is run directly.
    fn check_layers(&self, cwd: &Path, manifest_dir: Option<&Path>) -> std::io::Result<Output> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
        command.arg("check-layers").current_dir(cwd);
        match manifest_dir {
            Some(dir) => command.env("CARGO_MANIFEST_DIR", dir),
            None => command.env_remove("CARGO_MANIFEST_DIR"),
        };
        command.output()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn assert_fails_on_the_upward_edge(output: &Output, table: &Path) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains(
            "error: `low` (bottom tier 0) has a normal dependency on `high` (top tier 0)"
        ),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "check-layers: 1 violation(s) of the layer table ({})",
            table.display()
        )),
        "stderr: {stderr}"
    );
}

#[test]
fn run_by_cargo_it_checks_the_workspace_cargo_ran_it_for() -> TestResult {
    let workspace = Workspace::new("cargo-run")?;
    let xtask = workspace.root.join("xtask");
    let output = workspace.check_layers(&workspace.root.join("low"), Some(&xtask))?;
    assert_fails_on_the_upward_edge(&output, &xtask.join("layers.toml"));
    Ok(())
}

#[test]
fn run_directly_it_checks_the_workspace_of_its_working_directory() -> TestResult {
    let workspace = Workspace::new("direct")?;
    let output = workspace.check_layers(&workspace.root.join("high"), None)?;
    assert_fails_on_the_upward_edge(&output, &workspace.root.join("xtask/layers.toml"));
    Ok(())
}
