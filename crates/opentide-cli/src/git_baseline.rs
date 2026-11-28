//! The `git` program, asked for what the gix crates `opentide-compile` reads
//! git with do not answer yet: the author's `user.name` for `new`, and the
//! repository's layout and default branch for `setup hooks` and `setup ci`.
//! What changed against the default branch
//! is read with gix, `opentide_compile::git::changed_in_folders` (#1955).
//!
//! git runs with the run's environment ([`Env`]) and nothing else: the
//! process's own variables are cleared first, so what a test injects is what
//! git sees.

use std::path::Path;
use std::process::Command;

use crate::env::Env;

/// Git's trimmed stdout as text, when it ran and succeeded.
pub fn stdout(env: &Env, dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .envs(env.iter())
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
