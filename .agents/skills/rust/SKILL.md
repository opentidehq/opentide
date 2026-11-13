---
name: rust
description: The working loop for opentide's Cargo workspace - the pinned toolchain, clippy under the workspace lints, nextest's fast and ci profiles, insta snapshot review, trycmd cases, cargo xtask check-layers, and worktrees with one Cargo target pool each. Use when building, linting or testing any Rust crate here (crates/, bindings/python/, xtask/, a new unified-core crate), when clippy, nextest or the layer check fails, or when running several agents in parallel. The engine crates' coding rules are in rust-engine.
---

# Rust workspace: the loop

How to build, lint and test the Cargo workspace, and how to add a crate to it. Run every command
here from the repository root. This skill covers the tools. The code conventions are in two other
places:

| You need | Read |
|----------|------|
| The engine crates' rules: I/O-free engines, `thiserror` versus `anyhow`, the pinned dependencies, `OnceLock` catalogs, UTF-16 positions | [`rust-engine`](../rust-engine/SKILL.md) |
| The layer table, the lint policy, the test commands and the invariant scripts | [`crates/AGENTS.md`](../../../crates/AGENTS.md), then the crate's own `AGENTS.md` |
| Holding the command line to the Python oracle: goldens, `golden check --engine rust`, the ledger | [`golden`](../golden/SKILL.md) |

If this skill and `crates/AGENTS.md` disagree, `crates/AGENTS.md` is right: fix this skill.

## The toolchain

`rust-toolchain.toml` pins one exact release with `rustfmt` and `clippy`. rustup installs it on
first use in the checkout, and CI installs the same file's toolchain. Lint with that release, never
with a different local `stable`: a newer clippy brings new pedantic lints, and CI denies warnings.

```bash
rustup show active-toolchain   # names the release rust-toolchain.toml pins
cargo --version
```

The crates declare `rust-version = "1.95"` (what `yara-x-parser` and `yara-x-fmt` need), but no job checks that floor (the file says why). To
move to a newer release, follow the steps in the header of `rust-toolchain.toml`, in a change of
its own.

Install the two test tools once. They are not in the toolchain:

```bash
cargo install cargo-nextest --locked
cargo install cargo-insta --locked
```

## The loop

| When | Command |
|------|---------|
| While editing | `cargo check -p <crate>` |
| Tests, while editing | `cargo nextest run --profile fast` (whole workspace, about 15 s warm), or `-p <crate>` |
| Before a commit | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo xtask check-layers` |
| Everything | `cargo nextest run --workspace --profile ci`, then `cargo test --workspace --doc` |
| The engine's invariant scripts | `bash scripts/engine/check-io-free.sh`, `bash scripts/engine/check-names.sh`, `bash scripts/engine/validate-skills.sh` |
| Lint and types, Python and Rust | `scripts/ci-local.sh --quick` |

`Cargo.lock` is what cargo resolves, and CI builds with `--locked`. If a command rewrites it in a
change that is not about dependencies, restore it with `git checkout -- Cargo.lock`. The
`cargo xtask` alias passes `--locked` itself (`.cargo/config.toml`).

For one-shot runs (a check, a review, CI-like verification), set `CARGO_INCREMENTAL=0`: there is
then no incremental cache to grow in the target directory.

## clippy and the workspace lints

The lint levels are in the root `Cargo.toml`, `[workspace.lints]`. Every member sets
`[lints] workspace = true`, except `opentide-syntax` and `opentide-wasm`, which copy the table with
`unsafe_code = "deny"` (below). `clippy.toml` only tunes lints, and `rustfmt.toml` writes down
rustfmt's defaults.

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

- `-D warnings` turns every `warn` in the table into an error, as in CI. `clippy::pedantic` is on,
  except the lints the table allows, each with its reason.
- `unwrap`, `expect`, `dbg!`, `todo!` and `unimplemented!` are denied outside tests. `clippy.toml`
  allows the first three in `#[test]` functions and `#[cfg(test)]` modules. Where a value cannot
  fail (a catalog compiled in, a regex literal), put
  `#[expect(clippy::expect_used, reason = "...")]` on the narrowest item. An integration test
  file's helpers outside `#[test]` take a `#![expect]` at the top of the file.
- To silence a lint, use `#[expect(lint, reason = "...")]` where it fires: a stale expectation then
  fails the build. Use `#[allow]` only where an expectation cannot be fulfilled, and say why beside
  it. Adding a lint to the workspace allow-list is a decision of its own, with its reason, never
  part of a fix.
- `unsafe_code` is forbidden outside `opentide-syntax` and `opentide-wasm`, and every `unsafe`
  block needs a `// SAFETY:` comment. `xtask/tests/lint_policy.rs` fails when a crate leaves the
  workspace table, or when one of those two crates' copies of it drifts.
- `missing_docs` holds for every new crate. Inaccurate docs are worse than none.
- Code under `cfg(target_arch = "wasm32")` is linted only for that target:
  `bash scripts/engine/build-wasm.sh clippy` (CI's `engine-wasm` job).

## nextest

The profiles are in `.config/nextest.toml`.

| Profile | Use |
|---------|-----|
| `fast` | The agent loop. It leaves out the stdio server tests, the Pydantic comparison, the deep-nesting test and the public corpora. `--ignore-default-filter` runs everything |
| `ci` | As CI runs it: `fail-fast = false`, no retries, JUnit at `target/nextest/ci/junit.xml` |
| default | Everything |

```bash
cargo nextest run --profile fast -p xtask
cargo nextest run --workspace --profile ci
cargo test --workspace --doc
```

- nextest does not run doctests: run `cargo test --workspace --doc` as well.
- Each test runs in its own process: a test cannot rely on a `OnceLock` or other static that
  another test filled.
- The tests that compare the engine with the Pydantic models run `.venv`'s interpreter: run
  `uv sync --group dev` first (`OPENTIDE_PYTHON` names another).
- A flaky test is a bug. No profile retries, and none may be added.

## insta (snapshots)

`insta::assert_snapshot!` keeps the expected text in a `snapshots/` directory next to the test's
source file (`tests/snapshots/*.snap` for an integration test). It is committed and reviewed like
code. Snapshot what a contract fixes (a diagnostic's code, range and message, a renderer's output),
never a whole struct.

```bash
cargo nextest run -p opentide-analysis --test snapshots
cargo insta review
```

- After an intended change, run the test, then `cargo insta review` (or
  `INSTA_UPDATE=always cargo test -p <crate> --test <name>`). Read every diff before you accept it.
- CI sets `INSTA_UPDATE=no`: a changed or missing snapshot fails, and nothing is written.
- Never commit a `.snap.new` (it is gitignored).

## trycmd (command-line cases)

`tests/cmd/*.trycmd` hold a binary's commands with their output and exit status (`? 2`). The
directory `tests/cmd/<case>.in/` is the case's working directory, and `[..]` elides a part that
varies. `opentide-lsp` and `xtask` use it.

```bash
cargo nextest run -p xtask --test cli
```

After an intended change, `TRYCMD=overwrite cargo test -p <crate> --test cli` rewrites the expected
output. Read the diff before committing.

## xtask

`cargo xtask <command>` is the repository's Rust tooling ([`xtask/AGENTS.md`](../../../xtask/AGENTS.md)).

```bash
cargo xtask help
cargo xtask check-layers
```

- `check-layers` checks every dependency between workspace crates (normal, build and dev, on every
  target) against [`xtask/layers.toml`](../../../xtask/layers.toml). A crate may depend only on a
  lower layer, or on a lower tier of its own layer.
- **A new crate:** add it to `members` in the root `Cargo.toml` (members are listed, not globbed),
  set `[lints] workspace = true`, place it in `xtask/layers.toml` in the same change, and give it an
  `AGENTS.md`. `check-layers` fails until the crate is placed. Moving a crate between layers is a
  design decision for the maintainer, never a fix for a red check.
- `codegen [--check]` writes the artifacts generated from the Rust model and, with `--check`,
  compares them and what `opentide generate` writes with the golden recordings (UC-1.8, #814).
  A new command whose work item has not landed is a stub that exits 1 and names it; a stub never
  exits 0.

## Worktrees and target pools

Agents working at the same time each take a git worktree, and a Cargo target directory (a pool) of
their own, outside the worktree. The root [`AGENTS.md`](../../../AGENTS.md), "Parallel agents:
worktrees and target pools", has the recipe and the reasons. The rules:

- `CARGO_TARGET_DIR` is absolute. cargo resolves a relative one against each command's working
  directory, so a run from a subdirectory starts a new multi-GB target there.
- One pool per worktree in use. Never share one between two worktrees at the same time: cargo
  judges a workspace crate fresh by modification times, so it can run the other worktree's code
  without a word.
- When a pool passes to another worktree, touch the tracked files first:
  `git ls-files -z | xargs -0 touch -c`. `touch -c` does not recreate a file you deleted.
- `CARGO_INCREMENTAL=0` for one-shot runs.
- Keep a pool's environment the same (`RUSTFLAGS`, `CARGO_PROFILE_*`): a change rebuilds the
  workspace crates. CI's `engine` job sets `CARGO_PROFILE_DEV_DEBUG=line-tables-only`.
- A warm pool is several GB. Check `df -h /` and delete a pool nothing uses any more.

## Do not

- Lint with a toolchain other than the pinned one, or drop `-D warnings`.
- Grow the workspace allow-list, add an exclude, or retry a test, to get green.
- `#[ignore]`, delete or weaken a test (or skip or xfail a pytest) to get green. A failing test is
  fixed at its cause.
- Commit a rewritten `Cargo.lock` with a change that is not about dependencies.
- Hand-edit a snapshot or a trycmd case: regenerate it and review the diff.
- Point two worktrees at one target pool at the same time.
