---
name: golden
description: Hold the command line to its snapshots - the Rust-owned insta snapshots of every case of tests/golden/cases.toml (crates/opentide-cli/tests/cli_snapshots.rs), their review with cargo insta, adding a case or a fixture, and the crate-level snapshot tables that pin the models, the compiler, the renderers and serve. Use when a change means to alter what a command prints or writes, when a snapshot test fails, when adding a case, a fixture or a cassette case, or when reviewing a pull request's .snap diffs.
---

# Snapshots: what the command line does

The command line's regression net is the Rust-owned snapshots of
`crates/opentide-cli/tests/cli_snapshots.rs` (#1139): every case of `tests/golden/cases.toml`,
in every output mode, on a fresh copy of its fixture, with the **Rust CLI's own output** as the
expected value. The Python CLI it was ported from is retired as a reference: no test compares
with it, and its recordings, ledger and tooling are in git history only.

**`tests/golden/README.md` is the reference** for the case and fixture layout, the modes and
environment, what a snapshot holds and the normalisation rules. Where this skill and the README
disagree, the README is right: fix this skill.

## A change that alters what a command prints or writes

1. Run `cargo nextest run -p opentide-cli --test cli_snapshots` (narrow it with
   `OPENTIDE_SNAPSHOT_FILTER=<part of a case id>`, a case id being
   `<command>/<mode>/<fixture>/<variant>`).
2. `cargo insta review`: read every diff; accept the ones the change means, fix the code for the
   rest. `INSTA_UPDATE=always` accepts every diff at once; then read `git diff` as you would have
   read the review.
3. Commit the `.snap` files with the change. The reviewer reads them as the user-visible diff:
   each changed line follows from the change, and the information a user or an agent relies on
   (exit code, error code, the fields of a JSON envelope, the files written) is still there.
4. A user-visible change is also a `## [Unreleased]` entry in `CHANGELOG.md`
   ([release-notes](../release-notes/SKILL.md)).

## The rules

1. **Never hand-edit a `.snap`, never commit a `.snap.new`.** A snapshot changes only by
   running the test and accepting the diff.
2. **Normalisation hides only what differs between two runs of the same case**: temporary
   paths, the clock, durations, crash-log names, catalog fingerprints, the spinner, and minted
   UUIDs where a case opts in. A rule is code in `crates/opentide-compare/src/normalise.rs` with
   a unit test; widening one to make a difference go away is a review failure.
3. **A new behaviour gets a case.** A `[[case]]` in `cases.toml` (its `args`, `modes`,
   `fixtures`, and `input`, `cassette` or `normalise` where it needs them); its snapshot is
   written on the first run outside CI, and CI (`INSTA_UPDATE=no`) fails on a missing one.
4. **A new fixture is declared, not built by hand**: `[fixtures.<name>]` in `cases.toml` (a
   `source`, `edits`, `pushed` edits for a git checkout), laid out by
   `crates/opentide-cli/tests/common/fixtures.rs`. Files it copies live in
   `tests/golden/fixtures/` (LF bytes, `.gitattributes`).
5. **A case that talks to a tenant is a cassette case** (`cassette = "<name>"`,
   `tests/cassettes/<name>.json`): the replaying proxy fails the run unless its requests are the
   cassette's. `cargo xtask cassettes check` checks every cassette's digest and redaction.
6. **What a snapshot case cannot run has a test of its own**, held to its own snapshot:
   `serve`'s session (`tests/serve.rs`), `generate extract sentinel`'s tenant run
   (`tests/extract_sentinel.rs`), the generated fixtures (`fault`, `heavy-small`), which `cargo
   xtask corpus` builds and the snapshots leave out.

## The crate-level tables

Below the command line, the same rules hold for these snapshot tests (each a table of cases,
first written to compare with the Python CLI, now held to the Rust result):

| Test | Pins |
|------|------|
| `crates/opentide-schema/src/objects/table.rs`, `objects/platform/table.rs` (`tests/tables/objects.json`) | the object models and platform blocks: every error's type, path, message, span, or the value |
| `crates/opentide-schema/tests/from_node_table.rs`, `yaml_table.rs`, `configuration.rs` (`tests/tables/`) | the structural conversion, the YAML 1.2 loader, the configuration checks |
| `crates/opentide-compile/tests/compile_corpus.rs` (`tests/golden/payloads/`) | every request body the compiler builds for the compile corpus |
| `crates/opentide-compile/tests/generate_docs.rs`, `setup_ci.rs` (`tests/docs_pages/`, `tests/ci/`) | the GitLab and Azure DevOps docs pages, `setup ci`'s pipelines, compared with committed files |
| `crates/opentide-cli/tests/render.rs` (`tests/render/`) | the renderers: code frames, SARIF, Code Quality, CI sinks, outcome lines, progress |

## Where to look

- The harness: `crates/opentide-cli/tests/common/snapshot.rs` (the case list, the run, the
  snapshot text) and `common/fixtures.rs` (the case root, the fixtures).
- The normaliser: `crates/opentide-compare/src/normalise.rs`.
- The nextest profiles: `.config/nextest.toml`; the Rust loop: [rust](../rust/SKILL.md).
