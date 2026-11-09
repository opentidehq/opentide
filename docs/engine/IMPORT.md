---
title: "Importing language-server"
description: "How opentidehq/language-server moved into this repository with its history: the source commit, the git filter-repo invocation, the path mapping, and how to repeat it at a later commit."
---

# Importing language-server

The engine crates, their grammars, catalogs, editors, npm packages, fuzz targets and test data came from [opentidehq/language-server](https://github.com/opentidehq/language-server) with their git history ([#800](https://github.com/opentidehq/opentide/issues/800), plan decision D-4). This page records how, so the import can be checked and repeated.

| | |
|---|---|
| Source | `opentidehq/language-server` `main` at `6f2ad70e4b4a0f29d9f83cc735e0600bf9995a6d`, release 0.11.0, 296 commits |
| Date | 2026-11-07 |
| Tool | git-filter-repo `a40bce548d2c`, git 2.43 |
| Filtered tip | `86ac6b88e927ce463e6e60a6a626f836a6b1589b` |
| Merge | `7ca7fb6d`, `git merge --allow-unrelated-histories --no-ff` on a branch from `development` at `f41fe5e5` (0.23.0) |

No language-server tag was imported: its tags are `vX.Y.Z`, the form of opentide's release tags.

### Imports since

| Source | Date | Filtered tip | Merge | New commits |
|---|---|---|---|---|
| `main` at `b92fa305296d0866d99e68081d9138313a535216`, release 0.12.0 (CQL), 308 commits | 2026-11-09 | `f0c19938dd45a2c74a32c43423d9cd5bee06f6f1` | `3833048b`, `git merge --no-ff` on a branch from `integration/unified-core` at `96ef1424` | 12: [language-server#221](https://github.com/opentidehq/language-server/pull/221) (the `opentide-cql` crate, its grammar, catalogs, corpus and editors) and the 0.12.0 release ([language-server#224](https://github.com/opentidehq/language-server/pull/224)) |

The 0.12.0 run used the invocation below with only `sha` changed. Its filtered history up to `6f2ad70` was the 296 commits already merged, ending at `86ac6b88`, so the merge brought in the 12 new commits and nothing else. The commits after it follow the paths and lints of this repository ([Repeating it at a later commit](#repeating-it-at-a-later-commit)): `opentide-cql` reads `data/catalogs/cql/`, takes the workspace lints and a place in `xtask/layers.toml`, its `fuzz.yml` target went to `engine-fuzz.yml` and the fuzz smoke, and `NOTICE`'s CQL licences ship with the package. `opentide validate` and `opentide lint` do not report its `cql_*` codes until CrowdStrike is in `OFFLINE_QUERY_LANGUAGES`; the editor and `opentide tui` do.

## Path mapping

| language-server | Here |
|-----------------|------|
| `crates/`, `grammars/`, `highlights/`, `editors/`, `packages/`, `fuzz/`, `licenses/` | unchanged |
| `catalogs/` | `data/catalogs/` |
| `testdata/` | `crates/testdata/` |
| `docs/` | `docs/engine/` |
| `scripts/` | `scripts/engine/` |
| `tests/clients/` | `scripts/engine/clients/` |
| `skills/release-notes/` | `.agents/skills/engine-release-notes/` |
| `skills/release/` | `.agents/skills/engine-release/` |
| `skills/` (the other skills, `README.md`) | `.agents/skills/` |
| `.github/workflows/` | `.github/engine-workflows/`; then `ci.yml` → `.github/workflows/engine-ci.yml`, `fuzz.yml` → `.github/workflows/engine-fuzz.yml`, `oracle.yml` → `.github/workflows/oracle.yml` |
| `AGENTS.md` | `crates/AGENTS.md` |
| `CHANGELOG.md` | `crates/CHANGELOG.md` |
| `README.md` | `crates/opentide-lsp/README.md` |
| `pyproject.toml` (removed in language-server before 0.5.0) | `crates/opentide-lsp/pyproject.toml`, history only |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.config/nextest.toml`, `NOTICE`, `about.toml`, `about.hbs`, `LICENSE` (byte-identical) | the repository root |

Why the files that do not map one to one went where they did:

- **Skills.** opentide already has `release-notes` and `release-management`, so language-server's `release-notes` and `release` take an `engine-` prefix; no skill is overwritten. `crates/AGENTS.md` indexes the engine's skills, and `scripts/engine/validate-skills.sh` checks them.
- **`AGENTS.md`** is the engine's agent guide, so it sits beside the crates, and the root `AGENTS.md` sends engine work there.
- **`CHANGELOG.md`** records the engine crates' releases: `crates/CHANGELOG.md`, which `scripts/engine/release.py` reads.
- **`README.md`** describes the `opentide-lsp` binary and was already that crate's crates.io readme.
- **`tests/clients/`** is a pytest-lsp suite for the server binary, with its own dependencies. Under `scripts/engine/` ruff lints it, and opentide's test suite, which collects `tests/`, does not run it.
- **Workflows.** The filter puts them in `.github/engine-workflows/`, where GitHub does not run them: language-server's `release.yml` triggers on `v*.*.*` tags, which opentide's releases push, and would publish the engine crates and npm packages, so it stays there until UC-0.3 gives engine releases tags of their own. The commits after the merge move the others on to `.github/workflows/` with their history, so the engine keeps every gate it had: `oracle.yml` (without its tag trigger), `ci.yml` as `engine-ci.yml` (its name collides with opentide's; its rustfmt, clippy, test and WebAssembly steps run in `ci.yml`'s `engine` and `engine-wasm` jobs) and `fuzz.yml` as `engine-fuzz.yml`.
  Since UC-0.3 (#801) `engine-ci.yml` is folded into `ci.yml`, `release.yml` is `.github/workflows/engine-release.yml` (on `engine-v*` tags) with its asset jobs in `engine-release-build.yml`, and `.github/engine-workflows/` is gone; `.github/AGENTS.md` maps each language-server job to its home.
- **Commit messages.** A bare `#N` in a language-server commit message became `opentidehq/language-server#N`, so it still names the issue or pull request it meant. A `#N` right after a letter, digit, `_`, `/`, `&`, `.` or `-` was left as it was, as the expression below says: the second half of `#120-#122` or `#20/#21` still reads as this repository's issue of that number.

The merge had two add/add conflicts, resolved in the merge commit: `.gitignore` kept opentide's rules followed by language-server's, and `.cursor/environment.json` kept opentide's.

## The invocation

```bash
src=https://github.com/opentidehq/language-server.git   # or a local clone
sha=6f2ad70e4b4a0f29d9f83cc735e0600bf9995a6d
git clone --no-local --no-tags --single-branch --branch main "$src" ls-import
cd ls-import
git checkout -B main "$sha"
printf '%s\n' 'regex:(?<![A-Za-z0-9_/&.-])#([0-9]+)\b==>opentidehq/language-server#\1' > ../messages.txt
git filter-repo --force \
  --path-rename scripts/:scripts/engine/ \
  --path-rename tests/clients/:scripts/engine/clients/ \
  --path-rename catalogs/:data/catalogs/ \
  --path-rename testdata/:crates/testdata/ \
  --path-rename docs/:docs/engine/ \
  --path-rename skills/release-notes/:.agents/skills/engine-release-notes/ \
  --path-rename skills/release/:.agents/skills/engine-release/ \
  --path-rename skills/:.agents/skills/ \
  --path-rename .github/workflows/:.github/engine-workflows/ \
  --path-rename AGENTS.md:crates/AGENTS.md \
  --path-rename CHANGELOG.md:crates/CHANGELOG.md \
  --path-rename README.md:crates/opentide-lsp/README.md \
  --path-rename pyproject.toml:crates/opentide-lsp/pyproject.toml \
  --replace-message ../messages.txt
git rev-parse HEAD   # 86ac6b88e927ce463e6e60a6a626f836a6b1589b

cd ../opentide        # a branch cut from origin/development
git fetch --no-tags ../ls-import main
git merge --allow-unrelated-histories --no-ff FETCH_HEAD
```

The renames apply in order, each to the result of the one before, so `scripts/` comes before `tests/clients/`. Every blob of the source tree is in the filtered tree under its mapped path, unchanged, and a second run gives the same filtered tip.

## After the merge

The commits after the merge make the imported tree build and test here:

- One Cargo workspace at the root, with `analysis/` a member that takes `opentide-analysis` and `opentide-lsp` by path. Its lock is language-server's, all 120 packages at the same versions, plus the 9 packages only `analysis/` needs (PyO3 and its dependencies) at the versions `analysis/Cargo.lock` held. One lock holds one version of a crate, so the 23 crates the two locks held at different versions take language-server's version: 14 move to the older version (among them `serde_json` 1.0.154 → 1.0.151, `syn` 3.0.9 → 3.0.5, `cc` 1.10.0 → 1.4.6, `thiserror` 2.0.21 → 2.0.20, `wasm-bindgen` 0.2.129 → 0.2.128) and 9 to the newer (`icu_*` 2.1 → 2.4, `idna_adapter` 1.2.1 → 1.2.2, `tree-sitter-language` 0.1.7 → 0.1.8), and `foldhash`, which only `serde_json` 1.0.154 used, drops out. 17 of the changes are in `_native`'s dependencies (`cargo tree -p opentide-native --target all`); the other six (`cfg-if`, `js-sys`, `wasm-bindgen*`) are only `opentide-wasm`'s. They are the versions language-server 0.11.0 was tested and released with, on every target opentide builds wheels for. `hatch_build.py` builds the `_native` library of the workspace and finds it in cargo's JSON messages.
- Paths inside the moved files follow the move: `include_str!` and build scripts (`OPENTIDE_ASSETS` points at `data/catalogs/`), crate tests, scripts, docs, skills and parked workflows. Generated files keep their bytes: `data/catalogs/`, `highlights/generated/`, `highlights/queries/tide/highlights.scm` and the grammars' `src/` are what language-server 0.11.0 compiled in, so a header naming its generator still names the script's path before the import until the next regeneration.
- The cross-repository machinery is gone: `scripts/build/check_engine_pin.py`, `scripts/build/check_engine_catalog.py` (now `tests/test_generation/test_bundled_tide_catalog.py`), `opentide-canary.yml` and `requirements-opentide.txt`. `scripts/engine/sync_opentide_schemas.py` and `tide_corpus.rs` read `src/opentide`.

## Repeating it at a later commit

If language-server `main` moves after this import, run the invocation above with the new commit in `sha`, cloning from GitHub (a local clone's `main` may be behind its `origin/main`). git-filter-repo rewrites a commit to the same hash when its content, parents and message are the same, so the filtered history up to `6f2ad70` is the history already merged here, ending at `86ac6b88`, and the new commits follow it. Merge the new filtered tip into a branch of this repository with a merge commit, never a rebase: only the new commits come in. Check first that the filtered history holds the merged tip (`git merge-base --is-ancestor 86ac6b88 <filtered tip>`) and that `git rev-list <filtered tip> ^HEAD` lists only the new commits; a different hash would duplicate the history. Paths in their changes need the same follow-up as above, and a change to a workflow lands in `.github/engine-workflows/`, which no longer exists: apply it to the job's home in [Where the workflows went](#where-the-workflows-went).

## Where the workflows went

Since UC-0.3 ([#801](https://github.com/opentidehq/opentide/issues/801)), each job of language-server's workflows has this home here, or was dropped for the reason given.

| language-server | Job | Here |
| --- | --- | --- |
| `ci.yml` | `test` | ci.yml `engine` (rustfmt, clippy, layers, rustdoc, invariants, schemas test), `engine-test` (tests, doctests), `engine-wasm` (npm packs, lsp-client stdio), `textmate` |
| `ci.yml` | `windows` | ci.yml `engine-test` (windows-latest), now the whole workspace |
| `ci.yml` | `clients`, `bench` | ci.yml `clients`, `bench`, still informational |
| `ci.yml` | `package` | ci.yml `engine-package` (packaging and licence scan); its `release.py` tests run in `engine` |
| `ci.yml` | `grammars` | ci.yml `grammars` |
| `ci.yml` | `wasm` | ci.yml `engine-wasm` |
| `ci.yml` | `elastic-sweep` | ci.yml `elastic-sweep` |
| `fuzz.yml` | `fuzz` | `engine-fuzz.yml` (nightly, ten minutes per target), and ci.yml `fuzz-smoke` (60 s per target, every PR) |
| `oracle.yml` | every job | `oracle.yml`, its tag trigger `engine-v*` instead of `v*.*.*` |
| `release.yml` | every job | `engine-release.yml` (`git mv`); `native`, `wasm`, `highlights` and the licences of `assets` moved to `engine-release-build.yml`, which ci.yml also runs as a dry run |
| `backfill-releases.yml` | `backfill` | dropped: a one-off for language-server's tags before 0.5 |
| `opentide-canary.yml` | `canary` | dropped: `tests/test_generation/test_bundled_tide_catalog.py` checks the bundled Tide catalog against this checkout's models |
