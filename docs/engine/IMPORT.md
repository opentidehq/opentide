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
| `.github/workflows/` | `.github/engine-workflows/` |
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
- **Workflows.** GitHub runs only `.github/workflows/`. language-server's `release.yml` triggers on `v*.*.*` tags, which opentide's releases push, and would publish the engine crates and npm packages, so it must not run here; its `ci.yml` collides by name. They wait in `.github/engine-workflows/` for UC-0.3, which rebuilds CI. `oracle.yml` moved on to `.github/workflows/` (without its tag trigger), so the vendor-parser oracles keep checking the engine.
- **Commit messages.** A bare `#N` in a language-server commit message became `opentidehq/language-server#N`, so it still names the issue or pull request it meant.

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

- One Cargo workspace at the root, with `analysis/` a member that takes `opentide-analysis` and `opentide-lsp` by path. Its lock is language-server's with PyO3 and its dependencies added at the versions `analysis/Cargo.lock` held. `hatch_build.py` builds the `_native` library of the workspace and finds it in cargo's JSON messages.
- Paths inside the moved files follow the move: `include_str!` and build scripts (`OPENTIDE_ASSETS` points at `data/catalogs/`), crate tests, scripts, docs, skills and parked workflows. Generated files keep their bytes: `data/catalogs/`, `highlights/generated/`, `highlights/queries/tide/highlights.scm` and the grammars' `src/` are what language-server 0.11.0 compiled in, so a header naming its generator still names the script's path before the import until the next regeneration.
- The cross-repository machinery is gone: `scripts/build/check_engine_pin.py`, `scripts/build/check_engine_catalog.py` (now `tests/test_generation/test_bundled_tide_catalog.py`), `opentide-canary.yml` and `requirements-opentide.txt`. `scripts/engine/sync_opentide_schemas.py` and `tide_corpus.rs` read `src/opentide`.

## Repeating it at a later commit

If language-server `main` moves after this import, run the invocation above with the new commit in `sha`. git-filter-repo rewrites a commit to the same hash when its content, parents and message are the same, so the filtered history up to `6f2ad70` is the history already merged here, ending at `86ac6b88`, and the new commits follow it. Merge the new filtered tip into a branch of this repository: only the new commits come in. Paths in their changes need the same follow-up as above.
