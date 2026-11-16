# CI simplification proposal: opentide `integration/unified-core`

Read at `origin/integration/unified-core` @ 29e5e8c2a (2026-11-16). Timings come from the GitHub API:
PR runs 43852953810 and 43852762894, push 43852636429, and the nightly-scope Run workflow 43794001108.
No `schedule` run of this branch's ci.yml exists yet. Nothing was built or pushed.

## 0. Verdict in one paragraph

The **PR fast path is already well designed**. It has one planner (`scripts/ci/changes.py`), affected-crate
testing, one `build` job, one wheel (`native`), a single required `PR gate`, sccache with a weekly key and
correct concurrency. Keep it. The PR fast path has three real problems:

- `engine-wasm` is the long pole at 13 to 16 min, against the 5/8 min budget. It builds the WASI CLI that
  `wasi` also builds, and it builds native `opentide-lsp`/`opentide-cli` in another cache family.
- Two path filters are written as bash inside `build`.
- `xtask stubs --check` runs only nightly.

The **mess is in the release and nightly tiers**:

- The same smoke jobs are copy-pasted in `ci.yml` and `publish.yml`.
- Three overlapping wheel smokes and three overlapping npm checks.
- Six `npm (<platform>)` jobs that only copy two tarballs.
- Two fuzz runs every night.
- A PyPI dry run that rebuilds the wheel and sdist that `packages` already built.
- About 20 nightly-only jobs inlined in `ci.yml`, each behind `mode == 'nightly'`.

The fix is grouping and de-duplication, not a new architecture.

## 1. Inventory

### 1a. ci.yml (44 jobs, 2505 lines). Tiers come from `changes`: pr / full (push, `scope: full`) / release (release PR, `scope: release`) / nightly

| Job | Guards | Runs on | Typical | In `gate` |
|---|---|---|---|---|
| `changes` | plan: tier, affected crates, nextest filter | all | 0.2 m | yes |
| `lint` | ruff, ty (on checked-in `_native` stubs), actionlint, invariants, skills, tests/test_ci | PR (paths) / full | 0.3 m | yes |
| `engine-lint` | fmt, clippy ×2, rustdoc, workspace-wide | PR (rust) / full | 2.7–4.4 m | yes |
| `native` | maturin dev wheel for Python jobs | PR (python/gitlab) / full / nightly | 1.6–2.4 m | yes |
| `build` | affected crates' nextest + doctests, layers, cassettes, codegen, highlights, vocab/spec-fields, trybuild, CLI snapshots on generated workspaces | PR (rust) / full | 8.7 m PR, 17.7 m push | yes |
| `python` | pytest 3.14 package + E2E + coverage gate | PR (python) / full | 2.1 m | yes |
| `gitlab-ci-lint` | rendered GitLab pipeline linted | PR (paths) / full | 0.3 m | yes |
| `docs` | validate-docs + wheel-less docs tests | PR (docs) / full / release | 0.3 m | yes |
| `facade` | all-features rustdoc, semver-checks | PR (facade) / full | 6.7 m | yes |
| `node` | napi addon (linux), generated d.ts, npm test | PR (node) / full | 4–5 m | yes |
| `wasi` | `build-wasm.sh cli`, size budget, serve test | PR (wasi paths) / full | 3.5–5.1 m | yes |
| `engine-wasm` | browser + WASI builds, wasm clippy, npm packs, native lsp/cli build, TS client tests | PR (parser paths) / full / nightly | **12.5–16 m (long pole)** | yes |
| `grammars`, `textmate` | parser.c regenerate; TextMate | PR (paths) / full | 0.2 m | yes |
| `deny` | cargo deny (workspace, fuzz/, placeholder) | PR (paths) / full | 0.4 m | yes |
| `sdist`, `smoke-sdist` | maturin sdist + twine; build from sdist | release | n/a | yes |
| `packages` → build-packages.yml | 6 wheels, 6 wheel-smoke, 6 npm-native, npm-pack, 6 npm-platforms | release, nightly | 20 m wall, about 160 runner-min | yes |
| `smoke-wheel` ×4, `smoke-npm` ×3 | pip / npm install on each OS | release | n/a | yes |
| `engine-release-dry-run` → engine-release-build.yml | 6 binaries, wasm, highlights, licences, SBOM, assets | release, nightly | 24 m wall, about 125 runner-min | yes |
| `smoke-installer` ×4, `smoke-cargo` | installers, `cargo install` from packages | release | n/a | yes |
| `engine-package` | cargo package + licence scan | release, nightly | 7.4 m | yes |
| `publish-dry-run` → publish-dry-run.yml | placeholder crate/npm; **pypi job rebuilds wheel+sdist** | release, nightly | 11.4 m (pypi) | yes |
| `test-full` ×4, `e2e-full` | Python 3.10–3.13; full_set E2E | release, nightly | about 2 m each | yes |
| `engine-test-os` ×2 | workspace nextest macOS/Windows (cold) | nightly | 22–25 m | no (report) |
| `conformance` ×3 | Rust/Python/Node byte-equal, 3 OSes | nightly | 11 / 43 / 37 m | no |
| `coverage`, `benchmarks` (bench.yml ×2), `oracle` (7 jobs), `schema` | strength, perf, vendor oracles, schema abi3/wasm/stubs | nightly | 35, 10+28, 1–4 each, 19 m | no |
| `fuzz-smoke` ×8 | 60 s per target, 18 targets | nightly | 11–16 m each, about 100 runner-min | no |
| `npm-install` | dev addon → local registry → npm install (linux) | nightly | 4.4 m | no |
| `elastic-sweep`, `clients`, `bench` (informational), `cli-windows-smoke`, `engine-release-consumers` | misc | nightly | 2–13 m | no |
| `gate` (`PR gate`) | needs 26 jobs; success-or-skipped | all | 0.1 m | the only required check |
| `nightly-report` | issue `nightly-failure` | nightly | 0.2 m | no |

The nightly-scope run had 95 jobs, about 705 runner-min and 44 min wall.

### 1b. Other workflows

| Workflow | Trigger | Notes |
|---|---|---|
| build-packages.yml, engine-release-build.yml, publish-dry-run.yml, coverage.yml, bench.yml, oracle.yml, schema.yml | `workflow_call` (+ dispatch) | called by ci.yml; the first two also by publish.yml |
| publish.yml (1180 lines) | dispatch | guard → checks → builds → **its own copies of sdist / smoke-sdist / smoke-wheel (3 OS) / smoke-npm / smoke-cargo / smoke-installer** → attest → release → registries |
| engine-fuzz.yml | schedule 02:43 daily, 18 targets × 600 s | duplicates ci's `fuzz-smoke` (same targets, shorter) |
| rust-audit.yml | schedule daily | overlaps nightly `deny` (advisories); opens its own issue |
| mutants.yml | weekly | fine |
| codeql.yml | push / PR (paths) / schedule | path filter **twice**: `on.pull_request.paths` and an in-job diff step |
| vocab-upstream.yml, cache-report.yml | weekly | fine |

### 1c. Findings (checked against the files)

**Duplication**

- **Smoke jobs are copy-pasted.** `sdist`, `smoke-sdist`, `smoke-wheel`, `smoke-npm`, `smoke-installer` and
  `smoke-cargo` exist in both ci.yml and publish.yml. The step diffs are only `ref:`, plus one version line in
  `smoke-cargo`. They have already drifted: `smoke-wheel` covers 4 OSes in ci.yml and 3 in publish.yml
  (publish.yml has no linux-arm64).
- **Three wheel smokes.** `build-packages.yml` `wheel-smoke` runs on 6 platforms, including the native
  `macos-15-intel` and `windows-11-arm` runners. It does pip install, `--version`, the `_native` version, a KQL
  check, `smoke_package.py`, `setup` and `doctor`. That is a strict superset of ci/publish `smoke-wheel`, which
  does pip install and `smoke_package.py` on 4 or 3 OSes.
- **Three npm checks.** `node` (PR), `npm-install` (nightly: rebuilds a dev addon and runs the local-registry
  test) and `smoke-npm` (release: the same local-registry script on the packaged tarballs). In the nightly
  `packages` builds every npm tarball, but `smoke-npm` does not run on them; `npm-install` builds a new addon
  instead.
- **`npm-platforms` ×6 does no work.** Each job copies 2 tgz into a new artifact, 0.1 m per job; it is job
  overhead and graph noise.
- **Two fuzz runs every night.** ci `fuzz-smoke` (8 jobs × 60 s/target) and `engine-fuzz.yml` (18 jobs × 600 s)
  fuzz the same targets about 1.5 h apart.
- **`publish-dry-run.yml` `pypi` duplicates `packages`.** It rebuilds the sdist and a wheel (11.4 m) that
  `packages`/`sdist` already built in the same run. Only its assertion ("one version, cp310-abi3 wheels, one
  sdist") is unique.
- **`engine-package` (ci) duplicates publish.yml `checks`.** Both run the same `cargo package` and licence scan.
- **The WASI CLI is built twice on parser PRs.** `wasi` runs `build-wasm.sh cli` (278 s), and `engine-wasm` runs
  `build-wasm.sh`, which builds it again (314 s for all artifacts). `engine-wasm` also runs
  `cargo build -p opentide-lsp -p opentide-cli` natively (227 s) in the `full-set` cache family, which
  `build` already compiles in its own family.
- **Path filters are written twice.** `build` has bash diffs for the specifications (vocab/fields) and the
  trybuild inputs, outside `changes.py` and its tests. CodeQL filters by `on.paths` and by an in-job diff.

**Cache problems behind the long pole**

- The wasm builds in `engine-wasm` restore `sccache-full-set-Linux`, which `conformance` saves from native
  builds only, so no wasm32 compile is ever in it.
- The `wasi` family is saved only from `schedule` or `refs/heads/development`, never from a push to
  `integration/unified-core`, the branch these PRs target.
- So the wasm jobs build cold on every PR.

**Gaps**

- `cargo xtask stubs --check` (the `_native/*.pyi` that `lint`'s ty runs on) runs only in nightly `schema.yml`.
  A PR can change the binding, leave stale stubs and pass ty.
- Stale docs:
  - `docs/internal/unified-core.md` §"Maintainer steps outstanding" still lists required checks
    `Golden compare`, `Fuzz smoke (cql)` and `Engine release (dry run) / SBOMs`.
  - `scripts/ci-local.sh` comments refer to `engine-test` and `fuzz-smoke`.
  - `--full` runs `xtask lsp parity`, which no workflow runs.

**Never fail usefully, or belong elsewhere**

- **`bench.yml` `engine: python`** (10 m) measures the frozen Python CLI, which by the 2026-11-14 decision is
  compared by hand only.
- **`bench` (informational)** runs `cargo bench` for analyze with `continue-on-error`. The budgeted
  `benchmarks` job is the real check.
- **`clients`** is informational (`continue-on-error`).
- **The release-tier jobs inside `gate`'s `needs`** (14 of its 26) are fine but make the PR graph look huge.
  They only run on release PRs.

**Wall-time waste in packaging**

- `wheel-smoke` needs the whole `wheels` matrix, so every smoke starts after the slowest wheel
  (windows-x64, 19 m). Smokes started at +19.6 m and took 0.2–1.2 m.
- Each target is compiled 3 times with `lto = true, codegen-units = 1`: wheel, npm addon and binaries are
  separate jobs, 18 release builds in all.

**Measured, so I do not recommend: a nextest archive shared by test partitions.** `build`'s comment records the
2026-11-14 measurement: a 1.5 GB archive took 18 s to pack, 15–33 s to download and 41 s to extract per
partition, against 42–48 s of tests. Building and testing in one job is right at this size.

## 2. Target design: four tiers, one entry point

The current "one ci.yml" decision (.github/AGENTS.md, 2026-11-14) stays: ci.yml remains the only entry point
for PR, push, nightly and release-PR runs. The heavy tiers move into **two reusable workflows**, so the graph
groups them as `Release build / …` and `Nightly / …` and ci.yml holds only the fast path.

```
ci.yml
 ├─ changes ─┬─ lint ─ engine-lint ─ build ─ native ─ python ─ (path jobs: docs, facade, node, wasm,
 │           │                                                  grammars, textmate, gitlab-ci-lint, deny)
 │           ├─ release  → uses release-build.yml  (release PR, nightly)  ← publish.yml calls the same file
 │           └─ nightly  → uses nightly.yml        (schedule / scope: nightly)
 ├─ gate   ("PR gate": changes + fast-path jobs + release)
 └─ nightly-report
```

### Tier A: PR fast path (Linux, affected only; budget 8 min cold)

The jobs are unchanged except for the following.

| Change | Why |
|---|---|
| **Merge `wasi` and `engine-wasm` into one `wasm` job.** It runs `build-wasm.sh` once (browser + WASI LSP + WASI CLI), checks the WASI size budget and runs the `wasi-host` serve test. | Removes the duplicate WASI CLI build (about 4.5 runner-min per parser PR) and one job. |
| **Move the native `opentide-lsp`/`opentide-cli` build and the lsp-client TS tests** out of the PR path. They run on push/full, or on a PR only when `packages/` changes (new `changes.py` area). | 227 s of native build that `build` already does. These tests check the TS client, not the parser layer that triggers the job on PRs. |
| **Move `build-wasm.sh clippy` into `engine-lint`** (same `engine-check` family), run when `wasm == true`. | Lint belongs with lint and runs in parallel. `wasm` drops to about 5–6 m, below `build`'s 8.7 m. |
| **Give `wasm` its own `sccache-wasm` family**, saved by every push to a base branch (the same rule as `build`). | Today the wasm compiles never hit a cache on PRs (§1c). |
| **Add `cargo xtask stubs --check` to `native`** when the binding or schema changes (`changes.py` output `stubs`). Fold schema.yml's abi3/wasm32 clippy into `engine-lint` (feature `python`) or the nightly. | Closes the stale-stub gap; schema.yml goes. |
| **Move `build`'s bash filters (specs vocab/fields, trybuild inputs) into `changes.py`** as outputs `specs`, `fields`, `schema_ui`, with cases in `tests/test_ci/test_changes.py`. | One tested planner; no second path language in YAML. |

**Expected effect:** parser-crate PRs go from 13–16 m to about 9–10 m. `build` becomes the long pole, and
`wasm` warm is about 5 m. Other PRs are unchanged.

### Tier B: push to a base branch (`full`)

No change in scope: the same jobs with every filter on, Linux only, and sccache saved. Push is the only cache
saver. The PR bootstrap save stays as it is.

Merge queue: **not recommended now.** Stacked PRs dominate here, and `merge_group` would put the 17.7 m full
build in front of every merge. Revisit only if post-merge reds on `integration/unified-core` become frequent.

### Tier C: nightly (`nightly.yml`, `workflow_call` from ci.yml; never gates; one issue)

| Keep | Change |
|---|---|
| `engine-test-os` (macOS, Windows), which caught real Windows bugs (`fix/windows-*` runs on 2026-11-16) | none |
| `conformance` ×3, `coverage`, `oracle`, `elastic-sweep`, `engine-release-consumers`, `clients` | none |
| Fuzz | **Drop ci's `fuzz-smoke`.** Call `engine-fuzz.yml` (made `workflow_call` with a `seconds` input) from `nightly.yml`, so one fuzz run reports through `nightly-report`. Its own schedule goes. About −100 runner-min. |
| Python 3.10–3.13 + full_set | **One job, `python-matrix`**, looping `uv run --python 3.1x pytest` on `native`'s abi3 wheel. Also run on release PRs. Saves 4 setups. |
| npm | **Drop `npm-install`.** `release-build`'s per-target smoke runs the same `npm-local-registry/test.mjs` on the real tarballs, nightly too. |
| `cli-windows-smoke` | Keep the tests (launcher, Ctrl-C). Run them on the **windows-x64 wheel from `release-build`** instead of `uv sync`, which compiles the engine cold on Windows (13 m → about 3 m). |
| Benchmarks | Keep `bench.yml` `rust` (budgeted). **Drop the `python` engine cell** (frozen oracle; record its baseline once) and the informational `bench`, unless the maintainer still reads them. |
| `deny` advisories | Already run nightly through the full set. **Optionally retire rust-audit.yml** and let `nightly-report` file the issue. Keep it if the per-advisory issue title matters. |
| Release build | `release-build.yml` with `smoke: true`, the same as on release PRs, so installers are smoke-tested nightly too (today they are not). |

### Tier D: release (`release-build.yml`, called by ci.yml on release PRs and nightly, and by publish.yml)

This merges build-packages.yml, engine-release-build.yml, the sdist/smoke jobs and engine-package into **one
reusable workflow, with one copy of each smoke**:

| Job | Matrix | Content |
|---|---|---|
| `meta` | none | versions/tag (merges `versions` and `meta`) |
| `target` | 6 targets on **native runners** (ubuntu-latest, ubuntu-24.04-arm, macos-15-intel, macos-latest, windows-latest, windows-11-arm) | Wheel (maturin-action, manylinux on Linux) + npm addon + `opentide`/`opentide-lsp` binaries, then **smoke on that runner**: pip install + doctor, npm addon load, binary `--version`. |
| `wasm`, `highlights`, `licences`, `sbom`, `sdist`, `crates` (engine-package) | none | as today |
| `assemble` | none | npm-pack (packs all 6 platform packages, which replaces `npm-platforms` ×6), release assets, installers, SHA256SUMS, the dist-shape assertion taken from publish-dry-run `pypi` |
| `smoke` | 6 OSes (`linux-x64`, `linux-arm64`, `macos-arm64`, `macos-x64`, `windows-x64`, `windows-arm64`) | Installer from assets, npm local registry from the packed tarballs, pip from wheels. Linux-x64 also runs sdist build and `cargo install` from crates. One script, `scripts/build/smoke_release.sh` (+ `.ps1`). |
| `placeholders` | none | publish-dry-run's crate and npm placeholder checks (40 s); its `pypi` job is dropped |

**Effect:**

- Packaging and smoke go from about 48 jobs (6+6+6+1+6 packages, 7+5 engine release, 4+3+4+1+1+1 smokes,
  1 engine-package, 3 publish-dry-run) to about **20**.
- ci.yml loses about 350 lines.
- publish.yml loses about 400 lines and keeps only guard → `uses: release-build.yml` → attest → release →
  registries.

**Trade-offs:**

- A per-target job grows to about 25–30 m on Windows.
- Moving cross-builds to native runners depends on `macos-15-intel` and `windows-11-arm` capacity. Both are
  already used for smoke and npm-native.
- One failure now costs the whole target, not just one artifact.
- The shared-compile saving (wheel, addon and binaries share all dependency crates per target, but the
  `python`/`napi` features differ at the top) is **unmeasured**. Do it in two steps: 5a merges only the
  smoke jobs; 5b merges the builds, behind a timing comparison on one dispatch run.

### Guarantees kept

- Every affected language crate's tests run on PRs (`build`, unchanged).
- CLI snapshots on generated workspaces (unchanged).
- The wasm build runs when parser crates change.
- `cargo deny` on PR paths and on every push/nightly.
- macOS/Windows engine tests, conformance and the Windows CLI smoke run nightly.
- Every artifact is smoke-tested on its OS on release PRs, publish and nightly.

### What is dropped, and the risk

| Dropped | Risk |
|---|---|
| ci `fuzz-smoke` | None: engine-fuzz runs the same targets 10× longer the same night. |
| `npm-install` | It tested a dev-profile addon. The release smoke tests the shipped one, which is better. |
| `smoke-wheel` (ci and publish) | Subsumed by the per-target smoke. |
| publish-dry-run `pypi` | Its maturin invocation differs from `packages`'s. Keep the dist-shape assertion; check once that the args are the same. |
| `bench --engine python`, `bench` (informational) | Lose the oracle's perf trend. |
| `npm-platforms` ×6 | Downstream consumers of `npm-<platform>` artifacts (publish.yml `npm`) must read the single `npm-packages` artifact instead. |
| schema.yml | Its abi3/wasm32 clippy must land in engine-lint or the nightly first. |

## 3. Concrete simplifications and estimated savings

| # | Change | Saving |
|---|---|---|
| 1 | Composite actions `.github/actions/rust-setup` (rustup from `rust-toolchain.toml`, targets, `taiki-e` tools, sccache env, week key, restore) and `.github/actions/sccache-save` (stats + save-if-missed). Two actions, because a composite cannot own the post-save policy. They replace 13 restore blocks, 13 week steps and 21 `rustup toolchain install`s in ci.yml, plus 2 restores, 2 week steps and 10 installs in engine-release-build.yml. | about −450 YAML lines; the save rule lives in one place |
| 2 | One `wasm` job with its own cache family; native build and wasm clippy moved out of it | PR wall −4 to −6 m on parser PRs; about −8 runner-min per parser PR |
| 3 | Path filters only in `changes.py` (specs, fields, trybuild, packages/, stubs) | −2 bash filters; all of them tested |
| 4 | `release-build.yml` + a single smoke script; ci and publish call it | −28 jobs per release run; about −750 YAML lines |
| 5 | Drop nightly `fuzz-smoke`, `npm-install`, python bench, info bench, publish-dry-run `pypi`; `cli-windows-smoke` on the wheel; one python-matrix job | nightly about 705 → about 540 runner-min, 95 → about 60 jobs |
| 6 | Smoke per target in the same job as the build | removes the wait for the slowest wheel (+19.6 m start); nightly/release wall about −10 m |
| 7 | Naming: job ids `<area>-<verb>` (`rust-lint`, `rust-test`, `py-test`, `wasm-build`, `release-target`, `release-smoke`), display names `Area: what` | the graph reads as tiers |
| 8 | `gate` reads its needs from two lists, fast path plus `release` (one `uses` job), not 26 ids | the gate stays short and less likely to drift |
| 9 | Caches: fewer families (`build`, `native`, `check` (lint + wasm clippy), `wasm`, `full-set-Linux`, `release-<target>`). Each of oracle.yml's 6 `Swatinem/rust-cache` entries builds only `opentide-lsp`/xtask: share one key (`shared-key: oracle`). | less eviction under the 10 GB limit |
| 10 | Concurrency: already right (PR cancels, push/nightly unique). Add the same group to `nightly.yml`/`release-build.yml` only through the caller; no change needed. | n/a |

## 4. Migration plan: small, independently safe PRs

Each PR updates `tests/test_ci/test_workflows.py` / `test_changes.py` and `.github/AGENTS.md` in the same
change, and is proven by a Run workflow with the right `scope` on its branch.

1. **ci: composite `rust-setup` and `sccache-save`.** Mechanical; cache keys stay identical, so no cold week.
   Verify that sccache hit rates are the same on one PR run.
2. **ci: path filters into `changes.py`** (`specs`, `fields`, `schema_ui`), with test cases. `build` reads the
   outputs.
3. **ci: one `wasm` job.** Merge `wasi` and `engine-wasm`, put wasm clippy in `engine-lint`, add a `packages`
   area for the TS client tests, add the `sccache-wasm` family saved on push. Measure a parser PR before and
   after.
4. **ci: `stubs --check` in `native`.** Move schema.yml's checks, then delete schema.yml.
5. **release, step a: `release-build.yml` = build-packages + engine-release-build + sdist + crates + one smoke
   matrix.** ci.yml's release tier and publish.yml call it; delete both copies of `smoke-*`, `npm-platforms`
   and publish-dry-run `pypi`. Verify with `scope: release` and publish.yml `dry_run`.
6. **release, step b (optional, measured): per-target build + smoke in one job on native runners.** Merge only
   if a dispatch shows runner-min and wall time no worse.
7. **nightly: `nightly.yml` reusable.**
   - Move the nightly-only jobs into it.
   - Call `engine-fuzz.yml`; drop `fuzz-smoke`.
   - Drop `npm-install` and the python/info benches (maintainer confirms).
   - Make python-matrix a single job; run `cli-windows-smoke` on the wheel.
   - Optionally retire rust-audit.yml.
   - Verify with `scope: nightly`.
8. **docs: sync.** Update `.github/AGENTS.md` (tier tables, cache families), the stale required-check list in
   `docs/internal/unified-core.md` §Maintainer steps outstanding, and `scripts/ci-local.sh` (job names; decide
   whether `xtask lsp parity` belongs in CI or out of `--full`).

**Required checks after the change:** still exactly **`PR gate`**. It needs `changes`, the fast-path jobs
(`lint`, `engine-lint`, `native`, `build`, `python`, `gitlab-ci-lint`, `docs`, `facade`, `node`, `wasm`,
`grammars`, `textmate`, `deny`), `python-matrix` and `release`. Release-PR-only jobs are skipped elsewhere.
Nothing else goes in branch protection. CodeQL stays path-scoped and unrequired. If it should gate, move it into
ci.yml under `changes` (`pylint || ci`) and add it to `gate`'s needs, which also removes its duplicate filter.
