---
title: CI and release pipeline review (2026-11)
description: Every workflow and job, what each checks, what it costs, what repeats, and the changes ranked by saving and risk.
---

# CI and release pipeline review (2026-11)

The owner's brief: CI and the release pipeline have grown complex. Simplify them, make them faster,
and cut steps and jobs where that is possible, without losing any check that protects a merge or a
release. Out of scope here: `codeql.yml`, which #1779 changes separately.

The measurements come from GitHub's job timestamps on 2026-11-22:

| Run | What | Wall clock | Jobs | Job-minutes |
|---|---|---|---|---|
| [45034649508](https://github.com/opentidehq/opentide/actions/runs/45034649508) | publish.yml dry run (release build, no cache) | 32.4 min | 58 (50 ran) | 268 |
| [45034648407](https://github.com/opentidehq/opentide/actions/runs/45034648407) | ci.yml, a pull request that changed a workflow (every path filter on) | 18.6 min | 24 | ~120 |
| [45047043679](https://github.com/opentidehq/opentide/actions/runs/45047043679) | ci.yml, push to `integration/unified-core` (full tier) | 18.6 min | 24 (19 ran) | 86 |

Job-minutes are wall-clock minutes per job. They are not billed minutes: macOS and Windows runners
weigh more on a private plan.

## Safety properties every change keeps

The release-safety properties every change below keeps:

- **No compiler cache in a release build**, so nothing poisoned from a cache reaches a released
  artifact. Every cache step in the release workflows sits behind `inputs.dry-run`/`sccache`.
- Attestation, and verification of the published assets against `SHA256SUMS` and their
  attestations, **before any registry**.
- The **npm pre-flight check** in the guard, before anything is built.
- The **antivirus gate** in the release tier and the release train.
- **Trusted publishing** only (no stored token); only `attest`, `pypi`, `crates` and `npm` can
  mint an OIDC token.
- **Actions pinned by SHA**, least-privilege permissions, `persist-credentials: false`.
- **`PR gate`** needs every non-nightly job; a skipped job is skipped only because the change
  does not need it.

## Inventory

### ci.yml (pull request, push, release tier, nightly)

`changes` (scripts/ci/changes.py) decides the tier and what runs. The times below come from the
full PR run (45034648407) and the push (45047043679). "PR" means the job runs when its paths
change; the full tier runs every job.

| Job | Checks | PR run | Push | Notes |
|---|---|---|---|---|
| `changes` | the plan | 0.2 | 0.2 | |
| `lint` | ruff, ty, actionlint, sdist+twine, invariants, `test_release.py`, `tests/test_ci` | 0.9 | 0.7 | |
| `engine-lint` | fmt, workspace clippy, clippy w/o `terminal`, no-terminal test build, wasm32 clippy, schema `stubs`/wasm32 clippy, rustdoc, **in series** | **13.5** | 12.7 | the gate's longest job on most PRs (9.7 in the latest Rust PR) → **#1783** |
| `native` | the `_native` wheel (maturin, dev profile) for the Python jobs | 3.0 | 2.2 | |
| `stubs` | `xtask stubs --check` on 3.10 | 6.2 | 7.9 | its own compile of the extension with introspection |
| `wiring` | language and platform wiring tests | 2.3 | 2.0 | |
| `throughput` | callgrind instruction budgets | 7.6 | 4.8 | pinned to ubuntu-24.04 |
| `build` | the tests' build (7.1), nextest `ci` (8.8), doctests, trybuild (1.6), generated-file checks | **18.3** | **18.3** | the full tier's critical path; the full tier's 10 min budget is not met |
| `python` | pytest + E2E on 3.14, coverage gate | 1.3 | 1.6 | after `native` |
| `gitlab-ci-lint` | the rendered GitLab pipeline | 0.3 | 0.3 | |
| `docs` | validate-docs, docs tests | 0.2 | 0.2 | |
| `facade` | rustdoc every feature (2.8), `cli`/`queries` alone (1.9), default and no engines (2.2), semver-checks (3.4) | 10.5 | 13.2 | four builds in series |
| `node` | napi addon linux-x64, generated files, `npm test` | 5.0 | 7.7 | |
| `wasm` | build-wasm.sh browser+wasi+cli (10.8), WASI smoke, npm packs, native LSP+CLI (2.6), TS client | 14.3 | 14.0 | the native binaries are built again here (debug), beside `build` |
| `textmate` | TextMate grammars | 0.1 | 0.1 | |
| `deny` | cargo deny ×3 | 0.4 | 0.4 | |
| `release` | release-build.yml (release tier, nightly) | — | — | the release build below, with caches |
| `publish-dry-run` | publish-dry-run.yml: the crates.io and npm placeholders | — | — | release tier and nightly |
| `python-matrix` | 3.10–3.13 in series, then the `full_set` E2E | — | — | release tier and nightly |
| `nightly` | nightly.yml | — | — | nightly |
| `cli-windows-smoke`, `engine-release-consumers` | the Windows launcher and Ctrl-C; the assets in vscode-extension | — | — | nightly |
| `gate` (**PR gate**) | every job above passed or was skipped | 0.1 | 0.1 | |
| `nightly-report` | the `nightly-failure` issue | — | — | nightly |

Two pushes to `integration/unified-core` failed on 2026-11-22 (45044966570, 45044914301), before
#1778 fixed the npm lock. The review found no flaky gate job.

### The release build (release-build.yml → build-packages.yml, engine-release-build.yml, av-gate.yml)

Called by publish.yml's `build` (no cache) and by ci.yml's `release` (dry run, with caches).
Dry run 45034649508, minutes from the run's start:

| Job | Duration | Start → end | On the tail? |
|---|---|---|---|
| guard; release-versions; packages/versions; engine/meta | 0.1–0.2 each | 0 → 0.6 | three version jobs in a row before the first build |
| Crate packages and licence scan | 7.5 | 0.6 → 8.0 | |
| Sdist | 0.6 | 0.6 → 1.0 | |
| Licences, Highlights, SBOMs | 2.4–3.3 | 0.6 → 3.6 | |
| Wheel ×6 | 9.7–**19.9** (windows-arm64), 16.7 (macos-x64) | 0.5 → 20.5 | yes: windows-arm64 |
| npm native ×6 | 5.8–13.8 | 0.5 → 14.3 | |
| npm packages | 0.7 | 14.3 → 15.0 | |
| Wheel smoke ×6 | 0.2–0.8 | 20.5 → 21.3 | waits for every wheel |
| WebAssembly builds | 12.2 | 0.6 → 12.7 | |
| **Binaries ×4** (lsp then CLI in series) | 10.9, 11.1, 18.5, **21.1** (aarch64-apple-darwin) | 0.6 → 21.7 | **yes** |
| Release assets | 0.3 | 21.8 → 22.0 | |
| AV gate (assets) ×4 | 0.7–1.2 | 22.1 → 23.3 | |
| AV gate (packages) ×4 | 1.2–**4.9** (ClamAV) | 21.3 → 26.2 | yes |
| Smoke ×6 platforms | 0.5–2.6 | 23.3 → 25.9 | |
| **Smoke (sdist)** | **9.1** | 23.3 → **32.4** | **yes: the last 9 minutes** → **#1780** |
| Smoke (cargo install) | 1.9 | 23.3 → 25.2 | |
| publish jobs | skipped | | |

The causes:

1. `Smoke (sdist)`, a build from source with the runner's Rust, waited for **every** build because
   the smoke matrix had one `needs` list. It needs only the sdist. Moving it off the tail saves
   6 min (#1780).
2. `[profile.release]`: `lto = true`, `codegen-units = 1`. Every release build ends in a long
   single-core LTO and codegen tail, and a release build has no cache, deliberately. The binaries
   job runs that tail twice in series (`opentide-lsp`, then `opentide`) → **#1781**, plus the
   thin-LTO experiment (**#1782**).
3. The second-slowest path, Wheel windows-arm64 (19.9 min, a cross-compile on windows-latest) and
   then the packages' ClamAV (4.9 min), ends at about minute 26. Once #1780 lands, this path sets
   the release build's floor whatever the binaries do.

### publish.yml (the release train)

`guard` (version, channel, the npm pre-flight) → `build` (above) → for a release or public
candidate: `attest` → `release` → `verify-assets` → `pypi`, `crates`, `npm` → `smoke-registries`.
An internal candidate gets `internal-release` only. The review found nothing redundant: each job is
a separate permission boundary (OIDC in `attest`, `pypi`, `crates`, `npm` only; `contents: write`
in `release` and `internal-release` only). Merging them would weaken that, so they stay as they are.

### nightly.yml and what it calls (never gates)

| Job | Checks | Runners |
|---|---|---|
| `engine-test-os` | the workspace's tests on macOS and Windows | 2 |
| `conformance` | the cross-SDK suite (Python, Rust, Node), byte for byte | 3 OSes |
| `elastic-sweep` | the Elastic detection-rules sweep | 1 |
| `lsp-parity` | validate vs language server over the faults corpus | 1 |
| `clients` | pytest-lsp and Neovim (informational) | 1 |
| `coverage` (coverage.yml) | cargo-llvm-cov over the Rust tests and the Python suite, per-crate gates | 1 |
| `benchmarks` (bench.yml) | budgeted benchmarks, cold start (native, WASI) | 2 |
| `oracle` (oracle.yml) | Kusto.Language, Splunk, Elasticsearch, Lucene, Kibana, Falco, YARA | 6 |
| `fuzz` (engine-fuzz.yml) | every fuzz target, 10 min | matrix |

ci.yml also runs `release` (the release build), `publish-dry-run` and `python-matrix` in the
nightly. No scheduled ci.yml run exists on `integration/unified-core`: the schedule runs
`development`'s copy, so the nightly's timings are not in this review.

### The other workflows

| Workflow | Trigger | Checks |
|---|---|---|
| `rust-audit.yml` | daily | `cargo audit` of every lock file; the one `issues: write` job |
| `cache-report.yml` | weekly, a push that changes it | the Actions caches against the 10 GB |
| `vocab-upstream.yml` | weekly | the specifications' vocabulary, as a PR |
| `publish-dry-run.yml` | release tier, nightly, on demand | the crates.io and npm placeholders |
| `av-gate.yml` | called by the release build | markers and sizes, ClamAV, YARA, Defender |
| `codeql.yml` | PR (path-scoped), push, nightly | out of scope (#1779) |

### Composite actions and scripts

- `actions/rust-setup` and `actions/sccache-save` serve every ci.yml and nightly.yml Rust job.
  The release workflows deliberately do **not** use them. `scripts/engine/test_release.py` holds
  that every release job installs the pinned toolchain with one literal `rustup toolchain install`
  and adds its targets with `rustup target add`, which a composite would hide. The duplicated
  sccache steps in `engine-release-build.yml` (`native`, `wasm`: install sccache, wrap rustc,
  week, restore, save) could become one composite restricted to the dry run. That needs those
  contract tests reworked, and they guard the "no cache in a release" property, so it is not
  worth the risk for five steps.
- `scripts/ci/changes.py`, `scripts/ci/rustc-wrapper/sccache`, `scripts/ci/bench_reference.py`,
  `scripts/av/*` and `scripts/build/*` are all referenced from a workflow, a test or a guide: no
  dead script was found.

## Redundancies and stale parts found

| Finding | Where | Verdict |
|---|---|---|
| Three version jobs in a row (`release-versions`, `packages/versions`, `engine-assets/meta`) recompute the same versions and re-check the revision | release-build.yml, build-packages.yml, engine-release-build.yml | merge into `release-versions` and pass the values down; ~20–30 s off the critical path, −2 jobs (P3) |
| `wheel-smoke` (6 jobs) and `smoke` platform cells (6 jobs) run on the same six OSes | build-packages.yml, release-build.yml | merge the wheel install into the platform smoke cells: −6 jobs, ~1 min of runner start each, 2 macOS and 2 Windows (P2) |
| ClamAV scans every package twice, as archives (`--scan-archive`) and extracted, on one core | av-gate.yml | keep both scans: the gate's design (#1743), and the archive scan sees what the extractor might skip. Run them on every core: **#1785** |
| `wasm` builds the native language server and command line (2.6 min) that `build` also builds | ci.yml | different profile and features; only on `ts_packages` and pushes. Leave |
| The binaries' `native` job built lsp then CLI in series | engine-release-build.yml | **#1781** |
| The smoke matrix's single `needs` held the sdist build to the end | release-build.yml | **#1780** |
| `engine-lint` ran seven checks in series | ci.yml | **#1783** |
| "GitHub retired the Intel macOS runners; cross-compile on Apple silicon" | engine-release-build.yml, build-packages.yml | half-stale: `macos-15-intel` exists and the smoke jobs use it; cross-compiling is still the faster choice. Reword when next touched |
| engine-release-build.yml's header says ci.yml calls it "in its full set" | engine-release-build.yml | stale: release-build.yml calls it for both callers. Reword when next touched |
| `engine-release-consumers` (nightly) checks out opentidehq/vscode-extension at a pinned commit from 2026-11-06 (`9888813d…`, its PR #71) and runs that checkout's `scripts/engine-lib.mjs` on the release assets (`scripts/engine/check-vscode-extension.mjs`). That engine-lib refuses rc.3's engine zip, which now carries `data/catalogs/*/NOTICE` and `LICENSE*`. The check script's `pinsFor().wasi` lists four licence files where the extension now pins five (no `THIRD-PARTY-DATA-LICENSES.txt`), and it prints `licenses` where the extension's `pins.json` reads `licences`. The job prints the `wasi` section but runs none of the extension's WASI checks | ci.yml, scripts/engine/check-vscode-extension.mjs | stale: the nightly fails on a consumer that has moved on. Bump the `ref:` once vscode-extension #82 → #83 → #95 merge, and fix the script in the same change (P1, below) |
| The full tier's 10 min budget (.github/AGENTS.md) | ci.yml `build` | not met: 18.3 min. nextest takes 8.8 of them. Either restate the budget or split the run (below) |

## Prioritised changes

| # | Change | Saving | Risk | State |
|---|---|---|---|---|
| 1 | Smoke the sdist and crate builds as soon as their packages exist | ~6 min off every release build (32 → ~26) | low | **#1780** |
| 2 | Build `opentide-lsp` and `opentide` in parallel per target | macOS binary cells ~21 → ~12–14 min; wall clock only once the wheels' path is faster too | low; +4 jobs (2 macOS) | **#1781** |
| 3 | Split `engine-lint` into the workspace lint and the variants | ~3–5 min off a Rust PR's gate (engine-lint was its longest job) | low; one more cache family | **#1783** |
| 4 | Thin LTO, default codegen-units | −48% build time locally | **fails**: binaries +18–21% over their budgets, throughput up to +11% | **#1782**: measured, not proposed |
| 5 | Merge `wheel-smoke` into the platform smoke cells | −6 jobs per release build | low–medium (the contract tests pin `wheel-smoke`) | proposed |
| 6 | One version job for the release build | −2 jobs, ~20–30 s | low | proposed |
| 7 | The Windows wheels: 15–20 min each, the native x64 build as much as the arm64 cross-compile (19.4–19.8 min for windows-x64 in two runs). Profile one (`--timings`, the MSVC link of the fat-LTO module) before choosing: a native `windows-11-arm` build for arm64, a larger runner, or `lld-link` | the release build's next floor | medium | proposed: measure first |
| 8 | ClamAV over the packages on every core (one `--file-list` per core) | ~3–4 min off the release build's tail once #1780 lands | low | **#1785** |
| 9 | `build`: the full tier misses its 10 min budget (18.3). Partition nextest (two jobs on the same build's archive), or restate the budget | ~4–5 min off every push | medium (#1141 measured the archive's cost: 1.5 GB) | proposed: revisit only with a smaller archive |
| 10 | `facade`: four builds in series (10–13 min); semver-checks (3.4) could run beside the feature builds | ~3 min off a facade PR | low | proposed |
| 11 | `engine-release-consumers`: bump the vscode-extension `ref:` to the commit after its #82, #83 and #95. In `check-vscode-extension.mjs`, add `THIRD-PARTY-DATA-LICENSES.txt` to `pinsFor().wasi` and print the extension's key, `licences`. Then have the job run the extension's own WASI checks on the module (`prepareWasi`) instead of only printing the pins it would read | restores a nightly signal that now fails for a stale reason; the WASI check catches a module the extension would refuse before a release ships it | low (nightly only, never gates) | **#1786** |

After #1780, #1781 and #1785, the release build's floor is the slowest wheel (windows-x64 or
windows-arm64, 15 to 20 min from run to run): item 7 is the next lever.

## Measurements of the changes

Each change PR carries its own dry run or CI run. The numbers are filled in here as they land:

| Change | Before | After | Run |
|---|---|---|---|
| #1780 smoke split | build stage 32.4 min (45034649508) | **28.3 min** (45052093550): `Smoke (sdist)` runs from minute 7.3 to 15.7; the tail is now the packages' ClamAV (7.0 min that run) | publish.yml dry run, `release_candidate=3`, passed |
| #1781 binaries split | binaries done at 21.7 min; aarch64-apple-darwin 21.1, x86_64-apple-darwin 18.5 | binaries done at **15.2 min** (45052100493): `opentide` aarch64-apple-darwin 14.7, x86_64-apple-darwin 10.9; `opentide-lsp` 3.8–7.8. The stage still ends at 30.0 there (the sdist smoke, without #1780); the wheels (windows-x64 19.4) are the next floor | publish.yml dry run, passed |
| #1783 engine-lint split | 13.5 (PR), 12.7 (push) | **4.5 and 5.0 side by side**, warm (re-run of 45052276806); 4.1 and 14.4 on the first, cold run of the new family | the PR's CI, gate green |
| #1785 ClamAV on every core | packages' ClamAV 4.3–7.0 min (clamscan 269–392 s); assets' clamscan 42–51 s | packages' ClamAV **3.7 min** (clamscan 184 s, −32 to −53%; the largest archives set each list's floor); assets' clamscan 27 s | ci.yml `scope: release` 45055860045, passed; publish.yml dry run queued |
| #1782 thin LTO | fat, cgu 1: both binaries 920 s locally (4 vCPU); `opentide` 41.8 MB, `opentide-lsp` 19.3 MB | thin: 483 s (−48%); 50.7 MB (+21%) and 22.8 MB (+18%), **both over** `sizes.toml`; throughput +0.8 to +11.0% instructions (**fails**, 3% tolerance); bench.yml absolute budgets pass, no base comparison. Fat with cgu 16: 916 s, 44.2 MB (over) and 20.3 MB. **Not proposed** | local builds, the PR's throughput job, bench.yml 45052113448, publish.yml dry run 45055868566 |
