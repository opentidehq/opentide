# xtask — agent guide

`cargo xtask <command>` (the alias is in `.cargo/config.toml`: `run --locked --quiet --package
xtask --`): the repository's Rust tooling, as a workspace member that is never published.

| Command | Status |
|---------|--------|
| `check-layers [--metadata FILE] [--layers FILE]` | Checks that every dependency between workspace crates (normal, build and dev, on every target) points down the layer table, [`layers.toml`](layers.toml), against `cargo metadata --no-deps` |
| `coverage gate --report FILE [--policy FILE] [--metadata FILE]` | Line coverage per workspace crate (cargo-llvm-cov's JSON export) against the gates of [`coverage.toml`](coverage.toml): 90% for opentide-schema, -workspace, -compile and -cli once they exist, 80% for every other member; prints a Markdown table. UC-X.2 (#844) |
| `mutants crates`, `mutants report --outcomes FILE ...` | The crates the weekly mutation run mutates ([`mutants.toml`](mutants.toml)); the shards' cargo-mutants outcomes merged, scored against [`mutants-baseline.toml`](mutants-baseline.toml), with an issue body per crate above its threshold and `--write-baseline` to record a run. UC-X.2 (#844) |
| `parity dashboard [--root DIR] [--out FILE] [--check]` | Renders `docs/internal/parity.md` (each command × corpus × mode against the oracle, approved diffs, fault coverage) from the goldens, engine state, ledger and fault catalogue; `--check` fails on drift. UC-X.2 (#844) |
| `corpus generate\|faults\|clean\|codes\|coverage` | The corpora of UC-0.6 (#804): the seeded heavy workspace, the fault catalogue run against the oracle, the code inventory and coverage report ([`tests/corpora/README.md`](../tests/corpora/README.md)) |
| `codegen` | Not implemented: UC-1.8 (#814) generates schemas, stubs, types and references with it |
| `golden record [--check-determinism]`, `check`, `diff`, `lock`, `coverage` | Records what the frozen Python CLI (the oracle, `tests/golden/ORACLE`) does for every case of `tests/golden/cases.toml`, and checks an engine against the recordings: [`tests/golden/README.md`](../tests/golden/README.md) |
| `golden check --engine compare [--report FILE]` | Runs every case whose command has a Rust implementation (`opentide.cli.engines.RUST_COMMANDS`) through this repository's CLI with `OPENTIDE_ENGINE=rust`, and compares it with the recording through `opentide-compare` and `tests/golden/APPROVED_DIFFS.toml`; a stale ledger entry fails it (UC-0.7, #805; CI job `Golden compare`) |
| `compare --oracle DIR --candidate DIR --command PATH`, `compare --check-ledger` | Two runs on disk through the comparator; the ledger's schema and changelog references (`src/compare.rs`, `crates/opentide-compare/AGENTS.md`) |
| `bench [--engine python\|rust] [--scale 1\|10] [--json]`, `bench --check BUDGETS BENCH.json [--previous FILE]` | Runs the plan section 11 benchmarks on the heavy workspace and holds the result to [`tests/bench/budgets.toml`](../tests/bench/budgets.toml) and the last `development` result (below) |
| `help` | The usage |

Exit status: 0 passed; 1 a check failed, or the command is not implemented yet (so no script
takes a stub for a pass); 2 a usage error, or the check could not run.

## Place

tooling, the top layer: xtask may depend on any crate; no crate may depend on it.

## The layer table

[`layers.toml`](layers.toml) is the one written copy of plan §4's table; the docs cite it. Layers
go from the bottom up, each split into tiers from the bottom up. A crate may depend only on a
crate of a lower layer, or of a lower tier of its own layer: an upward edge, an edge within one
tier, a workspace member the table does not place, a placed crate that is not a member, and a
crate placed twice all fail. To add a crate, place it in the table in the same change and say why;
moving a crate between layers is a design decision for the maintainer, not a fix for a red check.

## bench

`cargo xtask bench` (`src/bench/`) measures each command of `SCENARIOS` (`src/bench/mod.rs`) as
fresh processes: one warm-up, then `--runs` (5) measured runs, each in a fresh copy of the
workspace, with a home, environment and dead proxies of its own (`src/bench/measure.rs`). Time is
wall time around spawn and `wait4(2)`; memory is the peak RSS `wait4` reports (the `wait4` crate,
since the workspace forbids `unsafe`); a report holds the medians and every sample. A run counts
only when the command ended as it should (exit code, one JSON document, what the scenario expects
of it): a command that failed early would measure nothing, so the bench stops with status 2.

- `--engine python` runs the oracle, opentide 0.23.0 from its PyPI wheel, installed with uv into
  `<target>/xtask-bench/oracle` from [`tests/bench/oracle-requirements.txt`](../tests/bench/oracle-requirements.txt)
  (every file's SHA-256 pinned) on a uv-managed CPython (`ORACLE_PYTHON`), bytecode compiled at
  install. `--engine rust` builds `opentide-lsp --release` for the language server and reports
  "no Rust yet" for every command without a Rust implementation.
- The language server's number is spawn to the first `publishDiagnostics` for the opened rule
  (`src/bench/lsp.rs`), with the workspace as its root.
- `--check` (`src/bench/check.rs`) fails a median or peak RSS more than `policy.regression` (10%)
  over the last `development` result (`--previous`) or over the oracle baseline in the budgets
  (`python`), and a rust result over the absolute plan section 11 target (or, where a
  `target_waiver` names the work item that will meet it, more than 10% over the Rust baseline);
  differences within the noise floor (20 ms, 2 MiB) never fail. With `--require-reference`
  (CI), a measured command that no baseline, target or comparable previous result applies to
  fails, and so does a report without a CPU model. It prints, and with `--summary` appends, a
  Markdown table per command.
- Comparability: a report is held to the oracle baseline only with the same oracle, workspace and
  run count as recorded in the budgets. Times are kept per CPU model (`[baseline]` and
  `[[cpu_baseline]]`: GitHub's runners of one class span CPUs up to 1.8x apart); on a CPU with
  no entry, times get the slowest recorded + `cross_cpu_regression` (20%). RSS keeps 10%. The
  workspace digest in the report must equal `[baseline] digest`. A previous result counts only with the same engine,
  oracle, workspace, run count and CPU model; GitHub's `ubuntu-24.04` runners come on several
  CPUs, so CI looks for the newest successful development run on the same CPU.
- Peak RSS has a floor: on Linux `exec` records the high-water mark of the memory a child shared
  with xtask until then, so a child's `ru_maxrss` is at least xtask's mark at the spawn. xtask
  resets its own mark to its current RSS before each spawn (`/proc/self/clear_refs`), generates
  the workspace in a child process, and refuses a sample at or under its mark, read after the
  wait (`VmHWM`): a page xtask touches between the reset and the exec (the spawn's own
  allocations) is in the child's floor too, so a mark read before the spawn let xtask's peak
  pass for the command's now and then (more often under load and coverage instrumentation).
- `XTASK_BENCH_INJECT_SLEEP_MS` is test-only: a sleep inside every measured run's timed window.
  `tests/bench.rs` proves that it makes the check fail.
- CI: [`bench.yml`](../.github/workflows/bench.yml). Re-record the baseline only from a CI run on
  its runner class, in a change of its own.

## Invariants

- The library (`src/lib.rs`, `src/layers.rs`) computes; `src/main.rs` reads files, runs cargo and
  prints. `src/corpus/` follows the same split inside its module: `generate`, `yaml`, `rng`,
  `workspace`, `faults` and `coverage` compute; `corpus/cli.rs` writes workspaces, runs the oracle
  and prints (main.rs only dispatches to it). `bench` keeps the same split inside `src/bench/`:
  `report` and `check` compute, the other modules run processes. Tests drive the library with
  synthetic metadata, no workspace needed.
- The corpus generator's output is a function of its options alone (own PRNG and YAML emitter, no
  clock, environment or file); `tests/corpus_generate.rs` records its digests.
- `golden` is its own module, `src/golden/`, a library the comparator (UC-0.7) reuses: the case
  model (`case.rs`), fixtures (`fixture.rs`), the oracle's install (`oracle.rs`), the runner
  (`run.rs`, `pty.rs`), the normaliser (in `crates/opentide-compare/src/normalise.rs`, re-exported
  as `golden::normalise`, so the CLI's compare mode shares it), recordings and their differences
  (`recording.rs`, `snapshot.rs`, `blob.rs`) and the coverage report (`coverage.rs`). `main.rs`
  only dispatches to `golden::main`. A normalisation rule changes with its unit test and a
  re-record in the same PR.
- The workspace to check is found at run time (`CARGO_MANIFEST_DIR` as `cargo run` sets it, else
  the working directory), and the table is `xtask/layers.toml` under the root `cargo metadata`
  prints. Never compile a path in with `env!`: a target pool that last served another worktree can
  hold a binary built there (root `AGENTS.md`, "Parallel agents").
- No panics: errors go through `anyhow` to exit status 2 (the workspace lints apply here too).
- New commands follow the same shape: a stub that fails names the work item that implements it.

## Test

```bash
cargo nextest run --profile fast -p xtask
cargo xtask check-layers
```

- `src/layers.rs` unit tests: synthetic tables and metadata, including a deliberate upward
  dependency on the repository's own table, which must fail.
- `tests/cli.rs`: the binary through trycmd (`tests/cmd/*.trycmd`, fixtures in
  `tests/cmd/<case>.in/`).
- `src/coverage.rs`, `src/mutants.rs`, `src/parity.rs`, `src/parity_inputs.rs` unit tests:
  synthetic llvm-cov exports, cargo-mutants outcomes and dashboard inputs. The test-strength
  measures are described in `docs/internal/test-strength.md`.
- `tests/workspace.rs`: the binary in a two-crate workspace of its own with an upward edge, run as
  `cargo run` and as a plain binary: it must check that workspace, not the repository.
- `src/golden/*.rs` unit tests: the case expansion, every normalisation rule (live regions, paths,
  timestamps, durations, hyperlink ids, fresh UUIDs), snapshots, recordings and their round trip,
  the blob store's SHA-256 against FIPS 180-4 vectors, the requirements pin, the coverage report.
- `tests/cmd/golden.trycmd`: `xtask golden`'s usage errors. Running the cases needs uv and the
  oracle: `cargo xtask golden check --engine python` (CI: `.github/workflows/golden.yml`).
- `tests/corpus_generate.rs`: the generator's recorded digests, counts, coverage of platforms and
  features, layouts, slug file names, no literal secret. `src/corpus/*` unit tests: the YAML
  emitter, the PRNG's reference values, the catalogue's parser, selectors, operations and verdicts.
  The oracle runs only in `cargo xtask corpus faults --check` (ci.yml's `corpus` job).
- `tests/corpus_runner.rs`: the runner's pass/fail guards (a mismatch, a dirty base, a silence
  that checked nothing, `clean`, `coverage --check`) through a fake oracle script (Unix only).
- `tests/bench.rs`: `bench` end to end on a stand-in `opentide`: a measured run, then an injected
  slowdown that `--check` must fail; `tests/cmd/bench.trycmd` holds `--check` to fixed reports.
- `tests/lint_policy.rs`: every member inherits `[workspace.lints]`, except the crates allowed
  `unsafe` (`UNSAFE_CRATES`), whose copies must equal the workspace table with
  `unsafe_code = "deny"`.

## Do not

- Weaken a check to let a crate through: change the table, with the reason, in a reviewed change.
- Make a stub exit 0.

## Work items that change this crate

UC-0.4 (#802) check-layers; UC-0.6 (#804) corpus; UC-1.8 (#814) codegen; UC-0.5 (#803) golden;
UC-0.7 (#805) the comparator over `golden`; UC-X.2 (#844) coverage, mutants, parity; UC-0.8 (#806) bench; UC-1.6 (#812) the
`sync_vocabularies --check` equivalent; UC-0.3 (#801) wired the checks into one
CI. Lints and tests: [`crates/AGENTS.md`](../crates/AGENTS.md).
