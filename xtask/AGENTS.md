# xtask — agent guide

`cargo xtask <command>` (the alias is in `.cargo/config.toml`: `run --locked --quiet --package
xtask --`): the repository's Rust tooling, as a workspace member that is never published.

| Command | Status |
|---------|--------|
| `check-layers [--metadata FILE] [--layers FILE]` | Checks that every dependency between workspace crates (normal, build and dev, on every target) points down the layer table, [`layers.toml`](layers.toml), against `cargo metadata --no-deps` |
| `coverage gate --report FILE [--policy FILE] [--metadata FILE]` | Line coverage per workspace crate (cargo-llvm-cov's JSON export) against the gates of [`coverage.toml`](coverage.toml): 90% for opentide-schema, -workspace, -compile and -cli once they exist, 80% for every other member; prints a Markdown table. UC-X.2 (#844) |
| `mutants crates`, `mutants report --outcomes FILE ...` | The crates the weekly mutation run mutates ([`mutants.toml`](mutants.toml)); the shards' cargo-mutants outcomes merged, scored against [`mutants-baseline.toml`](mutants-baseline.toml), with an issue body per crate above its threshold and `--write-baseline` to record a run. UC-X.2 (#844) |
| `conformance [--runners rust,python,node] [--corpus NAME,...] [--diverge RUNNER] [--keep]` | The cross-SDK conformance suite (UC-5.4, #839, `src/conformance/`): lays out the corpora of `tests/conformance/manifest.json`, runs the Rust, Python and Node runners on them and requires their documents byte-identical, the first difference of each named by its JSON pointer; `--diverge` is its own test, a runner diverging on purpose that it must catch ([`tests/conformance/README.md`](../tests/conformance/README.md)). CI's `conformance` job |
| `corpus generate\|faults\|clean\|codes\|coverage` | The corpora of UC-0.6 (#804): the seeded heavy workspace, the fault catalogue run against the oracle (and, `--engine rust --only objects`, against opentide-schema's object models), the code inventory and coverage report ([`tests/corpora/README.md`](../tests/corpora/README.md)) |
| `corpus faults --check --engine rust --only objects\|structural\|configuration` | The fault kinds the Rust model covers today, against the oracle finding for finding: the object files' findings outside the platform blocks (UC-1.3; `structural` is UC-1.2's subset, `src/corpus/structural.rs`) and the configuration files' findings (UC-1.5, `src/corpus/configuration.rs`) |
| `codegen [--check]` | The artifacts generated from the Rust model (`opentide_schema::generate`, UC-1.8 #814; `src/codegen.rs`): writes the committed platform templates (`src/opentide/schemas/data/platform_templates`), each revision's editor schema in `data/catalogs/tide/schemas/` (bundled configuration, no workspace objects, enum essays shortened), the language server's catalogs and the diagnostics reference; `--check` fails when one is stale. It also generates the typed AST of every `crates/opentide-<lang>/src/<lang>.ungram` (and the toolkit's test grammar) into `src/generated/ast.rs` beside it (`src/astgen.rs`, `ungrammar` 1.16.1, formatted by the pinned rustfmt; epic #1219): see `crates/opentide-parse/AGENTS.md`. CI's `Engine lint` job runs it. The comparisons with the oracle's recordings (`--oracle`) were retired with them (#1142); `src/verdict.rs` stays for the schema probes' test |
| `cassettes check`, `cassettes list` | The recorded-HTTP cassettes (UC-4.1, #831, `src/cassettes.rs`) of `tests/cassettes/scenarios.toml`, recorded from the oracle (`cassettes record` was retired with it, #1142): `check` fails on a digest that does not match (a hand edit), on anything redaction would still change and on a scenario without its cassette. A snapshot case with `cassette = "<scenario>"` is served from it by a replaying proxy, and fails unless its requests are the cassette's |
| `bench [--engine python\|rust] [--scale 1\|10] [--json]`, `bench --check BUDGETS BENCH.json [--previous FILE]` | Runs the plan section 11 benchmarks on the heavy workspace and holds the result to [`tests/bench/budgets.toml`](../tests/bench/budgets.toml) and the base branch's last result (below) |
| `throughput [--check\|--record] [--language L ...] [--runs N] [--budgets FILE]` | Each language's parse and full analysis, over its short corpus and its external public rules, counted with callgrind (valgrind required) in the bench binary's own instructions (within 3%) and its calls into the allocator (exactly), and held to [`tests/bench/instructions.toml`](../tests/bench/instructions.toml) (`src/throughput.rs`, #1571, [ADR 0014](../docs/internal/adr/0014-analysis-performance.md)). The languages and inputs are the bench binary's (`crates/opentide-analysis/benches/throughput.rs`, one row a language); `--record` writes the budgets. Wall time and MB/s: `cargo bench -p opentide-analysis --bench throughput` ([`docs/engine/THROUGHPUT.md`](../docs/engine/THROUGHPUT.md)) |
| `vocab sync [--check]`, `vocab sentinel-attack [--check] [--stix-dir DIR]` | The vocabularies (UC-1.6, #812, `src/vocab/`): the bundled vocabularies and schema pins against `opentidehq/specifications` and the lockfile (CI's drift gate runs `--check`); Sentinel's ATT&CK v18 list from MITRE's STIX bundles |
| `vocab ingest [--check\|--apply] [--no-fetch] [--stix-dir DIR] [--misp-url URL] [--specifications DIR] [--now TIMESTAMP]` | The weekly ATT&CK and MISP ingest (UC-6.3, `src/vocab/ingest/`; `.github/workflows/vocab-upstream.yml`): the latest STIX release and the MISP galaxy merged into the specifications' `att&ck`, `att&ck.groups`, `mitigations`, `datasources` and `actors` with RFC 0003 per-key versions; `--apply` writes them and runs `vocab sync`. The same data as the removed Python ingest's files, written by the `toml` crate (`ingest/value.rs`; the comparison is in [`scripts/vocabulary/README.md`](../scripts/vocabulary/README.md)) |
| `vocab malapi [--check\|--apply] [--specifications DIR] [--html-dir DIR] [--delay SECS] [--now TIMESTAMP]` | The MalAPI vocabulary (`src/vocab/malapi/`), run by hand: malapi.io's front page and API pages parsed with html5ever (`malapi/page.rs`), merged into the specifications' `malapi` through the ingest's lifecycle merge; pages fetched with curl one at a time, `--delay` apart (default 60 s), or read from saved pages (`--html-dir`, the tests' `tests/malapi/`); a run stopped part-way keeps the keys it did not reach. Ported from `generate_malapi.py` |
| `spec-fields [--specifications DIR] [--list]` | Every Rust model field's description (`revision_model_schema` of each object revision, every `$defs` model it reaches) against its row in the specifications' field tables (`src/spec_fields.rs`, UC-6.3): the Python check of the Pydantic docstrings, ported; deliberate rewrites in `REWRITTEN`; exits 2 without a checkout and 1 when under 100 rows match. CI's `lint` job, when the models change |
| `stubs [--check] [--library FILE]` | `src/opentide/_native/models.pyi` and `src/opentide/_native/sdk.pyi`, the stubs of the Tide models' Python classes and of the SDK's core (`opentide._native.sdk`, UC-5.2b), generated from the extension: builds `opentide-native` with feature `stubs` (PyO3's introspection data, `develop` profile) and reads it with `pyo3-introspection` (`src/stubs.rs`); `--check` fails on drift (CI's `schema` workflow). UC-1.9 (#815), ADR 0011 |
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

- `--engine python` runs the bench oracle, opentide 0.23.0 from its PyPI wheel (the correctness comparisons moved to 0.28.1; the bench keeps the release its baselines were measured on), installed with uv into
  `<target>/xtask-bench/oracle` from [`tests/bench/oracle-requirements.txt`](../tests/bench/oracle-requirements.txt)
  (every file's SHA-256 pinned) on a uv-managed CPython (`ORACLE_PYTHON`), bytecode compiled at
  install. `--engine rust` builds the `opentide` binary (`-p opentide --features cli
  --release`, what `cargo install opentide --features cli` installs) for every command-line
  scenario, or runs `--opentide PATH` instead, which the report records as its `oracle`
  (a different binary is not compared with this checkout's results). To compare two builds,
  pass each one's binary, with `--lsp` and `--launcher` for those scenarios; `load` is always
  this checkout's, and `--opentide` refuses a selection it would not cover, `opentide-lsp --release` for the language server and opentide-workspace's `load`
  example (`--release`) for `load`. `load` is the workspace's load and index: the oracle runs `Opentide.initialise()`
  with its interpreter (`ORACLE_LOAD`), the Rust engine the example, each timed spawn to exit.
- `startup` (`opentide --version`, 20 ms) and, under `--engine rust`, `explain` (30 ms) run the
  console script, `opentide._cli:main` (UC-3.8b, #960; UC-6.2, #841): the
  plan's startup budgets are what `pip install opentide` gives a person. The launcher is
  `.venv/bin/opentide` from `uv sync` (`--launcher PATH` names another); its warm-up runs may
  write the package's bytecode, as a wheel's install compiles it. The oracle's start is not
  measured. A `--version` process is smaller than xtask, so its peak RSS is the floor
  (below) and only its time has a budget.
- The language server's number is spawn to the first `publishDiagnostics` for the opened rule
  (`src/bench/lsp.rs`), with the workspace as its root.
- `--check` (`src/bench/check.rs`) fails a median or peak RSS more than `policy.regression` (10%)
  over the base branch's last result (`--previous`) or over the oracle baseline in the budgets
  (`python`), and a rust result over the absolute plan section 11 target (a time target + 10%:
  two runners of one CPU model differ by that much; or, where a
  `target_waiver` names the work item that will meet it, more than 10% over the Rust baseline;
  where the plan names no target, over the oracle's median on the same CPU, or on a CPU recorded
  nowhere over the slowest recorded + 20%: never slower than the implementation it replaces);
  differences within the noise floor (20 ms, 2 MiB) never fail. A miss of a rust absolute budget
  (time or RSS) that a `time_waiver` / `rss_waiver` names an issue for (`"#123, why"`, refused
  without one) is reported as waived, not failed, up to its measured `waived_s` /
  `waived_rss_mib` + 10%; past that, or against the last result, it fails, and the budget
  itself stays. A change of one engine's numbers made on purpose is `accepted` (`"#123, why"`)
  with `accepted_engine`, `accepted_unix` (its merge time: not before 2020, and a run older
  than it fails) and `accepted_s` / `accepted_rss_mib` (what it was measured at). A last
  result measured before then is not compared with for that command; the run is held to
  the accepted numbers + 10% and to its absolute budget instead, and the next run on the
  base branch becomes its reference. Record it with the profile that explains the change,
  as `[commands.lint]` does. With `--require-reference`
  (CI), a measured command that no baseline, target or comparable previous result applies to
  fails, and so does a report without a CPU model. It prints, and with `--summary` appends, a
  Markdown table per command.
- Comparability: a report is held to the oracle baseline only with the same oracle, workspace and
  run count as recorded in the budgets. Times are kept per CPU model (`[baseline]` and
  `[[cpu_baseline]]`: GitHub's runners of one class span CPUs up to 1.8x apart); on a CPU with
  no entry, times get the slowest recorded + `cross_cpu_regression` (20%). RSS keeps 10%. The
  workspace digest in the report must equal `[baseline] digest`. A previous result counts only with the same engine,
  oracle, workspace, run count and CPU model; GitHub's `ubuntu-24.04` runners come on several
  CPUs, so CI looks for the newest successful development run on the same CPU. One measured
  before the recorded reference (`[policy] reference_unix`) does not count: a CPU model last
  seen many merges back would hold a run to that whole interval, and stay red.
- Peak RSS has a floor: on Linux `exec` records the high-water mark of the memory a child shared
  with xtask until then, so a child's `ru_maxrss` is at least xtask's mark at the spawn. xtask
  resets its own mark to its current RSS before each spawn (`/proc/self/clear_refs`), generates
  the workspace in a child process, and refuses a sample at or under its mark, read as soon as
  the spawn returns (`VmHWM`; `measure::spawn`, the one spawn both the commands and the language
  server go through): a page xtask touches between the reset and the exec (the spawn's own
  allocations) is in the child's floor too, so a mark read before the spawn let xtask's peak
  pass for the command's now and then (more often under load and coverage instrumentation).
  What xtask touches after the exec (the language server's reader thread and messages) is not
  in the child's floor, so the read does not wait for the reap.
- A command-line scenario runs through a fresh xtask process (`bench --internal-measure`,
  `measure::run_isolated`) that spawns the command, waits for it and writes its time and
  `wait4` numbers to a file: the floor is that small process's memory (a few MiB), not the
  benchmark's (18 to 32 MiB by profile), which the smallest Rust commands (`rules unreviewed`,
  about 14 MiB) peak under. The language server is spawned directly: its time ends at its first
  diagnostics, and it peaks far above the floor.
- The `memory_*` tests of `measure` and `lsp` measure this process's own mark, which the other
  tests of a plain `cargo test` (threads of one process) move: each runs itself again in a child
  process of the test binary, alone (`bench::measured_alone`), under `cargo test` and nextest alike.
- `XTASK_BENCH_INJECT_SLEEP_MS` is test-only: a sleep inside every measured run's timed window.
  `tests/bench.rs` proves that it makes the check fail.
- CI: [`bench.yml`](../.github/workflows/bench.yml). "The last result" (`--previous`, named after the branch in the messages)
  is the last result of the workflow's comparison base, `BASE_BRANCH`: `integration/unified-core`
  (its pushes, nightly and manual runs) while development has no Rust command line, and
  development again once the Unified Core merges there. Only the rust engine is given a last result:
  the python engine is a fixed PyPI wheel no change here touches, so a 10% rule against its last
  result measured the runner (one CPU model's runs differed by up to 27%, every command together)
  and it is held to the oracle baseline of its CPU alone. Re-record the baseline only from a CI run
  on its runner class, in a change of its own.

## Invariants

- The library (`src/lib.rs`, `src/layers.rs`) computes; `src/main.rs` reads files, runs cargo and
  prints. `src/corpus/` follows the same split inside its module: `generate`, `yaml`, `rng`,
  `workspace`, `faults` and `coverage` compute; `corpus/cli.rs` writes workspaces, runs the oracle
  and prints (main.rs only dispatches to it). `bench` keeps the same split inside `src/bench/`:
  `report` and `check` compute, the other modules run processes. Tests drive the library with
  synthetic metadata, no workspace needed.
- The corpus generator's output is a function of its options alone (own PRNG and YAML emitter, no
  clock, environment or file); `tests/corpus_generate.rs` records its digests.
- `src/corpus/approved.rs` holds the approved classes of difference `corpus faults --check --engine
  rust` applies (moved from the retired `validate diff` and `lint diff`, #1142); `src/files.rs` the
  file helpers the kept commands share.
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

- Every git repository a test builds runs git with automatic maintenance and gc
  off (`GIT_CONFIG_COUNT`: `maintenance.auto=false`, `gc.auto=0`):
  either works under `.git` in the background after a commit, and a copy of `.git` made meanwhile
  failed (#934). A state's copy leaves git's `*.lock` files out and fails loudly otherwise.
- A test never spawns `cargo xtask` (or `cargo run`) on this workspace: under `cargo nextest
  run --workspace` the spawned cargo builds xtask alone, with other features than the test build,
  and recompiles much of it (#948).
- `src/layers.rs` unit tests: synthetic tables and metadata, including a deliberate upward
  dependency on the repository's own table, which must fail.
- `tests/cli.rs`: the binary through trycmd (`tests/cmd/*.trycmd`, fixtures in
  `tests/cmd/<case>.in/`).
- `src/coverage.rs`, `src/mutants.rs` unit tests:
  synthetic llvm-cov exports, cargo-mutants outcomes and dashboard inputs. The test-strength
  measures are described in `docs/internal/test-strength.md`.
- `tests/workspace.rs`: the binary in a two-crate workspace of its own with an upward edge, run as
  `cargo run` and as a plain binary: it must check that workspace, not the repository.
- `tests/corpus_generate.rs`: the generator's recorded digests, counts, coverage of platforms and
  features, layouts, slug file names, no literal secret. `src/corpus/*` unit tests: the YAML
  emitter, the PRNG's reference values, the catalogue's parser, selectors, operations and verdicts.
  The oracle runs only in `cargo xtask corpus faults --check` (ci.yml's `corpus` job).
- `tests/corpus_runner.rs`: the runner's pass/fail guards (a mismatch, a dirty base, a silence
  that checked nothing, `clean`, `coverage --check`) through a fake oracle script (Unix only).
- `src/lsp.rs` unit tests run `lsp parity` in-process on a few fault kinds; `src/codegen.rs` unit
  tests write the committed artifacts and the engine catalog into a scratch layout and check them.
- `tests/bench.rs`: `bench` end to end on a stand-in `opentide`: a measured run, then an injected
  slowdown that `--check` must fail; `tests/cmd/bench.trycmd` holds `--check` to fixed reports.
- `tests/lint_policy.rs`: every member inherits `[workspace.lints]`, except the crates allowed
  `unsafe` (`UNSAFE_CRATES`), whose copies must equal the workspace table with
  `unsafe_code = "deny"`.

## Do not

- Weaken a check to let a crate through: change the table, with the reason, in a reviewed change.
- Make a stub exit 0.

## Work items that change this crate

UC-0.4 (#802) check-layers; UC-0.6 (#804) corpus; UC-1.8 (#814) codegen; UC-2.1 (#816) the `load` benchmark; UC-X.2 (#844) coverage, mutants, parity; UC-0.8 (#806) bench; UC-1.6 (#812) `vocab`; UC-6.3 `vocab ingest` and `spec-fields`; UC-0.3 (#801) wired the checks into one
CI; #1142 retired the oracle comparisons (`golden`, `compare`, `mcp`, `config`, `registry`,
`validate`, `lint`, `payloads`, `schema`, `vocab diff`). Lints and tests: [`crates/AGENTS.md`](../crates/AGENTS.md).
