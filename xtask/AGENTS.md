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
| `config diff --against python [--oracle BIN] [--corpus all\|fixtures\|generated]` | Every fixture and generated workspace's configuration resolved by `opentide-schema` and compared, as JSON, with the oracle's `resolve_configurations`, with its `validate --check configuration` findings (`src/config.rs`, `oracle/config_resolve.py`). UC-1.5 (#811) |
| `registry diff --against python [--oracle BIN] [--corpus all\|fixtures\|generated\|faults] [--show-approved]` | Every corpus (the golden fixtures, an edge-case workspace, the heavy workspace and layouts, each fault kind alone) loaded by `opentide-workspace` and its index compared, as JSON, with the Python registry's (`src/registry.rs`, `oracle/registry_export.py`); differences only through the named rules of `APPROVED`, none stale. UC-2.1 (#816) |
| `validate diff [--filter GLOB] [--keep DIR] [--show-approved]` | Every recorded `validate --json` case that checks, run by `opentide-workspace`'s validate in-process and its report, check statuses and summary compared with the recording (`src/validate.rs`); the `--fix` and `--fix --dry-run` cases on a fresh copy of their fixture, with `fixed`/`would_fix`, the diff text and every file written; differences only through the named rules of `APPROVED`, none stale on a complete run; needs no oracle. CI's `corpus` job. UC-2.2 (#817), UC-2.3 (#818) |
| `lint diff [--filter GLOB] [--keep DIR] [--show-approved]` | Every recorded `lint --json` case (no `--format`), each on a fresh copy of its fixture, run by `opentide-workspace`'s lint in-process: every finding (keys, values, their order), counts, verdict, message, exit code, summary, next steps and the files `--fix` renamed compared with the recording (`src/lint.rs`); the queries check's findings are UC-2.5's and left out; differences only through `APPROVED`, none stale. CI's `corpus` job. UC-2.3 (#818) |
| `codegen [--check]` | The artifacts generated from the Rust model (`opentide_schema::generate`, UC-1.8 #814; `src/codegen.rs`): writes the committed platform templates (`src/opentide/schemas/data/platform_templates`); `--check` fails when they are stale, and when the templates, snippets or router schema generated from a fixture's resolved configuration differ by a byte from those of a golden recording of an `opentide generate` that ran the `schemas`, `templates` and `snippets` phases and exited 0 (each fixture and mode: tide-corpus, and vscode through `generate schemas templates vocabs snippets`), or either side has one the other has not. It also writes and drift-checks each revision's editor schema in `data/catalogs/tide/schemas/` (bundled configuration, no workspace objects, enum essays shortened), and `--check` compares the JSON Schemas of the `schemas` phase (each revision's, `visibility.toml`'s) in those recordings and the configuration schemas (`crates/opentide-schema/tests/oracle/configuration_schemas.json`, written by `configuration_schemas.py` with the oracle) with Rust's by verdict, not text (`src/verdict.rs`, the `jsonschema` crate, UC-1.8b #900): every object and configuration file of the fixtures, every fault of `tests/corpora/faults.toml` applied alone, the configuration table's texts and the bundled configuration files must be accepted or refused by both; the configuration router must be the same document. CI's `Engine lint` job runs it. The language server's field catalog is not generated yet (UC-2.6) |
| `golden record [--check-determinism]`, `check`, `diff`, `lock`, `coverage` | Records what the frozen Python CLI (the oracle, `tests/golden/ORACLE`) does for every case of `tests/golden/cases.toml`, and checks an engine against the recordings: [`tests/golden/README.md`](../tests/golden/README.md) |
| `golden record --oracle FILE --out DIR`, `golden check\|diff --recordings DIR`, `golden lock --oracle FILE` | A preview of the next oracle (`tests/golden/ORACLE.next`): recorded into DIR, never into `tests/golden`, and compared there; no `COVERAGE.md`, no stale-ledger check. CI's `Golden preview` job on `train/catchup-0.28` ([`tests/golden/README.md`](../tests/golden/README.md), "A preview of the next oracle") |
| `golden check --engine rust [--report FILE] [--partition K/N [--unused FILE]]` | Runs every case through this repository's CLI (the console script of `.venv`, the Rust core) and compares it with the recording through `opentide-compare` and `tests/golden/APPROVED_DIFFS.toml`; a stale ledger entry fails it (UC-0.7, #805; every case since UC-6.2, #841; CI job `Golden compare`). `--partition K/N`: only the cases whose id's FNV-1a hash falls in part K; `--unused FILE` writes the entries the part did not apply instead of failing (an entry in every part's file is stale: CI's gather) |
| `golden check --runner wasi [--report FILE]` | The same cases and comparison, with the candidate the WASI build of the command line (`target/wasm32-wasip1/wasi/opentide.wasm`, `scripts/engine/build-wasm.sh cli`) under wasmtime, or Node's WASI (`OPENTIDE_WASI_RUNTIME=node`, `scripts/engine/wasi-run.mjs`); the host's root is mapped at the guest's. It leaves out the network cases: those with a cassette, and those `tests/golden/WASI_EXCLUDED.toml` lists, each with network evidence (`golden::wasi`, whose tests check the list); and it judges no ledger entry stale. CI job `WASI command line` (ADR 0007's amendment) |
| `golden check --runner node [--report FILE]` | The same cases and comparison, with the candidate launched as the npm package's `opentide` bin (`bindings/node/cli.js` under `node`, after `npm run build` in `bindings/node`): the Node runner of UC-5.3 (#838); CI job `Node package`. It would leave out, and count, the runs the PyPI CLI still answers in Python (`compare::node_leaves_out`, #977), and so find no stale ledger entry; none is left out now: `--help` is the Rust command line's on both since UC-6.0b, and `doctor` is compared on every fixture since it checks nothing in Python (UC-6.0d) |
| `cassettes record <scenario>…\|--all [--oracle FILE]`, `cassettes check`, `cassettes list` | The recorded-HTTP cassettes (UC-4.1, #831, `src/cassettes.rs`): `record` runs each scenario of `tests/cassettes/scenarios.toml` (the oracle as the client, with a stand-in tenant where it names one) behind `opentide-cassette`'s recording proxy and writes `tests/cassettes/<scenario>.json`; `check` fails on a digest that does not match (a hand edit), on anything redaction would still change and on a scenario without its cassette. A golden case with `cassette = "<scenario>"` is served from it by a replaying proxy, and fails unless its requests are the cassette's |
| `mcp record --python PATH\|--oracle FILE [--only NAME]`, `mcp replay --engine rust FILE...` | The recorded MCP sessions (UC-3.7, #829, `src/mcp.rs`): the recordings in `tests/golden/mcp/<session>.jsonl` are the Python server's answers, frozen since UC-6.2 (#841); `record` writes them again from the Python server of an opentide release that has one (`--python`, with `OPENTIDE_ENGINE=python` for it), and `replay` sends each session to this repository's server and compares every answer through `opentide-compare` (JSON text blocks as their documents, keys sorted, the workspace path, the version and `wall_ms` hidden); a difference only through `APPROVED_DIFFS.toml` (command `mcp start`, case `<session>/<step>`, which `golden check` leaves to it), none stale on a complete run. CI's `Golden compare` job |
| `compare --oracle DIR --candidate DIR --command PATH`, `compare --check-ledger` | Two runs on disk through the comparator; the ledger's schema and changelog references (`src/compare.rs`, `crates/opentide-compare/AGENTS.md`) |
| `bench [--engine python\|rust] [--scale 1\|10] [--json]`, `bench --check BUDGETS BENCH.json [--previous FILE]` | Runs the plan section 11 benchmarks on the heavy workspace and holds the result to [`tests/bench/budgets.toml`](../tests/bench/budgets.toml) and the last `development` result (below) |
| `vocab sync [--check]`, `vocab sentinel-attack [--check] [--stix-dir DIR]`, `vocab diff --against python` | The vocabularies (UC-1.6, #812, `src/vocab/`): the bundled vocabularies and schema pins against `opentidehq/specifications` and the lockfile (CI's drift gate runs `--check`); Sentinel's ATT&CK v18 list from MITRE's STIX bundles; `opentide-schema`'s resolution and suggestions against the oracle on every corpus fixture, suggestion differences approved in `tests/golden/vocab/APPROVED.toml` |
| `vocab ingest [--check\|--apply] [--no-fetch] [--stix-dir DIR] [--misp-url URL] [--specifications DIR] [--now TIMESTAMP]` | The weekly ATT&CK and MISP ingest (UC-6.3, `src/vocab/ingest/`; `.github/workflows/vocab-upstream.yml`): the latest STIX release and the MISP galaxy merged into the specifications' `att&ck`, `att&ck.groups`, `mitigations`, `datasources` and `actors` with RFC 0003 per-key versions; `--apply` writes them and runs `vocab sync`. The same data as the removed Python ingest's files, written by the `toml` crate (`ingest/value.rs`; the comparison is in [`scripts/vocabulary/README.md`](../scripts/vocabulary/README.md)) |
| `vocab malapi [--check\|--apply] [--specifications DIR] [--html-dir DIR] [--delay SECS] [--now TIMESTAMP]` | The MalAPI vocabulary (`src/vocab/malapi/`), run by hand: malapi.io's front page and API pages parsed with html5ever (`malapi/page.rs`), merged into the specifications' `malapi` through the ingest's lifecycle merge; pages fetched with curl one at a time, `--delay` apart (default 60 s), or read from saved pages (`--html-dir`, the tests' `tests/malapi/`); a run stopped part-way keeps the keys it did not reach. Ported from `generate_malapi.py` |
| `spec-fields [--specifications DIR] [--list]` | Every Rust model field's description (`revision_model_schema` of each object revision, every `$defs` model it reaches) against its row in the specifications' field tables (`src/spec_fields.rs`, UC-6.3): the Python check of the Pydantic docstrings, ported; deliberate rewrites in `REWRITTEN`; exits 2 without a checkout and 1 when under 100 rows match. CI's `lint` job, when the models change |
| `schema diff --against python [--only schemas\|objects] [--fixture NAME] [--python PATH] [--report FILE]` | opentide-schema's object models (UC-1.3, #809, `src/schema/`) against the oracle: each model's JSON Schema against Pydantic's, structurally after normalisation (`src/schema/normalise.rs`), and the findings on every object file of every corpus (the golden fixtures and the heavy workspace) against `validate --json`, the platform blocks (UC-1.4, #810) included |
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

- `--engine python` runs the oracle, opentide 0.23.0 from its PyPI wheel, installed with uv into
  `<target>/xtask-bench/oracle` from [`tests/bench/oracle-requirements.txt`](../tests/bench/oracle-requirements.txt)
  (every file's SHA-256 pinned) on a uv-managed CPython (`ORACLE_PYTHON`), bytecode compiled at
  install. `--engine rust` builds the `opentide` binary (`-p opentide --features cli
  --release`, what `cargo install opentide --features cli` installs) for every command-line
  scenario, `opentide-lsp --release` for the language server and opentide-workspace's `load`
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
  over the last `development` result (`--previous`) or over the oracle baseline in the budgets
  (`python`), and a rust result over the absolute plan section 11 target (or, where a
  `target_waiver` names the work item that will meet it, more than 10% over the Rust baseline;
  where the plan names no target, over the oracle's median on the same CPU, or on a CPU recorded
  nowhere over the slowest recorded + 20%: never slower than the implementation it replaces);
  differences within the noise floor (20 ms, 2 MiB) never fail. A miss of a rust absolute budget
  (time or RSS) that a `time_waiver` / `rss_waiver` names an issue for (`"#123, why"`, refused
  without one) is reported as waived, not failed, up to its measured `waived_s` /
  `waived_rss_mib` + 10%; past that, or against the last result, it fails, and the budget
  itself stays. With `--require-reference`
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
- CI: [`bench.yml`](../.github/workflows/bench.yml). "The last development result" (`--previous`)
  is the last result of the workflow's comparison base, `BASE_BRANCH`: `integration/unified-core`
  (its pushes, nightly and manual runs) while development has no Rust command line, and
  development again once the Unified Core merges there. Re-record the baseline only from a CI run
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

- Every git repository a test or `payloads git` builds runs git with automatic maintenance and gc
  off (`GIT_CONFIG_COUNT`: `maintenance.auto=false`, `gc.auto=0`; `payloads::git::QUIET_GIT`):
  either works under `.git` in the background after a commit, and a copy of `.git` made meanwhile
  failed (#934). A state's copy leaves git's `*.lock` files out and fails loudly otherwise.
- A test never spawns `cargo xtask` (or `cargo run`) on this workspace: under `cargo nextest run --workspace` the
  spawned cargo builds xtask alone, with other features than the test build (resolver 2 unifies
  them across the workspace), and recompiled much of it, which held the corpus tests for minutes
  on Windows (#948). A `generated` fixture whose argv is `cargo xtask corpus ...` therefore runs
  the corpus command in-process (`golden::fixture`); `cargo metadata` is fine.
- `src/layers.rs` unit tests: synthetic tables and metadata, including a deliberate upward
  dependency on the repository's own table, which must fail.
- `tests/cli.rs`: the binary through trycmd (`tests/cmd/*.trycmd`, fixtures in
  `tests/cmd/<case>.in/`).
- `src/coverage.rs`, `src/mutants.rs` unit tests:
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
- `tests/mcp_replay.rs`: `mcp`'s command line and `replay` end to end on a stand-in server (a
  shell script as the package's interpreter, Unix only): equal answers pass under each `launch`, a
  different one fails, a server that writes anything but JSON-RPC to stdout or exits non-zero
  cannot be replayed. The real server's replay is CI's `Golden compare` job.
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

UC-0.4 (#802) check-layers; UC-0.6 (#804) corpus; UC-1.8 (#814) codegen; UC-0.5 (#803) golden;
UC-0.7 (#805) the comparator over `golden`; UC-2.1 (#816) `registry diff` and the `load` benchmark; UC-X.2 (#844) coverage, mutants, parity; UC-0.8 (#806) bench; UC-1.6 (#812) `vocab`; UC-6.3 `vocab ingest` and `spec-fields`; UC-0.3 (#801) wired the checks into one
CI. Lints and tests: [`crates/AGENTS.md`](../crates/AGENTS.md).
