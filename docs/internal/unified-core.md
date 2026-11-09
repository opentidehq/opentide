---
title: Unified core
description: The plan to move every opentide implementation into one Rust workspace, with the CLI, the Python SDK, the TypeScript SDK and the language server built from it, and how each step is proven correct.
---

# Unified core

**Status:** proposed, 2026-11-07. **Epic:** [#790](https://github.com/opentidehq/opentide/issues/790). **Companion page:** the "opentide Unified Core" artifact (benchmarks, figures).

opentide is implemented twice today. Python decides in the CLI, the SDK and MCP; the Rust engine from `opentidehq/language-server` decides in the editor, fed a catalog generated from the Pydantic models. This plan moves every implementation into one Rust workspace in this repository. The CLI, the Python SDK, the TypeScript SDK, the language server and the WebAssembly build are all built from that one core. Python becomes the SDK wrapper and the CLI launcher; it does no work of its own.

The plan is written for agents implementing it to extreme correctness. Every step is a strangler step: the user-visible contract does not move, and each step is proven by differential tests against the current Python implementation, which stays the oracle until the step's default flips.

## Status

Backlog: epic [#790](https://github.com/opentidehq/opentide/issues/790), with one phase issue each (#791 to #798) and one task per `UC-x.y` item; the epic's index maps every item to its issue and dependencies. Each phase's final PR updates this table (UC-X.3).

| Phase | Issue | Status |
|-------|-------|--------|
| UC-0 Foundation | #791 | done on `integration/unified-core` ([Phase 0](#phase-0-on-integrationunified-core)) |
| UC-1 `opentide-schema` | #792 | UC-1.1 done on `integration/unified-core` (ADR and skeleton); the rest not started |
| UC-2 `opentide-workspace` | #793 | not started |
| UC-3 `opentide-compile`, `opentide-cli` | #794 | not started |
| UC-4 `opentide-connectors` | #795 | not started |
| UC-5 SDKs and distribution | #796 | not started |
| UC-6 Adoption and decommission | #797 | not started |
| UC-X Quality gates | #798 | UC-X.1, UC-X.2 and UC-X.3 done on `integration/unified-core` |

### Phase 0 on `integration/unified-core`

Phase 0 merges into `integration/unified-core`, not `development`. The integration branch merges into `development` with a merge commit once the migration is ready.

| Item | Pull request | Merge commit |
|------|--------------|--------------|
| UC-0.1 | [#846](https://github.com/opentidehq/opentide/pull/846) | `1922b7d3` |
| UC-0.2 | [#847](https://github.com/opentidehq/opentide/pull/847) | `d49b92e0` |
| UC-0.2, language-server 0.12.0 (CQL) imported with its history; `crowdstrike_unsupported` kept as a retired code | [#859](https://github.com/opentidehq/opentide/pull/859) | `1462ff00` |
| UC-0.3 | [#852](https://github.com/opentidehq/opentide/pull/852) | `96ef1424` |
| UC-0.4 | [#848](https://github.com/opentidehq/opentide/pull/848) | `5b6b6fb9` |
| UC-0.5 | [#857](https://github.com/opentidehq/opentide/pull/857) | `2a25998e` |
| UC-0.6 | [#851](https://github.com/opentidehq/opentide/pull/851) | `637b8344` |
| UC-0.7 | [#854](https://github.com/opentidehq/opentide/pull/854) | `8b099be3` |
| UC-0.8 | [#856](https://github.com/opentidehq/opentide/pull/856) | `110655bb` |
| UC-1.1, ADR and skeleton only | [#853](https://github.com/opentidehq/opentide/pull/853) | `90698295` |
| UC-X.1 | [#858](https://github.com/opentidehq/opentide/pull/858) | `c5e82dc4` |
| UC-X.3 | [#849](https://github.com/opentidehq/opentide/pull/849) | `91079386` |
| Test fix: forget the cached repository root when a test ends | [#867](https://github.com/opentidehq/opentide/pull/867) | `51a52c27` |
| Test fix: keep the caller's `PYTEST_ADDOPTS` out of the root-cache probe | [#868](https://github.com/opentidehq/opentide/pull/868) | `47ae6f97` |
| UC-X.2 | [#855](https://github.com/opentidehq/opentide/pull/855) | `1cc105ab` |

### Decisions taken during Phase 0

- `engine_not_ported` (exit 2) added for `OPENTIDE_ENGINE=rust` on a command with no Rust implementation; `engine_unavailable` unchanged ([#854](https://github.com/opentidehq/opentide/pull/854)).
- `opentide-compare` is in the layer table (foundation, tier 0) though the [Crates](#crates) table does not name it; it goes with compare mode (UC-6.2). `OPENTIDE_ENGINE` is appended last to the environment variables of `opentide --json commands`, so the oracle's list is a prefix: an approved addition ([#854](https://github.com/opentidehq/opentide/pull/854)).
- `crowdstrike_unsupported` is kept as a retired code that `opentide explain` still explains, so the CQL import only adds codes ([#859](https://github.com/opentidehq/opentide/pull/859)).
- The golden budget is 128 MiB of apparent bytes (`cases/` and `blobs/`); `lsp start` is recorded as `--help` only, as `mcp start` is ([#857](https://github.com/opentidehq/opentide/pull/857)).
- The language server's 0.1 s first-diagnostics target ([Metrics](#11-metrics)) is waived until UC-2.6 ([#856](https://github.com/opentidehq/opentide/pull/856)).
- A runner CPU with no recorded baseline is held to the slowest recorded CPU's median + 20% ([#856](https://github.com/opentidehq/opentide/pull/856)).
- A per-CPU baseline keeps each command's slower median of two runs ([#856](https://github.com/opentidehq/opentide/pull/856)).
- cargo-deny skips the duplicate `syn@2.0.119` (`garde_derive`) and `bitflags@2.13.2` (`xtask` only) ([#853](https://github.com/opentidehq/opentide/pull/853), [#857](https://github.com/opentidehq/opentide/pull/857)).
- Phase 0 ends here; Phase 1 onwards is the next run.

### Maintainer steps outstanding

- Freeze language-server `main`, and disable its opentide canary or accept that it fails.
- Branch protection on `integration/unified-core`: the required checks of [`.github/AGENTS.md`](https://github.com/opentidehq/opentide/blob/integration/unified-core/.github/AGENTS.md#required-checks), among them `Golden compare`, `Supply chain (cargo deny)`, every `Fuzz smoke` cell including `Fuzz smoke (cql)`, and `Engine release (dry run) / SBOMs`; add `Rust coverage gates` (#855). The Golden workflow (`golden.yml`) is path-filtered, so requiring it blocks pull requests that do not touch its paths.
- Registry steps and trusted publishers ([publishing](https://github.com/opentidehq/opentide/blob/integration/unified-core/docs/internal/publishing.md#maintainer-steps)), including `opentide-cql`'s trusted publisher and second owner.
- The engine release-candidate tag, and the `opentidehq/vscode-extension` pull request that pins it.
- The `.claude/settings.json` allow-list.
- Transfer language-server's 9 open issues to this repository.
- Run `mutants.yml` once to record the mutation baseline (#855).
- Optional: set the repository variable `PARITY_COMMIT` (#855).
- [#788](https://github.com/opentidehq/opentide/pull/788) (CrowdStrike offline checks) needs a repin to engine 0.12.0 when it is scheduled.

## Contents

1. [Decisions](#1-decisions)
2. [Evidence](#2-evidence)
3. [Invariants](#3-invariants)
4. [Target architecture](#4-target-architecture)
5. [Correctness strategy](#5-correctness-strategy)
6. [Work plan](#6-work-plan)
7. [Rollout](#7-rollout)
8. [Distribution](#8-distribution)
9. [Repository and agentic development](#9-repository-and-agentic-development)
10. [Risks](#10-risks)
11. [Metrics](#11-metrics)

## 1. Decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| D-1 | All opentide logic is Rust: schema, workspace, validation, catalogue, compile, connectors, the CLI | One implementation removes the CLI/editor disagreement class; measured speed-ups of 4.6× (clean) to 18× (1,000 findings) on validate |
| D-2 | The Tide model is Rust code: serde (shape) + garde (constraints, custom validators, context) + schemars (JSON Schema) + PyO3 `#[pyclass]` (Python class), one concrete struct per revision | The Pydantic equivalent, verified in a prototype. JSON Schema, field hints, templates, snippets, `.pyi` and `.d.ts` are build artifacts of the code |
| D-3 | The CLI is `opentide-cli` (clap). Python's console script is `opentide = "opentide._native:main"`; npm's `bin` calls the same `main(argv)`; standalone binaries come from the same crate | 11–12 ms end to end through Python in the prototype. maturin cannot ship a PyO3 module and a binary in one wheel (PyO3/maturin#368); its guide recommends this route |
| D-4 | `opentidehq/language-server` merges into this repository with its history and is archived with a pointer. Every crate keeps its name and is published from here | 11.7% of language-server commits (23 of 197, 13 of them regenerating the Tide catalog) and 28 engine pins in 10 days exist only to keep the repositories in step; its test suite needs this repository's Python package |
| D-5 | An `opentide` facade crate is the Rust SDK and the only crate with a stability promise. Every binding depends on it alone | One API for Rust, Python and TypeScript. Internal crates are published for the facade's sake, documented as internal, as uv, ruff, polars and biome do |
| D-6 | npm: `@opentide/opentide` is both the SDK and the CLI (`bin: opentide`), with `@opentide/<platform>` native packages (napi-rs 3) and `@opentide/wasm` for the browser. The plain `opentide` name is an alias | The same shape as PyPI. A split into `sdk` and `cli` would be one native module behind two names |
| D-7 | `opentidehq/vscode-extension` stays a separate repository and consumes `@opentide/opentide` at one pinned version | Different toolchain, release channel and test harness; its coupling becomes one version number |
| D-8 | Connectors are Rust (tokio + reqwest). Third-party platforms keep a Python plugin hook | Six of nine platforms already use plain `requests`; the other three wrap REST APIs. opentide uses only `ClientSecretCredential`, which `azure_identity` 1.0 covers |

Each decision has an ADR on `integration/unified-core` ([index](https://github.com/opentidehq/opentide/blob/integration/unified-core/docs/internal/adr/index.md)): D-1 0002, D-2 0001, D-3 0003, D-4 0004, D-5 0005, D-6 0006, D-7 0007, D-8 0008 (#849, #853).

## 2. Evidence

Measured on 2026-11-07, linux-x64, 4 vCPU, opentide 0.22.0 from PyPI, a generated workspace of 300 threats, 300 objectives (450 signals) and 500 rules (1,100 objects, 1,000 queries in Sentinel KQL, Splunk SPL, Elastic KQL and ES|QL), medians of 3 cold runs.

| Command | Python CLI today | Rust |
|---------|-----------------:|-----:|
| `validate`, clean | 3.18 s, 171 MB | 0.69 s, 90 MB: language-server 0.10.0's engine, 4 threads, unoptimised |
| `validate`, 1,000 warnings | 12.76 s | 0.69 s |
| `validate --file`, `lint --file` | 1.77 s, 0.73 s | ~0.07 s (estimate: index 47 ms + 5 ms + launcher 11 ms) |
| `info catalog` (1.3 MiB) | 1.36 s | ~0.1 s (estimate) |
| `deploy --dry-run` (1,000 blocks) | 2.20 s | ~0.2 s (estimate) |
| `generate docs` (1,104 files) | 11.61 s | ~1 s (estimate) |
| Launcher | Typer + Rich import alone 69 ms | Python → `_native.main` 11 ms; native binary 1.1 ms |

The CLI's profile on `validate`: 34% ruamel re-reading files for line numbers, 27% repeated file I/O and globbing, 10% TOML parsing (about 22 parses per object), 3.5% the Rust query engine.

**Parity today.** 80 injected faults (16 kinds × 5 files): 61 identical in the CLI and the engine, 8 with different codes, 6 seen by one side only, 5 by neither (`frequency: hourly` in a Sentinel block). On a clean workspace the engine reports 2,200 warnings (`missing_author`, `missing_organisation`) where `validate` reports none and `lint` reports 1,100 `metadata_recommended` infos.

**History.** Same team, same agents: 1.46 code fixes per 1,000 lines per month in language-server (Rust) against 2.49 in this repository (Python). Full test suite: 69 s (Rust, with build) against 8.5 minutes on 4 workers (Python).

## 3. Invariants

These do not change at any step. A change to one is a separate, explicit decision with its own changelog entry.

1. **The CLI contract** in [`cli-experience.md`](./cli-experience.md), [`docs/cli/json-output.md`](../cli/json-output.md), [`docs/cli/exit-codes.md`](../cli/exit-codes.md) and [`docs/cli/diagnostics.md`](../cli/diagnostics.md): output modes and their resolution order, global flag hoisting, the JSON envelope (keys, types, indentation rule, trailing newline), exit codes and `failure.code` values, outcome-line grammar and glyphs, code frames, `next_actions`, CI sinks, SARIF and Code Quality reports, the crash handler and its redaction, Ctrl-C (exit 130, `error: interrupted`).
2. **The command tree**: `opentide --json commands` (paths, options, types, choices, defaults, environment variables, examples, `output_schema`) is byte-identical, or differs only by approved additions.
3. **Diagnostic codes**: every code keeps its meaning, severity, `field_path` and position rules (1-based lines, Unicode code-point columns, exclusive `end_column`) and its `opentide explain` page.
4. **Cross-repository contracts**: `opentide serve` (JSON-RPC, one message per line), `info catalog`, the tenants in `info`, progress events, as `opentidehq/vscode-extension` `docs/CONTRACTS.md` defines them; the LSP custom requests in language-server `docs/EDITORS.md`.
5. **MCP**: tool names, input schemas and payload shapes; the server instructions.
6. **Workspace formats**: object YAML (every published revision), configuration TOML, `.opentide/` layout, deployment state, generated files' paths and contents.
7. **SDK import paths** for one deprecation cycle: `from opentide import Opentide`, `opentide.models.*`, `opentide.validation.session.run_validation`, platform plugin entry points.
8. **Supported platforms**: CPython 3.10–3.14; the wheel targets of today plus native `win_arm64`.
9. **Security posture**: no secret in logs, JSON, crash logs or webviews; per-tenant TLS and CA settings; proxies from `OPENTIDE_PROXY` and the standard variables; nothing deploys on a dry run.

## 4. Target architecture

### Crates

Each crate depends only on crates in rows below it. `xtask check-layers` enforces this in CI, from [`xtask/layers.toml`](https://github.com/opentidehq/opentide/blob/integration/unified-core/xtask/layers.toml), the one place the enforced table is written down. It differs from this table in two ways: the bindings sit above the facade, since they wrap it (ADR 0005), and `opentide-compare` (UC-0.7) is a foundation crate that goes with compare mode (UC-6.2). The query crates include `-cql` since language-server 0.12.0 (#859).

| Layer | Crate | Responsibility | From |
|-------|-------|----------------|------|
| Facade | `opentide` | The public Rust API, features `schema`, `workspace`, `compile`, `connectors`, `cli`, `lsp`; re-exports; docs | new |
| Application | `opentide-cli` | clap command tree, output modes, renderers, envelopes, `serve`, `mcp`, `tui`, `main(argv)` | `src/opentide/cli/`, `mcp_server/` |
| Application | `opentide-lsp` | LSP host over `opentide-workspace`, incremental | language-server `opentide-lsp` |
| Domain | `opentide-workspace` | Loading, configuration resolution, index, validate, lint, fixes, catalogue, coverage, chaining | `loading/`, `registry/`, `indexing/`, `validation/`, `core/`; language-server `opentide-analysis`, `opentide-tide` checks |
| Domain | `opentide-compile` | Payload compile per platform, deploy plan, docs, exports, explorer, CI templates (minijinja) | `deployment/` planning, `platforms/*/compile`, `documentation/`, `export/`, `ci/` |
| Domain | `opentide-connectors` | Tenant clients over tokio + reqwest, deploy, live validation, query runners, MISP, migrate-state | `platforms/*/{client,deployer,runner,validator}`, `sharing/`, `query/` |
| Foundation | `opentide-schema` (+ `-derive`) | The Tide model as code, revisions, migrations, vocabularies, pins, configuration models, generated artifacts | `models/`, `vocabulary/`, `data/pins/`, `generation/` |
| Foundation | `opentide-core`, `-syntax`, `-highlight`, query crates (`-kql`, `-spl`, `-esql`, `-eql`, `-kuery`, `-lucene`, `-falco`, `-ecs`) | Shared types, YAML/TOML spans and edits, highlighting, query languages | language-server, unchanged |
| Bindings | `bindings/python` (PyO3 abi3), `bindings/node` (napi-rs 3), `bindings/wasm` (wasm-bindgen) | Thin wrappers over the facade; generated `.pyi` and `.d.ts` | `analysis/`, language-server `opentide-wasm` |

### The facade API

```rust
pub use opentide_schema::{Rule, Objective, Threat, SchemaId, Revision};
pub use opentide_workspace::{Workspace, Report, Diagnostic, Fix};

let ws = opentide::Workspace::open(path, &Options::default())?;  // parallel load + index
let report: Report = ws.validate(&ValidateOptions::default());   // every finding, with spans
let doc: serde_json::Value = opentide::cli::run_json(["info", "catalog"], &ws)?; // a --json document
#[cfg(feature = "connectors")]
let outcome = opentide::connectors::deploy(&ws.deploy_plan(Strategy::Preview)?).await?;
```

Every binding function is a one-line wrapper over a facade function. Logic in a binding fails review.

### The model

- One concrete struct per revision (`RuleV1_0`, `RuleV1_1`); unchanged sub-structs are shared; a declarative macro repeats shared fields; `#[pyclass]` does not accept generics.
- Derives: `Deserialize`, `Serialize`, `JsonSchema`, `Validate` (garde, with a `Pins` context carrying the revision's vocabulary versions), `#[pyclass(frozen, get_all)]` behind the `python` feature.
- The 23 `tide.*` metadata keys become `#[schemars(extend(...))]` attributes; constraints are `#[garde(...)]`, which schemars also reads.
- Structural errors: serde stops at the first. `opentide-schema-derive` generates a conversion from the saphyr node tree that collects every structural error with its span, as Pydantic reports every error; serde serves the happy path and serialisation. (`eserde` covers JSON and TOML only.)
- Of the 21 Pydantic validators ([ADR 0001](https://github.com/opentidehq/opentide/blob/integration/unified-core/docs/internal/adr/0001-tide-model-as-rust-code.md#validators), #853): 16 stay in the model (5 garde constraints or `custom` validators with `Pins`; 3 `mode="before"` checks in the structural conversion (UC-1.2) or a `deserialize_with`; 3 garde `custom` on a field type; 5 `deserialize_with`, the 3 enum names and the 2 date coercions `_coerce_dates` and `_coerce_reviewed`), none disappears, 3 become named checks (`elastic_rule_shape`, `sysdig_rule_shape`, `columns_fit_system`), and 2 sit outside the object models (the schema-identifier parser, UC-1.7; the vocabulary entry, UC-1.6). The date coercions stay because `core.io`'s loader stringifies YAML dates and timestamps (`isoformat()`, a `+00:00` offset written `Z`, a space written `T`), and the validators then turn any scalar into a string, not only a date; ADR 0001 has the case table.
- Revisions: `metadata.schema` selects the struct; an unknown revision is checked against the newest of its family without the unknown-key check, with a finding; migrations are `From` impls along a forward one-step chain, applied in memory. Files change only through `opentide migrate`.

## 5. Correctness strategy

The Python implementation at a frozen tag is the **oracle**. Nothing is ported without a test that compares the Rust result with the oracle's.

### 5.1 Golden capture (`xtask golden`)

For every command path in `opentide --json commands`, every output mode (`human` through a pseudo-terminal at fixed width, `plain`, `json`, `agent`), and every fixture workspace: record stdout, stderr, exit code, the JSON document, and every file written (path, bytes, mode). Normalise only what is non-deterministic: `duration_ms`, timestamps, absolute paths, temporary directory names, crash-log paths. Normalisation rules are code, reviewed and tested. Recordings live under `tests/golden/cases/<command>/<mode>/<fixture>/<variant>/` (a command path's words joined by `.`, `_root` for the bare program), a file of 16 KiB or more stored once in `tests/golden/blobs/<sha256>`, with their size and coverage in `tests/golden/COVERAGE.md`; they are reviewed like code ([`tests/golden/README.md`](https://github.com/opentidehq/opentide/blob/integration/unified-core/tests/golden/README.md)).

### 5.2 Differential runner and shadow mode

`OPENTIDE_ENGINE=python|rust|compare` selects the implementation per command during the migration. `compare` runs both and fails (exit 70, `failure.code: engine_mismatch`) on any difference, writing a structured diff report. CI runs every golden in `compare`. Users can run `compare` in their own CI before a default flips. Intended differences are recorded in `tests/golden/APPROVED_DIFFS.toml` with the reason, the issue and the changelog entry; anything else is a bug.

### 5.3 Corpora

- `tests/fixtures/tide_corpus` and every existing fixture.
- The heavy workspace generator (seeded; 300/300/500 by default, scalable to 10× for benchmarks).
- The fault catalogue: at least one fault kind per diagnostic code in `VALIDATION_CODES`, `LINT_CODES`, configuration and query codes, each in at least five files, plus combinations; today's 16 kinds are the start.
- Real-world corpora the team can share.
- Generated objects: proptest strategies derived from the models, and cargo-fuzz targets for the derive, the YAML/TOML layers and every query parser.

### 5.4 Layered tests

| Layer | Tool | What |
|-------|------|------|
| Unit | cargo-nextest | Every crate; a `fast` profile for agent loops and a full profile for CI |
| Snapshot | insta | Every diagnostic code's message, help and frame; every renderer |
| CLI | trycmd + goldens | Every command, mode and fixture |
| Property | proptest | Round trip (parse → serialise → parse), migration idempotence and totality, revision dispatch, fix safety (`is_safe_replacement`) |
| Fuzz | cargo-fuzz | Parsers, derive, configuration, never panic |
| HTTP | recorded cassettes | Connectors: method, URL, headers (secrets redacted) and body byte-equal to the Python client's; replayed with wiremock |
| Payload | byte-equality | Deploy compile output per platform and rule |
| Conformance | cross-SDK | The same corpus through Rust, Python and Node: identical documents |
| Strength | cargo-llvm-cov, cargo-mutants | Coverage gates per crate (90% for schema and workspace); mutation score tracked for schema and workspace |
| API | cargo-semver-checks | The facade |
| Performance | xtask bench | Budgets in [Metrics](#11-metrics); a regression over 10% fails |

### 5.5 Code rules

`#![forbid(unsafe_code)]` outside the bindings; workspace lints (`clippy::pedantic` subset, `unwrap_used` and `expect_used` denied outside tests, `missing_docs` on the facade); no panics on user input (fuzzed); every public error is a typed enum mapped to a stable code; `cargo-deny` for licences (EUPL-1.2-compatible), bans and advisories.

## 6. Work plan

Work items are numbered `UC-<phase>.<n>` and filed as sub-issues of the epic, one phase issue each. Every item lists its dependencies, its acceptance criteria and the commands that verify them.

| Phase | Python lines it replaces (opentide 0.23 `src/opentide`) | Rust it reuses |
|-------|------------------------------------------------------:|----------------|
| UC-1 | about 11.6k: `models` 5.1k, `generation` 5.2k, `vocabulary` 1.3k | `opentide-tide` field catalog and checks |
| UC-2 | about 11.0k: `validation` 4.6k, `core` 4.3k, `registry` 1.0k, `indexing` 0.7k, `loading` 0.5k | `opentide-analysis`, `opentide-tide`, the query crates (about 40k lines) |
| UC-3 | about 43k: `cli` 32.1k, `documentation` 3.5k, `ci` 3.0k, `deployment` 2.6k, `mcp_server` 1.8k, `export` 0.6k | `opentide-lsp` |
| UC-4 | about 17k: `platforms` 11.4k, `sharing` 2.8k, `extraction` 1.5k, `query` 1.1k | none |

### Phase 0: foundation

| ID | Item | Exit |
|----|------|------|
| UC-0.1 | Reserve names and trusted publishing: `opentide` on crates.io, the `@opentide` npm organisation (it exists already, holding `@opentide/explorer`: ADR 0006) and the `opentide` alias, trusted publishing on crates.io, PyPI and npm | Every name is owned; a dry-run publish succeeds from CI |
| UC-0.2 | Import language-server with its history (`git filter-repo`) into `crates/`, `grammars/`, `highlights/`, `catalogs/`, `editors/`, `packages/`, `fuzz/`, `testdata/`; one Cargo workspace; `analysis/` builds from path dependencies; `AGENTS.md` sections on the engine, its gates and the layout rewritten. `catalogs/` became `data/catalogs/` and `testdata/` `crates/testdata/`; [`docs/engine/IMPORT.md`](https://github.com/opentidehq/opentide/blob/integration/unified-core/docs/engine/IMPORT.md) has the mapping (ADR 0004) | `cargo test --workspace` and the Python suite pass; the engine pin, `check_engine_pin.py`, `check_engine_catalog.py`, `sync_opentide_schemas.py` and the canary are deleted or folded into in-repo tests. The vendor-parser oracles (`oracle.yml`, `scripts/oracles`: Kusto.Language, Splunk, Elasticsearch, Falco) are kept |
| UC-0.3 | One CI: Rust (fmt, clippy, nextest, doc) on Linux, macOS and Windows, Python (unchanged), WebAssembly, npm packages, the vendor-parser oracles; language-server's release assets keep publishing from here; required checks | All required checks green on `development`; a release of the engine assets from this repository |
| UC-0.4 | Agentic scaffolding: root and per-crate `AGENTS.md`, workspace lints, `xtask` (codegen, golden, bench, check-layers), nextest profiles, insta and trycmd | `cargo xtask check-layers` and `cargo nextest run --profile fast` exist and pass |
| UC-0.5 | Golden capture from the frozen Python CLI (5.1) | Every command × mode × fixture recorded; `xtask golden check` passes against Python |
| UC-0.6 | Corpora: heavy generator, fault catalogue, real-world intake (5.3) | Every diagnostic code has a fault kind; the generator is deterministic by seed |
| UC-0.7 | Differential runner and shadow mode (5.2) | `OPENTIDE_ENGINE=compare` runs both and reports diffs; the ledger exists |
| UC-0.8 | Benchmarks in CI with budgets (11) | Baselines recorded; regressions fail |

### Phase 1: `opentide-schema`

| ID | Item | Exit |
|----|------|------|
| UC-1.1 | Conventions and crate skeleton: derive stack, revision structs, naming, attribute mapping | ADR merged; skeleton compiles for native, PyO3 and wasm32 |
| UC-1.2 | `opentide-schema-derive`: collect-all structural errors with spans from the saphyr tree | Property and fuzz tests; codes and messages match Pydantic's on the fault catalogue |
| UC-1.3 | Object models: metadata, references, response, threat 1.0, objective 1.0 (signals), rule 1.0 and 1.1 | Pydantic verdict parity on every corpus |
| UC-1.4 | Platform blocks (nine), legacy keys, deprecations, named checks | Parity, including `elastic_rule_shape` and `sysdig_rule_shape` |
| UC-1.5 | Configuration models (platforms and tenants, deployment, documentation, paths, sharing, visibility, lint) with `toml_edit` spans | Parity with `configuration_text_issues` |
| UC-1.6 | Vocabularies and pins (RFC 0003), scoped vocabularies, stages, ATT&CK and Sentinel v18 | `sync_vocabularies --check` equivalent in `xtask`; parity |
| UC-1.7 | Revision registry and migrations | Dispatch, unknown-revision policy and migration chain property-tested |
| UC-1.8 | Generated artifacts from Rust: JSON Schemas and router, LSP field hints, templates, snippets, configuration schemas | Byte parity with `opentide generate` output, or approved diffs; drift check in CI |
| UC-1.9 | Python exposure: pyclasses under today's names, `.pyi`, `opentide.models.*` compatibility | The SDK test suite passes on the Rust models |

### Phase 2: `opentide-workspace`

| ID | Item | Exit |
|----|------|------|
| UC-2.1 | Loading: discovery, configuration resolved once, parallel parse, index, incremental invalidation | Parse counts equal file counts; index parity |
| UC-2.2 | Validation and the one diagnostic model; decisions on the parity gaps | `validate` goldens identical in `compare` on every corpus |
| UC-2.3 | Lint, `--fix` (safe text splices), `--watch` semantics as library API | `lint` and `validate --fix` goldens identical |
| UC-2.4 | Catalogue and info: `info`, `info catalog`, sections, `rules unreviewed`, coverage, chaining | Byte-identical documents |
| UC-2.5 | Query analysis wired through the workspace; `validate query` offline | Query findings identical |
| UC-2.6 | The language server on `opentide-workspace`: duplicate checks removed, configuration checks native, WebAssembly with configuration checks | LSP tests pass; editor and CLI agree by construction |
| UC-2.7 | Python wiring: `validate`, `lint`, `info`, `explain`, `rules`, `serve` read paths and MCP read tools call Rust, shadow then default | Defaults flipped after the parity window |

### Phase 3: `opentide-compile` and `opentide-cli`

| ID | Item | Exit |
|----|------|------|
| UC-3.1 | Deploy compile and plan: nine platforms, strategies, modifiers, deployment state, git baseline (gix) | Byte-identical payloads and plan documents |
| UC-3.2 | Generation: docs, exports, explorer, inflight, extract (offline), CI templates (minijinja) | Byte-identical files |
| UC-3.3 | CLI framework: command tree, modes, hoisting, envelope, codes, indentation, did-you-mean, crash handler, Ctrl-C, logging (levels per mode, stderr only, redaction), soft wrap, brand | `opentide --json commands` identical; framework goldens identical |
| UC-3.4 | Renderers: code frames (annotate-snippets), outcome lines, SARIF, Code Quality, CI sinks | Renderer snapshots and goldens identical |
| UC-3.5 | Commands, batch A: validate, lint, info, explain, rules, commands, doctor, new, migrate, generate | Goldens identical in `compare` |
| UC-3.6 | Commands, batch B: setup (wizard, JSONC edits keeping comments and CRLF), tui, serve, lsp start | Goldens and protocol tests identical |
| UC-3.7 | MCP on rmcp | Tool and resource parity, recorded sessions identical |
| UC-3.8 | Python launcher; Typer, Rich, Textual, questionary, ruamel, dulwich and structlog leave the runtime dependencies | The wheel's runtime dependencies are the connectors' only, until Phase 4 |

### Phase 4: `opentide-connectors`

| ID | Item | Exit |
|----|------|------|
| UC-4.1 | Framework: traits, tokio, reqwest with per-tenant TLS, CA, proxy and timeouts, credentials, cancellation, progress; recorded-HTTP harness | Cassettes recorded from Python replay identically |
| UC-4.2 | CrowdStrike, Defender, Elastic, HarfangLab, SentinelOne, Sysdig | Cassette and live parity |
| UC-4.3 | Splunk, Carbon Black, Sentinel (ARM, `azure_identity`, Log Analytics) | Cassette and live parity |
| UC-4.4 | MISP sharing, `query`, live validation, `deploy migrate-state`, online `generate extract`, CVE lookups, `doctor` network checks, `setup skills discover` | Cassette and live parity |
| UC-4.5 | Python platform plugin hook | A third-party plugin runs from Rust |

### Phase 5: SDKs and distribution

| ID | Item | Exit |
|----|------|------|
| UC-5.1 | Facade API, features, docs (docs.rs and a Rust page in `docs/sdk`), examples, semver checks | docs.rs builds; semver checks in CI |
| UC-5.2 | Python SDK: `Workspace` API, async, compatibility shims, `docs/sdk` | SDK docs examples run as tests |
| UC-5.3 | `@opentide/opentide` (napi-rs 3), platform packages, `bin`, `.d.ts`, alias; `@opentide/wasm`; the fate of `@opentide/lsp-client` and `@opentide/lsp-worker`; TypeScript docs | `npx @opentide/opentide --json commands` byte-identical to PyPI's |
| UC-5.4 | Cross-SDK conformance suite | Identical documents across Rust, Python and Node |
| UC-5.5 | Release train: lockstep versions, wheels (abi3; manylinux, musllinux, macOS, Windows x64 and arm64) and the sdist, npm, binaries (cargo-dist), the engine assets the extension pins (highlights zip, WebAssembly zip, licences, `SHA256SUMS`), SBOMs, attestations | One tag publishes everything |

### Phase 6: adoption and decommission

| ID | Item | Exit |
|----|------|------|
| UC-6.1 | VS Code extension on `@opentide/opentide` and `@opentide/wasm`; CPython bundle removed (filed in `opentidehq/vscode-extension` #75); licence review of an EUPL-1.2 library loaded in-process by the MIT extension | Packages without CPython, about 12 MiB; the licence review recorded |
| UC-6.2 | Default flip and Python implementation removal | No Python implementation left; `compare` removed |
| UC-6.3 | Archive language-server; docs and migration guide | Pointers in place; crates' repository URLs updated |

### Cross-cutting: quality gates

| ID | Item | Exit |
|----|------|------|
| UC-X.1 | Supply chain and safety: cargo-deny, unsafe policy, fuzzing in CI, SBOM | Gates required |
| UC-X.2 | Test strength: coverage gates, mutation testing, parity dashboard | Thresholds met |
| UC-X.3 | ADRs and contributor docs | Every decision in this page has an ADR |

## 7. Rollout

1. Every command runs Python by default until its Rust implementation is identical in `compare` on every corpus for one release.
2. The default flips per command with a changelog entry; `OPENTIDE_ENGINE=python` remains for one more release as an escape hatch.
3. The Python implementation of a command is deleted one release after its flip.
4. SDK names that change keep a deprecated alias for one minor release.
5. The extension moves when `@opentide/opentide` passes the conformance suite.

## 8. Distribution

| Channel | Package | Contents |
|---------|---------|----------|
| PyPI | `opentide` | abi3 wheel (CPython 3.10+): `opentide._native` (SDK + `main`), a thin Python layer, `.pyi` |
| crates.io | `opentide` and internal crates | Lockstep versions; internal crates documented as internal |
| npm | `@opentide/opentide`, `@opentide/<platform>`, `@opentide/wasm`, `opentide` | napi-rs 3 SDK + CLI, native binaries, browser subset, alias |
| GitHub Releases | `opentide`, `opentide-lsp` binaries | cargo-dist installers, checksums, attestations |
| Editors | `opentide-lsp` | Neovim, Helix and Zed configurations under `editors/` |

## 9. Repository and agentic development

```text
AGENTS.md            map of the repository, under 200 lines
Cargo.toml           workspace members, shared dependencies, [workspace.lints]
crates/              opentide, opentide-schema(-derive), -workspace, -compile, -connectors, -cli, -lsp,
                     -core, -syntax, -highlight, query/*
bindings/python/     maturin project: PyO3 crate + python/opentide
bindings/node/       napi-rs crate + npm/<platform>/
bindings/wasm/       wasm-bindgen crate
data/                vocabularies, pins, catalogs
grammars/ editors/   tree-sitter grammars, editor configurations
tests/               golden/, corpora/, conformance/, bench/
xtask/               codegen, golden, bench, check-layers, release
docs/                user and internal docs; references generated
```

- **Crates are context boundaries.** Each crate has an `AGENTS.md` of under 200 lines: purpose, invariants, how to test it, what not to touch.
- **The compiler is the first reviewer.** `cargo check` takes 0.7 s incremental; `clippy -D warnings` is required.
- **The verifier is near-perfect.** Goldens, the fault catalogue, conformance and benchmarks decide "done", not the agent.
- **Fast loops by default.** `cargo nextest run --profile fast` per crate; the full suite in CI.
- **Generated, never hand-edited.** `cargo xtask codegen` writes schemas, stubs, TypeScript types, the docs reference and the command tree; CI fails on drift.
- **Parallel agents** share a target directory per worktree pool, or set `CARGO_INCREMENTAL=0` for one-shot runs.
- **One concern per pull request**, cut from `development`, Conventional Commits, as [`AGENTS.md`](../../AGENTS.md) says.

## 10. Risks

| Risk | Mitigation |
|------|------------|
| Collecting every structural error | `opentide-schema-derive` (UC-1.2), fuzzed and property-tested |
| Comment- and format-preserving edits (`--fix`, `new`, `migrate`, `setup` JSONC) | Span-based text splices, as today's `--fix` already does; yamlpatch for structural changes; a dedicated JSONC editor for `setup` (#743) |
| Vendor authentication beyond client secrets | `azure_identity` 1.0 has ClientSecret, ClientCertificate, ManagedIdentity, WorkloadIdentity, AzureCli; no DeviceCode or InteractiveBrowser, which opentide does not use |
| Rendering drift (Rich vs Rust renderers) | Goldens in `human` mode through a fixed-width pseudo-terminal; approved diffs only |
| Third-party Python platforms | The plugin hook (UC-4.5) |
| Pre-1.0 dependencies (jsonschema is not used; rmcp, ratatui, gix move fast) | Exact pins, wrapped behind internal APIs, upgraded on purpose |
| Compile time and disk with parallel agents | Small crates, shared target directories, `fast` profiles |
| Scope (about 85k lines of Python) | Strangler order; each phase ships value on its own; the oracle stays until each flip |
| Licensing: today the extension (MIT) runs opentide (EUPL-1.2) as a separate program; in-process loading changes that argument | A licence review before UC-6.1, recorded with the decision; relicensing the bindings or keeping a process boundary are the fallbacks |
| Losing the vendor-parser oracles in the merge | They are kept as CI jobs (UC-0.3): they check the query parsers against Kusto.Language, Splunk, Elasticsearch and Falco, not against Pydantic |

## 11. Metrics

| Metric | Baseline (2026-11-07) | Target |
|--------|----------------------:|-------:|
| Heavy `validate`, clean / 1,000 findings | 3.18 s / 12.76 s | ≤ 0.7 s / ≤ 0.7 s |
| Heavy `validate --file` | 1.77 s | ≤ 0.1 s |
| Heavy `info catalog` | 1.36 s | ≤ 0.15 s |
| Heavy `deploy --dry-run` | 2.20 s | ≤ 0.3 s |
| Heavy `generate docs` | 11.61 s | ≤ 1.5 s |
| Light command (`explain`) | 0.18 s | ≤ 0.03 s |
| Language server first diagnostics (500 rules) | 0.7–3.0 s | ≤ 0.1 s |
| CLI/editor disagreement on the fault catalogue | 14 of 80 differ, 5 missed | 0 |
| Cross-repository coupling commits | 11.7% (language-server) | 0 |
| Heavy `validate` peak RSS | 171 MB | ≤ 100 MB |
| Editor memory per window (language server + backend) | 250–400 MB (vscode-extension SPEC D2) | ≤ 150 MB |
| Full test suite | 8.5 min (Python) | ≤ 3 min |
| VS Code package per platform | 50–61 MiB | ≤ 15 MiB |
| Wheel runtime dependencies | 73 packages | 0 |
