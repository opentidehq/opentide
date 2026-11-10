# opentide-workspace — agent guide

Loading a Tide workspace once, in parallel, into the index the CLI, the SDK, `serve`, MCP and the
language server share (plan §4, the `opentide-workspace` domain crate; UC-2.1, #816). It ports the
oracle's `core/root.py`, `registry/discovery.py`, `registry/paths.py`, `registry/catalogue.py`,
`registry/builder.py` (object loading), `registry/signals.py`, `core/chaining.py` and the
references `validation/checks/cross_object.py` follows. It runs `validate` (UC-2.2, #817:
`validation/`, `cli/services/validation.py`, `cli/ui/diagnostics.py`) and reports every finding
as the one `Diagnostic` ([ADR 0010](../../docs/internal/adr/0010-one-diagnostic-model.md)). It
runs `lint`, `validate --fix` (safe edits as text splices) and `--watch`'s pass selection (UC-2.3,
#818: `cli/services/lint.py`, `cli/ui/fixes.py`, `cli/ui/watch.py`). The catalogue, the queries
check and the language server come next (UC-2.4 to UC-2.6).

## Place

domain, tier 0 (`xtask/layers.toml`), beside opentide-tide: it depends on opentide-schema (the
YAML 1.2 node tree, the configuration models and their layering) and on no other domain crate.
`publish = false` while opentide-schema is unpublished; CI packages it with neither and scans its
source (`ci.yml` `engine-package`, `scripts/ci-local.sh`).

## Layout

| Path | What |
| --- | --- |
| `src/fs.rs` | `FileSystem` (every read goes through it), `OsFs` (the disk), `MemoryFs` (tests, editor buffers; counts reads by path); `WriteFs` (what `--fix` writes: `replace` only while the file holds what was read, through a temporary file renamed into place; `rename_file`), `Stamp` (`--watch`'s snapshot) |
| `src/root.rs` | `RootOptions` (`--repo`, `OPENTIDE_REPO_ROOT`, `OPENTIDE_TIDE_WORKSPACE`, the working directory: the host passes them, `from_env` reads the process's), `resolve` |
| `src/config.rs` | The configuration folders read through the `FileSystem` and resolved once (`opentide_schema::configuration::resolve`), `paths.toml` checked, the object folders |
| `src/discover.rs` | Object files: direct children of a family folder, `.yaml`/`.yml` case-sensitively, `.debug.*` left out; deeper files are nested; linked folders are not entered |
| `src/load.rs` | One file: bytes to a YAML 1.2 `Document`, or its `Failure` (`not_utf8_problem` and `root_mapping_problem` word for word as the oracle's) |
| `src/index.rs` | `assemble`: the index from the scans and parses, in discovery order: objects, `file_paths`, duplicates, load errors (`yaml_parse`, `missing_uuid`), nested files, signals, references, chaining |
| `src/workspace.rs` | `Workspace::open` (parallel read and parse with rayon), `Stats`, `invalidate` |
| `src/registry.rs` | `Registry`: the SDK lifecycle (`initialise` once, `reload`, accessors, `lookup`) |
| `src/diagnostic.rs` | `Diagnostic`, `Severity`, `Fix`, `TextEdit`: the one finding type, serialised exactly as an issue of `validate --json` (keys in order); the frame's label and notes ride along unserialised |
| `src/validate/mod.rs` | `validate` / `Workspace::validate`: the checks in the oracle's order, `--check`, `--queries`, `--strict`, the report (errors sorted as `sort_issues`), `checks` statuses, `summary`; `QueryCheck`, the host's query analysis (UC-2.5) |
| `src/validate/scope.rs` | `--file`, `--uuid`, `--type` (`validation/scope.py`) |
| `src/validate/objects.rs` | One object's checks: UUID format, schema (`revisions::dispatch`), the vocabulary walk over the revision's JSON Schema with its pins, configured values, deprecated fields, `platform_not_enabled`, vendor ids, references, chaining, `merge_reference_findings` |
| `src/validate/states.rs` | `.opentide/states/deployment/` shards (`states/deployment.py`) |
| `src/validate/annotate.rs` | `path`, `line`, `column`, `end_*`, `help`, `fix`, label and notes of each finding (`diagnostic_from_issue`) |
| `src/fix.rs` | `validate --fix`: `plan` (safe edits re-checked at their span, the file still parsing and differing in that one value), `FixPlan::write`, `FixPlan::diff` (the `similar` crate's unified diff, never a port of difflib), `Workspace::validate_fix` |
| `src/lint/` | `lint` / `Workspace::lint`: every `LINT_CODES` rule, `lint.toml`, `--check`, `--file`, `--changed` (the host's diff), `--strict`, `--fix` renames; `LintFinding` (the JSON entry, keys in the oracle's order, and its `Diagnostic`; `info` is `Severity::Info`, framed `note`); `lint_file` (the editor's file name and metadata findings, KG-03/KG-05); `stems.rs` (`slugify`, `expected_stem`, `.debug` suffixes) |
| `src/watch/` | `--watch`: `Watcher` (snapshot, references, findings by file), `select_pass` and `scoped_pass_holds` (the full-versus-scoped rules of `docs/internal/cli-experience.md`), `WorkspaceValidate`; `events.rs`, `notify`'s events that wake the loop (not on WebAssembly). Drawing a pass is UC-3.5's |
| `src/export.rs` | `Index::to_json`: what `cargo xtask registry diff` compares |
| `examples/load.rs` | `cargo xtask bench`'s `load` command for the Rust engine |
| `examples/validate.rs` | `cargo xtask bench`'s `validate_*` commands for the Rust engine |
| `tests/loading.rs` | Discovery, counts (one read and one parse per file, one resolution), load errors, duplicates, signals, references, the registry lifecycle, invalidation, the disk |
| `tests/validate.rs` | Each check's findings, places and steps, the scope, the verdict and counts; every recorded `validate --json` finding round-trips through `Diagnostic` byte for byte |
| `tests/index.rs` | Property test: after any edits, creations, deletions, renames and `paths.toml` changes, the incremental index equals a full rebuild |
| `tests/lint.rs` | Each lint rule's JSON entry and frame, `lint.toml`, the scope options, `--fix` renames, `lint_file` |
| `tests/fix.rs` | Property test: any set of fixes changes no byte outside its spans and the result parses; a file changed after it was read is not written |
| `tests/watch.rs` | The watch pass rules case by case, the watcher end to end, `notify` on disk |
| `tests/external_difflib.rs` | The dry run's diff against CPython's `difflib` (needs a Python: `OPENTIDE_PYTHON` or `.venv`; left out of the fast profile): both patch the file to the same result |

## Invariants

- The Python registry at the frozen tag is the oracle: `cargo xtask registry diff --against python
  --corpus all` compares the index on every fixture, the heavy workspace, the generator's layouts
  and each fault kind alone. A difference is a bug unless a rule of `xtask/src/registry.rs`
  `APPROVED` (or `INVALID_DATES`) explains it, with its CHANGELOG lead; a rule that explains
  nothing fails the run.
- Each object file is read once and parsed once per load; an invalidation re-reads only the files
  its changes name. The configuration is resolved once per load and again only when a path in a
  configuration folder changes. `Stats` counts all three; the tests hold them.
- The index is a pure function of the scans and the parses (`index::assemble`), taken in discovery
  order: a full load and an incremental one build the same index from the same parses.
- `validate` reports what the oracle's `validate --json` reports: `cargo xtask validate diff`
  runs every recorded checking case against its recording; a difference is a bug unless a rule of
  `xtask/src/validate.rs` `APPROVED` explains it, with its CHANGELOG lead (a stale rule fails).
  The queries check's findings are UC-2.5's and left out of the comparison.
- A `Diagnostic`'s JSON keys and their order are the CLI contract (plan §3): never add, drop or
  move one; what only a frame shows goes in `label` and `notes`.
- YAML is opentide-schema's (YAML 1.2, saphyr); never re-implement a YAML 1.1 rule for parity.
- No panics on what a file holds. `std::fs` only in `fs.rs` (`OsFs`); the rest reads and writes
  through the `FileSystem` and `WriteFs`, and `watch/events.rs` holds the one other OS handle,
  `notify`'s watcher. No environment read but `RootOptions::from_env`.
- `lint` reports what the oracle's `lint --json` reports, key for key: `cargo xtask lint diff`
  runs every recorded case (`--fix` on a fresh copy, its renames compared); `validate diff` runs
  the `--fix` and `--fix --dry-run` cases with their diff and files. A difference is a bug unless a
  rule of `xtask/src/lint.rs` or `xtask/src/validate.rs` `APPROVED` explains it.
- A fix is a text splice: every byte outside its span is kept (`tests/fix.rs`), and a file is
  written only while it holds the text the plan read. Never write YAML back from a parsed tree.

## Test

```bash
cargo nextest run -p opentide-workspace loading index validate lint fix watch
cargo xtask validate diff                                 # the recordings; no oracle needed
cargo xtask lint diff                                     # the recordings; no oracle needed
OPENTIDE_PYTHON=python3 cargo test -p opentide-workspace --test external_difflib
cargo xtask bench --engine rust --only validate_clean,validate_warnings,validate_file
cargo xtask registry diff --against python --corpus all   # needs the oracle (OPENTIDE_ORACLE)
cargo xtask bench --engine rust --only load
```

## Work items that change this crate

UC-2.1 (#816) loading; UC-2.2 (#817) validation and the diagnostic model; UC-2.3 (#818) lint and
fixes; UC-2.4 (#819) catalogue and info; UC-2.5 (#820) query analysis; UC-2.6 (#821) the language
server on it; UC-2.7 (#822) the Python wiring. Lints, tests and the layer rule:
[`crates/AGENTS.md`](../AGENTS.md).
