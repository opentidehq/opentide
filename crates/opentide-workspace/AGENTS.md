# opentide-workspace — agent guide

Loading a Tide workspace once, in parallel, into the index the CLI, the SDK, `serve`, MCP and the
language server share (plan §4, the `opentide-workspace` domain crate; UC-2.1, #816). It ports the
oracle's `core/root.py`, `registry/discovery.py`, `registry/paths.py`, `registry/catalogue.py`,
`registry/builder.py` (object loading), `registry/signals.py`, `core/chaining.py` and the
references `validation/checks/cross_object.py` follows; the catalogue, coverage, `info`'s data and
`rules unreviewed` (UC-2.4, `cli/services/catalog.py`, `info.py`, `rules.py`). Validation, lint
and the language server come next (UC-2.2, UC-2.3, UC-2.5, UC-2.6).

## Place

domain, tier 0 (`xtask/layers.toml`), beside opentide-tide: it depends on opentide-schema (the
YAML 1.2 node tree, the configuration models and their layering) and on no other domain crate.
`publish = false` while opentide-schema is unpublished; CI packages it with neither and scans its
source (`ci.yml` `engine-package`, `scripts/ci-local.sh`).

## Layout

| Path | What |
| --- | --- |
| `src/fs.rs` | `FileSystem` (every read goes through it), `OsFs` (the disk), `MemoryFs` (tests, editor buffers; counts reads by path) |
| `src/root.rs` | `RootOptions` (`--repo`, `OPENTIDE_REPO_ROOT`, `OPENTIDE_TIDE_WORKSPACE`, the working directory: the host passes them, `from_env` reads the process's), `resolve` |
| `src/config.rs` | The configuration folders read through the `FileSystem` and resolved once (`opentide_schema::configuration::resolve`), `paths.toml` checked, the object folders |
| `src/discover.rs` | Object files: direct children of a family folder, `.yaml`/`.yml` case-sensitively, `.debug.*` left out; deeper files are nested; linked folders are not entered |
| `src/load.rs` | One file: bytes to a YAML 1.2 `Document`, or its `Failure` (`not_utf8_problem` and `root_mapping_problem` word for word as the oracle's) |
| `src/index.rs` | `assemble`: the index from the scans and parses, in discovery order: objects, `file_paths`, duplicates, load errors (`yaml_parse`, `missing_uuid`), nested files, signals, references, chaining |
| `src/workspace.rs` | `Workspace::open` (parallel read and parse with rayon), `Stats`, `invalidate` |
| `src/registry.rs` | `Registry`: the SDK lifecycle (`initialise` once, `reload`, accessors, `lookup`) |
| `src/fields.rs` | Reading fields by their model role (`core/object_fields.py`): role paths from `opentide_schema::objects::fields`, Python's `str()` of a value |
| `src/coverage.rs` | Own and inherited techniques of each rule, `info coverage`'s match (`core/technique_coverage.py`) |
| `src/catalogue.rs` | `info catalog`'s document (UC-2.4): object rows, load-error rows read from the text, edges (`covers`, `implements`, `parent`, `chains`, `technique`, `logsource`), signals, the ATT&CK matrix, the summary |
| `src/state.rs` | The deployment state shards, read only, for the catalogue's `deployment` |
| `src/info.rs` | `info`: the platforms with their tenants (names of variables, never values), the vocabularies and their pins |
| `src/review.rs` | `rules unreviewed`: the window, review instants (jiff), the RFC 0008 predicate |
| `src/export.rs` | `Index::to_json`: what `cargo xtask registry diff` compares |
| `examples/load.rs` | `cargo xtask bench`'s `load` command for the Rust engine |
| `tests/loading.rs` | Discovery, counts (one read and one parse per file, one resolution), load errors, duplicates, signals, references, the registry lifecycle, invalidation, the disk |
| `tests/index.rs` | Property test: after any edits, creations, deletions, renames and `paths.toml` changes, the incremental index equals a full rebuild |

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
- YAML is opentide-schema's (YAML 1.2, saphyr); never re-implement a YAML 1.1 rule for parity.
- No panics on what a file holds. `std::fs` only in `fs.rs` (`OsFs`); the rest reads through the
  `FileSystem`. No environment read but `RootOptions::from_env`.

## Test

```bash
cargo nextest run -p opentide-workspace loading index
cargo xtask registry diff --against python --corpus all   # needs the oracle (OPENTIDE_ORACLE)
cargo xtask bench --engine rust --only load
```

## Work items that change this crate

UC-2.1 (#816) loading; UC-2.2 (#817) validation and the diagnostic model; UC-2.3 (#818) lint and
fixes; UC-2.4 (#819) catalogue and info; UC-2.5 (#820) query analysis; UC-2.6 (#821) the language
server on it; UC-2.7 (#822) the Python wiring. Lints, tests and the layer rule:
[`crates/AGENTS.md`](../AGENTS.md).
