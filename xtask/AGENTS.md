# xtask — agent guide

`cargo xtask <command>` (the alias is in `.cargo/config.toml`: `run --locked --quiet --package
xtask --`): the repository's Rust tooling, as a workspace member that is never published.

| Command | Status |
|---------|--------|
| `check-layers [--metadata FILE] [--layers FILE]` | Checks that every dependency between workspace crates (normal, build and dev, on every target) points down the layer table, [`layers.toml`](layers.toml), against `cargo metadata --no-deps` |
| `corpus generate\|faults\|clean\|codes\|coverage` | The corpora of UC-0.6 (#804): the seeded heavy workspace, the fault catalogue run against the oracle, the code inventory and coverage report ([`tests/corpora/README.md`](../tests/corpora/README.md)) |
| `codegen` | Not implemented: UC-1.8 (#814) generates schemas, stubs, types and references with it |
| `golden` | Not implemented: UC-0.5 (#803) records and checks the oracle's goldens with it |
| `bench` | Not implemented: UC-0.8 (#806) runs the benchmarks against their budgets with it |
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

## Invariants

- The library (`src/lib.rs`, `src/layers.rs`) computes; `src/main.rs` reads files, runs cargo and
  prints. `src/corpus/` follows the same split inside its module: `generate`, `yaml`, `rng`,
  `workspace`, `faults` and `coverage` compute; `corpus/cli.rs` writes workspaces, runs the oracle
  and prints (main.rs only dispatches to it). Tests drive the library with synthetic metadata, no
  workspace needed.
- The corpus generator's output is a function of its options alone (own PRNG and YAML emitter, no
  clock, environment or file); `tests/corpus_generate.rs` records its digests.
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
  `tests/cmd/check-layers.in/`).
- `tests/workspace.rs`: the binary in a two-crate workspace of its own with an upward edge, run as
  `cargo run` and as a plain binary: it must check that workspace, not the repository.
- `tests/corpus_generate.rs`: the generator's recorded digests, counts, coverage of platforms and
  features, layouts, slug file names, no literal secret. `src/corpus/*` unit tests: the YAML
  emitter, the PRNG's reference values, the catalogue's parser, selectors, operations and verdicts.
  The oracle runs only in `cargo xtask corpus faults --check` (the `Corpus` workflow).
- `tests/lint_policy.rs`: every member inherits `[workspace.lints]`, except the crates allowed
  `unsafe` (`UNSAFE_CRATES`), whose copies must equal the workspace table with
  `unsafe_code = "deny"`.

## Do not

- Weaken a check to let a crate through: change the table, with the reason, in a reviewed change.
- Make a stub exit 0.

## Work items that change this crate

UC-0.4 (#802) check-layers; UC-0.6 (#804) corpus; UC-1.8 (#814) codegen; UC-0.5 (#803) golden; UC-0.8 (#806) bench;
UC-1.6 (#812) the `sync_vocabularies --check` equivalent; UC-0.3 (#801) wires the checks into one
CI. Lints and tests: [`crates/AGENTS.md`](../crates/AGENTS.md).
