# Fuzzing (#182)

`cargo-fuzz` targets for each engine and for the LSP host. Each language
target runs what an editor asks of a document (`src/lib.rs::exercise`):
`analyze()`, then hover, completion and signature help at a few offsets, and
for Tide its index, outline, links, lens and inlay hints. `protocol` frames
each `\0`-separated chunk of its input as a message and runs a session
through `opentide_lsp::serve`; `framing` hands its input to `serve` unframed,
so the header reader sees what a client could send. `config` is configuration
TOML as the engine sees it (`opentide_analysis::config`): its first byte picks
a file, then the buffer, then `\0`-separated field paths that a stand-in host
checker reports, for the engine to place; hover and completion walk the
schemas in `crates/testdata/config/schemas/`. A panic, or an input that runs
past `-timeout`, is a failure.

| Target | Seeds |
| --- | --- |
| `kql`, `spl`, `esql`, `eql`, `kuery`, `lucene`, `falco`, `cql` | `crates/testdata/corpus/<lang>/`, `crates/testdata/conformance/external/<lang>/` |
| `tide` | `crates/testdata/objects/`, `crates/testdata/workspaces/tide_corpus/objects/` |
| `protocol` | `fuzz/seeds/protocol/` |
| `framing` | `fuzz/seeds/framing/` (the protocol seeds, framed) |
| `config` | `fuzz/seeds/config/` (opentide's configuration templates, `src/opentide/data/configurations/`, each with its file byte and a few field paths) |
| `cli` | `fuzz/seeds/cli/` (`\0`-separated command lines: the framework goldens' usage errors, hoisting, `--version`, `--help`) |

## Targets the plan adds later

UC-X.1 (#843) asks for four more inputs to be fuzzed. Three have Rust code today
and a target here: configuration TOML (`config`), the message reader
(`framing`, the language server's; `protocol` covers what follows it) and the
`opentide` command line (`cli`, UC-3.3: `\0`-separated arguments through the
clap tree, hoisting, the output modes and the usage errors of
`opentide_cli::run`; a crash report, `error[internal]`, is the failure, since
the run catches its own panics). The item that writes the code adds the
target:

| Input | Target arrives with |
| --- | --- |
| `from_node`: a Tide object from its YAML tree | UC-1.2 (#808), `opentide-schema-derive` |
| `opentide serve`'s message reader (one JSON-RPC message per line) | UC-3.6 (#828) |

```bash
rustup toolchain install "$(cat fuzz/NIGHTLY)"   # the dated nightly CI fuzzes with
cargo +"$(cat fuzz/NIGHTLY)" install cargo-fuzz --locked --version 0.13.2
cargo +"$(cat fuzz/NIGHTLY)" fuzz run kql fuzz/corpus/kql crates/testdata/corpus/kql -- -timeout=10 -max_total_time=300
```

The first corpus directory is where libFuzzer keeps what it learns
(`fuzz/corpus/`, not committed); the others are read-only seeds.
`scripts/engine/fuzz.sh <target> [seconds]` runs one target with its seeds.

A crash is saved under `fuzz/artifacts/<target>/`. Fix it, then copy the
input to `fuzz/regressions/<target>/` with a name that says what it was
(`spl-prev-sibling-cycle`): `crates/opentide-analysis/tests/fuzz_regressions.rs`,
`crates/opentide-analysis/tests/config_fuzz_regressions.rs`,
`crates/opentide-lsp/tests/fuzz_regressions.rs` and
`crates/opentide-cli/tests/fuzz_regressions.rs` replay every saved input (and
the `protocol`, `framing`, `config` and `cli` seeds) on stable Rust in the normal
test run. Add a unit test that names what was wrong, too, failing before the
fix (`crates/opentide-lsp/src/protocol.rs`,
`a_length_longer_than_the_input_ends_it_without_allocating_the_length`, came
from `framing`).

`.github/workflows/engine-fuzz.yml` runs every target for ten minutes every night,
keeps each target's corpus in the Actions cache, and uploads what crashed.
ci.yml's `fuzz-smoke` runs every target for 60 s on each pull request: a panic
or a timeout there fails the PR. `tests/test_ci/test_one_ci.py` and
`tests/test_ci/test_supply_chain.py` fail when a target is missing from either
matrix.
