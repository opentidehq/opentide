# Fuzzing (#182)

`cargo-fuzz` targets for each engine and for the LSP host. Each language
target runs what an editor asks of a document (`src/lib.rs::exercise`):
`analyze()`, then hover, completion and signature help at a few offsets, and
for Tide its index, outline, links, lens and inlay hints. `protocol` frames
each `\0`-separated chunk of its input as a message and runs a session
through `opentide_lsp::serve`. A panic, or an input that runs past
`-timeout`, is a failure.

| Target | Seeds |
| --- | --- |
| `kql`, `spl`, `esql`, `eql`, `kuery`, `lucene`, `falco` | `crates/testdata/corpus/<lang>/`, `crates/testdata/conformance/external/<lang>/` |
| `tide` | `crates/testdata/objects/`, `crates/testdata/workspaces/tide_corpus/objects/` |
| `protocol` | `fuzz/seeds/protocol/` |

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run kql fuzz/corpus/kql crates/testdata/corpus/kql -- -timeout=10 -max_total_time=300
```

The first corpus directory is where libFuzzer keeps what it learns
(`fuzz/corpus/`, not committed); the others are read-only seeds.
`scripts/engine/fuzz.sh <target> [seconds]` runs one target with its seeds.

A crash is saved under `fuzz/artifacts/<target>/`. Fix it, then copy the
input to `fuzz/regressions/<target>/` with a name that says what it was
(`spl-prev-sibling-cycle`): `crates/opentide-analysis/tests/fuzz_regressions.rs`
and `crates/opentide-lsp/tests/fuzz_regressions.rs` replay every saved input
on stable Rust in the normal test run.

`.github/workflows/engine-fuzz.yml` runs each target for five minutes every night
and uploads what crashed. It does not gate pull requests.
