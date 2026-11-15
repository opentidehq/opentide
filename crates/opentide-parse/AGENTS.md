# opentide-parse — agent guide

The parsing toolkit every pure-Rust query parser builds on (ADR 0012, epic #1219), on the
rust-analyzer pattern. Language-agnostic: kinds are `rowan::SyntaxKind` (`u16`), and a language
names the few the toolkit needs in a `Grammar`. I/O-free, no `unsafe`, no workspace dependency.

| Module | What |
|--------|------|
| `token_set.rs` | `TokenSet`: a 512-kind bitset (expected sets, recovery sets); a kind past `CAPACITY` panics, never vanishes |
| `input.rs` | `Grammar`, `Lexeme`, `lex` (a logos token source that resumes one character after an error), `Input` (trivia kept, skipped for lookahead) |
| `parser.rs` | `Parser` (`nth`/`at`/`eat`/`expect`/`bump_as`/`err_*`/`enter`/`exit`), `Marker`/`CompletedMarker::precede`, `Event`, `ErrorKind` |
| `tree.rs` | `build`: events to a lossless rowan `GreenNode` and `SyntaxError`s, iteratively |
| `differential.rs` | feature `differential`: the old-versus-new harness (below) |
| `debug.rs` | `debug_tree`/`debug_errors` for insta snapshots, `describe_expected` for messages |

## Place

foundation, tier 1 (`xtask/layers.toml`), beside `opentide-syntax`, which it replaces: it depends
on no workspace crate, and the query engines (tier 2 and up) build on it. Published with them.

## Invariants

- **Lossless.** Every byte of the source is in exactly one token of the tree: a language's logos
  token type never `skip`s (whitespace and comments are trivia kinds), and `build` puts whatever
  the grammar left unconsumed into an error node at the end of the root.
- **Finite on every input.** Three guards, each one diagnostic (`ErrorKind`) and never a panic in
  a release build:
  - nesting past `Grammar::max_depth` (`Parser::enter` returns `false`; the caller returns
    without `exit`) wraps the rest of the input in one error node: `TooDeep`;
  - a grammar loop that looks ahead without consuming runs out of fuel (2²⁴ lookups between two
    consumed tokens): `Stalled`, and debug builds panic in `Parser::finish`;
  - events that are not one balanced root become one error node over the source: `Unbalanced`,
    and debug builds panic in `build`.
- **No recursion in the toolkit.** `build`, `debug_tree` and the guards are iterative. A
  language keeps its own recursion bounded with `enter`, and keeps chains flat (`a or b or c` is
  one n-ary node): rowan drops a green tree recursively, one stack frame chain per level.
- **Markers.** A `Marker` is completed or abandoned; dropping one otherwise panics in debug
  builds (a grammar bug).
- **Spans** are rowan's `TextRange`/`TextSize` (bytes). UTF-16 is converted only at the LSP edge,
  by `opentide-core`.

## A language on the toolkit

- One `SyntaxKind` enum: token kinds first (below `TokenSet::CAPACITY`, 512), then node kinds.
  A `const` `TokenSet` built from a kind past the capacity fails to compile.
- `max_depth` at or above the language's floor in `crates/opentide-analysis/tests/deep_queries.rs`
  (what its tree-sitter engine accepted).
- Messages: the language maps `SyntaxError::kind` to its diagnostic codes and renders
  `SyntaxError::expected` with `describe_expected`.

## Differential harness (feature `differential`)

`differential::run(old, new, files, &config)` compares two `Engine`s (`observe` for whole-input
surfaces, `observe_at` for offset-indexed ones: hover, completions) over each file, its prefixes,
seeded token mutations (delete, duplicate, swap, insert a sample, duplicate a line, drop a
bracket, drop a quote) and random sentences. It knows no language: the caller's `Config` carries
the `verdict` (valid, judged from an observation), the lexer's token ranges and the token samples.

- Gates (`assert_gates`): valid input, zero differences on every surface (`Class::Valid`); broken
  input, the same verdict (`Class::Verdict`). Message and range changes on broken input
  (`Class::Broken`) are counted and listed, never failed: review them as snapshot diffs.
- Every difference is counted; `max_examples` caps only the listed examples per (surface, class).
- Offsets: every char boundary up to `max_offsets` per input, else an even stride (always with `0`
  and the end), so the sample is the same on every run. Prefixes are sampled the same way.
- Deterministic from `Config::seed`. `Report::write_json(path)` writes the report.
- Only dev-dependencies enable the feature (`opentide-parse = { workspace = true, features =
  ["differential"] }`): production code never links both engines. The test target needs it, so run
  `cargo nextest run -p opentide-parse --all-features`.

## Test

```bash
cargo nextest run --profile fast -p opentide-parse --all-features
cargo test -p opentide-parse --doc
```
