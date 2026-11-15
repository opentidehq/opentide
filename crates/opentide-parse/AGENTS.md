# opentide-parse — agent guide

The parsing toolkit every pure-Rust query parser builds on (ADR 0012, epic #1219), on the
rust-analyzer pattern. Language-agnostic: kinds are `rowan::SyntaxKind` (`u16`), and a language
names the few the toolkit needs in a `Grammar`. I/O-free, no `unsafe`, no workspace dependency.

| Module | What |
|--------|------|
| `token_set.rs` | `TokenSet`: a 512-kind bitset (expected sets, recovery sets); a kind past `CAPACITY` panics, never vanishes |
| `input.rs` | `Grammar`, `Lexeme`, `lex` (a logos token source that resumes one character after an error), `Input` (trivia kept, skipped for lookahead) |
| `parser.rs` | `Parser` (`nth`/`at`/`eat`/`expect`/`bump_as`/`err_*`/`enter`/`exit`), `Marker`/`CompletedMarker::precede`, `Event`, `ErrorKind` |
| `tree.rs` | `build`: events to a lossless rowan `GreenNode` and `SyntaxError`s, iteratively, no deeper than `MAX_TREE_DEPTH` |
| `ast.rs` | `AstNode` and `support`: the runtime of the typed AST `cargo xtask codegen` generates from a language's `.ungram` (below) |
| `conformance.rs` | `check`/`assert_conforms`: every node's children against its `.ungram` rule (`NodeRule`s, data the generated `RULES` holds), every mismatch reported with its range |
| `differential.rs` | feature `differential`: the old-versus-new harness (below) |
| `debug.rs` | `debug_tree`/`debug_errors` for insta snapshots, `describe_expected` for messages |

## Place

foundation, tier 1 (`xtask/layers.toml`), beside `opentide-syntax`, which it replaces: it depends
on no workspace crate, and the query engines (tier 2 and up) build on it. Published with them.

## Invariants

- **Lossless.** Every byte of the source is in exactly one token of the tree: a language's logos
  token type never `skip`s (whitespace and comments are trivia kinds), and `build` puts whatever
  the grammar left unconsumed into an error node at the end of the root.
- **Finite on every input.** Four guards, each one diagnostic (`ErrorKind`) and never a panic in
  a release build:
  - nesting past `Grammar::max_depth` (`Parser::enter` returns `false`; the caller returns
    without `exit`) wraps the rest of the input in one error node: `TooDeep`;
  - a tree deeper than `MAX_TREE_DEPTH` (4 096) nodes, which a `precede` loop reaches without
    calling `enter` (a left-associative `a + b + c …`), is flattened by `build`: the nodes past
    the limit are not opened and their tokens go to the node at the limit: `TreeTooDeep`;
  - a grammar loop that looks ahead without consuming runs out of fuel (2²⁴ lookups between two
    consumed tokens): `Stalled`, and debug builds panic in `Parser::finish`;
  - events that are not one balanced root become one error node over the source: `Unbalanced`,
    and debug builds panic in `build`.
- **No recursion in the toolkit.** `build`, `debug_tree` and the guards are iterative. A
  language keeps its own recursion bounded with `enter`, and keeps chains flat (`a or b or c` is
  one n-ary node): rowan drops a green tree recursively, a few stack frames per level, and
  `MAX_TREE_DEPTH` keeps under half of what a 1 MB debug-build stack holds.
- **Markers.** A `Marker` is completed or abandoned; dropping one otherwise panics in debug
  builds (a grammar bug). Abandoning a marker `precede` opened lets go of the node it was to
  wrap, which can be preceded again; preceding a node twice panics in debug builds.
- **Lexemes tile the source**: in order, contiguous, from 0 to the source's length, on char
  boundaries. `Input::new` checks it in debug builds only: a hand-driven lexer (modes) that
  breaks it loses bytes in a release build, so its tests must run its corpus in debug.
- **Spans** are rowan's `TextRange`/`TextSize` (bytes). UTF-16 is converted only at the LSP edge,
  by `opentide-core`.

## A language on the toolkit

- One `SyntaxKind` enum: token kinds first (below `TokenSet::CAPACITY`, 512), then node kinds.
  A `const` `TokenSet` built from a kind past the capacity fails to compile.
- `max_depth` at or above the language's floor in `crates/opentide-analysis/tests/deep_queries.rs`
  (what its tree-sitter engine accepted).
- Messages: the language maps `SyntaxError::kind` to its diagnostic codes and renders
  `SyntaxError::expected` with `describe_expected`.

## The typed AST (`.ungram`)

A language that navigates its tree writes `src/<lang>.ungram` (rust-analyzer's grammar DSL: the
readable spec of the tree, beside the vendor grammar) and runs `cargo xtask codegen`, which writes
`src/generated/ast.rs` (`codegen --check` fails when it is stale; `xtask/src/astgen.rs`): a struct
per node, an enum per `A = B | C`, an accessor per child (nodes, `<token>_token`, or the label's
name), and `RULES`. The crate supplies `Lang` (its `rowan::Language`), `SyntaxKind` (a variant per
node, `UPPER_SNAKE` of its name), `SyntaxNode`, `SyntaxToken` and a `T!` macro (`T![where]`,
`T!['(']`) for the grammar's tokens. A corpus test then runs
`assert_conforms(&root, RULES, GRAMMAR)` on every tree it parses. The generator refuses a node
type twice in one rule outside a repetition unless every occurrence is labeled, required and not
repeated (and, where an enum contains another occurrence's type, each after only occurrences its
type includes: `Index = base:Name idx:Expr` with `Name` in `Expr` is fine, `a:Expr b:Name` is not):
label them or write the accessor by hand. Unlabeled tokens of one kind share one accessor that
returns the first (`R = ('+' Name)*` gives one `plus_token`), and unlabeled repeated nodes of one
type merge into one `AstChildren` (`Call = Name '(' Name*` puts the callee in `names()`): label
what you need apart. A label also overrides the default plural (`day` -> `days`, `box` -> `boxes`
by the common English rules only). A Rust keyword becomes a raw identifier (`r#use`; `self`,
`Self`, `crate` and `super` take a trailing `_`). The toolkit's own test language
(`tests/ast_fixture/`) shows the whole loop.

## Differential harness (feature `differential`)

`differential::run(old, new, files, &config)` compares two `Engine`s (`observe` for whole-input
surfaces, `observe_at` for offset-indexed ones: hover, completions) over each file, its prefixes,
seeded token mutations (delete, duplicate, swap, insert a sample, duplicate a line, drop a
bracket or insert a stray one, drop a quote) and random sentences. It knows no language: the
caller's `Config` carries the `verdict` (valid, judged from an observation), the lexer's token
ranges and the token samples.

- Gates (`assert_gates`): valid input, zero differences on every surface (`Class::Valid`); broken
  input, the same verdict (`Class::Verdict`). Message and range changes on broken input
  (`Class::Broken`) are counted and listed, never failed: review them as snapshot diffs.
- Every difference is counted; `max_examples` caps only the listed examples per (surface, class).
  A surface an engine reports more than once is compared as the ordered list of its values.
- Offsets: every char boundary up to `max_offsets` per input, else an even stride (always with `0`
  and the end), so the sample is the same on every run. Prefixes are sampled the same way.
- Deterministic from `Config::seed`, which is mixed (splitmix64), so nearby seeds give unrelated
  inputs. `Report::to_json`/`to_json_string` render the report; the caller writes the file (the
  crate is I/O-free).
- Only dev-dependencies enable the feature (`opentide-parse = { workspace = true, features =
  ["differential"] }`): production code never links both engines. The crate's own tests turn it
  on through a dev-dependency on itself, so a plain `cargo test -p opentide-parse` (what CI runs)
  includes them; `cargo xtask check-layers` does not count that self-edge.

## Test

```bash
cargo nextest run --profile fast -p opentide-parse
cargo test -p opentide-parse --doc
```
