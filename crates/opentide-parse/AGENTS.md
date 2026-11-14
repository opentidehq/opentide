# opentide-parse — agent guide

EXPERIMENT (exp/pure-rust-parser-kuery, never merged): the shared parsing toolkit a pure-Rust
parser builds on, on the rust-analyzer pattern. A logos lexer feeds a token source (trivia kept
for the tree, skipped for lookahead); hand-written grammar functions drive a `Parser` that records
events (`Start`/`Token`/`Finish`/`Error`) with markers (`precede` for left-associative and Pratt
loops), an expected-token set and a nesting guard; `build` turns the events into a lossless rowan
`GreenNode` plus `SyntaxError`s. Language-agnostic: kinds are `rowan::SyntaxKind` (`u16`).

## Place

foundation, tier 1 (beside opentide-syntax): depends on no workspace crate.

## Test

```bash
cargo nextest run --profile fast -p opentide-parse
```
