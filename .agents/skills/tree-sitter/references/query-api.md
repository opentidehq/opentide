# tree-sitter 0.25 Rust API

Crate: `tree-sitter` 0.25.10. Docs: <https://docs.rs/tree-sitter/0.25.10/tree_sitter/>.

## Loading the language

Published grammar crates export `LANGUAGE: LanguageFn` and callers write `parser.set_language(&tree_sitter_rust::LANGUAGE.into())`. This repo vendors `parser.c` and does not use `LanguageFn`.

```rust
unsafe extern "C" {
    fn tree_sitter_opentide_kql() -> *const ();
}

fn from_raw(ptr: *const ()) -> tree_sitter::Language {
    // from_raw expects *const TSLanguage and the pointer must be non-null.
    unsafe { tree_sitter::Language::from_raw(ptr as usize as *const tree_sitter::ffi::TSLanguage) }
}
```

`Language::new` takes a `LanguageFn`, not a raw pointer. Do not pass the C function to `Language::new`. Do not use a pre-0.24 `from_raw` signature that accepted `*const ()` without the `TSLanguage` cast; 0.25's `from_raw` is `pub const unsafe fn from_raw(ptr: *const TSLanguage) -> Self`.

`set_language` returns `Result<(), LanguageError>`. Map the error. Do not ignore it with `let _ =`.

## Queries and StreamingIterator

`QueryCursor::matches` and `QueryCursor::captures` return types that implement `StreamingIterator`, not `Iterator`. The trait is re-exported:

```rust
use tree_sitter::{Query, QueryCursor, StreamingIterator};

let query = Query::new(&language, scm).map_err(|e| e.to_string())?;
let mut cursor = QueryCursor::new();
let mut captures = cursor.captures(&query, tree.root_node(), source.as_bytes());
while let Some((m, cap_index)) = captures.next() {
    let cap = m.captures[*cap_index];
    let name = query.capture_names()[cap.index as usize].to_string();
    let start = cap.node.start_byte();
    let end = cap.node.end_byte();
    // `name`, `start`, and `end` are owned. `cap.node` is not valid after the next call.
}
```

Why this is not optional: the C cursor reuses the match buffer. Collecting `QueryMatch` values, or holding a `Node` across `next()`, reads freed or overwritten memory. The old `Iterator` impl was removed because `.collect()` returned the same last node repeated. Copy byte offsets and capture names out before the next iteration.

`captures` yields `(match, capture_index)` in highlight order (earliest start, then earliest pattern). `query_captures` in `opentide-syntax` then sorts and drops overlapping spans so LSP semantic tokens do not overlap. Keep that resolution. Do not emit two tokens for the same byte range.

`Query::new` fails when a pattern names a node kind the grammar does not have, or a capture the query cannot compile. Surface that error. Do not `unwrap` a query built from a file the user can edit. Queries compiled from `include_str!` of `highlights/queries/` may `expect` in tests; the highlight generator checks them in CI.

## Nodes

- `node.kind()` is the rule or token name (`"where_operator"`, `"|"`, `"identifier"`).
- `node.utf8_text(source.as_bytes())` borrows `source`. Do not store the `&str` after `source` moves.
- `start_byte` / `end_byte` are UTF-8 offsets into that source. Convert to LSP positions with `opentide_core::span_to_range`, which counts UTF-16.
- Anonymous nodes (`is_named() == false`) are literals such as `"|"`. Highlight queries name them explicitly (`"|" @operator.pipe`).
- `has_error()` on the root is the gate for `kql_parse_error` / `spl_parse_error`. Walk the tree only after that check, unless the walk is how you place the diagnostic on the `ERROR` node.

## What changed relative to blog posts

| Old snippet | 0.25 in this repo |
| --- | --- |
| `Language::from_raw(tree_sitter_kql())` with `*const ()` | cast to `*const TSLanguage` |
| `parser.set_language(language).unwrap()` ignoring `Result` | `map_err` |
| `.matches(...).collect()` | `StreamingIterator::next` and copy fields |
| `use streaming_iterator::StreamingIterator` as a direct dependency | `use tree_sitter::StreamingIterator` |
| `tree_sitter_highlight` crate | not used; HighlightSpec is ours |
