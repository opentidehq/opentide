---
title: Unsafe code
description: Every unsafe block, extern block and unsafe attribute in the Rust workspace, with why it is sound.
---

# Unsafe code

The workspace forbids `unsafe` (`unsafe_code = "forbid"` in the root `Cargo.toml`,
`[workspace.lints]`), and no crate holds any: the last two, the tree-sitter FFI
(`opentide-syntax`) and the browser build's libc shims (`opentide-wasm`), left with
tree-sitter (#1231). A crate that came to need it would copy the workspace's lint table with
`unsafe_code = "deny"`, allow it on each item with a reason, and be listed in
`xtask/tests/lint_policy.rs`, which fails when a copy drifts or another crate leaves the
workspace table. Every member, the PyO3 binding (`bindings/python/`) included, inherits
`forbid`, but one:

| Crate | Why it copies the table with `deny` |
|-------|-------------------------------------|
| `bindings/node` | napi-rs: each `#[napi]` item expands to a static constructor (the `ctor` crate) that registers it with Node and carries `#[allow(unsafe_code)]`, which `forbid` refuses whatever the item. The crate writes no `unsafe` of its own and has no row below; an `unsafe` there would need its own `allow`, `SAFETY:` comment and row |

The `unsafe` napi-rs and PyO3 generate sits in their macros' expansions, which these lints do
not report (code from an external macro); the crates that ship it (`napi`, `pyo3`) answer for it.

Two clippy lints hold every block to account:

- `undocumented_unsafe_blocks` (denied): each `unsafe` block carries a `// SAFETY:` comment.
- `multiple_unsafe_ops_per_block` (denied): each block holds one unsafe operation, so its
  comment answers for exactly one thing.

Neither lint reads an `unsafe extern` block, an `unsafe fn` or an unsafe attribute. Those
carry a `SAFETY` comment by this policy (and an `unsafe fn` a `# Safety` section), and the
table below lists them with the blocks. `xtask/tests/unsafe_listing.rs` fails when an
`unsafe` keyword has no `SAFETY:` comment in the lines just above it.

## Every site

`xtask/tests/unsafe_listing.rs` counts the `unsafe` keywords in each Rust file of the
workspace and of `fuzz/` (comments and string literals left out) and fails when a file's
count differs from its rows here. Adding `unsafe` means adding its row, with the reason,
in the same change.

There are none.

| File | Item | What is unsafe | Why it is sound |
|------|------|----------------|-----------------|

## Not ours

Code from dependencies is not listed: PyO3's and wasm-bindgen's macro expansions,
libfuzzer-sys. `cargo deny check` (`deny.toml`) gates those crates' licences, advisories and sources.
