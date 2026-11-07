# Edition 2024

`edition = "2024"` applies to every workspace member. Code copied from an edition 2021 example will fail `cargo clippy -- -D warnings` or fail to compile. The migration guide is <https://doc.rust-lang.org/stable/edition-guide/rust-2024/>.

## unsafe extern

Extern blocks are `unsafe`. The syntax crate already uses the required form:

```rust
unsafe extern "C" {
    fn tree_sitter_opentide_kql() -> *const ();
    fn tree_sitter_opentide_spl() -> *const ();
}
```

A bare `extern "C" { ... }` is an edition error (`missing_unsafe_on_extern`). The author of the block is responsible for the signatures matching the generated C. `tree-sitter generate` emits `tree_sitter_<grammar_name>` where the grammar `name` uses underscores (`opentide_kql`).

## unsafe attributes

`no_mangle`, `export_name`, and `link_section` are written `#[unsafe(no_mangle)]`. wasm-bindgen's `#[wasm_bindgen]` attribute is its own macro; do not wrap it in `unsafe(...)`. Do not add `#[no_mangle]` on an engine function to "make it visible" to the host. The wasm crate exports through `#[wasm_bindgen]`.

## Tail-expression temporaries

Temporaries in a tail expression drop at the end of the block, before local variables. This compiles on 2021 and fails on 2024 when a temporary is borrowed past the block:

```rust
// Edition 2024: the temporary from `foo()` drops at the end of the block.
fn bad() -> &'static str {
    let s = String::from("x");
    s.as_str() // error: returns a reference to data owned by the current function
}
```

Bind the value you need to return. Do not "fix" it by leaking (`Box::leak`) or by `unsafe`.

## RPIT capture

`impl Trait` in return position captures every in-scope generic lifetime in edition 2024, not only the lifetimes written in the bounds. If a public function returns `impl Trait` and callers break after a signature change, the precise bound is `impl Trait + use<'_>` (or `use<'a, T>`). Prefer a named return type in this repo. The public engine API uses structs (`Diagnostic`, `AnalyzeResponse`, `HighlightResult`), not RPIT.

## if-let chains and let chains

`if let Some(x) = a && let Some(y) = b` is stable. Use it when it removes a nested match. Do not mix `&&` on a boolean with a `let` chain in a way that changes which side is evaluated; `let` chains short-circuit left to right.

## gen blocks

`gen` is a keyword in edition 2024. Do not name a variable, module, or field `gen`. Catalog words and KQL identifiers are data, not Rust identifiers, so a KQL `let` binding called `gen` is fine inside a string.

## unsafe review

New `unsafe` needs a comment that states the invariant the compiler cannot check. The existing tree-sitter `from_raw` call is the model: the pointer is the `TSLanguage` returned by the generated C function and is non-null for the life of the process. Do not use `unsafe` to silence a lifetime error.

`cargo clippy --workspace --all-targets -- -D warnings` includes `clippy::all` plus the warning-deny flag. `#[allow(dead_code)]` needs a reason on the same item. Unused imports fail the build.
