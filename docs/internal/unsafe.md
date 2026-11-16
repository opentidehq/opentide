---
title: Unsafe code
description: Every unsafe block, extern block and unsafe attribute in the Rust workspace, with why it is sound.
---

# Unsafe code

The workspace forbids `unsafe` (`unsafe_code = "forbid"` in the root `Cargo.toml`,
`[workspace.lints]`). One crate may hold it, because it crosses into C:

| Crate | Why it needs `unsafe` |
|-------|-----------------------|
| `crates/opentide-wasm` | The wasm32 libc shims: the WASI import symbols wasi-libc links against |

It copies the workspace's lint table with `unsafe_code = "deny"` and allows it on each
item with a reason; `xtask/tests/lint_policy.rs` fails when a copy drifts or another crate
leaves the workspace table. Every other member, the PyO3 binding (`bindings/python/`) included,
inherits `forbid`, but one:

| Crate | Why it copies the table with `deny` |
|-------|-------------------------------------|
| `bindings/node` | napi-rs: each `#[napi]` item expands to a static constructor (the `ctor` crate) that registers it with Node and carries `#[allow(unsafe_code)]`, which `forbid` refuses whatever the item. The crate writes no `unsafe` of its own and has no row below; an `unsafe` there would need its own `allow`, `SAFETY:` comment and row, as in the crate above |

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

| File | Item | What is unsafe | Why it is sound |
|------|------|----------------|-----------------|
| `crates/opentide-wasm/src/libc_syscalls.rs` | `fd_write` | `#[unsafe(no_mangle)]` on `__imported_wasi_snapshot_preview1_fd_write` | Two definitions of one symbol would be undefined behaviour. wasi-libc declares this import in `libc-bottom-half/sources/__wasilibc_real.c` with the same i32 parameters and i32 result; on wasm32-unknown-unknown there is no WASI host, so this is the only definition the linker sees. The module compiles for that target only. `scripts/engine/build-wasm.sh` checks the artifact imports nothing but wasm-bindgen's glue |
| `crates/opentide-wasm/src/libc_syscalls.rs` | `fd_read` | `#[unsafe(no_mangle)]` on `__imported_wasi_snapshot_preview1_fd_read` | As `fd_write` |
| `crates/opentide-wasm/src/libc_syscalls.rs` | `fd_close` | `#[unsafe(no_mangle)]` on `__imported_wasi_snapshot_preview1_fd_close` | As `fd_write` |
| `crates/opentide-wasm/src/libc_syscalls.rs` | `fd_seek` | `#[unsafe(no_mangle)]` on `__imported_wasi_snapshot_preview1_fd_seek` | As `fd_write` (its offset is the i64) |
| `crates/opentide-wasm/src/libc_syscalls.rs` | `fd_fdstat_get` | `#[unsafe(no_mangle)]` on `__imported_wasi_snapshot_preview1_fd_fdstat_get` | As `fd_write` |
| `crates/opentide-wasm/src/libc_syscalls.rs` | `fd_fdstat_set_flags` | `#[unsafe(no_mangle)]` on `__imported_wasi_snapshot_preview1_fd_fdstat_set_flags` | As `fd_write` |
| `crates/opentide-wasm/src/libc_syscalls.rs` | `clock_time_get` | `#[unsafe(no_mangle)]` on `__imported_wasi_snapshot_preview1_clock_time_get` | As `fd_write` (its precision is the i64) |
| `crates/opentide-wasm/src/libc_syscalls.rs` | `clock_time_get` | `unsafe extern "C" fn`: the function writes through a caller-supplied address | Its `# Safety` section states the contract: `time` must be the address of a `u64` writable for the call. wasi-libc's `__wasi_clock_time_get`, the only caller, passes exactly that; no Rust code calls it. A safe signature would promise any caller could pass any i32 |
| `crates/opentide-wasm/src/libc_syscalls.rs` | `clock_time_get` | `unsafe { (time as usize as *mut u64).write_unaligned(0) }` | wasi-libc's `__wasi_clock_time_get` passes the address of its caller's `__wasi_timestamp_t` (a u64 in linear memory) as this i32. A wasm32 address is 32 bits, so `as usize` restores it whole; it is valid for an 8-byte write for the call; `write_unaligned` asks nothing of alignment |

## Not ours

Code from dependencies is not listed: PyO3's and wasm-bindgen's macro expansions,
libfuzzer-sys. `cargo deny check` (`deny.toml`) gates those crates' licences, advisories and sources.
