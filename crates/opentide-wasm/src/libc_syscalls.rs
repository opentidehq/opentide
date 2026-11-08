//! The syscalls wasi-libc can reach, answered inside the module.
//!
//! tree-sitter and the grammars are C. On `wasm32-unknown-unknown` they get
//! their libc (`malloc`, `snprintf`, `strncmp`, `iswalnum`, …) from wasi-sdk's
//! `libc.a`, linked by `scripts/engine/build-wasm.sh`. libc's stdio and clock code
//! can reach seven WASI syscalls. Defining their import symbols here keeps the
//! artifact free of WASI imports, so a browser loads it with wasm-bindgen's
//! glue alone: there are no files (every descriptor is bad) and no clock (time
//! is 0, so parse timeouts never fire).
//!
//! `#[unsafe(no_mangle)]` is unsafe because two definitions of one symbol are
//! undefined behaviour. Each name below is an import symbol wasi-libc
//! declares in `libc-bottom-half/sources/__wasilibc_real.c`
//! (`__imported_wasi_snapshot_preview1_<call>`, with the same i32/i64
//! parameters and i32 result), and nothing else in the
//! artifact defines it: on wasm32-unknown-unknown there is no WASI host to
//! import it from, so these are the only definitions the linker sees. The
//! module is compiled for that target only (`#[cfg]` in lib.rs). The one
//! `unsafe` block, in `clock_time_get`, is the only memory access.
//! `docs/internal/unsafe.md` lists every site.

const ERRNO_SUCCESS: i32 = 0;
const ERRNO_BADF: i32 = 8;

// SAFETY: the only definition of a wasi-libc import symbol (module docs).
#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_write(_: i32, _: i32, _: i32, _: i32) -> i32 {
    ERRNO_BADF
}

// SAFETY: the only definition of a wasi-libc import symbol (module docs).
#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_read(_: i32, _: i32, _: i32, _: i32) -> i32 {
    ERRNO_BADF
}

// SAFETY: the only definition of a wasi-libc import symbol (module docs).
#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_close(_: i32) -> i32 {
    ERRNO_BADF
}

// SAFETY: the only definition of a wasi-libc import symbol (module docs).
#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_seek(_: i32, _: i64, _: i32, _: i32) -> i32 {
    ERRNO_BADF
}

// SAFETY: the only definition of a wasi-libc import symbol (module docs).
#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_fdstat_get(_: i32, _: i32) -> i32 {
    ERRNO_BADF
}

// SAFETY: the only definition of a wasi-libc import symbol (module docs).
#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_fdstat_set_flags(_: i32, _: i32) -> i32 {
    ERRNO_BADF
}

/// `clock_time_get(id, precision, *time)`: always 0 ns.
// SAFETY: the only definition of a wasi-libc import symbol (module docs).
#[unsafe(no_mangle)]
#[expect(
    clippy::cast_sign_loss,
    reason = "the WASI ABI passes a linear-memory address as i32; on wasm32 `as usize` keeps its 32 bits"
)]
extern "C" fn __imported_wasi_snapshot_preview1_clock_time_get(_: i32, _: i64, time: i32) -> i32 {
    // SAFETY: wasi-libc's `__wasi_clock_time_get` (`__wasilibc_real.c`) passes `retptr0`, the
    // address of the caller's own `__wasi_timestamp_t` (a u64 in linear
    // memory), as this i32. On wasm32 a linear-memory address is 32 bits, so
    // `as usize` restores it whole, and it is valid for an 8-byte write for
    // the length of this call. `write_unaligned` asks nothing of alignment.
    unsafe { (time as usize as *mut u64).write_unaligned(0) };
    ERRNO_SUCCESS
}
