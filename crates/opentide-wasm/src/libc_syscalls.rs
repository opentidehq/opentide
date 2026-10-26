//! The syscalls wasi-libc can reach, answered inside the module.
//!
//! tree-sitter and the grammars are C. On `wasm32-unknown-unknown` they get
//! their libc (`malloc`, `snprintf`, `strncmp`, `iswalnum`, …) from wasi-sdk's
//! `libc.a`, linked by `scripts/build-wasm.sh`. libc's stdio and clock code
//! can reach seven WASI syscalls. Defining their import symbols here keeps the
//! artifact free of WASI imports, so a browser loads it with wasm-bindgen's
//! glue alone: there are no files (every descriptor is bad) and no clock (time
//! is 0, so parse timeouts never fire).

const ERRNO_SUCCESS: i32 = 0;
const ERRNO_BADF: i32 = 8;

#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_write(_: i32, _: i32, _: i32, _: i32) -> i32 {
    ERRNO_BADF
}

#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_read(_: i32, _: i32, _: i32, _: i32) -> i32 {
    ERRNO_BADF
}

#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_close(_: i32) -> i32 {
    ERRNO_BADF
}

#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_seek(_: i32, _: i64, _: i32, _: i32) -> i32 {
    ERRNO_BADF
}

#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_fdstat_get(_: i32, _: i32) -> i32 {
    ERRNO_BADF
}

#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_fd_fdstat_set_flags(_: i32, _: i32) -> i32 {
    ERRNO_BADF
}

/// `clock_time_get(id, precision, *time)`: always 0 ns.
#[unsafe(no_mangle)]
extern "C" fn __imported_wasi_snapshot_preview1_clock_time_get(_: i32, _: i64, time: i32) -> i32 {
    // SAFETY: libc passes the address of a u64 in linear memory.
    unsafe { (time as usize as *mut u64).write_unaligned(0) };
    ERRNO_SUCCESS
}
