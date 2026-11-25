//! Threads where the target has them.
//!
//! WASI (`wasm32-wasip1`) has none: `std::thread::spawn` fails there, and a
//! scoped spawn panics. What a command runs on threads of its own runs on
//! the calling thread instead, with the same result. A command's network
//! work runs on the process's one runtime
//! ([`opentide_connectors::runtime::sync_call`], #1558).

/// Whether this build can start threads.
pub const AVAILABLE: bool = cfg!(not(target_os = "wasi"));
