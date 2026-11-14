//! Threads where the target has them.
//!
//! WASI (`wasm32-wasip1`) has none: `std::thread::spawn` fails there, and a
//! scoped spawn panics. What a command runs on a thread of its own runs on
//! the calling thread instead, with the same result.

/// Whether this build can start threads.
pub const AVAILABLE: bool = cfg!(not(target_os = "wasi"));

/// Runs `work` on a thread of its own and waits for it, as
/// `std::thread::scope(|s| s.spawn(work).join())` does (a fresh thread for a
/// runtime of its own, or a tracing dispatcher of its own); without threads,
/// on this one. A panic in `work` is the `Err`, as `join` gives it.
pub fn run_apart<T: Send>(work: impl FnOnce() -> T + Send) -> std::thread::Result<T> {
    if AVAILABLE {
        std::thread::scope(|scope| scope.spawn(work).join())
    } else {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_run_apart_gives_its_result_or_its_panic() {
        assert_eq!(run_apart(|| 1 + 1).ok(), Some(2));
        assert!(run_apart(|| -> u8 { panic!("stopped") }).is_err());
    }
}
