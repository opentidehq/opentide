//! An opt-in trace of where a request's time goes: with `OPENTIDE_LSP_TIMING`
//! set (to anything but `0`), each [`Span`] writes `opentide-lsp: timing
//! <label> <ms>` to stderr when it ends. Stdout stays protocol only. Off (the
//! default) a span costs one atomic load; on the browser's WebAssembly build,
//! which has no clock to rely on, it is always off (WASI has one).

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod clock {
    use std::sync::OnceLock;
    use std::time::Instant;

    fn enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| {
            std::env::var_os("OPENTIDE_LSP_TIMING").is_some_and(|value| value != "0")
        })
    }

    /// A span of a request: reports its duration when dropped.
    pub(crate) struct Span {
        label: String,
        start: Option<Instant>,
    }

    impl Span {
        pub(crate) fn new(label: &str) -> Self {
            Self::named(label, "")
        }

        /// A span named `prefix` and `name`, joined only when the trace is on.
        pub(crate) fn named(prefix: &str, name: &str) -> Self {
            let start = enabled().then(Instant::now);
            Self {
                label: if start.is_some() {
                    format!("{prefix}{name}")
                } else {
                    String::new()
                },
                start,
            }
        }
    }

    impl Drop for Span {
        fn drop(&mut self) {
            if let Some(start) = self.start {
                eprintln!(
                    "opentide-lsp: timing {} {:.2}",
                    self.label,
                    start.elapsed().as_secs_f64() * 1000.0
                );
            }
        }
    }
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod clock {
    /// Always off on the browser build, which has no clock to rely on (WASI has one).
    pub(crate) struct Span;

    impl Span {
        pub(crate) fn new(_label: &str) -> Self {
            Self
        }

        pub(crate) fn named(_prefix: &str, _name: &str) -> Self {
            Self
        }
    }
}

pub(crate) use clock::Span;
