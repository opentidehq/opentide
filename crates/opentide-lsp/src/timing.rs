//! An opt-in trace of where a request's time goes: with `OPENTIDE_LSP_TIMING`
//! set (to anything but `0`), each [`Span`] writes `opentide-lsp: timing
//! <label> <ms>` to stderr when it ends. Stdout stays protocol only. Off (the
//! default) a span costs one atomic load; on a WebAssembly target, which has
//! no clock to rely on, it is always off.

#[cfg(not(target_family = "wasm"))]
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
        pub(crate) fn new(label: impl Into<String>) -> Self {
            let start = enabled().then(Instant::now);
            Self {
                label: if start.is_some() {
                    label.into()
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

#[cfg(target_family = "wasm")]
mod clock {
    /// Always off on WebAssembly.
    pub(crate) struct Span;

    impl Span {
        pub(crate) fn new(_label: impl Into<String>) -> Self {
            Self
        }
    }
}

pub(crate) use clock::Span;
