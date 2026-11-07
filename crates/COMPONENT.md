# A component of the opentide engine

This crate is one part of the [opentide language server](https://github.com/opentidehq/language-server) engine. It is published so the crates that build on it can be, not to be used on its own: its API serves the other engine crates and changes with them.

Depend on [`opentide-analysis`](https://crates.io/crates/opentide-analysis) instead. It is the engine's public entry point: an I/O-free `WorkspaceHost` plus `analyze`, `highlight`, `hover`, `completions`, and `signature_help`, with the types they use re-exported. The [`opentide-lsp`](https://crates.io/crates/opentide-lsp) binary, the browser build, and the `opentide` Python package all build on it.

Every engine crate shares one version and pins the others to it exactly; the [changelog](https://github.com/opentidehq/language-server/blob/main/CHANGELOG.md) covers them together.
