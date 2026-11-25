# An internal component of opentide

This crate is one part of [opentide](https://opentide.org)'s Rust workspace. It is internal: it is published so the crates that build on it can be, not to be used on its own. Its API serves the other opentide crates, changes with them and carries no stability promise.

Depend on [`opentide`](https://docs.rs/opentide) instead: the opentide Rust SDK, and the only opentide crate with a stability promise. It opens a Tide workspace, validates and lints it, reads its catalogue and coverage, plans a deploy, runs the command line and serves the language server, with the types they use re-exported. The `opentide` Python package, the npm packages, the `opentide` and `opentide-lsp` binaries and the browser build all build on the same crates.

Every opentide crate shares one version and pins the others to it exactly; the [changelog](https://github.com/opentidehq/opentide/blob/development/crates/CHANGELOG.md) covers them together.
