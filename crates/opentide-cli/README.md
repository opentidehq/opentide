# opentide-cli

The [opentide](https://opentide.org) command line as a library: the command tree, the output modes, the JSON envelope and exit codes, the renderers and the crash handler that every `opentide` command runs on, whether from the standalone binary or the Python and npm launchers.

Internal to opentide, with no stability promise: depend on [`opentide`](https://docs.rs/opentide), the opentide Rust SDK, instead (its `cli` feature: `opentide::cli::main`, `opentide::cli::run_json` and the `opentide` binary, `cargo install opentide --features cli`).

Licensed under the [EUPL-1.2](https://github.com/opentidehq/opentide/blob/development/LICENSE).
