# opentide-cli — agent guide

The opentide command line (plan D-3, [ADR 0003](../../docs/internal/adr/0003-cli-is-opentide-cli.md)):
one `main(argv)` for the standalone `opentide` binary and, from UC-3.8, the Python and npm
launchers. This crate is the framework every command runs on (UC-3.3, #825); the commands are
ported onto it one by one (UC-3.5, UC-3.6). Until a command is ported, the Rust CLI refuses it
with `engine_not_ported`, exit 2, as `OPENTIDE_ENGINE=rust` does.

| Module | What |
|--------|------|
| `tree.rs` | The command tree in clap derive: every path, option, type, choice, default and environment variable of the CLI, hidden ones included |
| `tree_meta.rs` | What clap's model cannot say for the catalogue: the negative flag of a pair, a default that is not the flag's |
| `catalog.rs` | `opentide commands` from the clap tree: the catalogue document and the plain tree |
| `schemas.rs` | Each command's `output_schema` and `$defs`, generated into `data/output-schemas.json` from the oracle's catalogue until each command's typed result derives it with schemars |
| `app.rs` | One run: hoisting, mode, logging, parse, usage errors, dispatch, the crash handler around it; Ctrl-C |
| `hoist.rs` | `--json`, `--no-color`, `--debug`, `--quiet` typed after the command move in front |
| `mode.rs`, `env.rs` | The output mode's resolution order, `OPENTIDE_JSON_INDENT`, `DEBUG` only as a boolean |
| `envelope.rs`, `json.rs` | The JSON envelope, its key order, exit codes, `failure.code`s; an order-keeping JSON tree |
| `usage.rs`, `suggest.rs` | clap's errors as the contract's usage errors, in the CLI's wording; "did you mean" (strsim, clap's measure) |
| `style.rs` | `error:` / `help:` / `usage:` lines, `→` next actions, the agent tip; SGR in `human`, bold without colour for `--no-color` on a terminal; wrapping on a terminal only |
| `logging.rs` | A `tracing` layer: levels per mode, stderr only, redacted |
| `crash.rs`, `redact.rs` | `error[internal]`, the crash log in the state directory, the issue link; the redaction of secrets and tenant names |

## Place

application (`xtask/layers.toml`), beside `opentide-lsp`: it owns the terminal, the process and
the filesystem. The bindings (`main(argv)` from Python and npm, UC-3.8 and UC-5.3) sit above it.

## Invariants

- Plan §3 invariants 1 and 2 hold: the envelope's keys and their order, exit codes 0, 1, 2, 3,
  70 and 130, every `failure.code`, and `opentide --json commands` byte-identical to the Python
  CLI's. `tests/framework_goldens.rs` replays the oracle's recordings of the framework cases.
- stdout carries the command's output or its one JSON document, nothing else. Logs, usage errors
  in the text modes, the crash report and `error: interrupted` go to stderr. In `mcp` mode stdout
  is never written by the framework.
- Everything the CLI writes about itself (log lines, the crash report, the crash log) goes
  through `redact::Redactor`. Never print an environment value, a URL or a configuration value
  without it.
- The tree is code: a port changes its struct. When an option's catalogue entry needs what clap
  cannot say, add a row to `tree_meta.rs`, never a special case in `catalog.rs`.
- `data/output-schemas.json` is generated, never edited: `OPENTIDE_CLI_BLESS=1 cargo nextest run
  -p opentide-cli framework_schemas` rewrites it from the oracle's recording.
- Library crates log through `tracing` and never print; this crate's `logging` layer writes their
  events.

## Test

```bash
cargo nextest run -p opentide-cli                       # unit, goldens, fuzz seeds
cargo nextest run -p opentide-cli framework             # the framework's tests (UC-3.3)
bash scripts/engine/fuzz.sh cli 60                      # the argv fuzz target (nightly)
```
