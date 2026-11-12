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
| `logging.rs` | A `tracing` layer: levels per mode, stderr only, redacted |
| `crash.rs`, `redact.rs` | `error[internal]`, the crash log in the state directory, the issue link; the redaction of secrets and tenant names |
| `commands/` | The commands ported onto the framework: `info` (every section) and `rules unreviewed` (UC-2.4), `generate exports` and its three exports (UC-3.2: a phase as a checklist step, its files counted on disk), `generate docs` and its four scopes (UC-3.2b), `generate explorer`, `generate inflight` and `inflight prune`, and `setup ci` (UC-3.2c; `git_baseline.rs` asks the `git` program, in the run's environment, what changed against the default branch and which branch that is); `generate <phase>` (the `schemas`, `templates` and `snippets` phases named as words; a bare `generate` and `vocabs` refused) and `new threat|objective|rule` (UC-3.5d: `new.rs`, the workspace's generated template filled line by line in `new/scaffold.rs`, never YAML written back); `setup` (scripted runs and `--plan`), `setup env`, `hooks`, `mcp`, `platforms` and `repo` (UC-3.6: `setup/stage.rs` holds each step's writes in memory, so `--plan` lists them and a run commits them; `setup/jsonc.rs` merges into the user's JSON with comments on jsonc-parser's syntax tree, every other byte kept); `setup vscode`, `setup --vscode-setup` and the `setup`, `setup repo` and `setup mcp` wizards (UC-3.6c: `setup/vscode.rs` stages the generated files with the editor settings; `setup/wizard.rs` asks the Python wizards' questions through a `Prompter`, inquire at a terminal, a script in the tests, and `tests/setup_wizard.rs` drives the binary on a pseudo-terminal with portable-pty); `validate` with `--fix`, `--format`/`--output` and `--watch` (`watch.rs`: the workspace watcher as a live view cropped to the terminal, or a pass's frames in `plain`), `lint`, `explain` (UC-3.5); `validate query --live` on the connectors (UC-4.6: `validate_live.rs` makes the deploy plan, each tenant's batch with the platform's modifiers, and checks every rule's queries through the platform's `LiveValidator`, an Elastic rule as a whole; the oracle's result dictionary becomes the `Report` with `report_of`; `tests/validate_live.rs` replays the platforms whose check searches the last minute with the time fixed); `deploy` that sends on the connectors (UC-4.6: `deploy_send.rs` makes the dry run's plan, sends each tenant's batch through the platform's connector, prints a line per rule as it ends on the log stream (`Lines`), and keeps deployment state with `deploy_state.rs`, the shards read and written as `states/deployment.py` does; `tests/deploy_send.rs` replays Sentinel, a Carbon Black Cloud create and HarfangLab against their connectors' cassettes); `deploy_promote.rs` runs the status promotion of a RELEASE run on a push (UC-4.6c) before it plans: every changed rule file planned, then written through a temporary file, the edit itself `opentide_compile::promotion`; an invalid target ends the run as the oracle's `sys.exit` does, `Report::bare_exit`); `share` and its subcommands over MISP's REST API (UC-4.4b: `share/` loads `sharing.toml` through `opentide-schema`'s merge, reads the catalogue's files as they are, builds each event, resolves galaxy clusters and runs push, preview, status and retract with `opentide_connectors::misp`, keeping the sharing ledger as `sharing/ledger.py` does; UC-4.4e: `push --changed` narrows the run to the object files `opentide_compile::git::changed_through_head` names); `generate extract defender|elastic` (UC-4.4b: `extract.rs`, Defender's template filled in and Elastic's rule written by serde-saphyr's emitter, formatted as serde-saphyr formats YAML and loading to the oracle's data, which `tests/command_goldens.rs` checks); `findings.rs` the report files and CI sinks they share. Each returns a `Report` that `Run::emit_report` prints in the run's mode (`Block::Raw`/`Block::Stderr` for text laid out by the command, `whole_stdout` for a `--format` report). `tests/generate_goldens.rs` and `tests/command_goldens.rs` replay every recorded case in-process (`tests/common/replay.rs`; `OPENTIDE_REPLAY_FIXTURES` adds the generated fixtures, `OPENTIDE_REPLAY_DUMP` writes the runs `scripts/golden/ledger_entries.py` drafts ledger entries from) |
| `tui/`, `commands/tui.rs` | `opentide tui` (UC-3.6d, #951) on ratatui through crossterm: `commands/tui.rs` decides whether the UI can open (`usage_tui_needs_tty`, as #949 ports it); `tui/model.rs` the snapshot (the catalogue from the index, coverage from `opentide-workspace`'s lookup, the language server's findings from `opentide_lsp::ObjectFindings` and the engine's analysis of each object file, the Visibility report of `generate explorer`, the chains and object page of `opentide_workspace::views`); `tui/actions.rs` validate, generate and `deploy --dry-run` run in process through `app::run_keeping_document` (the output the renderers print at a terminal, read back with ansi-to-tui, and the report's JSON document); `tui/app.rs` the state, keys and drawing; `tui/detail.rs`, `tui/panes.rs`, `tui/text.rs` what it lays out. The Configuration tab and a bare `generate` are not ported: the tab says so and `generate` prints the CLI's refusal. `tests/tui.rs` draws it on ratatui's `TestBackend`, `tests/tui_pty.rs` drives the binary in a pseudo-terminal (rexpect, vt100), `tests/tui_terminal.rs` runs the gate in pseudo-terminals |
| `embed.rs` | What a host running opentide in its own process calls (UC-2.7, #822), through `opentide._native`: `run_captured` (one run with its own environment, working directory and captured streams; `warm` activates the workspace session), `interrupt` (`serve`'s cancel), `validate_json` (`validate`'s report, checks and summary for the SDK and MCP), the session's `invalidate`, `clear` and `stats` |
| `mcp/` | `opentide mcp start` (UC-3.7, #829) on rmcp, the official Rust MCP SDK, on a current-thread tokio runtime: `server.rs` the `ServerHandler` (what the server says of itself is `data/mcp/manifest.json`, generated from the Python server by `scripts/build/mcp_manifest.py` and never edited), `tools.rs` the tools that run in Rust (`NATIVE_TOOLS`); every other tool and every resource goes to the host's `Delegate` (`opentide._native` installs `opentide.mcp_server.bridge`, the Python server's own handlers in this process) until its Rust implementation exists (`DELEGATED_TOOLS`). Frames go to a duplicate of stdout while descriptor 1 points at stderr. `cargo xtask mcp replay` holds both servers to the recorded sessions in `tests/golden/mcp/` |
| `serve/` | `opentide serve`'s host (UC-3.8, #830): `server.rs` the JSON-RPC loop (one message a line, in order; `$/cancelRequest` and `exit` act at once; a panic answers `-32603` and the loop goes on), `decode.rs` the line as JSON with Python's `json` parse errors, `runner.rs` the runs: a command the engine selection gives to Rust runs through `embed::run_captured` with its workspace warm, any other goes to the `Delegate` (`opentide.cli.services.serve_bridge`, the Python package's runner in this process; `opentide._native` installs it). `tests/serve.rs` holds the protocol's scenarios and replays the recorded sessions and the `serve` fuzz seeds |
| `commands/lsp.rs` | `opentide lsp start` (UC-3.6b, #947): `opentide-lsp`'s server on stdio, after the host hands it the configuration schemas and names itself; LSP's exit code |
| `explain.rs` | The `opentide explain` pages: `src/opentide/data/diagnostics/*.md` compiled in by `build.rs`, the engine's codes from `opentide_core::codes`, the retired codes; the SARIF rule catalogue |
| `queries.rs` | The query engines behind `opentide-workspace`'s `QueryCheck` and `LintQueryCheck` (UC-2.5, #820; UC-3.5): `EngineLintQueries` (lint's `queries` check: warnings and notes, advisories, placeholders left out), `EngineQueries` (validate's `queries` check: errors placed by the engine, `--queries warn`, placeholders skipped), `Profiles` (the workspace's Elastic tenants and `visibility.toml` datasets, installed process-wide under `ENGINE`), `CheckedQuery`/`Finding` in the CLI's coordinates, `engine_help` (`diagnostic_from_engine`'s help line). `opentide-analysis` cannot host it: it is published and `opentide-workspace` is not |
| `render/` | The renderers (UC-3.4, #826): `text.rs` styled text written as SGR runs and OSC 8 links, cells by `unicode-width`; `codeframe.rs` the `error[code]` frames (hand-drawn: `annotate-snippets` cannot draw this layout), `--fix`'s diff and `fixed:` lines; `outcome.rs` outcome, warning, error and next-step lines and a result's text, the framework's usage errors and failures included (`Run::emit`): one renderer, wrapped by textwrap's first-fit algorithm at a terminal, never inside a word; `report.rs` SARIF and Code Quality (`sha2` fingerprints); `ci.rs` and `summary.rs` the GitHub, GitLab and Azure sinks; `table.rs` `info`'s tables, drawn by comfy-table (custom preset; widths are comfy-table's, cells wrapped at words by textwrap where a column is narrower than its text), and aligned columns; `progress.rs` step lines, the checklist and `OPENTIDE_PROGRESS=json` events |

## Place

application (`xtask/layers.toml`), the tier above `opentide-lsp`: it owns the terminal, the
process and the filesystem, and hosts the language server (`lsp start`, UC-3.6b). The bindings
(`main(argv)` from Python and npm, UC-3.8 and UC-5.3) sit above it.

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
- Redact a value as it was written, before it is escaped or formatted (JSON, `{:?}`, shell
  quoting): an escaped secret no longer matches.
- A write to stdout or stderr that fails is the run's error, never ignored: exit 1 as an
  internal error, or quietly when the reader closed the pipe (`BrokenPipe`). Commands write
  through `Run::emit` and return its `io::Result`.
- Ctrl-C sets the run's `Interrupt`: a long job polls `Run::interrupted` and stops; the run then
  prints `error: interrupted` and exits 130 with no document. A second Ctrl-C, or a run still
  going after `INTERRUPT_GRACE`, ends the process.
- Parsing is clap's, set in `catalog::parse_settings`: the last of a repeated option wins, and an
  option's value may start with `-`. A `--` where a group expects its command is dropped
  (`hoist::drop_group_separators`).
- The tree is code: a port changes its struct. When an option's catalogue entry needs what clap
  cannot say, add a row to `tree_meta.rs`, never a special case in `catalog.rs`.
- `data/output-schemas.json` is generated, never edited: `OPENTIDE_CLI_BLESS=1 cargo nextest run
  -p opentide-cli framework_schemas` rewrites it from the oracle's recording.
- Library crates log through `tracing` and never print; this crate's `logging` layer writes their
  events.
- The renderers' output is the contract (plan §3 invariant 1): `tests/render.rs` renders the
  oracle's inputs (`tests/render/*.input.json`) and compares with the oracle's output
  (`tests/render/snapshots/`) byte for byte. Both are written by
  `scripts/golden/render_oracle.py` run with the oracle's interpreter, never edited and never
  updated from the Rust side (`cargo insta accept` would hide a regression): golden.yml checks
  them against the oracle on every pull request into integration/unified-core.

## Test

```bash
cargo nextest run -p opentide-cli                       # unit, goldens, fuzz seeds
cargo nextest run -p opentide-cli framework             # the framework's tests (UC-3.3)
cargo nextest run -p opentide-cli render                # the renderers against the oracle (UC-3.4)
bash scripts/engine/fuzz.sh cli 60                      # the argv fuzz target (nightly)
```

Regenerating the renderers' oracle files (after a change to the driver's cases, or a new oracle):

```bash
cargo xtask golden record --filter 'validate/plain/fault/default'   # installs the oracle
cargo xtask corpus faults --out /tmp/fault
python="$(echo "$CARGO_TARGET_DIR"/golden/oracle-*/bin/python)"
"$python" -I scripts/golden/render_oracle.py --fault /tmp/fault --scratch "$(mktemp -d)" \
    --out crates/opentide-cli/tests/render          # --check: compare instead of writing
```
