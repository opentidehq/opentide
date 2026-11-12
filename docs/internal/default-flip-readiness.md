---
title: Default-flip readiness
description: What still runs on Python before Rust becomes the default engine (UC-6.2, #841), why, the proposed path for each, the steps of the flip and the decisions it needs.
---

# Default-flip readiness (UC-6.0)

> Status: **inventory of `integration/unified-core`** after phases 1–5 and this change
> (UC-6.0). Tracked by [#841](https://github.com/opentidehq/opentide/issues/841) (the flip and the
> removal of the Python implementations) under [#790](https://github.com/opentidehq/opentide/issues/790).
> The per-command table is the [parity dashboard](parity.md); this page lists what the dashboard
> does not show and what the flip itself must change.

## Summary

- `cargo xtask golden check --engine compare` on this branch: **1,660 cases, 1,568 compared,
  0 unexplained differences, 0 stale ledger entries, 92 Python only.** Before this change it was
  106 Python only: the 14 cases of a bare `opentide generate` (the full pipeline), ported here.
- Every command path with a leaf implementation is in `RUST_COMMANDS`, and no recorded run of
  one is refused with `engine_not_ported` any more. What the goldens still send to Python is the
  root command, the bare command groups, `query` runs outside its platform routing, and
  `--help` everywhere.
- **`--help` is the largest group and needs a maintainer decision** (below): 236 cases print
  Typer's help, 204 of them on commands that otherwise run on Rust, plus 10 bare runs that print
  a help screen and the 2-case home screen.
- Outside the goldens, Python still answers 8 of the MCP server's 10 tools and all 12 of its
  resources, the `serve` host's engine selection, the default `tui`, the language server's
  launcher, two `doctor`/`setup mcp` probes, shell completion, and three narrow in-Rust
  refusals (`new` at a prompt, two status-promotion edge cases, a `query --rule` on a plugin).

## How the inventory was taken

```bash
uv sync --group dev                                       # this checkout's CLI in .venv
cargo xtask golden check --engine compare --report report.json
```

`--engine compare` runs every case with `OPENTIDE_ENGINE=rust` against the oracle's recording.
A case is **Python only** when `RUST_COMMANDS` (`src/opentide/cli/engines.py`, read by
`xtask/src/compare.rs`) does not cover its command and arguments; those are not run. A `--help`
case of a covered command *is* run, but the Python launcher answers it before the dispatcher
(`opentide.cli.launch`, `opentide.cli.engines.dispatch`), so it compares Typer's help with
itself: it is Python in disguise and is counted with the help group below.

## Remaining Python-only runs in the goldens

| # | Group | Cases | What runs on Python, and why | Rust today | Proposed path |
|---|-------|------:|------------------------------|------------|---------------|
| G1 | `--help` on a command that runs on Rust | 204 | `dispatch` and the launcher hand every `--help` to Click: help is printed by Typer and Rich | clap's long help: the same descriptions and options, a different layout (below) | **Decision D1**: approve, or keep on Python until removal |
| G2 | `--help` on the root, the six bare groups and `query` | 32 | as G1, and their command is not in `RUST_COMMANDS` (root, groups) or not covered (`query`, G6) | as G1 | with D1 |
| G3 | A bare group or root that prints a help screen: `opentide` in plain and agent mode (4), `lsp`, `mcp`, `new` in human and plain mode (6, exit 2) | 10 | Typer's `no_args_is_help` | clap's help (`framework_goldens.rs` leaves these out as "help") | with D1 |
| G4 | The home screen: a bare `opentide` at a terminal | 2 | Python renders a logo, the workspace's catalogue, health and platforms, and suggested commands with Rich | prints the root's help | **Port** (bounded: two recordings, the data is `info`'s) or approve the help instead (D3) |
| G5 | Root and group runs that do not print help: `--version` (4), a mistyped command (4) or root option (4), `--repo` that is not a folder (4), `--debug info` (4), `--json` with no command (2); `generate extract`, `migrate`, `rules` bare in every mode (12), `lsp`, `mcp`, `new` bare in json and agent mode (6) | 40 | The launcher (`_may_run_on_rust`, `_plain_root_options`) and Click answer them before the dispatcher, and neither the root nor a group is a key of `RUST_COMMANDS` | byte for byte the oracle's: `crates/opentide-cli/tests/framework_goldens.rs` replays every one of them in-process | **Port the routing at the flip** (flip step 2): no Rust code is missing |
| G6 | `query` without `--platform` or with a mistyped one (`sentinal`) | 8 | `query`'s `platforms=RUST_QUERY_PLATFORMS` covers a run only when it names a platform with a Rust connector | the same usage errors as Python (checked by hand: `query x`, `query --platform sentinal x`, plain and json). One run differs: `query --platform sysdig` is refused with `engine_not_ported`, where Python answers `sysdig has no query runner` (`usage_invalid_value`, `argument` `--platform`, the eight platforms with a runner as `choices`) | **Port** the Sysdig answer (`commands/query.rs`, where it calls `not_ported`), then **drop `platforms` from `query`'s entry** once UC-4.5b's plugin routing lands (D7). The app's unit tests use the Sysdig refusal as their example of `engine_not_ported`: they need another (a command taken out of the table, as the Python tests do here) |

The Node runner (`cargo xtask golden check --runner node`, the npm bin, no Python at all) leaves
out G1 and `doctor`'s 8 cases on workspaces that enable a platform (#977); it was not run for
this page.

### `--help`: how far clap is from the oracle

Each help case was run through the Rust command line (`python -m opentide.cli.rust <path> --help`,
plain) and its words compared with the recording's:

- **Content is at parity.** For all 59 command paths, the words the oracle prints and clap does
  not are framework vocabulary only (`Show this message and exit`, `[ARGS]...`, `OPTIONS`, Typer's
  type names `str`, `int`, `path`), apart from the root (below). Every option, choice, default and
  description is there; clap adds its value names (`<FILE>`, `<OBJECT_TYPE>`) and `[possible values: ...]`.
- **Layout differs everywhere**: Typer's Rich panels (`╭─ Options ─╮`, two aligned columns,
  wrapped at the terminal) against clap's long help (an indented list, one option per paragraph).
  No case would compare equal; an approval is a whole-stdout difference per case.
- **The root's help** lacks the command panels (Typer's `rich_help_panel` groups: Workspace,
  Author, Ship, Agents) and the completion options (`--install-completion`, `--show-completion`,
  D2).
- **clap lists a `help` subcommand** under every group (`help  Print this message or the help of
  the given subcommand(s)`) that the command tree does not have: `opentide validate help` is
  refused (`No such command 'help'.`), as in Python. Whatever D1 decides, the Rust tree should
  set `disable_help_subcommand(true)` so its help does not advertise a command that does not
  exist (the command tree is a plan §3 invariant).

## Refusals and fallbacks the goldens do not show

| Where | What falls back to Python, or is refused | Proposed path |
|-------|------------------------------------------|---------------|
| `new <family>` at a terminal | Without `--name`, or a rule without `--platform` on a workspace that enables platforms, it prompts in Python: the Rust command refuses with `engine_not_ported` (`commands/new.rs`, `not_ported`) | **Port**: the `setup` wizards' prompts are on Rust already (UC-3.6c); compare in a pty test as `tui_pty.rs` does |
| `deploy` status promotion | `Stop::Unported` (`commands/deploy_promote.rs`) when `[promotion]` names no target, and where a rule file, or its promoted text, does not read (`opentide-compile` `promotion::Error::Unported`): the oracle fails there with ruamel's words | **Approve** with the Rust loader's words (one ledger entry and changelog lead), or port the messages; no golden case reaches either |
| `query --rule` / `--file` on a platform plugin | refused as not ported (`commands/query.rs`) | UC-4.5b's (plugin routing); not touched here |
| `validate_query::live` and `live_not_ported` | no caller since UC-4.6 routed `--live` to `validate_live` | **Delete** (dead code) |
| `generate docs`, `exports`, `explorer`, `inflight` with `OPENTIDE_PROGRESS=json` | Python's checklist writes one `progress` event per step (`done: 1, total: 1`); the Rust commands write none. No golden case sets the variable for them | **Port**: set `Report::step_events` on their reports, as this change does for `generate` |

## Runtime pieces outside the CLI

| Piece | Python today | Needed before Python can go | Path |
|-------|--------------|-----------------------------|------|
| MCP server (`opentide mcp start`) | Default engine: the Python server (`src/opentide/mcp_server/`). Under `rust`: the rmcp server (`crates/opentide-cli/src/mcp/`) runs `explain` and `validation_report` and delegates `search`, `get_chaining`, `coverage`, `validate_rule`, `deployment_status` (UC-5.2, the SDK registry), `validate_query`, `run_query`, `deploy_rule` (tenants) and all 6 resources and 6 templates to `opentide.mcp_server.bridge` in-process | Rust implementations of the 8 tools and 12 resources, each replayed against `tests/golden/mcp/` (`cargo xtask mcp replay --engine compare`) | **Port** (D4 decides the order: the registry tools need UC-5.2's catalogue on the facade) |
| `opentide serve` | The Rust host asks `opentide.cli.services.serve_bridge` which engine runs each request (`Bridge.plan`) and runs Python's choices through the Python `CommandRunner` | Engine selection in Rust (the defaults table), and nothing left for Python to run | At the flip: selection reads Rust's default; delete the bridge with the Python implementations |
| `opentide tui` | Default and `compare`: the Textual UI. `rust`: the ratatui UI, whose Configuration tab says it is not ported | The Configuration tab | **Port** the tab, then flip |
| `opentide lsp start` | The Python launcher (`cli/services/lsp.py`) hands the Rust server the workspace's catalogs generated by Python (`own_catalog`) and its host info | The catalogs generated in Rust (#941's field-catalog generator) | **Port** `_supply_catalogs` to the Rust host; `lsp start` under `rust` already serves |
| `doctor` | `platform_sdk` reads the platforms' Python modules from `OPENTIDE_PYTHON_MODULES`, set by the launcher; `python_version` is skipped on Rust | Neither check means anything once the platforms are Rust connectors | **Approve** dropping both (D5, #977) |
| `setup mcp`, `setup --mcp` | Reads `OPENTIDE_MCP_SERVER` (whether the Python MCP server's imports resolve) from the launcher | Moot once `mcp start` is Rust's | **Drop** with the Python MCP server |
| Shell completion | `--install-completion`, `--show-completion` are Typer's | A Rust completion, or none | **Decision D2** |
| The launcher (`opentide.cli.launch`) | Decides Rust or Python before Typer loads; sends `--help`, `--version`, completion, root errors and `compare` to Python | At the flip, everything but the escape hatch to Rust; at removal, a console script that only calls `opentide._native.main` | Flip steps 2 and 5 |
| SDK | `opentide.Workspace` and `run_json` are the Rust facade (UC-5.2); `opentide.models` are Rust classes (UC-1.9); `opentide.Opentide` (the Python registry) and the Pydantic shims in `opentide.models` warn as deprecated | The end of their deprecation cycle; UC-5.2b (async methods, `sdk.pyi`) in flight | Delete `core/registry.py` and the shims when their cycle ends, independent of the CLI flip |
| Platform plugins | Entry points (`opentide.platforms`) are Python by design; the Rust core calls them through PyO3 (`plugins.rs`, `opentide.plugins`) | Nothing: the plugin hook stays in the SDK layer (#841's acceptance) | Keep |

## The flip, step by step

The plan's rule (§7, `src/opentide/cli/engine_defaults.py`): a command runs one release in
`compare` with zero differences, then its default flips with a changelog entry, then one release
keeps `OPENTIDE_ENGINE=python` as an escape hatch, then its Python implementation is deleted.

1. **Release N — compare, zero diffs.** Today's state for every path in `RUST_COMMANDS`: CI's
   `Golden compare` passes with 0 unexplained differences. Close G6 and the in-Rust refusals
   above, and settle D1–D5, in this release.
2. **Release N+1 — the default flips.**
   - `DEFAULT_ENGINES` (`engine_defaults.py`) maps every path in `RUST_COMMANDS` to `rust`
     (one entry per path, or a default for every path: D6), with a changelog entry per area.
   - The launcher routes root-level runs to Rust: `runs_on_rust` currently returns `False` when
     no command path is found, for `--version`/`-V`, for a root option it does not know and for a
     `--repo` that is not a folder. Under a `rust` default, all of these (G5) go to
     `opentide._native.main`, which answers them as the oracle does. Add the root `()` and the
     six groups to `RUST_COMMANDS` (and to `xtask/src/compare.rs`'s reading of it, which keys the
     root as `""`), so the golden compare runs G5's 40 cases.
   - `--help`, G3 and the home screen follow D1 and D3.
   - `OPENTIDE_ENGINE=python` keeps working and **warns**: a `DeprecationWarning`-style log line
     (`engine_python_deprecated`, stderr only, never in `--json`'s stdout) naming the release that
     removes it; `OPENTIDE_ENGINE=compare` keeps working for CI. Changelog: Deprecated.
   - `serve` reads the same defaults (`Bridge.plan`), `mcp start` flips only when D4's tools are
     ported, `tui` when its Configuration tab is.
3. **Release N+2 — delete, per command family** (each PR lists the tests it ports or deletes,
   #841):

   | Python to delete | Once |
   |------------------|------|
   | `cli/commands/*`, `cli/services/*` of a flipped command, `cli/ui/` renderers it alone uses | its default flipped one release ago |
   | `generation/`, `documentation/`, `export/`, `ci/` | `generate`, `generate docs`, `generate exports`, `generate explorer`, `generate inflight`, `setup ci` flipped |
   | `deployment/`, `states/`, `platforms/`, `query/`, `extraction/`, `vulnerability_lookup.py` | `deploy`, `deploy migrate-state`, `query`, `validate query --live`, `generate extract *`, `doctor` flipped (and UC-4.5b merged) |
   | `sharing/` | `share *` flipped |
   | `validation/`, `loading/`, `indexing/`, `registry/`, `vocabulary/`, `mutation/` | `validate`, `lint`, `info`, `rules unreviewed`, `migrate vocab-scope`, `new` flipped, and nothing in the SDK imports them |
   | `mcp_server/`, `cli/services/serve*.py`, `cli/tui*` | `mcp start` (D4), `serve`, `tui` flipped |
   | `models/` Pydantic shims, `core/registry.py` | their SDK deprecation cycle ends |
   | `cli/launch.py`'s Python path, `cli/engines.py`, `cli/engine_defaults.py`, `OPENTIDE_ENGINE`, the comparator's Python path, `ORACLE` as an install target | everything above is gone; the goldens stay as the Rust CLI's specification and `golden check --engine rust` replaces `compare` |

   `src/opentide` then holds the SDK layer: `__init__.py`, `sdk.py`, `models/` (Rust classes),
   `analysis.py`, `plugins.py`, `_native/` stubs, `data/`, docs helpers. Today the package has
   93,503 lines of Python, 37,844 of them in `cli/` and 11,384 in `platforms/`.

## Decisions the maintainer needs to make

| # | Decision | Options | Consequence |
|---|----------|---------|-------------|
| D1 | `--help` (G1–G3: 246 cases) | **(a)** approve clap's help per case group (one `APPROVED_DIFFS.toml` entry per command path's help cases, a whole-stdout rule, one `CHANGELOG.md` lead: "`--help` is printed by the Rust command line"), and route `--help` to Rust at the flip; **(b)** keep `--help` on Python until removal | (a) lets the flip be whole and the npm bin reach parity (#977); Typer and Rich can go with the rest. (b) keeps Typer, Rich and the Python command tree installed until the last removal PR, which must then approve (a) anyway or reproduce Typer's layout, which the standing rule (no Python library ported) rules out. Either way, disable clap's `help` subcommand |
| D2 | Shell completion | generate completions with a crate (`clap_complete`) under the same options, or drop the options with a changelog entry | Typer's scripts call back into Python; they cannot survive the removal unchanged |
| D3 | The home screen (G4) | port it (2 recordings; `info`'s data) or approve the root's help in its place | A person running `opentide` with no arguments sees it first |
| D4 | The MCP server's 8 delegated tools and 12 resources | the order of their ports (UC-5.2 registry tools first, or the tenant tools), and whether `mcp start` flips separately | Until they are ported, `mcp start` cannot flip, and Python stays installed for MCP clients |
| D5 | `doctor`'s `platform_sdk` and `python_version` without Python | drop both checks, or approve their "not checked" rows in the ledger | Closes the `doctor` half of #977 |
| D6 | Flip granularity | per command family across several releases (plan §7), or every path at once in one release since compare is green for all | One release is shorter; per family limits what the escape hatch must cover |
| D7 | `query` routing (G6) | port the Sysdig answer and drop `platforms` from `query`'s entry once UC-4.5b merges | 8 cases (and 4 help cases) move from Python only to compared |

## What this change ported

- **A bare `opentide generate`** (the full pipeline, `run_generate_all`): the `docs`, `exports`,
  `vocabularies`, `templates`, `schemas` and `snippets` phases on the workspace read once, the
  failing phase's `phase` and rows, the `nested_object_file` warning after the rows, and
  `OPENTIDE_PROGRESS=json`'s events out of six (and out of the named phases for
  `generate schemas templates`). 14 cases moved from Python only to compared; 12 equal, 2 differ
  only by the spinner Python drew in human mode (approved, #841).
