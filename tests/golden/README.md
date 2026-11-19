# The command line's snapshot cases

What every `opentide` command prints and writes is held by Rust-owned insta snapshots
(`crates/opentide-cli/tests/cli_snapshots.rs`). This folder holds their inputs:
[`cases.toml`](cases.toml), the argument sets, and [`fixtures/`](fixtures/), the workspaces
they run in; [`payloads/`](payloads/) is the deploy compile's corpus
(`crates/opentide-compile/tests/oracle.rs`).

Until #1139 and #1142 this folder also held the recordings of the frozen Python CLI (the
oracle: `cases/`, `blobs/`, `mcp/`, `APPROVED_DIFFS.toml`) and `cargo xtask golden`, `compare`
and `mcp` compared the Rust engine with them. Once the snapshots and the crates' own tests held
the same behaviour, the recordings and that tooling were deleted; git history keeps them.

## Snapshots

`cases.toml` is the manifest of the CLI's snapshot tests,
`crates/opentide-cli/tests/cli_snapshots.rs`. Each case (its command, flags, mode, fixture and
cassette) runs in-process through `opentide_cli::run` on a fresh copy of its fixture, and what
it did is held to an insta snapshot of the **Rust CLI's own output**, one file per case:
`crates/opentide-cli/tests/cli_snapshots/<command>/<mode>__<fixture>__<variant>.snap`. A
snapshot holds the arguments, the exit code, stdout, stderr, and every file the run created,
modified or deleted under the workspace, home and the temporary directory, with its mode.
Byte-for-byte parity with Python is not what they check; what the Rust CLI does today is.

- **A JSON stream is its parsed value**: stdout or stderr that is one JSON document is
  pretty-printed with sorted keys, under a header with its line count and final newline, so its
  fields and values are checked and its spacing and key order are not. A **written file** is
  its text as written (key order, indentation and final newline included), with control
  characters shown.
- **Control characters are shown**: ESC as `␛`, so a colour or cursor change is a visible diff.
- **A file over 64 KiB**: a JSON one (the editor schemas, the SARIF report) keeps its structure
  with strings over 200 characters, then its largest parts (a schema's definitions, SARIF's rule
  catalogue), replaced by their size and SHA-256 until it fits in 16 KiB; any other is its size
  and SHA-256. Only the case's paths are replaced in such a file (the full normaliser takes
  seconds on megabytes), so it must hold nothing else that changes between runs.
- **Normalised, and only because it differs between two runs or two hosts** (the snapshots'
  normaliser, `crates/opentide-cli/tests/common/normalise.rs`, the rules below): the case's temporary root (`<WS>`, `<HOME>`, `<TMP>`, a root of
  fixed length, so wrapping is stable), the clock (dates, timestamps, durations, `<SECONDS>`;
  the week back only for `query`'s default window), the spinner's glyph and a live frame's
  content where the case opts in, crash-log names, catalog fingerprints, UUIDs a run mints where
  the case opts in (`fresh-uuids`), the host's git version where the case opts in (`host-git`, the vendor's suffix with it),
  a refused connection's errno (`<ECONNREFUSED>`, 111 on Linux, 61 on macOS), and `validate`'s worker counts in JSON
  (`<CORES>`). The host reports a fixed version (`0.28.1`, `tests/common/snapshot.rs`
  `VERSION`), so a release changes nothing. Every case runs under umask 022 with `/dev/null` as
  standard input, and the fixtures get fixed modes.
- **Fails, never snapshotted**: a request a case's cassette does not hold, and a panic.
- **Left out**: `serve`'s session, which feeds standard input: `tests/serve.rs` holds it in its own
  snapshots (#1285), while `cli_snapshots` still lists `serve` among its skipped commands.
- **Needs the generated workspaces**: the cases on `fault`, `fault-lint` and `heavy-small` run in
  three tests (`generated_fault`, `generated_fault_lint`, `generated_heavy_small`) when
  `OPENTIDE_REPLAY_FIXTURES` names the workspaces `cargo xtask corpus` writes, which a crate test
  cannot build; without it they print "skipped". CI writes two workspaces, `fault` and `heavy-small`;
  `fault-lint` is `fault` with lint's recommended check off, which the harness derives itself. The Linux PR gate and the Coverage workflow
  write them and set `OPENTIDE_SNAPSHOT_REQUIRE_GENERATED`, so a gate cannot pass by skipping
  them. The nightly `engine-test-os` (macOS, Windows) does not write them, by
  design (minutes of debug-build CPU per OS for output the Linux snapshots already hold): the 101
  cases are a Linux-gate check. To run or record
  them (about 4 minutes of CPU in a debug build):

  ```sh
  out=$(mktemp -d)
  cargo xtask corpus faults --out "$out/fault"
  cargo xtask corpus generate --seed 1 --threats 30 --objectives 30 --rules 50 --out "$out/heavy-small"
  OPENTIDE_REPLAY_FIXTURES="fault=$out/fault,heavy-small=$out/heavy-small" \
    cargo nextest run -p opentide-cli --test cli_snapshots -E 'test(/^generated_/)'
  ```

They are ordinary nextest tests, one per command group, in the PR gate whenever `opentide-cli` or
a crate below it changes. A change to what a command prints or writes fails them, by design:

```bash
cargo nextest run -p opentide-cli --test cli_snapshots          # every group
OPENTIDE_SNAPSHOT_FILTER=validate/json cargo nextest run -p opentide-cli --test cli_snapshots
cargo insta review                                              # read each diff, accept or reject
INSTA_UPDATE=always cargo nextest run -p opentide-cli --test cli_snapshots   # accept all (then read git diff)
```

Commit the accepted `.snap` files with the change that causes them: the diff is the review of the
user-visible change. Never edit a `.snap` by hand, never commit a `.snap.new`, and never widen a
normalisation rule to make a diff go away. A new case is a `[[case]]` in `cases.toml`; its
snapshot is written on the first run outside CI (CI sets `INSTA_UPDATE=no`, so a missing
snapshot fails there).

**Recording on macOS.** The snapshots are Linux's, and a re-record on macOS gives no diff when
the host differences are masked (git's `(Apple Git-157)` suffix, errno 61, the clock) and the
case roots are on a **case-sensitive** volume: the `tide-corpus` fixture holds `Objects/` and
`objects/` side by side, which are one folder on macOS's default volume, and the harness stops
with a message instead of recording that. Make a small case-sensitive volume and point the
roots at it (a short mount point keeps the roots as long as the snapshots', so paths wrap
alike):

```bash
hdiutil create -size 2g -fs 'Case-sensitive APFS' -volname cs -type SPARSE "$HOME/cs.sparseimage"
hdiutil attach "$HOME/cs.sparseimage" -mountpoint /Volumes/cs
OPENTIDE_CASE_ROOT=/Volumes/cs INSTA_UPDATE=always cargo nextest run -p opentide-cli --test cli_snapshots
git status --short   # nothing changed: a diff here is a real change, or a host difference to mask
```

A date that a case's own cassette or fixture holds (`2026-10-27` in the query cassettes) is
content, so it is never masked as the clock: no snapshot depends on the day it is run.

## Cases

[`cases.toml`](cases.toml) is the reviewed source. Each `[[case]]` is an argument set run in each
of its modes (`human`, a terminal; `plain`, pipes; `json`, `--json` right after `opentide`;
`agent`, `AI_AGENT` set) against every fixture it lists; `crates/opentide-cli/tests/common/snapshot.rs`
sets the mode, the environment and the case's root up. `mcp start` is not a mode of these
cases: the MCP server's own tests (`crates/opentide-cli/src/mcp/tests.rs`, `tests/mcp_stdio.rs`)
hold it. Tenant-contacting paths (`deploy`, `query`, `share`, `validate query --live`,
`generate extract`) run to their failure without tenants, unless the case names a cassette. A case with
`cassette = "<name>"` in `cases.toml` is served from `tests/cassettes/<name>.json` instead, through a
replaying proxy started for the case. The run
fails unless its requests are the cassette's, byte for byte and in order. The cassettes were
recorded from the oracle and are checked with `cargo xtask cassettes check`
(`crates/opentide-cassette/AGENTS.md`).

A command no case can replay (`generate extract sentinel`: MSAL and azure-core stamp its requests with random ids) is run by an integration test against its connector's cassette (`crates/opentide-cli/tests/extract_sentinel.rs`): the files it writes load to the oracle's data, and their bytes are held to a snapshot of the Rust command's own output (`tests/extract_sentinel/snapshots/`, #1139).

The arguments come from the examples of `opentide --json commands` and `docs/cli/`, the error cases
of `docs/internal/cli-experience.md` ("Errors people and agents make": a typo in a command, an
option or a choice, a missing option, a prompt without a terminal, `--json` after the subcommand,
`DEBUG='*'`), and one `--help` case per command path. Two things do not run in human mode:
`opentide tui` (only `tui --help`: the full-screen app redraws on a timer) and an interactive prompt
(prompt_toolkit works the terminal in raw mode and asks it for the cursor position, which needs a
terminal emulator); their non-terminal behaviour, exit 2 naming the flags, runs in the other modes.

Examples in `docs/cli` that are not cases, and why: `--install-completion` and
`--show-completion` (they detect the shell from the parent process); `--proxy
http://proxy.internal.example:8080 …` (a host name to resolve: the network is refused through a
proxy on the loopback instead); `--repo /path/to/repo …` and `--repo path/to/detections tui`
(stand-in paths; `--repo does-not-exist` is a case); `mcp start` (UC-3.7) and `lsp start` (the
language server's own stdio tests), run as `--help`; `opentide --debug generate` (its debug
log names each phase's time and the slowest phase, so it runs as `--no-color generate`).
Examples with a placeholder (`<uuid>`) run with a fixture's real identifier.

`opentide serve` runs in plain mode only: it speaks JSON-RPC on stdio, and its replies are
the same with `--json` or `AI_AGENT` set; a terminal adds nothing but the echo of its input.

## Fixtures

| Name | What |
|------|------|
| `tide-corpus` | [`tests/fixtures/tide_corpus/current`](../fixtures/tide_corpus/), moved to the `.opentide/` layout as `tests/corpus_support.py` does |
| `vscode` | the VS Code extension's fixture workspace, vendored unchanged in [`fixtures/vscode-workspace/`](fixtures/vscode-workspace/) (source and commit in `vscode-workspace.SOURCE.toml`, MIT licence in `vscode-workspace.LICENSE`) |
| `tide-corpus-typo` | `tide-corpus` with one declared edit (`edits` in `cases.toml`): `severity: high`, a typo `validate --fix` repairs, so a file changed in place is snapshotted |
| `vscode-unscoped` | `vscode` with one declared edit: signal entities written without their stage or in the wrong case (`hostname`, `'host::command line'`, `Process`), so the file `migrate vocab-scope --apply` rewrites is snapshotted (`tide-corpus` links its object folders, which the command does not follow) |
| `vscode-long-query` | `vscode` with one declared edit: `long.lucene`, a Lucene query on one line longer than a frame shows, whose `(` never closes, so the frame shows the line in part |
| `vscode-ambiguous` | `vscode` with one declared edit: `Account`, defined under two stages, which `migrate vocab-scope` leaves for a person (exit 2), beside `Process`, which it rewrites |
| `heavy-small` | UC-0.6's generator, seed 1: 30 threats, 30 objectives, 50 rules (`cargo xtask corpus generate`), generated once per run and copied per case, never committed |
| `fault` | UC-0.6's fault workspace (`cargo xtask corpus faults`), likewise generated; its outputs are snapshotted as they are, not asserted against the fault manifest |
| `setup-merge` | [`fixtures/setup-merge/`](fixtures/setup-merge/): the files `setup` merges into, a `.vscode/mcp.json` with a byte-order mark, comments and a trailing comma, and a `sentinel.toml` with `enabled = false` |
| `live-tenants` | [`fixtures/live-tenants/`](fixtures/live-tenants/): the platforms' stand-in tenants of `tests/cassettes/<platform>/tenant.py` (credentials as `$NAME`s the cases set) and a rule or more for each platform whose tenants check queries, for `validate query --live` (UC-4.6) |
| `deploy-tenants` | [`fixtures/deploy-tenants/`](fixtures/deploy-tenants/): the `tenants` workspace with Sysdig's stand-in tenant, tenants that take `PREVIEW` and `RELEASE` runs, rules to create, update, retire and refuse on each platform, and the deployment state of the rules already deployed, for a deploy that sends (UC-4.6); a cassette's client copies it before the deploy writes state |
| `deploy-tenants-sysdig` | `deploy-tenants` with every platform but Sysdig disabled (`edits` in `cases.toml`): a deploy without `--platform` sends to the workspace's enabled platforms, so the `golden/deploy-sysdig` cassette serves it (UC-4.4c) |
| `deploy-push`, `deploy-push-production`, `deploy-push-anchor` | `deploy-tenants` as a git checkout of two commits (`pushed` in `cases.toml`): the fixture, then a push that changed one rule, in `STAGING`, already in `PRODUCTION`, or with its status written as an anchor: the status promotion of a `RELEASE` deploy on a push (UC-4.6c). The commits' author and time are fixed, so their ids are the same on every host |
| `deploy-push-no-target`, `deploy-push-key`, `deploy-push-unreadable` | `deploy-tenants` as the same git checkout, the push giving the status promotion something it fails the run on: a `deployment.toml` (an `edits` entry with an empty `find` writes a file the fixture does not have) whose `promotion_target` is a number, a `STAGING` block whose key is a number, or a flow-mapping block promoted to a status named `LIVE}`, whose promoted text does not read back (UC-6.2e) |
| `share-misp` | [`fixtures/share-misp/`](fixtures/share-misp/): three `[[misp]]` destinations (one served by the MISP stand-in of `tests/cassettes/misp/tenant.py`, one whose paths answer 403, one disabled with a literal key), a threat, an objective and rules to create, update, leave unchanged and skip, and the sharing ledger of what was shared before, for `share` (UC-4.4b); a cassette's client copies it before a push or retract writes the ledger |
| `share-misp-broken` | `share-misp` with one declared edit: a `max_tlp` that is no TLP name, the `sharing_config` preflight |
| `share-misp-push`, `share-misp-push-config` | `share-misp` as a git checkout of two commits (`pushed` in `cases.toml`): the fixture, then a push that changed one shared rule, or `sharing.toml` alone: `share push --changed` on a GitHub, GitLab or Azure push and with `--since` (UC-4.4e); the `golden/share-push-changed` cassette's client builds the same checkout |
| `tide-corpus-compile-missing-field`, `-invalid-value`, `-empty-block`, `-invalid-rule`, `-elastic-severity` | `tide-corpus` with one declared edit each, a rule the platform's compiler refuses: the Sentinel rule without `grouping.alert`, with `alert.suppression: true`, with an empty `response`, with `frequency: hourly`; the Elastic rule's `severity` without `mapping`: `validate`'s compile check (UC-2.2, #817) |
| `tide-corpus-compile-hidden` | `tide-corpus-compile-missing-field` with an unrelated `tlp: clearr` in another rule: the compile check runs only when nothing else failed (KG-10) |
| `empty` | a workspace with an empty `.opentide/` |
| `none` | no workspace: an empty directory |

Each case gets a fresh copy of its fixture.
