# Goldens: what the frozen Python CLI does

The recordings here are the specification every Rust port is checked against
([plan §5.1](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md),
UC-0.5, [#803](https://github.com/opentidehq/opentide/issues/803)). They record, for every command
path of `opentide --json commands`, every output mode and every fixture, what the oracle prints, the
exit code and every file it creates, changes or deletes.

```bash
cargo xtask golden record                       # run every case through the oracle, write cases/
cargo xtask golden record --check-determinism   # the same, each case twice: both runs must agree
cargo xtask golden check --engine python        # a fresh run against the recordings
cargo xtask golden diff --filter 'validate/*'   # check, printing every difference in full
cargo xtask golden lock                         # rewrite oracle-requirements.txt from ORACLE
```

`--filter` takes a glob over case ids, `<command>/<mode>/<fixture>/<variant>`. The code is
`xtask/src/golden/`, a library the comparator (UC-0.7) reuses.

## Review rules

1. **Never edit a recording by hand**: not `cases/`, not `blobs/`, not `COVERAGE.md`. A change is
   a re-record (`cargo xtask golden record`) plus a reviewed diff. `golden check` fails on any byte
   that differs, and on a blob whose bytes do not match its name.
2. **A change to the recordings has a cause in the same PR**: a new or changed case in
   `cases.toml`, a fixture change, a normalisation rule (with its unit test), or a new oracle.
   Review the diff of `cases/` as you would code: each changed line follows from that cause.
3. **The oracle changes only in a PR of its own**: edit `ORACLE` (tag, wheel, its SHA-256 from
   PyPI), run `cargo xtask golden lock` and `cargo xtask golden record`, and review every
   difference: each one is a behaviour change between the two releases.
4. **Normalisation hides only what differs between two runs of the same case** (below). A rule
   is code in `crates/opentide-compare/src/normalise.rs` (moved there by UC-0.7 so the CLI's compare mode shares it) with a unit test; widening one to make a difference
   go away is a review failure.
5. **Recording is deterministic**: CI records every case twice and fails on any difference, and
   on any difference from the committed recordings (`.github/workflows/golden.yml`).
6. **Coverage**: every command path has at least one case in every mode. `COVERAGE.md` is
   generated with the recordings; `record` and `check` fail when a path or mode has none, or when
   the recordings outgrow their budget.
7. **An approved difference is as narrow as the change**: an entry in `APPROVED_DIFFS.toml`
   (UC-0.7) names one command, a case glob and a target. A text rule is one whole line on each
   side, approved where the oracle and candidate lines match it at the same line number; a lines
   rule is a block of consecutive whole lines on each side, of any length, approved where the
   candidate has its block at the place the oracle has its own (a row a port adds or drops); a
   JSON rule is one value at one pointer.

## The oracle

[`ORACLE`](ORACLE) names the release (`v0.23.0`, commit `f41fe5e5`), its manylinux x86-64
wheel and the wheel's SHA-256, the CPython it runs on (uv-managed, so every machine runs the same
build) and the platform. [`oracle-requirements.txt`](oracle-requirements.txt) pins every package
with its hashes; the opentide line carries the ORACLE wheel's hash alone, so the install fails
unless PyPI serves that very file. The oracle is installed with `uv pip install --require-hashes`
into a virtual environment under the Cargo target directory (`target/golden/`, or
`$OPENTIDE_GOLDEN_CACHE`), never from the working tree. Recording needs Linux (pseudo-terminals,
`setsid`) and uv.

## Cases

[`cases.toml`](cases.toml) is the reviewed source. Each `[[case]]` is an argument set run in every
mode against every fixture it lists:

| Mode | How it runs |
|------|-------------|
| `human` | stdin, stdout and stderr are pseudo-terminals of 100 × 40, `TERM=xterm-256color`, stdin the controlling terminal; the input is followed by end of file (Ctrl-D) |
| `plain` | pipes, so output resolves to plain mode |
| `json` | pipes, with `--json` right after `opentide` |
| `agent` | pipes, with `AI_AGENT=golden` |

`mcp` mode (`opentide mcp start`) is UC-3.7's. The environment is exactly the one in each case's
`case.toml`: no CI or agent variable unless the case sets one, `HOME` and `TMPDIR` inside the case's
directory (cases live under `/tmp`, whatever `TMPDIR` says, so absolute paths have one length), `TZ=UTC`, `LANG=C.UTF-8`, `PYTHONHASHSEED=0`, git without system or user configuration.
Network traffic goes to a proxy on `127.0.0.1:9`, which refuses it: tenant-contacting paths
(`deploy`, `query`, `share`, `validate query --live`, `generate extract`) are recorded as their
failure without tenants; their success paths are UC-4.1's recorded HTTP cassettes. On Linux each
case runs in a session of its own (`setsid`), so it never reaches the terminal of whoever records.

The arguments come from the examples of `opentide --json commands` and `docs/cli/`, the error cases
of `docs/internal/cli-experience.md` ("Errors people and agents make": a typo in a command, an
option or a choice, a missing option, a prompt without a terminal, `--json` after the subcommand,
`DEBUG='*'`), and one `--help` case per command path. Two things are not recorded in human mode:
`opentide tui` (only `tui --help`: the full-screen app redraws on a timer) and an interactive prompt
(prompt_toolkit works the terminal in raw mode and asks it for the cursor position, which needs a
terminal emulator); their non-terminal behaviour, exit 2 naming the flags, is recorded in the other modes.

Examples in `docs/cli` that are not recorded, and why: `--install-completion` and
`--show-completion` (they detect the shell from the parent process); `--proxy
http://proxy.internal.example:8080 …` (a host name to resolve: the network is refused through a
proxy on the loopback instead); `--repo /path/to/repo …` and `--repo path/to/detections tui`
(stand-in paths; `--repo does-not-exist` is recorded); `mcp start` (UC-3.7) and `lsp start` (the
language server's own stdio tests), recorded as `--help`; `opentide --debug generate` (its debug
log names each phase's time and the slowest phase, so it is recorded as `--no-color generate`).
Examples with a placeholder (`<uuid>`) run with a fixture's real identifier.

A path that `COVERAGE.md` marks "`--help` or bare only" is a group that does nothing alone (run
bare, it prints its usage) or one of the two protocol servers above, `mcp start` and `lsp start`.
`opentide serve` is recorded in plain mode only: it speaks JSON-RPC on stdio, and its replies are
the same with `--json` or `AI_AGENT` set; a terminal adds nothing but the echo of its input.

## Fixtures

| Name | What |
|------|------|
| `tide-corpus` | [`tests/fixtures/tide_corpus/current`](../fixtures/tide_corpus/), moved to the `.opentide/` layout as `tests/corpus_support.py` does |
| `vscode` | the VS Code extension's fixture workspace, vendored unchanged in [`fixtures/vscode-workspace/`](fixtures/vscode-workspace/) (source and commit in `vscode-workspace.SOURCE.toml`, MIT licence in `vscode-workspace.LICENSE`) |
| `tide-corpus-typo` | `tide-corpus` with one declared edit (`edits` in `cases.toml`): `severity: high`, a typo `validate --fix` repairs, so a file changed in place is recorded |
| `heavy-small` | UC-0.6's generator, seed 1: 30 threats, 30 objectives, 50 rules (`cargo xtask corpus generate`), generated once per run and copied per case, never committed |
| `fault` | UC-0.6's fault workspace (`cargo xtask corpus faults`), likewise generated; its outputs are recorded as they are, not asserted against the fault manifest |
| `empty` | a workspace with an empty `.opentide/` |
| `none` | no workspace: an empty directory |

Each case gets a fresh copy of its fixture.

## A recording

`cases/<command>/<mode>/<fixture>/<variant>/` (the command path's words joined by `.`, `_root`
for the root):

| File | Holds |
|------|-------|
| `case.toml` | argv, the full environment, stdin, mode, fixture, timeout |
| `stdout`, `stderr` | the streams, normalised; ANSI codes are kept in human mode |
| `outcome.toml` | the exit code, and each file created, modified or deleted under the case's root (`ws/`, `home/`, `tmp/`): path, kind, mode, size |
| `files/<path>` | the bytes of each created or modified file under 16 KiB, normalised. Stored paths are portable: `%` and the characters Windows forbids (`<>:"\|?*\`) become `%XX`, and a name that starts with `.git` or `~`, a reserved Windows name (`CON`, `NUL`, …) or one ending in `.` or a space gets a `~` before it |

A file of 16 KiB or more is stored once in `blobs/<sha256>` and named in `outcome.toml`: the
generated schemas and catalogs, which many cases write.

## Normalisation

Applied to stdout, stderr, file paths and file contents (UTF-8 only), in this order:

| Rule | Becomes | Why |
|------|---------|-----|
| A Rich live region (spinner, progress) between hiding and showing the cursor | `<LIVE>`, keeping what was printed above it | its frames are redrawn on a timer |
| The case's workspace, home, root, the engine's directories and the Python its environment links to | `<WS>`, `<HOME>`, `<TMP>`, `<ENGINE_BIN>`, `<ENGINE>`, `<PYTHON>` | temporary directories, the recorder's home |
| The host's kernel release (the crash handler's `os` fact and issue link) | `<KERNEL>` | the host |
| `crash-<time>-<pid>.log` | `crash-<TIMESTAMP>-<PID>.log` | the crash handler's log name |
| ISO 8601 date-times on the dates the case ran or the 7 days before (a default window reaches back), and the clock time that starts a log line (`18:22:33 debug: …`) | every digit `0` (`0000-00-00T00:00:00.000000+00:00`), so the format is still compared | the clock |
| The dates the case ran (`YYYY-MM-DD`) | `<TODAY>` | the clock |
| JSON `duration_ms`, `elapsed_ms`, `wall_ms`, `seconds` | `0`, or `0.0` for a float | wall times; the document keeps its types |
| `1.3s`, `2m05s` in text, and the spaces around it | `<SECONDS>`, one space each side at most | wall times in outcome lines and padded table columns |
| `id=` of a terminal hyperlink (`ESC]8;id=…`) | `id=<ID>` | Rich numbers hyperlinks at random |
| `git <version>`, in cases with `normalise = ["host-git"]` (`doctor`) | `git <GIT_VERSION>` | `opentide doctor` prints the host's git; help text quotes a literal example, which stays |
| `lsp-catalogs/<32 hex>` | `lsp-catalogs/<CATALOG-FINGERPRINT>` | the catalog cache is keyed by the installation's paths and file times |
| UUIDs the fixture does not hold, in cases with `normalise = ["fresh-uuids"]` | `<UUID-1>`, `<UUID-2>`, … by first appearance | `new`, `setup` and `generate` mint them |

Known limits, each a one-in-a-million chance or a case no fixture has today: a timestamp whose
microseconds are exactly 0 loses its fraction in Python's `isoformat()`, so it records shorter; two
files that differ only by fresh UUIDs (same masked path and bytes) are numbered in path order; the
8-hex suffix `new` adds to a colliding file name is not normalised. Any of them shows as a
determinism failure, never as a silent pass.

## Size

`COVERAGE.md` reports the size of `cases/` and `blobs/` in bytes (apparent size: the sum of the
files' lengths, not the blocks they take on disk) against a budget of 128 MiB (`BUDGET_BYTES` in
`xtask/src/golden/coverage.rs`); `record` and `check` fail over it. Git stores them far smaller: the schemas of one
fixture differ from another's in a few lines, and pack deltas keep one copy.
