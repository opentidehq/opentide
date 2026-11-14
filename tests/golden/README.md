# The CLI's snapshot cases

[`cases.toml`](cases.toml) is the manifest of the command line's snapshot tests,
`crates/opentide-cli/tests/cli_snapshots.rs` (#1139): every command path of
`opentide --json commands`, in every output mode, on the fixtures each case lists. The
fixtures it names are in [`fixtures/`](fixtures/) and `tests/fixtures/`. The cases were first
written to record the frozen Python CLI; since the command line is Rust's, the snapshots of the
Rust CLI's own output are the specification.

## Snapshots: the command line's behaviour, owned by Rust

Each case (its command, flags, mode, fixture and cassette) runs in-process through
`opentide_cli::run` on a fresh copy of its fixture, and what it did is held to an insta snapshot of
the **Rust CLI's own output**, one file per case:
`crates/opentide-cli/tests/cli_snapshots/<command>/<mode>__<fixture>__<variant>.snap`. A
snapshot holds the arguments, the exit code, stdout, stderr, and every file the run created,
modified or deleted under the workspace, home and the temporary directory, with its mode.

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
- **Normalised, and only because it differs between two runs or two hosts** (`opentide-compare`'s
  normaliser, `crates/opentide-compare/src/normalise.rs`, each rule with its unit test): the
  case's temporary root (`<WS>`, `<HOME>`, `<TMP>`, a root of fixed length, so wrapping is
  stable), the clock (dates, timestamps, durations, `<SECONDS>`; the week back only for
  `query`'s default window), the spinner's glyph and a live frame's content where the case opts
  in (`live-frames`), crash-log names, catalog fingerprints, UUIDs a run mints where the case
  opts in (`fresh-uuids`), the host's git version where the case opts in (`host-git`), a refused
  connection's errno (`<ECONNREFUSED>`), and `validate`'s worker counts in JSON (`<CORES>`). The
  host reports a fixed version (`0.28.1`, `tests/common/snapshot.rs` `VERSION`), so a release
  changes nothing. Every case runs under umask 022 with `/dev/null` as standard input, and the
  fixtures get fixed modes.
- **Fails, never snapshotted**: a request a case's cassette does not hold, and a panic.
- **Left out**: cases on the generated fixtures (`fault`, `fault-lint`, `heavy-small`: `cargo
  xtask corpus` builds them, which a crate test cannot), and `serve`'s session, which feeds
  standard input (`tests/serve.rs` drives it and holds it to its own snapshots).

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

## Cases

Each `[[case]]` is an argument set (`args`, after `opentide`) run in every mode of `modes`
against every fixture of `fixtures` (`[defaults]` unless the case sets its own); `{name}` in an
argument is a variable of the fixture (`vars`), and a fixture without it is left out of that
case. `input` is the case's standard input; `cassette = "<name>"` serves its HTTP traffic from
`tests/cassettes/<name>.json` through a replaying proxy that fails the run unless its requests are
the cassette's, in order (`crates/opentide-cassette/AGENTS.md`); `normalise` opts the case into
the rules above.

| Mode | How it runs |
|------|-------------|
| `human` | stdout and stderr are terminals of 100 columns, `TERM=xterm-256color` |
| `plain` | not terminals, so output resolves to plain mode |
| `json` | not terminals, with `--json` right after `opentide` |
| `agent` | not terminals, with `AI_AGENT=golden` |

The environment is exactly the case's: no CI or agent variable unless the case sets one, `HOME`
and `TMPDIR` inside the case's root (`/tmp/golden-XXXXXX`, so absolute paths have one length),
`TZ=UTC`, `LANG=C.UTF-8`, git without system or user configuration. Network traffic without a
cassette goes to a proxy on `127.0.0.1:9`, which refuses it: tenant-contacting paths (`deploy`,
`query`, `share`, `validate query --live`, `generate extract`) are recorded as their failure
without tenants, and their success paths are the cassette cases'. `generate extract sentinel`'s
tenant run (MSAL and azure-core stamp its requests with random ids) is
`crates/opentide-cli/tests/extract_sentinel.rs`'.

## Fixtures

`[fixtures.<name>]` in `cases.toml` declares each fixture: its `source`, the `edits` laid over it
(each `find` found once and replaced; an empty `find` writes a new file), and, for a git checkout
of two commits, the `pushed` edits of its second commit (fixed author and time, so the commit ids
are the same on every host). `crates/opentide-cli/tests/common/fixtures.rs` lays them out; each
case gets a fresh copy.

| Name | What |
|------|------|
| `tide-corpus` | [`tests/fixtures/tide_corpus/current`](../fixtures/tide_corpus/), moved to the `.opentide/` layout as `tests/corpus_support.py` does |
| `vscode` | the VS Code extension's fixture workspace, vendored unchanged in [`fixtures/vscode-workspace/`](fixtures/vscode-workspace/) (source and commit in `vscode-workspace.SOURCE.toml`, MIT licence in `vscode-workspace.LICENSE`) |
| `tide-corpus-*`, `vscode-*` | those two with the edits `cases.toml` declares: a typo `validate --fix` repairs, legacy rule ids, a rule each platform's compiler refuses, signal entities `migrate vocab-scope` rewrites, a legacy docs folder |
| `heavy-small`, `fault`, `fault-lint` | `cargo xtask corpus generate` (seed 1: 30 threats, 30 objectives, 50 rules) and `cargo xtask corpus faults --out`: generated, never committed, and left out of the snapshots |
| `setup-merge`, `skills-merge` | [`fixtures/setup-merge/`](fixtures/setup-merge/), [`fixtures/skills-merge/`](fixtures/skills-merge/): the files `setup` merges into |
| `tenants`, `live-tenants`, `deploy-tenants` | [`fixtures/`](fixtures/): the platforms' stand-in tenants of `tests/cassettes/<platform>/tenant.py`, with rules for `query`, `validate query --live` and a deploy that sends |
| `deploy-tenants-sysdig`, `deploy-push*` | `deploy-tenants` with every platform but Sysdig disabled, or as a git checkout whose last commit is a push (the status promotion of a `RELEASE` deploy) |
| `share-misp*` | [`fixtures/share-misp/`](fixtures/share-misp/): MISP destinations, objects and a sharing ledger for `share`, broken or as a pushed checkout |
| `empty` | a workspace with an empty `.opentide/` |
| `none` | no workspace: an empty directory |

## Other data here

- [`payloads/corpus/`](payloads/corpus/) and [`payloads/oracle.json`](payloads/oracle.json): the
  compile corpus and the list of its rules, platforms and tenants that
  `crates/opentide-compile/tests/compile_corpus.rs` compiles and holds to its snapshot (first
  written to compare the compiler with the Python CLI's; the list keeps its name).

The byte-for-byte recordings of the Python CLI (`cases/`, `blobs/`), their ledger of approved
differences, the oracle's pin and the tooling that recorded and compared them (`cargo xtask
golden`, `compare` and the other `--against python` diffs) were retired in #1139: git history
holds them.
