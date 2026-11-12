---
name: golden
description: Prove a Rust port against the Python oracle - golden capture of the frozen Python CLI (cargo xtask golden record, check and diff, from UC-0.5), OPENTIDE_ENGINE=python|rust|compare and the comparator (UC-0.7), and the tests/golden/APPROVED_DIFFS.toml ledger, where every intended difference needs a reason, an issue and a changelog entry. Use when porting a command or a check to Rust, when a golden or a compare run fails, when recording or reviewing goldens, or when a change means to alter what a command prints or writes.
---

# Goldens, compare and the approved-diffs ledger

The unified core ([#790](https://github.com/opentidehq/opentide/issues/790)) moves the CLI's logic
from Python to Rust one command at a time, and the user-visible contract does not move. The Python
CLI at a frozen tag is the **oracle**. No Rust code replaces Python code without a test that
compares the Rust result with the oracle's. The source of this skill is the plan,
§5.1 and §5.2 ([`unified-core.md`](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#5-correctness-strategy)),
and the issues of the two items that build the tools.

**Status.** These tools are being built:

| Tool | Work item | State |
|------|-----------|-------|
| `cargo xtask golden`, `tests/golden/` (`ORACLE`, `cases.toml`, `cases/`, `blobs/`, `COVERAGE.md`, `README.md`) | UC-0.5, [#803](https://github.com/opentidehq/opentide/issues/803) | Present: 1160 cases recorded from opentide 0.23.0; `.github/workflows/golden.yml` runs `check` and `record --check-determinism` |
| `OPENTIDE_ENGINE`, the comparator, `tests/golden/APPROVED_DIFFS.toml` | UC-0.7, [#805](https://github.com/opentidehq/opentide/issues/805) | Not present |

**`tests/golden/README.md` is the reference** for the commands, the case and recording layout,
the fixtures and the normalisation rules. Where this skill and the README disagree, the README is
right: fix this skill. Never use a flag that neither names (`cargo xtask golden help` prints the
usage).

## The rules

1. **The oracle is the Python CLI installed from a frozen tag**, recorded in `tests/golden/ORACLE`
   (the tag, the wheel and its SHA-256). UC-0.5 chooses the tag and writes that file. Changing the
   oracle is a pull request of its own: edit `ORACLE`, `cargo xtask golden lock`,
   `cargo xtask golden record`, and review every difference.
2. **Recordings are generated, never hand-edited**: not `cases/`, not `blobs/`, not
   `COVERAGE.md`. A change is a re-record plus a reviewed diff.
3. **Anything that differs from the oracle is a bug**, unless the difference is recorded in
   `tests/golden/APPROVED_DIFFS.toml` with its reason, its issue and its changelog entry.
4. **Never loosen the comparison** to get green: no widened normalisation rule, no broader ledger
   entry, no skipped case, no deleted recording. Normalisation hides only what differs between two
   runs of the same case; each rule is code in `xtask/src/golden/normalise.rs` with a unit test.
5. **The plan's invariants (§3) do not move.** If a port seems to need a change to the CLI
   contract, the command tree, a diagnostic code, a cross-repository contract, MCP, a workspace
   format, an SDK import path, the supported platforms or the security posture, stop and raise it
   as a separate decision. A ledger entry does not authorise that.

## Golden capture (UC-0.5)

| Command | What it does |
|---------|--------------|
| `cargo xtask golden record` | Runs every case of `cases.toml` through the oracle and writes `cases/`, `blobs/` and `COVERAGE.md`. Only the oracle records: `record` takes no `--engine` |
| `cargo xtask golden record --check-determinism` | Runs every case twice and fails, writing nothing, unless both runs agree byte for byte |
| `cargo xtask golden check --engine python` | A fresh run against the recordings; also checks `COVERAGE.md` and that no recording is missing or orphaned |
| `cargo xtask golden diff` | `check`, printing every difference in full |
| `cargo xtask golden lock` | Rewrites `oracle-requirements.txt` from `ORACLE` |
| `cargo xtask golden coverage` | Rewrites `COVERAGE.md` |

`record`, `check` and `diff` take `--filter GLOB` (over case ids,
`<command>/<mode>/<fixture>/<variant>`) and `--jobs N`; `check` and `diff` take
`--engine python|rust|compare`, where `rust` and `compare` cannot start until UC-3 and UC-0.7.

What is recorded (the README has the detail):

- **Coverage:** every command path in `opentide --json commands`, in every mode (`human` through a
  pseudo-terminal, `plain`, `json`, `agent`; `mcp` comes with UC-3.7), against the fixtures each
  case lists. `record` and `check` fail when a path or mode has no case.
- **A recording:** `tests/golden/cases/<command>/<mode>/<fixture>/<variant>/` holds `case.toml`,
  `stdout`, `stderr`, `outcome.toml` (exit code and every file created, modified or deleted) and
  `files/`. A file of 16 KiB or more is stored once in `tests/golden/blobs/<sha256>`.
- **Normalisation:** only values that differ between two runs of the same case (temporary paths,
  clock times, wall times, random ids; the README's table lists every rule). ANSI codes are kept in
  `human` mode.
- **Tenants:** paths that contact a tenant are recorded only as their failure without tenants.
  Their success paths are UC-4.1's recorded HTTP cassettes.

## Shadow mode and the comparator (UC-0.7)

`OPENTIDE_ENGINE=python|rust|compare` selects the implementation of a command (plan §5.2, #805):

| Value | Effect |
|-------|--------|
| `python` | The Python implementation, the default until the command's default flips |
| `rust` | The Rust implementation. A command without one is a usage error, exit 2, with a new failure code whose name is to be confirmed on #805 (not `engine_unavailable`, which already exists with another meaning) |
| `compare` | Runs both on the same input, each on its own copy of the workspace when the command writes files, and compares them |

`compare` compares stdout, stderr, the exit code, the files and the JSON document (structurally,
then byte for byte), with the goldens' normalisation. JSON key order counts: the oracle's order is
the contract. On any difference it exits 70 with `failure.code: engine_mismatch`, writes a
structured diff report under `$XDG_STATE_HOME/opentide/compare/`, and gives the report's path in
`failure.message`. CI runs every golden in `compare` for each command that has a Rust
implementation.

## The approved-diffs ledger

`tests/golden/APPROVED_DIFFS.toml` records each intended difference from the oracle. Every field
is required (#805):

| Field | Holds |
|-------|-------|
| command | The command path |
| case glob | The cases it applies to, as narrow as possible |
| rule | A JSON pointer; a `help` rule: a help screen laid out by clap where the oracle's was Typer's, approved only where both say the same (`opentide_compare::help`), with `help-text` for one wording changed on purpose; a text rule: one whole line on each side, approved where the oracle and candidate lines match it at the same line number (`<SHA256>` once in the candidate: any digest there, for a digest over the version); or a lines rule: consecutive whole lines on each side, approved where the candidate has its block where the oracle has its own (an inserted or removed row); or a mode rule: one file's permission bits, four octal digits a side (`0600`, `0644`), its bytes still compared |
| oracle value | What Python prints or writes |
| candidate value | What Rust prints or writes |
| reason | Why the difference is right |
| issue | The issue that decided it |
| changelog | The `CHANGELOG.md` entry users read |

The comparator applies each entry narrowly and fails on a stale entry that no longer matches
anything. The field names in the file are UC-0.7's: read them from its schema, not from this table.

To add an entry:

1. Make sure the difference is meant. If not, fix the Rust code.
2. Link the issue that decides it, or open one.
3. Write the `CHANGELOG.md` entry under `## [Unreleased]` ([`release-notes`](../release-notes/SKILL.md)).
4. Add the entry with the narrowest case glob and rule that covers the difference.
5. Re-run the compare and the golden check. Both must pass, and no other entry may go stale.

## Reviewing a golden diff

- Every changed recording has a cause in the same pull request: a new or changed case in
  `cases.toml`, a fixture change, a normalisation rule with its unit test, or a new oracle (in a PR
  of its own). Each changed line follows from that cause.
- A changed recording with none of those causes means the recording is not deterministic. Fix the
  normalisation code, with a test, rather than accept the churn.
- Read the diff of every file. A diff too big to read is a reason to split the pull request.

## Related

- [`rust`](../rust/SKILL.md): the workspace loop. [`review-checklist`](../review-checklist/SKILL.md):
  the golden and compare rules as review items.
- [`docs/internal/cli-experience.md`](../../../docs/internal/cli-experience.md): the CLI contract
  the goldens record.
