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

**Status.** These tools are being built. Until they land, the commands below do not exist yet, or
exit 1:

| Tool | Work item | Today |
|------|-----------|-------|
| `cargo xtask golden`, `tests/golden/`, `tests/golden/ORACLE` | UC-0.5, [#803](https://github.com/opentidehq/opentide/issues/803) | `cargo xtask golden` prints "not implemented yet" and exits 1 |
| `OPENTIDE_ENGINE`, the comparator, `tests/golden/APPROVED_DIFFS.toml` | UC-0.7, [#805](https://github.com/opentidehq/opentide/issues/805) | not present |

The rules below hold already: they are the plan's. When the tools land, their own docs
(`tests/golden/README.md`, [`xtask/AGENTS.md`](../../../xtask/AGENTS.md)) are the reference for
flags and file formats. Update this skill to match them, and never use a flag that this skill or
those docs do not name.

## The rules

1. **The oracle is the Python CLI installed from a frozen tag**, recorded in `tests/golden/ORACLE`
   (the tag and the wheel's SHA-256). UC-0.5 writes that file; the tag it is to freeze is v0.23.0
   (`development` at `f41fe5e5`). Re-recording against a new tag is an explicit pull request of
   its own.
2. **Goldens are generated, never hand-edited.** A change to a golden is a re-record plus a
   reviewed diff. A pull request that edits a file under `tests/golden/<command>/` by hand fails
   review.
3. **Anything that differs from the oracle is a bug**, unless the difference is recorded in
   `tests/golden/APPROVED_DIFFS.toml` with its reason, its issue and its changelog entry.
4. **Never loosen the comparison** to get green: no new normalisation rule, no broader ledger
   entry, no skipped case, no deleted golden. A normalisation rule is reviewed code with unit tests,
   and covers only what is non-deterministic.
5. **The plan's invariants (§3) do not move.** If a port seems to need a change to the CLI
   contract, the command tree, a diagnostic code, a cross-repository contract, MCP, a workspace
   format, an SDK import path, the supported platforms or the security posture, stop and raise it
   as a separate decision. A ledger entry does not authorise that.

## Golden capture (UC-0.5)

`cargo xtask golden record | check | diff`, with `--engine python|rust|compare` and
`--filter <glob>` (#803).

| Command | What it does |
|---------|--------------|
| `cargo xtask golden record` | Runs the oracle on every case and writes the goldens |
| `cargo xtask golden record --check-determinism` | Records twice and fails unless both are byte-identical |
| `cargo xtask golden check --engine python` | Checks the oracle against the committed goldens |
| `cargo xtask golden diff` | Shows how a run differs from the committed goldens |

What a golden holds (plan §5.1, #803):

- **Coverage:** every command path in `opentide --json commands`, subcommands included. Every
  output mode: `human` (through a pseudo-terminal at 100 columns with a fixed `TERM`, and no agent
  or CI variables), `plain`, `json` and `agent`; `mcp` comes with UC-3.7. Every fixture:
  `tide_corpus`, the VS Code extension's fixture workspace, a small heavy workspace, the fault
  workspace (UC-0.6), an empty workspace, and no workspace.
- **Per case:** `case.toml` (argv, environment, mode, fixture), stdout, stderr, the exit code, and
  every file created, changed or deleted (path, mode, bytes), under
  `tests/golden/<command>/<mode>/<fixture>/`.
- **Normalised, and nothing else:** `duration_ms`, timestamps, the absolute workspace path
  (`<WS>`), temporary directory names, crash-log paths. ANSI codes are kept in `human` mode.
- **Tenants:** paths that contact a tenant are recorded only as their failure without tenants.
  Their success paths are UC-4.1's recorded HTTP cassettes.

## Shadow mode and the comparator (UC-0.7)

`OPENTIDE_ENGINE=python|rust|compare` selects the implementation of a command (plan §5.2, #805):

| Value | Effect |
|-------|--------|
| `python` | The Python implementation, the default until the command's default flips |
| `rust` | The Rust implementation. A command without one is a usage error: exit 2, `failure.code: engine_unavailable` |
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
| rule | A JSON pointer, or a text rule |
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

- Every changed golden has a cause in the same pull request: a re-record against a new oracle tag
  (its own PR), a new case, or a new fixture.
- A changed golden with no new case and no new oracle tag means the recording is not deterministic.
  Fix the normalisation code, with a test, rather than accept the churn.
- Read the diff of every file. A diff too big to read is a reason to split the pull request.

## Related

- [`rust`](../rust/SKILL.md): the workspace loop. [`review-checklist`](../review-checklist/SKILL.md):
  the golden and compare rules as review items.
- [`docs/internal/cli-experience.md`](../../../docs/internal/cli-experience.md): the CLI contract
  the goldens record.
