---
name: golden
description: Change what an opentide command prints or writes - the command line's Rust-owned snapshots (crates/opentide-cli/tests/cli_snapshots.rs), the cases of tests/golden/cases.toml and their fixtures, the normalisation rules, and cargo insta review. Use when a change alters a command's output, files, exit code or JSON, when a snapshot test fails, when adding a case or a fixture, or when reviewing snapshot diffs. The Python oracle's recordings and the compare tooling were retired (#1142).
---

# The command line's snapshots

The unified core ([#790](https://github.com/opentidehq/opentide/issues/790)) moved the CLI from
Python to Rust. Through the port, the frozen Python CLI was the **oracle**: `cargo xtask golden`
recorded what it did, and the Rust engine was compared with those recordings through an
approved-diffs ledger. Once the Rust-owned snapshots held the same behaviour, the replays (#1139)
and then the recordings, the ledger and their tooling (#1142) were deleted. Since #1743 the
snapshots no longer try to hold every behaviour byte for byte: **behaviour is held by unit and
end-to-end tests; the snapshots hold the `--json` contract, the files a command writes, the exit
codes and a small rendering set.** A wording, help or explain-page change is a unit test's diff,
not a snapshot's.

**[`tests/golden/README.md`](../../../tests/golden/README.md) is the reference** for the cases,
the fixtures, the snapshot layout and the normalisation rules. Where this skill and the README
disagree, the README is right: fix this skill.

## Changing what a command prints or writes

`crates/opentide-cli/tests/cli_snapshots.rs` runs every case of `tests/golden/cases.toml`
in-process and holds what it did (exit code, stdout, stderr, every file written, changed or
deleted) to an insta snapshot under `crates/opentide-cli/tests/cli_snapshots/<command>/`. A case
runs in json mode unless it lists `modes`; a fixture's or a case's `view` says how much of the run
is held (`full`, `streams`, or `diagnostics` for the generated corpora: findings as code, severity,
file, line and column, and counts, never message text); `same_as = "<variant>"` holds no snapshot, only that the case does what that json variant does. A change that alters the `--json`
document, a written file, an exit code or the rendering set updates its snapshots in the same pull
request:

1. Run `cargo nextest run -p opentide-cli --test cli_snapshots` (narrow it with
   `OPENTIDE_SNAPSHOT_FILTER=<part of a case id>`). If a change to a message, a help text or an
   explain page moves a lint, validate or generated-corpus snapshot, a snapshot holds text it
   should not: fix the case's view, not the snapshot.
2. `cargo insta review`: read every diff; accept the ones the change means, fix the code for the
   rest.
3. Commit the `.snap` files with the change. The reviewer reads them as the user-visible diff:
   each changed line follows from the change, and the information a user or an agent relies on
   (exit code, error code, the fields of a JSON envelope, the files written) is still there.
4. A user-visible change has its `CHANGELOG.md` entry ([`release-notes`](../release-notes/SKILL.md)).

The cases on the generated workspaces (`fault`, `fault-lint`, `heavy-small`) need
`OPENTIDE_REPLAY_FIXTURES`: the README's "Snapshots" section has the commands.

## The rules

1. **Never hand-edit a `.snap`**, never commit a `.snap.new`.
2. **Never loosen the net** to get green: no widened normalisation rule, no skipped case, no
   deleted snapshot, no new `#[ignore]`. Normalisation hides only what differs between two runs of
   the same case or two hosts; each rule is code in `crates/opentide-cli/tests/common/normalise.rs`
   with a unit test.
3. **A new behaviour gets a test at the level it is used** (a unit test of the code, an
   end-to-end assertion). It gets a `[[case]]` in `cases.toml` (and a fixture under
   `tests/golden/fixtures/` when none fits) only for what the exact output is the product of: its
   `--json` document and the files it writes, in json mode (the default). A text mode is added to a
   case only for a behaviour no other test holds, in the "text modes" section of `cases.toml`, with
   the reason; never as a copy of the json case in another layout.
4. **The plan's invariants (§3) do not move.** A change to the CLI contract, the command tree, a
   diagnostic code, a cross-repository contract, MCP, a workspace format, an SDK import path, the
   supported platforms or the security posture is a separate decision, not a snapshot update.

## Reviewing a snapshot diff

- Every changed snapshot has a cause in the same pull request: a code change, a new or changed case
  in `cases.toml`, a fixture change, or a normalisation rule with its unit test. Each changed line
  follows from that cause.
- A changed snapshot with none of those causes means the run is not deterministic. Fix the
  normalisation code, with a test, rather than accept the churn.
- Read the diff of every file. A diff too big to read is a reason to split the pull request.

## Related

- [`rust`](../rust/SKILL.md): the workspace loop, insta and nextest.
  [`review-checklist`](../review-checklist/SKILL.md): the snapshot rules as review items.
- [`docs/internal/cli-experience.md`](../../../docs/internal/cli-experience.md): the CLI contract
  the snapshots hold.
