# opentide-compare — agent guide

The differential comparator of the unified core (plan §5.2, UC-0.7 #805): it compares what the
oracle (the Python CLI) and a candidate (a Rust implementation) did on the same input, and
reports every difference the approved-diffs ledger (`tests/golden/APPROVED_DIFFS.toml`) does
not approve. I/O-free: callers read runs and the ledger and write the report.

| Module | What |
|--------|------|
| `lib.rs` | `Run`, `FileState`, `compare()`, `compare_normalised()`, `CaseReport`, `RunReport` (stale entries) |
| `json.rs` | An ordered JSON tree (key order kept, duplicates kept), pointers, structural and key-order differences, the CLI's two layouts |
| `ledger.rs` | The ledger's schema, its checks, and which entries apply where |
| `normalise.rs` | The goldens' normaliser (UC-0.5's, moved here): paths, live regions, crash logs, timestamps on the run's dates, durations, hyperlink ids; `xtask::golden::normalise` re-exports it |
| `glob.rs` | The ledger's case globs |

## Place

foundation, tier 0 (`xtask/layers.toml`): it depends on no workspace crate. xtask (`cargo xtask
compare`, `golden check --engine rust`) and opentide-cli's golden replays (dev-dependency) depend
on it. `publish = false`: it holds the Rust command line to the oracle's recordings, the goldens
that stay its specification since UC-6.2 (#841) removed the Python implementation and compare
mode.

## Invariants

- The oracle's output is the contract: JSON is compared by data, then by the order of every
  object's keys, then by bytes. Never compare JSON as a map alone, and never re-serialise a
  document before the byte comparison: normalisation rewrites bytes in place.
- An approved difference is applied only where both of its values are found as written, and only
  at its target; everything else is still compared. With an approved JSON value, the bytes are
  checked by layout (both sides must be the same one of `json::LAYOUTS`), so a layout change is
  never hidden behind an approval.
- A text rule is one whole line on each side, approved where the oracle and candidate lines match
  it at the same line number (without the line ending, which is still compared). Part of a line
  approves nothing.
- A json-extend rule names the elements a candidate adds to the oracle's array at its pointer,
  by their indices in the candidate's array, and the oracle array's length. They are set aside
  (outer arrays first) and what is left is compared with the oracle's array as any value is: an
  oracle element changed, dropped or moved, or an added element it does not name, is still a
  difference. JSON rules address an extended array by the oracle's indices.
- A sha256 rule approves one whole file by the SHA-256 digests of the oracle's and the
  candidate's normalised bytes: it applies only where both files are exactly the pinned ones. It
  is for a generated file another check compares (an editor JSON Schema, by verdict in `cargo
  xtask codegen --check`), never for one whose text is the behaviour.
- A mode rule approves one file's permission bits, four octal digits on each side (`0600`,
  `0644`), where both sides wrote the file with exactly those bits; its bytes are still compared.
  A file only one side wrote, or deleted, has no rule but `presence`.
- A lines rule is a block of whole lines on each side, naming its one case; a case may have
  several, one per block, each placed by its oracle side (the same block twice is a duplicate).
  Its candidate may be
  `(absent)`: the oracle's block is dropped and the candidate writes no line in its place. Its
  oracle side is always quoted.
- A ledger entry that applies to no case in a complete run is stale, and the run fails
  (`RunReport::new`). A single CLI run (`compare_normalised`) does not check staleness.
- Every ledger field is required; the schema is in the comment at the top of
  `tests/golden/APPROVED_DIFFS.toml` and in `ledger.rs`. Change both together.
- serde_json is used without `preserve_order`: enabling it would change the map type of every
  crate built with this one. Key order lives in `json::Json`.
- No `std::fs` in `src/` (`scripts/engine/check-io-free.sh`).

## Test

```bash
cargo nextest run --profile fast -p opentide-compare     # unit tests
cargo nextest run -p xtask comparator                     # the acceptance cases of #805
cargo xtask compare --check-ledger                        # the repository's ledger
```

## Do not

- Approve a difference by loosening the comparison: record it in the ledger, with its reason,
  issue and changelog entry.
- Add a normalisation rule without a unit test, or one that hides what an implementation decides
  (anything but wall time, timestamps and the paths of the workspace and temporary folders).

## Work items that change this crate

- UC-0.5 (#803): the golden normaliser, which lives here so that the goldens and the CLI share it.
- UC-X.2 (#844): the parity dashboard reads `RunReport`.
- UC-6.2 (#841): removes compare mode, and this crate with it.
