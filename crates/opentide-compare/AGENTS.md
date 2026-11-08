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
| `normalise.rs` | Literal replacements (a workspace copy's path to `<WS>`) and `duration_ms` |
| `glob.rs` | The ledger's case globs |

## Place

foundation, tier 0 (`xtask/layers.toml`): it depends on no workspace crate. xtask (`cargo xtask
compare`, `golden check --engine compare`) and opentide-native (`compare_runs`, which the CLI's
`OPENTIDE_ENGINE=compare` calls) depend on it. `publish = false`: it serves the migration and
goes when compare mode does (UC-6.2, #841).

## Invariants

- The oracle's output is the contract: JSON is compared by data, then by the order of every
  object's keys, then by bytes. Never compare JSON as a map alone, and never re-serialise a
  document before the byte comparison: normalisation rewrites bytes in place.
- An approved difference is applied only where both of its values are found as written, and only
  at its target; everything else is still compared. With an approved JSON value, the bytes are
  checked by layout (both sides must be the same one of `json::LAYOUTS`), so a layout change is
  never hidden behind an approval.
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

- UC-0.5 (#803): the golden normaliser; the golden runner and this crate are to share one.
- UC-X.2 (#844): the parity dashboard reads `RunReport`.
- UC-6.2 (#841): removes compare mode, and this crate with it.
