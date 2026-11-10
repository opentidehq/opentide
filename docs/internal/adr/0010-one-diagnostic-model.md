---
title: "0010: One diagnostic model, and the CLI/editor parity gaps"
description: "UC-2.2: validate runs in opentide-workspace and reports one Diagnostic type, serialised as validate --json does today, that the CLI, the SDK, MCP and the language server share; each known gap between the CLI and the editor is decided."
---

# 0010: One diagnostic model, and the CLI/editor parity gaps

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-10 |
| Decision | UC-2.2 |
| Issues | [#817](https://github.com/opentidehq/opentide/issues/817), epic [#790](https://github.com/opentidehq/opentide/issues/790) |

## Context

`opentide validate` (Python, `validation/`) and the language server (`opentide-analysis`,
`opentide-tide`) each had their own checks and their own finding type. On 80 injected faults, 61
were reported the same way, 8 with different codes, 6 by one side only and 5 by neither; on a clean
workspace the editor reported 2,200 warnings `validate` never showed (plan §2). The fault
catalogue's known gaps (`tests/corpora/KNOWN_GAPS.md`) list where the two disagree. Plan §3
invariant 3 holds every code's meaning, severity, field path and position rules.

## Decision

1. **One finding type.** `opentide_workspace::Diagnostic` is every finding of `validate`, and the
   type the SDK, MCP and the language server read as they move onto `opentide-workspace`
   (UC-2.6, UC-2.7). It serialises exactly as an entry of `validate --json`'s `report.issues` does
   today, keys in that order: `code`, `severity`, `object_uuid`, `object_type`, `file_path`,
   `yaml_line`, `field_path`, `message`, `suggestion`, `context`, then `path`, `line`, `column`,
   `end_line`, `end_column` (exclusive, in code points), `help`, `fix` (`{safe, edits[]}`, each
   edit a text range and its replacement) and `explain`. What only a code frame shows (the label
   under the underline, notes such as `also: <file>:<line>:<column>` for a duplicate UUID and
   `expected: one of …`) travels beside these fields and is not serialised: adding a key would
   change the JSON envelope (invariant 1), and nothing reads it there.
2. **Validation in `opentide-workspace`.** `Workspace::validate` runs every check of `validate`
   (`id-uniqueness`, `uuid-format`, `schema` with references, chaining relations, vocabularies,
   configured values, deprecated fields, platform blocks, vendor ids and deployment state shards,
   `configuration`, `sharing-config`, nested object files, the scope's `scope_no_match`) with
   `--check`, `--type`, `--uuid`, `--file`, `--strict` and `--queries`, the summary counts and
   each check's status. The queries check is the host's (`QueryCheck`), which UC-2.5 (#820)
   supplies from `opentide-analysis`, a crate above this one. The compile check (`compile_*`,
   the deploy payload) waits for `opentide-compile` (Phase 3).
3. **The oracle comparison.** `cargo xtask validate diff` runs every recorded `validate --json`
   case that only checks, against its recording, and fails on any difference no approved rule
   explains; `crates/opentide-workspace/tests/validate.rs` holds every recorded finding to the
   type byte for byte.
4. **The gaps** (`tests/corpora/KNOWN_GAPS.md`):

   | Gap | Decision |
   | --- | --- |
   | KG-01 Sentinel `frequency` | Decided by UC-1.4: the Sentinel model refuses a duration deploy cannot convert, as `schema_validation` on the field; `validate` reports it through that model |
   | KG-02 `metadata.reviewed` | The model's check (UC-1.3), everywhere: a word, an offset-less datetime and an impossible date are the field's `schema_validation`; the editor reads the same model (UC-2.6). A future date is accepted, as before |
   | KG-03 `filename_mismatch` and `filename_slug` | One rule and one code, lint's `filename_mismatch` (the exact slug, or `<slug>-<uuid8>` when names collide), in `lint` (UC-2.3) and in the editor (UC-2.6); `filename_slug` retires once a maintainer approves it |
   | KG-04 invalid and duplicate UUIDs | `invalid_uuid` on every file whose UUID is not a UUID v4, a file displaced from the index by a later one with the same UUID included; `duplicate_id` stays one per file written again, on the later file, naming the first (`also:` in the frame) |
   | KG-05 metadata recommendations | One code, lint's `metadata_recommended` (info), in the CLI and the editor; `missing_author`, `missing_organisation` and `recommended_field_missing` retire once a maintainer approves it; `validate` reports no recommendation |

5. **The UUID scan reads the files the index reads.** The oracle's ID scan also read
   `*.debug.yaml` scratch output; the Rust scan reads the indexed files and the files the index
   displaced, so debug output is neither a duplicate nor a parse error. No corpus holds such a
   file.

## Consequences

- `validate` reports the same findings as the oracle on every recorded checking case (the
  fixtures, the heavy workspace and the fault workspace), but for the approved differences:
  `suggestions` (the one suggestion rule, #812), `yaml-error-text` and `yaml-1-2-dates` (YAML 1.2,
  #808 and #816) and `invalid-uuid-every-file` (KG-04). Each is written into
  `tests/golden/APPROVED_DIFFS.toml` with its rule when `validate` routes to Rust (UC-2.7): an
  entry no golden case reaches through `OPENTIDE_ENGINE=compare` fails as stale before then.
- Two decisions retire language-server codes (KG-03, KG-05). They change what the editor reports,
  a plan §3 invariant 3 matter, and are carried out in UC-2.6 only once a maintainer approves.
- The CLI's renderers (`opentide-cli`, UC-3.4) read their own frame type; the command that wires
  `validate` into the Rust CLI (UC-3.5) builds it from this one, label and notes included.
- The editor's quick fix that replaces a whole pipe stage (#887) is a query engine's range, not
  this type's: a `Diagnostic` already carries its fix's edits apart from its range, and the
  queries check moves here with UC-2.5, which decides #887.

## Update (UC-2.5, #820)

- The `QueryCheck` the queries check runs is `opentide-cli`'s `queries::EngineQueries`, not
  `opentide-analysis`'s: `opentide-analysis` is published to crates.io and `opentide-workspace` is
  not yet, so the engine crate cannot depend on it. `opentide-cli` is the host the trait was made
  for; the trait passes the `Workspace` (its root and configuration) and each object's text.
- #887 is decided by its option 2: the diagnostics keep their range (the pipe stage, plan §3
  invariant 3), and the language server's "Apply suggestion" edit replaces only the word the stage
  starts with. The CLI's query findings carry no fix, so nothing else changes.

## Evidence

- Issue [#817](https://github.com/opentidehq/opentide/issues/817); plan
  [§2](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#2-evidence),
  [§3](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#3-invariants)
  and [§5](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#5-correctness-strategy).
- The oracle: `src/opentide/validation/` (`session.py`, `errors.py`, `field_vocab.py`,
  `checks/cross_object.py`, `external_ids.py`), `cli/services/validation.py` and
  `cli/ui/diagnostics.py` at v0.23.0; its recordings in `tests/golden/cases/validate/json/`.
- The gaps, with the fault kinds that pin the oracle: `tests/corpora/KNOWN_GAPS.md`.
