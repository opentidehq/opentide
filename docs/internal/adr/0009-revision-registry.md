---
title: "0009: The revision registry"
description: "UC-1.7: one registry of schema revisions decides which struct reads an object, checks an unknown revision of a family against the family's newest, and migrates objects forward in memory, one step at a time."
---

# 0009: The revision registry

| | |
|---|---|
| Status | Proposed |
| Date | 2026-11-10 |
| Decision | UC-1.7 |
| Issues | [#813](https://github.com/opentidehq/opentide/issues/813), epic [#790](https://github.com/opentidehq/opentide/issues/790) |

## Context

A Tide object names its revision in `metadata.schema` (`rule::1.1`). Three places decided what that means, and they disagreed:

- **The CLI** (`models/schema_registry.py`, `loading/object_loader.py`) looked the identifier up as written. An identifier it did not hold stopped the check before any model ran: one `schema_validation` finding, `unknown schema identifier: 'rule::7.0'`, and nothing else about the object.
- **The language server** (`opentide-tide`) checked an unknown revision of a family against the family's newest revision, without the unknown-key check (the revision it does not know may add keys), and reported the identifier (`vocab_unknown`, from the catalog's list of the family's revisions).
- **The SDK** exposed `SchemaVersion` and `SchemaVersionChain`, but the CLI registered no migration: the chains were empty, so loading a `rule::1.0` object as `rule::1.1` failed with `no migration registered from rule::1.0`.

The plan (§4, "The model") had already written the language server's policy down: "an unknown revision is checked against the newest of its family without the unknown-key check, with a finding; migrations are `From` impls along a forward one-step chain, applied in memory. Files change only through `opentide migrate`."

## Decision

`opentide-schema` holds one registry, `revisions`, that the CLI, the SDK and the language server share as they move onto the Rust core.

1. **Identifiers.** `SchemaId` is `family::major.minor`: the family trimmed and lower-cased, never empty; a version without a minor is minor 0; identifiers order by family, major, minor (`SchemaVersion.sort_key`). The version is the text after the last `::`, so a platform block's `platform::sentinel::1.0` is the family `platform::sentinel`. Version numbers are ASCII digits within 32 bits. Python's `SchemaVersion.parse` split at the first `::` and used `int()`, which also took signs, `_`, blanks and other scripts' digits; it only ever parsed identifiers its registry already held, so no command shows the difference.
2. **The registry.** One table, `REVISIONS`: `objective::1.0`, `rule::1.0`, `rule::1.1`, `threat::1.0`, `visibility::1.0`, the nine `platform::<id>::1.0` blocks and `sharing::misp::1.0`, each with what it describes (object, configuration, platform block, sharing block) and its model's name. `lookup` takes an identifier as written (`Rule::1.1` is not registered); `newest(family)` is what `new` and the templates write. The identifiers `metadata.schema` accepts are the object and configuration rows, the oracle's `registered_identifiers()`.
3. **Dispatch.** `metadata.schema` is read first, then the selected revision's conversion and checks run:

   | `metadata.schema` | Result |
   | --- | --- |
   | absent, `null`, empty (Python's falsy values) | `schema_missing`, no model runs |
   | `metadata` not a mapping | `dict_type` at `metadata` |
   | a registered revision of the expected family | that revision's struct |
   | another family's registered revision | refused: `'threat::1.0' is not a rule schema identifier` |
   | an unregistered revision of the expected family (`rule::7.0`, `Rule::1.1`) | **the family's newest revision, without the unknown-key check, with an error at `metadata.schema`** |
   | anything else (`threat::9.0`, `rule`, `platform::sentinel::1.0`) | refused: `unknown schema identifier: '…'` |

4. **Unknown revisions: one behaviour.** The language server's policy, as the plan states it. The finding stays an error, `schema_validation` at `metadata.schema`, so the object still fails, with the same code and exit code: `unknown schema identifier: 'rule::7.0'; checked against rule::1.1, the newest rule revision, without the unknown-key check`. Every other error the newest revision finds follows it. Unknown keys are not reported, at any depth: a newer revision may add them, and reporting them would bury the one finding that matters under keys that may be right.
5. **Migrations.** A forward one-step `From` impl per edge (`From<RuleV1_0> for RuleV1_1`: the metadata gains `reviewed`, unset). `TideObject::step` takes the one edge out of a revision; `migrate_to` walks the chain as `SchemaVersionChain.migrate` did, refusing a target that is unregistered, of another family or older; `path` lists the revisions on the way (`SchemaVersionChain.path`); `into_newest` is what the catalogue and the compilers read. A migrated object carries its new identifier in `metadata.schema`, as `stamp_schema_identifier` set it; that function, on an untyped document, keeps its semantics. Migration is in memory: only `opentide migrate` writes a file, with span-based text edits (UC-3.5).

## Consequences

- **The CLI changes, the language server does not.** When `validate` runs on the registry (UC-2.x, UC-3.5), an object with an unknown revision of its family gets the newest revision's findings after the identifier's. The difference is decided here: `tests/golden/APPROVED_DIFFS.toml` (entered with its rule when `validate` routes to Rust; an entry no golden case reaches would fail as stale), `crates/opentide-schema/tests/oracle/objects_cases.toml` (`unknown-revision`, checked case by case against the oracle) and the CHANGELOG ("An unknown schema revision is checked against the newest revision of its family").
- **No contract moves.** Codes (`schema_validation`, `schema_missing`), exit codes and the JSON envelope stay; only the finding's text and the findings that follow it change. The language server reports the identifier as `vocab_unknown` today; whether it moves to `schema_validation` when `opentide-analysis` reads the registry (UC-2.6, #821) is a parity decision of UC-2.2 (#817).
- **Rules wait for their platform blocks.** Dispatch selects a rule revision everywhere, but reads one only with the `unchecked-platform-blocks` feature until the platform models arrive (UC-1.4, #810), as every rule read does.
- **A new revision is one row and one step.** Adding `rule::1.2` adds its struct, a row in `REVISIONS`, a `From<RuleV1_1> for RuleV1_2` and the arm of `step`; the property tests (dispatch is total over identifiers; composed steps equal a direct migration; migration is idempotent on the newest revision; a valid object migrates to a valid object) cover it without new cases, and a field added to a revision fails to compile in its `From` until the step says what it becomes.

## Evidence

- Plan: [§4 Target architecture](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#4-target-architecture) ("The model"), [§5 Correctness strategy](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#5-correctness-strategy) (property tests: migration idempotence and totality, revision dispatch).
- Issue [#813](https://github.com/opentidehq/opentide/issues/813); the object models it builds on, [#809](https://github.com/opentidehq/opentide/issues/809).
- The oracle: `src/opentide/models/version.py`, `models/schema_registry.py`, `models/migration.py` and `loading/object_loader.py` at v0.23.0; its verdicts on the revision cases are in `crates/opentide-schema/tests/oracle/objects_table.json` (`revision-*`).
- The language server's policy: `crates/opentide-tide/src/lib.rs` (`diagnose_shape`, `a_revision_the_catalog_does_not_know_reports_no_unknown_key`).
