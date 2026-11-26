---
title: "rule::2.0 and opentide 2.0"
description: "How opentide moves to the rule::2.0 document shape (RFC 0012, revision 3): why it ships as opentide 2.0.0, the seam every reader goes through, the work in order with its proofs, and every place in the code that changes."
---

# rule::2.0 and opentide 2.0

**Status:** plan, 2026-11-26. The design is [RFC 0012 revision 3](./rule-2.0-rfc.md), which is under review after the first maintainer pass. Nothing here is implemented yet.

**In one paragraph:** a rule becomes an envelope (`name`, `metadata`, `references`) plus one `rule:` block, like a threat or an objective. The block holds what the rule is (`description`, `signals`, `mitre_attack`, `false_positives`, `blind_spots`), how it is handled (`response`, `searches`), and one key per platform. Each platform block owns its operational state: `enabled`, `status`, `severity`. `signals` is one list of objective or signal UUIDs, across objectives. Searches are typed and runnable by id. `rule::1.0` and `rule::1.1` keep working. The work ships as **opentide 2.0.0**, because the Rust SDK's public types cannot gain a revision without a semver-major release.

## 1. Why a major release

The schema revision and the package version are independent. `rule::2.0` does not imply opentide 2.0. In this case the package major is forced anyway, for these reasons:

| Contract | Today | Why it breaks |
|---|---|---|
| `opentide::models::TideObject` (facade, semver-checked in CI by cargo-semver-checks) | an exhaustive `enum` with `RuleV1_0`, `RuleV1_1`, `ThreatV1_0`, `ObjectiveV1_0` (`crates/opentide-schema/src/revisions/dispatch.rs:31-40`, re-exported at `crates/opentide/src/models.rs:25`) | Adding `RuleV2_0` is `enum_variant_added` on an exhaustive enum. |
| `opentide::models::Rule` | `pub type Rule = RuleV1_1` ("the newest rule revision", `crates/opentide-schema/src/objects/rule.rs:287`) | Repointing it to `RuleV2_0` changes every field a user reads. |
| The lockstep version | one version for the PyPI package, the crates and npm (`Cargo.toml:44-45`, [publishing](./publishing.md)) | A facade major is a package major. |
| MCP `opentide://templates/rule`, `opentide new rule`, `opentide extract` | write `rule::1.1`, or `rule::1.0` for extract | New files change shape. Agents and scripts that template from them see a different document. |
| Plugin API (`src/opentide/plugins.py:77,105,215,236`) | `check_configuration`, `configuration_model`, and the deploy body `{"rule", "configuration"}` | The rename from "configuration" to "block" is breaking. Do it now, not in a minor. |

A major is also the moment to make future revisions cheap. **Mark `TideObject` `#[non_exhaustive]`** (and give it a version-neutral read API, §3). Then `objective::1.1` ([#587](https://github.com/opentidehq/opentide/issues/587)), a `threat::1.1`, or a `rule::2.1` ships in a minor.

What opentide 2.0 does **not** break: every `rule::1.0` and `rule::1.1` file validates, deploys, shares and documents as it does in 1.0. The exceptions are the two convergences in §6, which are listed under Upgrade. The `--json` envelope, the codes and the exit codes stay. Paths in findings for 1.x files stay `configurations.<platform>.*`.

## 2. Release train

| Release | Contents | Visible to users |
|---|---|---|
| 1.x patches and minors | Phases A and B below: the rule-shape seam, every reader routed through it, family detection by `metadata.schema`, and `rule::2.0` built behind the cargo feature `rule-2` (off in every published artifact) | Nothing changes. The golden suite holds that. |
| **2.0.0** | Phases C to E: `rule::2.0` registered, `opentide migrate rule`, `new`/`extract`/MCP templates on 2.0, `#[non_exhaustive]`, the plugin API's "block" names (the old names kept as deprecated aliases through 2.x), docs and the skills companion | The new revision, the migrate command, Upgrade and Breaking notes |
| 2.x | Search `parameters` (an additive field of `rule::2.0`), `rule_revision_superseded` hint tuning, the `objective::1.1` signal reuse (#587) on the same seam | Additive |

## 3. Strategy

Every reader of a rule hard-codes 1.x paths today: `data.get("configurations")`, `root.get("detection_model")`, `body.get("severity")`. There are more than a hundred such sites across seven crates (§7). Two ways to add a second shape:

- **Normalise on load.** Migrate every 1.x object to 2.0 in memory, read only 2.0, and map paths back for diagnostics. This fails on the readers that work on source text and positions: promotion's in-place status rewrite, the language server's query injection and highlighting, `migrate-state`, and findings that point at a line. All of them need the source path, not the canonical one.
- **One seam that knows both shapes (chosen).** A small module in `opentide-schema` answers, for a document's revision, *where* each rule concept lives and *what* it means. Readers ask the seam instead of hard-coding a path. Source paths stay exact for every revision, and a third shape is one more table row.

The seam, `opentide_schema::objects::rule_shape`:

```rust
pub enum RuleShape { V1, V2 }                 // from metadata.schema; never from key sniffing

impl RuleShape {
    pub fn of(schema_id: &str) -> Option<RuleShape>;
    pub fn body(self) -> &'static [&'static str];                  // [] or ["rule"]
    pub fn block(self, platform: &str) -> Vec<&str>;               // ["configurations", p] | ["rule", p]
    pub fn field(self, f: RuleField) -> &'static [&'static str];   // Description, Severity, Attack, Response, ...
    pub fn blocks<'n>(self, root: &'n Node) -> impl Iterator<Item = (&'n str, &'n Node)>;
}

pub struct RuleFacts { ... }                   // the semantics, computed once per rule
impl RuleFacts {
    pub fn block_severity(&self, platform: &str) -> &str; // 1.x: response.alert_severity (one for all); 2.0: rule.<p>.severity
    pub fn rule_severity(&self) -> &str;        // derived: 1.x response.alert_severity; 2.0 the highest enabled block's
    pub fn own_attack(&self) -> &[String];      // 1.x: techniques; 2.0: rule.mitre_attack
    pub fn signals(&self) -> Vec<&str>;         // 1.x: [detection_model]; 2.0: rule.signals
    pub fn searches(&self) -> Vec<Search>;      // 1.x: response.procedure.searches (system as text); 2.0: rule.searches
    pub fn triage(&self) -> Option<&str>;       // 1.x: response.procedure.analysis; 2.0: rule.response.triage
    pub fn fallback_status(&self) -> Option<&str>; // 1.x root status; None on 2.0
    pub fn block_statuses(&self) -> Vec<(&'static str, &str)>;
}
```

Rules for the seam:

- It lives in `opentide-schema`, the lowest layer, so compile, workspace, tide, lsp, analysis, highlight and cli can all use it (`xtask/layers.toml`).
- The family is read from `metadata.schema`, never inferred. Four places infer "rule" from `has("configurations")` (`crates/opentide-compile/src/generate/docs/inflight.rs:56-75`, `generate/inflight.rs:105-127`, `generate/explorer.rs:69-84`, `generate/relations.rs:197`), and a 2.0 rule would read as no family.
- Policies that differ per platform today (ATT&CK, §6) are written once in `RuleFacts` and called from every compiler.
- Field roles (`FieldRole::Configurations`, `crates/opentide-schema/src/objects/role.rs:19-32`) stop being "a container key". On 2.0 the platform keys sit beside `description` inside `rule:`. Roles become a per-shape path list that the seam generates from the platform registry.

## 4. Phases

Each phase lists PR-sized items. An item is done when its proof passes. Phases A and B change nothing a user can see.

### Phase A: the seam (1.x, no behaviour change)

| # | Item | Proof |
|---|---|---|
| A1 | `rule_shape` module with `RuleShape::V1` only, `RuleField`, `RuleFacts`, and property tests | unit tests; `cargo xtask check-layers` |
| A2 | Family by `metadata.schema` in the four `has("configurations")` sites | golden unchanged; a test with a rule that has no `configurations` |
| A3 | opentide-compile through the seam: `rule.rs:52-79` (`block`, `response`, `alert_severity`, `description`), every compiler, `plan.rs` (247-263, 286, 348-375), `modifiers.rs:245-259`, `dry_run.rs`, `preview.rs`, `promotion.rs:252-348`, docs `catalog.rs`/`render.rs`, explorer, relations, visibility, exports | golden 465 cases unchanged (`cargo nextest run -p opentide-cli --test cli_snapshots`) |
| A4 | opentide-workspace through the seam: `validate/objects.rs` (27-31, 513-531, 624-628, 996-1110), `validate/mod.rs` (340-351, 940-1030, 1811-1838), `index.rs:154-171`, `catalogue.rs:433-455,755-760`, `coverage.rs:63-72`, `fields.rs:122-160`, `vocabularies.rs:91-94`, `views/object.rs:30-35`, `review.rs:237-247`, `lint/mod.rs:107-110` | golden unchanged; nextest |
| A5 | Editor through the seam: opentide-tide `lib.rs:83-95` (`language_for_field_path`), `injection.rs`, `outline.rs`, `refs.rs`, the `["configurations", p]` prefixes in `yara.rs`, `sysdig.rs`, `falco.rs`, `bitdefender.rs`, `google_secops.rs`, `elastic.rs`; opentide-analysis `queries.rs:192-212`; opentide-highlight `lib.rs:543-556,1138-1205` and `tide_grammar.rs` | LSP tests, highlight snapshots unchanged |
| A6 | CLI through the seam: `share/engine.rs:538-563`, `share/event.rs:249-373`, `mcp/catalog.rs` (105-121, 174-186, 305-319, 679-766, 804-863), `mcp/deploy.rs`, `deploy_send.rs` (1008, 1566, 5691-5701), `deploy_retire.rs`, `deploy_promote.rs`, `validate_live.rs`, `migrate_state.rs`, `query_rule.rs`, `generate.rs:877-906`, `tui/*` | golden unchanged; Python E2E |

### Phase B: the revision, unpublished (1.x, behind `rule-2`)

| # | Item | Notes |
|---|---|---|
| B1 | `RuleV2_0`, `RuleBody`, `RuleResponseV2`, `Search` (`crates/opentide-schema/src/objects/rule.rs`, `response.rs`) | `FromNode` refuses `#[serde(flatten)]` (`crates/opentide-schema-derive/src/lib.rs:115-123`), so the 13 platform fields are generated by a macro from `platforms::IDS`, shared with `RuleConfigurations`. A registry test asserts that platform ids and body field names never collide. |
| B1b | The block envelope | The shared fields are generated into every platform struct by the macro at `objects/platform/mod.rs:91-120` (`enabled`, `name`, `schema`, `status`, `flags`, `tenants`, `contributors`). 2.0 needs a second envelope (adds `severity`, drops `contributors`, strict `schema`). The macro emits two structs per platform, `SentinelConfig` (1.x envelope) and `SentinelBlock` (2.0 envelope), with one payload definition. The payload's JSON Schema, per-platform checks and advisories are shared. This is the largest modelling item. |
| B2 | Registry row `rule::2.0`, dispatch arm, `checks::REGISTERED` | `revisions/mod.rs:86-134`, `dispatch.rs:31-51,241-274`, `objects/checks.rs:29-35`. The tests at `revisions/tests.rs:139,210,394,489` demand it. |
| B3 | The 1.1→2.0 step | `From<RuleV1_1> for RuleV2_0`, as ADR 0009 prescribes. It needs no index, because `detection_model: X` becomes `signals: [X]`. A search whose `system` names no platform cannot be converted, so this edge is `TryFrom` and reports the search. In-memory reads never need the step, because the seam reads 1.x as 1.x. |
| B4 | `RuleShape::V2` and its `RuleFacts` | the seam's second row; every reader from phase A works unchanged |
| B5 | Schemas, template, router, catalog | `generate/schema.rs:83-91,245-299,418,475` (2.0 required set: name, metadata, rule; the rule body's required: description), `generate/workspace.rs:52-62,97-110`, `router.rs`, `catalog.rs:52-56,95-116`, `snippets.rs:118-121`; committed `data/catalogs/tide/schemas/rule.2.0.schema.json`, `templates/rule.2.0.template.yaml`, `generated/fields.json` (`cargo xtask codegen`) |
| B6 | Pins and vocabulary | `src/opentide/data/pins/rule.toml` `["rule::2.0"]` (`rule.mitre_attack`, `rule.searches.kind`, a `rule.<p>.severity` row per platform); the new `search.kind::1.0` vocabulary; synced from specifications (`data/specifications.lock.json`) |
| B7 | Spec drift check | `xtask/src/spec_fields.rs:41-73`: `SPEC_FILES` reads `objects/*-1.0.md` only; add `rule-2.0.md` and drop the `REWRITTEN` exceptions for `severity` and `status` on 2.0 |
| B8 | Corpus slice | `tests/fixtures/tide_corpus/manifest.toml`: slice `future_rule_2_0` (`status = "reserved"`), following the `future_rule_1_1` precedent |
| B9 | Python stubs and classes | `crates/opentide-schema/src/python.rs:878-918,995,1128-1130`, `generate/models.rs:126-129`; `cargo xtask stubs` adds `DetectionRule_v2_0` and `RuleBody` to `src/opentide/_native/models.pyi` |

### Phase C: 2.0 semantics

| # | Item | Where |
|---|---|---|
| C1 | Severity per block: every compiler reads `RuleFacts::block_severity(platform)` where it read `rule.alert_severity()`; a native vendor field still wins | the ten `alert_severity()` call sites: `crowdstrike.rs:107`, `sentinel_one.rs:99`, `splunk.rs:435,712`, `sentinel.rs:456`, `harfanglab.rs:113,383`, `sysdig.rs:433`, `carbon_black.rs:90,165`, and the derivations in `elastic.rs`, `bitdefender.rs`, `graylog.rs`, `exabeam.rs`, `google_secops.rs`, `microsoft_defender.rs` |
| C1b | The derived rule severity (highest enabled block) for MISP `threat_level`, documentation and catalogue sorting | `share/event.rs:344-373`; `generate/docs/render.rs:631-645` (a severity column per block); `workspace/src/views/object.rs:30-35` |
| C2 | One ATT&CK policy (block's own, else `rule.mitre_attack`, else inherited through each listed signal or objective) | `compile/src/deploy.rs:231-276` (`platform_techniques` already implements explicit-beats-inherited); `attack.rs:68-79` (walks one `detection_model`, and must walk a list); `splunk.rs:457`, `elastic.rs:865` (they merge today); `share/event.rs:290`; `workspace/src/coverage.rs` |
| C3 | `signals` list: one index edge per entry, coverage as a union, `invalid_ref`, `duplicate_signal`, `signal_covered_by_objective` (hint) | `workspace/src/index.rs:154-171` (`DetectionModel` becomes a multi-valued ref kind), `validate/objects.rs:1073-1110`, `catalogue.rs:755-760` (an `implements` edge per entry, `field_path` `rule.signals[i]`), `coverage.rs:63-72` (`rule_objective` becomes `rule_objectives`), `generate/relations.rs`, `explorer.rs:168-182`, `share/event.rs:249-258`, `tui/model.rs:611-621` |
| C4 | Status: no root fallback on 2.0 | `share/engine.rs:538-563`, `mcp/catalog.rs:757-766` |
| C5 | Response and knowledge: `triage` feeds Elastic `note` (`elastic.rs:840-850`), `false_positives` feeds the Elastic and HarfangLab blocks when they set none, `responders` keeps its `[[responders]]` check (`validate/objects.rs:186,918-962`), docs render the new sections (`render.rs:684-720`) | compile, workspace, docs |
| C6 | Searches: typed `platform`, `language` rules, unique `id`, `kind` vocabulary; injection by `platform` instead of free-text `system` (`tide/src/injection.rs:110-111`, `analysis/src/lib.rs:273`); documentation stops guessing (`generate/docs/platforms.rs:144-164` `search_language`); `opentide query --rule <uuid> --search <id>` (`query_rule.rs`; google_secops's refusal at 249-253 points at it) and the MCP `run_query` tool take a search id | tide, analysis, compile, cli, mcp |
| C7 | Editor: completion of `signals` (objectives and signals), of `searches[].platform` and `kind`; the TextMate grammar anchors `^(rule)` as well as `^(configurations)`; outline per block and per search under `rule` | opentide-tide `elastic.rs:117-148,351-365,522-542`, `lib.rs:654-1055`, `outline.rs`; opentide-highlight `lib.rs:1138-1205`, `highlights/generated/tide.tmLanguage.json`; `lsp/server.rs:73` (`warm_up` the newest rule revision, not a literal) |
| C8 | New diagnostics: an explain page each in `src/opentide/data/diagnostics/` and `docs/cli/diagnostics.md` | `duplicate_signal` (rule), `signal_covered_by_objective` (hint), `search_platform_unknown`, `search_id_duplicate`, `search_language_required`, `block_severity_missing`, `rule_revision_superseded` (hint) |

### Phase D: `opentide migrate rule`

| # | Item | Notes |
|---|---|---|
| D1 | Engine: `crates/opentide-schema/src/migration/rule_2_0.rs` | A structural move, not a scalar splice. Root entries move under an inserted `rule:` with +2 indentation, carrying their comments. Platform blocks keep their bytes (indentation 2 before and after), plus one inserted `severity:` line after `status:`. `response.procedure` is flattened (`analysis` becomes `triage`), and `searches` move up to `rule.searches` with `id`, `kind` and `platform` written. Keys are renamed in place. Every file is parsed again and compared with the intended `RuleV2_0` (as `vocab_scope.rs:396-433` does). |
| D2 | Command: a `MigrateCommand::Rule` variant | `crates/opentide-cli/src/tree.rs:495-512,1968-1978`, `app.rs:670-680`, `commands/migrate.rs` (reuse `migrate`, `report` and `issues`: resolve all, then write; BOM, CRLF and symlinks kept). Flags: `--apply`, `--file`, `--force`. Exit 2 `needs_human_decision` for a search `system` that names no platform, or a `configurations`/`platforms` conflict. |
| D3 | Report | One row per file: moved, renamed, the severity conflict (dropped root value), the dropped root status of a rule with no enabled block, a dropped `file`, merged block `contributors`, a normalised block `schema`, the search ids it chose. `--json` contract with a golden case. |
| D4 | **Equivalence corpus** | For every 1.x rule fixture in `tests/golden/fixtures` and the tide corpus, `migrate rule --apply` then: the deploy dry-run payloads are byte-identical, except rules listed in an approved-deltas table (ATT&CK merges, MISP threat level); `info catalog` is identical apart from paths; generated docs are identical. This one test proves that both shapes mean the same thing. |
| D5 | Fixtures | Comments between root keys, block scalars, flow lists, CRLF, BOM, a severity conflict, searches (including a `system` that needs a person and two `purpose`s that slug alike), legacy `platforms`, a legacy block `schema`, block `contributors`. Seeds for `fuzz/` (`from_node`) for 2.0. |

### Phase E: flip and release 2.0.0

| # | Item | Where |
|---|---|---|
| E1 | Drop the `rule-2` feature. `newest("rule")` becomes 2.0. | `new.rs:251-271,969-1000`, `new/scaffold.rs:918-959`; the `revisions` sort is by string (`generate/workspace.rs:97-110`), so sort by `SchemaId`, or `rule::10.0` will someday sort first |
| E2 | `extract` writes 2.0 | `commands/extract.rs:662-722,1355-2068`, `extract/sentinel.rs:50-51` (string templates become a typed `RuleV2_0` serialisation) |
| E3 | Templates and skills | MCP `resources.rs:409-441` (also serve `opentide://templates/rule/1.1` for 1.x authors); `skills.rs:86` ("Author rules as rule::2.0"); the LSP snippet template (`tide/lib.rs:74`, `xtask/src/codegen.rs:83-85` uses 1.0 today) |
| E4 | Facade | `TideObject` `#[non_exhaustive]`; `Rule = RuleV2_0`; a version-neutral `RuleFacts` exported; `crates/opentide/src/models.rs:18-25` |
| E5 | Plugin API: "block" names | `plugins.py` `check_block`, `block_model`, request key `block`, with the old names as deprecated aliases; `bindings/python/src/plugins.rs:43,87,118,449`; `validate/mod.rs:340-351` (`PlatformConfigurations` becomes `PlatformBlocks`) |
| E6 | "Configuration" means workspace TOML only | user text in `render.rs:607,2701` ("Platform configuration"), `snippets.rs:121`, `tree.rs:1425`, `plan.rs:361`, `python.rs:914`, schema title "Detection System Technical Setup" (`schema.rs:296`), `data/output-schemas.json:955,5523`. Workspace-TOML uses (`resolve_configurations`, the TUI Configuration tab, `setup platforms`) keep the word. |
| E7 | Docs | `docs/usage/concepts/object-model.md`, `schema-revision.md`, `platforms.md`, `glossary.md`, `tutorial.md`, `troubleshooting.md`; `docs/cli/new.md`, `validate.md`, `deploy.md`, `info.md`, `migrate.md` (new section), `generate.md`, `share.md`, `tui.md`, `lsp.md`; `docs/mcp/tools.md`; `docs/sdk/models.md`, `platforms.md`; `docs/engine/OBJECTS.md`; 99 explain pages that name `configurations.*` or `detection_model` (show both paths) |
| E8 | Changelog | `## [Unreleased]`: summary, **Upgrade** (`opentide migrate rule`, then `--apply`; plugin renames; scripts reading `implements` edges), **Breaking** (facade enum, `Rule` alias, plugin API, templates), and the 1.x convergences of §6 |
| E9 | Companion PRs | opentidehq/specifications (RFC acceptance, `rule-2.0.md`, pins, fixtures), opentidehq/skills (authoring on 2.0; review-checklist item 7), opentidehq/explorer (reads `objects.export.json`: verify the rule's description and link), opentidehq/vscode-extension (router and snippets come from the engine; verify), opentidehq/website (docs sync) |

## 5. Tests that hold it

- **Golden suite, phases A and B:** 465 cases unchanged. Any snapshot diff in those phases is a bug in the seam.
- **Twins:** each 1.x rule fixture that a feature test uses gets a 2.0 twin. That means 77 in `tests/fixtures`, 91 in `tests/golden`, 120 in `crates/testdata` and 62 fuzz seeds. `migrate rule` generates them, so the migration also produces its own test data.
- **The equivalence corpus (D4)** is the acceptance test for the whole release.
- **Mixed workspace:** one workspace holds a `rule::1.0`, a `rule::1.1` and a `rule::2.0` rule. It validates, dry-run deploys, shares, documents and serves MCP, and each rule reads from its own paths (the acceptance of the closed #394, restated for the Rust core).
- **Property tests** (`revisions/tests.rs:489`): dispatch is total, steps compose, migration is idempotent on 2.0, and a valid 1.x object migrates to a valid 2.0 object.

## 6. Behaviour that changes for 1.x files

Both items are convergences that the 2.0 design makes visible. Each is its own PR with its own changelog line. Each can also be left out, keeping 1.x exactly as it is.

| Today | Proposed for 1.x as well | Why |
|---|---|---|
| Splunk correlation searches and Elastic send root `techniques` ∪ inherited; MISP shares root `techniques` only; the other platforms send the block's own list, else inherited | One policy: block's own, else root `techniques`, else inherited | The same rule should claim the same techniques on every platform |
| MISP `threat_level_id` from the root `severity` | From the derived rule severity (`response.alert_severity` on 1.x, which every block deploys with) | A rule's threat level in MISP should match the severity it alerts with |

## 7. Code inventory

The number of non-test sites that name a 1.x rule path, per crate. Workspace-TOML uses of "configurations" are counted too.

| Crate | `configurations` | `detection_model` |
|---|---:|---:|
| opentide-schema | 299 | 42 |
| opentide-cli | 177 | 146 |
| opentide-tide | 76 | 37 |
| opentide-compile | 38 | 57 |
| opentide-workspace | 38 | 29 |
| opentide-analysis | 25 | 10 |
| opentide-lsp | 7 | 19 |

The file:line references in §4 come from that inventory. Fixtures that declare `rule::1.x`: 77 YAML in `tests/fixtures`, 91 in `tests/golden`, 120 in `crates/testdata`, 62 fuzz seeds, plus inline YAML in 120 Rust test modules and 63 `.snap` files.

## 8. Decisions this plan needs

Settled in the first review (2026-11-26): `mitre_attack` inside `rule:`; `enabled` stays on blocks; one `signals` list, objectives or signals, across objectives; severity per platform block; `response` and searches redesigned.

Still open:

1. The envelope `severity` (opentide's scale, required on every block, with vendor-native fields as overrides) versus native fields only (RFC "Alternatives").
2. The new `rule` fields and names: `false_positives`, `blind_spots`, `response.triage`, `searches[].kind` (`pivot`, `hunt`).
3. Search parameters now, or as a later additive field.
4. Ship as opentide **2.0.0** with `#[non_exhaustive]` (recommended), or hold the facade at 1.x by keeping `rule::2.0` out of `TideObject`.
5. Apply the two 1.x convergences of §6, or keep 1.x byte-identical.
6. Rename the plugin API's "configuration" to "block" in 2.0, with aliases through 2.x.
