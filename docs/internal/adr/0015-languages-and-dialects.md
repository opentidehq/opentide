---
title: "0015: When a vendor's syntax is a language, a dialect or a profile"
description: "A written rule for the engine's query languages: a syntax gets its own crate and LanguageId when it changes the tree, has a reference of its own or needs its own editor grammar; a product that runs an existing language is a dialect, chosen by platform; a use within one product is a profile, chosen by position. Applied to KQL, Lucene, YARA, Exabeam, YARA-L, CQL, ES|QL, Falco and the Datadog crate the RFC proposes, with what it costs under the facade's 1.x semver."
---

# 0015: When a vendor's syntax is a language, a dialect or a profile

| | |
|---|---|
| Status | Accepted |
| Date | 2026-11-26, accepted 2026-11-27 |
| Decision | Accepted by the owner, with option B of §6: `LanguageId` becomes `#[non_exhaustive]` in the next major. That major is already forced by `LanguageId::Datadog` (#1902). Raised by the [Datadog Cloud SIEM RFC](../rfc-datadog-cloud-siem.md), §6.2 ([#1898](https://github.com/opentidehq/opentide/pull/1898)). Raw query files keep their default dialect, and platform-specific checks on raw queries go through the crates or the SDK ([#1917](https://github.com/opentidehq/opentide/issues/1917), not planned). The `.cql` file profile is settled in [#1912](https://github.com/opentidehq/opentide/issues/1912) |
| Issues | Tracked in [#1910](https://github.com/opentidehq/opentide/issues/1910): step 1 [#1912](https://github.com/opentidehq/opentide/issues/1912), step 2 [#1913](https://github.com/opentidehq/opentide/issues/1913), step 3 [#1914](https://github.com/opentidehq/opentide/issues/1914) and [#1915](https://github.com/opentidehq/opentide/issues/1915), step 4 [#1911](https://github.com/opentidehq/opentide/issues/1911); step 5 is Datadog's phase 2, [#1920](https://github.com/opentidehq/opentide/issues/1920) |

## Context

The engine checks 11 query languages for 12 of the 13 platforms
([`platforms.rs`](https://github.com/opentidehq/opentide/blob/development/crates/opentide-schema/src/platforms.rs),
`offline_languages`). Several platforms share a language, and the engine expresses the differences
between them in four ways, with no written rule for which to use:

- `opentide-lucene` serves Elastic, Carbon Black Cloud and Graylog behind one grammar, with a
  `Dialect` enum (`crates/opentide-lucene/src/lib.rs:54-80`) and dialect modules
  (`src/graylog.rs`, `src/carbon_black.rs`).
- `opentide-kql` serves Sentinel and Microsoft Defender with a `Profile` enum
  (`crates/opentide-kql/src/lib.rs:135-139`: `Core`, `Sentinel`, `Defender`). That enum does what
  Lucene's `Dialect` does, with a different name: it picks per-product catalogs and severities. The
  owner suspected the two Microsoft products should be dialects. In substance they already are.
  Only the name and parts of the content are missing (§5.1).
- `opentide-yara` has a `Profile` for HarfangLab and Bitdefender (`crates/opentide-yara/src/lib.rs:56-84`),
  which is also a product. `opentide-exabeam` and `opentide-yaral` have a `Profile` with `Rule` and
  `Search` (`crates/opentide-exabeam/src/check.rs:22-45`, `crates/opentide-yaral/src/lib.rs:58-80`),
  which is a use within one product. `opentide-cql` expresses the same rule-versus-search axis as
  `Context { correlation_rule }` (`crates/opentide-cql/src/lib.rs:40-50`).
- The [Datadog Cloud SIEM RFC](../rfc-datadog-cloud-siem.md) (§6.2) makes Datadog's search syntax a new crate, `opentide-datadog`, and not a fourth
  Lucene dialect. In Datadog, `AND` binds tighter than `OR`, while Lucene has no precedence. Datadog
  also has `@attribute` paths, `#calculated` fields, a `CIDR()` function and `**`, and lacks
  Lucene's regex, fuzzy and boost. The RFC draws the line as "the precedence changes the tree's
  shape". The owner agrees with that call and wants the general rule written down. This ADR's
  test 1 is that line, stated for every language.

The choice matters for three reasons. A language costs a full crate and a `LanguageId` variant, and
the [add-language](https://github.com/opentidehq/opentide/blob/development/.agents/skills/add-language/SKILL.md)
checklist (a corpus gate, a fuzz target, throughput budgets, editors, companions) comes with it. A
dialect costs a branch inside one crate. Getting the call wrong either way is expensive:

- **A dialect that should have been a language** puts a dialect parameter into the lexer or parser.
  Then one grammar has two corpora, and an `__invalid` fixture of one dialect is valid in the other.
  The fuzz target, the depth floors and the `KEYWORDS` table become wrong for one of them.
- **A language that should have been a dialect** duplicates a grammar. The copies then drift. A
  user's `.kql` file also gets two editor ids for one syntax.

And since 1.0.0 (2026-11-25), `LanguageId` is under the facade's semver promise (§6).

## Decision

### 1. Terms

| Term | What it is | What selects it | Code |
|---|---|---|---|
| **Language** | One grammar: one lexer, one parser and one tree shape, with its own reference. It has its own `LanguageId`, crate, corpus, `.ungram`, fuzz target, `KEYWORDS` table, TextMate grammar and file suffixes | The `LanguageId`: a block's field, a hunt's `system`, a file's suffix, an editor's language id | `opentide_core::LanguageId`, `crates/opentide-<id>` |
| **Dialect** | A product that runs a language. It varies catalogs (tables, fields, functions and their availability), diagnostics and their severity, text normalization before the parse that keeps byte offsets, product limits on the text, and hover and completion content. It never varies the lexer, the grammar or the tree | The platform: the `configurations` key or a hunt's `system`, through the crate's one `Dialect::for_platform` | `<crate>::Dialect` |
| **Profile** | A use of the text within one product: a correlation rule, a search, an assembled rule's sections. It may refuse a subset of the grammar (Exabeam's advanced operators in a rule) and pick catalog availability (YARA-L's function tags). It never varies the tree | Where the text sits: the field path of the injection, or the file. Never the platform | `<crate>::Profile` |
| **Context** | Facts the workspace or the block supplies at run time: declared tables and columns (`visibility.toml`), ECS indices, Falco macros, lists and event source, an Elastic tenant's stack version | The workspace and the block. It is an input, not a variant | `<crate>::Context` and parameters |

A query is checked as **(language, dialect, profile, context)**. Each axis is independent. A
dialect has profiles (Sentinel KQL in a scheduled rule or in a hunt). A profile is the same in
every dialect that shares it.

### 2. The rule

Apply the tests in order. The first that answers "language" decides.

1. **The tree test.** A syntax is a separate language when either of these holds:
   - **the tree's shape changes**: the same text, accepted by both, needs a differently shaped
     tree. Precedence, associativity and where a token ends all change the shape. A difference in
     meaning that leaves the shape alone does not: Carbon Black's default operator `AND` changes
     what a bare run of terms means, but both readings are the same flat `BooleanQuery`, so Carbon
     Black is a dialect. Precedence is different, because it nests one operator's operands under
     the other's, so a precedence difference is a shape difference;
   - one of them accepts a construct the shared grammar has no node or token for, such as a new
     token class or a new production.

   A sign, not a test: if a dialect flag would make the crate's single walk (ADR 0014 §5a) branch
   at almost every node, as the RFC's §6.2 finds for Datadog, one of the two conditions above
   usually holds. Check which.

   **Exception: a subset is a dialect or a profile.** A product that accepts only part of the
   shared grammar is checked by parsing the superset and diagnosing what it excludes. This is
   already precedent:
   - YARA's HarfangLab and Bitdefender refuse YARA-X-only syntax "by one setting … not by a
     second grammar" ([`YARA.md`](../../engine/YARA.md));
   - Exabeam's `rule` profile refuses the advanced operators (`exabeam_advanced_in_rule`,
     `crates/opentide-exabeam/src/check.rs:1174-1184`).
2. **The reference test.** A syntax is a separate language when its vendor documents it as a
   language of its own, with a reference that does not defer to the shared one, on its own release
   cadence. Being similar today does not count: a separate reference is where later drift reaches
   the tree. Graylog does not meet this test, because it sends the query to `query_string`
   unchanged (`crates/opentide-lucene/src/graylog.rs:4-7`), so it is a dialect. Neither do Carbon
   Black's watchlists: they use Solr's classic parser, which is Lucene's.
3. **The editor test.** A syntax is a separate language when a file of it needs its own suffix,
   editor language id or TextMate keywords. All three key on `LanguageId`
   (`LanguageId::from_extension`, `crates/opentide-core/src/lib.rs:129-145`;
   `crates/opentide-highlight/src/keywords/`), so a dialect shares them. Shared HighlightSpec captures
   prove nothing, because the legend is global (`highlights/spec.toml`).
4. **Otherwise it is a dialect** (a different product) or a **profile** (a different use in the same
   product).

**Invariant.** A lexer or parser never takes a dialect or a profile as a parameter. A crate's
corpus gate, fuzz target, depth floors and `.ungram` describe one grammar. If honoring a variant
would need a parameter there, test 1 has answered "language".

### 3. How a dialect is built

- **One enum per crate.** It is named `Dialect`, has a documented default, and has one
  `Dialect::for_platform(&str)`. It is the only map from a platform key to the dialect. Tide
  (`opentide-tide`) and analysis (`opentide-analysis`) call it and keep no copy.
- **The variation lives in four places:**
  - catalog rows tagged with the dialect (as KQL's `profile = "sentinel"` rows and YARA's
    `[profile.<platform>]` tables already are);
  - diagnostic branches in the crate's single walk (ADR 0014 §5a), as Lucene's checks branch on
    `dialect` (`crates/opentide-lucene/src/lib.rs:139-171`);
  - text normalization before the parse that keeps byte offsets, as Carbon Black's newline join
    does (`lib.rs:113-120`);
  - hover and completion that read the same catalogs.
- **Catalogs:** a dialect's catalog is built once per dialect, in its own `OnceLock` (ADR 0013 §3),
  as KQL's `Catalog::cached` already does (`crates/opentide-kql/src/lib.rs:525-541`).
- **Raw files.** A raw query file is checked under the language's default dialect unless its host
  names a platform. `opentide validate query --platform`, `opentide-lsp analyze --platform` and
  MCP `validate_query`'s `platform` each name one. The default is the language's own reference, or
  the least strict dialect where they differ. Lucene's is Elastic (the reference `query_string`),
  KQL's is Sentinel (its open schema makes an unknown table a warning), and YARA has none.
- **The facade.** A dialect never crosses it. `opentide::analysis::QueryRequest` already selects
  one with `platform: Option<String>`, so adding a dialect changes no facade API (§6).

### 4. How a profile is built

- A profile is chosen by where the text sits: the injection's field path in Tide (Exabeam's
  sequence filter is `rule`, `crates/opentide-tide/src/lib.rs:1010-1015`), or by what a file is.
- A profile is not chosen from the platform. `QueryRequest.platform` names the dialect only.
- A file's profile is the one the language's specification gives a file: a `.exabeam` file is a
  search, and a `.yaral` file is decided by its text.

### 5. The rule applied

| Language (`LanguageId`) | Platforms | Variation today | Under this ADR |
|---|---|---|---|
| KQL (`kql`) | sentinel, microsoft_defender | `Profile::{Core, Sentinel, Defender}`: per-product tables, columns, ASIM parsers and unknown-table severity | One language, two **dialects**: rename `Profile` to `Dialect` and add the missing content (§5.1) |
| Lucene (`lucene`) | elastic, carbon_black_cloud, graylog | `Dialect::{Elastic, CarbonBlack, Graylog}` | Unchanged: the model the others follow |
| Kibana KQL (`kuery`), ES\|QL (`esql`), EQL (`eql`) | elastic | ES\|QL: `StackTarget` (version). ECS checks by the block's indices | Three **languages** for one product (test 1: different grammars). The stack version and ECS indices are **context** |
| YARA (`yara`) | harfanglab, bitdefender | `Profile::{Harfanglab, Bitdefender}`: size, ASCII and `yara_x_syntax` | One language, two **dialects** (a subset, test 1's exception): rename `Profile` to `Dialect` |
| Exabeam (`exabeam`) | exabeam | `Profile::{Rule, Search}` | One dialect, two **profiles**: correct as named. Selection by platform in `analyze_query` breaks §4 (§5.3) |
| YARA-L (`yaral`) | google_secops | `Profile::{Rule, Search}`; `Context::{FILE, SECTIONS, SEARCH}` | **Profiles**: correct |
| CQL (`cql`) | crowdstrike | `Context { correlation_rule }` | A **profile** named as context: rename when next touched. Selection by platform in `analyze_query` breaks §4 (§5.3) |
| Falco (`falco`) | sysdig | `Context`: event source, macros, lists, `append`, `macro_condition` | **Context**, plus a tuning-versus-rule **profile** (`append`). No dialect |
| SPL (`spl`) | splunk | None | One dialect. Splunk Cloud versus Enterprise would be a dialect if a difference were ever found |
| Datadog (proposed: `datadog`, `.datadog`) | datadog (RFC) | Not built | A new **language** (§5.2) |
| S1QL or PowerQuery | sentinel_one | No offline language (`platforms.rs:196-207`) | Decided by add-language step 0. Both have their own vendor reference |

#### 5.1 KQL: Sentinel and Defender are dialects

KQL is one grammar, Kusto's, and both products' references defer to it, so KQL does not meet
test 2. No difference between them reaches the tree, so it does not meet test 1. Both use the
`.kql` suffix and the same keywords, so it does not meet test 3 either. Every difference that does exist is a catalog, a diagnostic, a limit
or a profile:

| Aspect | Sentinel (analytics rules) | Defender XDR (advanced hunting, custom detections) | opentide today |
|---|---|---|---|
| Tables | A Log Analytics workspace: Azure Monitor tables, custom `_CL` tables, and Defender XDR tables the connector streams in. Open-ended | The advanced hunting schema, closed. In the unified portal, it also includes a connected Sentinel workspace's tables [^unified] | Per-dialect catalogs (`data/catalogs/kql/{sentinel,defender}/`, 99 and 65 hand-written tables) plus the Azure Monitor reference for Sentinel (`lib.rs:356-374`). An unknown table is a warning in Sentinel and an error in Defender (`lib.rs:1192-1232`). A Defender workspace can declare Sentinel tables in `visibility.toml` |
| Functions | `_GetWatchlist`, ASIM parsers, workspace functions | `FileProfile`, `DeviceFromIP` and `SeenBy` (all `invoke`d), and `AssignedIPAddresses` [^functions]. Custom Sentinel functions are not supported in custom detections [^unified] | ASIM parsers are Sentinel-only (`lib.rs:516-521`). The four Defender functions are in no catalog, so they get no hover, completion or signature help. They are not flagged under Sentinel either, because an unknown function is reported only as a near miss (`diagnose.rs:572-597`) |
| Time column | A rule's query must return `TimeGenerated`, which the lookback uses [^sentinel-rules] | `Timestamp` is recommended (`TimeGenerated` is accepted), with `ReportId` and an entity column such as `DeviceId` [^custom-detections] | Not checked |
| Text limits (rule profile) | 1 to 10,000 characters. No `search *` or `union *` [^scheduled] | Near-real-time (NRT) rules: one table, no joins, unions or `externaldata`, and no comment lines [^custom-detections] | `kql_unscoped_search` and `kql_unscoped_union` are performance warnings in both dialects (`perf.rs:69-73`). Length is not checked |
| Schedule | Frequency and lookback each 5 minutes to 14 days, frequency ≤ lookback [^sentinel-rules] | Fixed pairs: 24 h → 30 days, 12 h → 48 h, 3 h → 12 h, 1 h → 4 h. Custom only for Sentinel data [^custom-detections] | The platform model's concern (`opentide-schema`), not the dialect's. Sentinel's bounds are not checked offline |
| Run limits | 150 alerts per run [^scheduled] | 100,000 rows, 10 minutes, 64 MB, 30 days of data, 150 alerts per run [^overview] | Tenant limits. Nothing offline can check them |
| Operators, functions, grammar | Kusto | Kusto | One parser, one core catalog (`lib.rs:323-341`) |

So KQL stays one language with two dialects. The work is a rename plus content, not a crate split:

- **Rename** `opentide_kql::Profile` to `Dialect`. `Core` is the dialect with no product tables,
  which tests and the throughput benchmark use. Outside the crate, the rename touches three files
  that import it (`opentide-analysis`'s `lib.rs` and two of its tests, and `opentide-tide`'s
  `lib.rs`) and nine `Profile::` call sites.
- **Defender's functions:** add the four functions to the catalog with a dialect availability tag,
  as YARA-L tags functions by profile (`crates/opentide-yaral/src/lib.rs:64-71`). Hover, completion
  and signature help follow. Under Sentinel, an exact call to one of them can then be reported,
  unless the workspace declares a function of that name.
- **Rule-only limits:** in the Sentinel dialect and the rule profile, `search *` and `union *`
  become errors, and the 10,000-character limit gets an error of its own. This needs a KQL profile
  (rule or search), which KQL does not have today: a Sentinel hunt may use `union *`.
- **Do not split.** A `LanguageId::DefenderKql` would duplicate the grammar and give `.kql` files two
  ids, and the unified portal is making the two schemas overlap more, not less.

#### 5.2 Datadog: a new language

The [Datadog Cloud SIEM RFC](../rfc-datadog-cloud-siem.md)'s §6.2 meets test 1 on both of its conditions:

- **The tree's shape changes.** With `AND` binding tighter than `OR`, `a OR b AND c` is
  `a OR (b AND c)` in Datadog: an `and_expr` nested under an `or_expr` (RFC §6.3). In Lucene it is
  `a +b +c`, one flat `BooleanQuery` (`crates/opentide-lucene/src/parser.rs:1-5`).
  `lucene_mixed_operators` warns exactly where the two disagree (`lib.rs:367-381`), so the same text
  is correct in one and a warning in the other. This is the RFC's own line.
- **Constructs Lucene has no node for:** `@attribute` paths, `#calculated` fields, `CIDR(...)`
  calls, `**` across words, and duration units on numbers. In the other direction, Lucene's regex,
  fuzzy and boost are absent, so `/` is an ordinary character in Datadog.

The RFC marks the precedence as unverified on Cloud SIEM (its open question 2). The call does not
depend on it: the second condition holds whatever the precedence turns out to be.

Datadog also meets test 2, because it documents its own search syntax with its own reference. It
meets test 3, because `CIDR` would be a keyword only one of the two TextMate grammars should
color. It therefore gets its own crate and `LanguageId`, at add-language's full cost. Its
Datadog-specific variants inside that language are then that crate's dialects and profiles, under
this ADR. The RFC already has the two profiles §4 asks for: `rule` for a block's `queries[].query`,
and `search` for `.datadog` files, hunts and `opentide query`, chosen by position (RFC §6.1).

#### 5.3 Two findings the rule settles

- **Platform → dialect is mapped in five places.** The map is `kql_profile` in
  `crates/opentide-analysis/src/lib.rs:734-740`, a copy in `crates/opentide-tide/src/lib.rs:889-893`,
  `opentide_kql`'s `dataset_platform` (`lib.rs:1090-1095`), `opentide_lucene::Dialect::for_platform`,
  and `opentide_yara::Profile::for_platform`. They agree today. §3 makes the crate's
  `for_platform` the only one.
- **Profiles are sometimes chosen from the platform.** `analyze_query` picks Exabeam's `rule` profile
  and CQL's correlation rule when `platform` is `exabeam` or `crowdstrike`
  (`crates/opentide-analysis/src/lib.rs:384-396`), as `QueryRequest`'s own docs say
  (`lib.rs:363-367`). Tide picks them by field path. A valid
  search in a `.exabeam` file, `SELECT DISTINCT user, src_ip WHERE vendor:"Microsoft"`, passes
  `opentide validate query --file s.exabeam` but fails with `exabeam_advanced_in_rule` under
  `--platform exabeam`. The engine's own documentation says such a file is a search
  (`check.rs:25`; `docs/engine/LANGUAGE.md`, "Exabeam"). §4 fixes this by choosing the profile from
  the file. Whether a `.cql` file is a rule or a search is the owner's call (§7, step 1).

### 6. What a language costs: `LanguageId` and the facade's semver

A dialect or profile costs no facade API. A language costs a `LanguageId` variant:

- `LanguageId` is an exhaustive `pub enum` (`crates/opentide-core/src/lib.rs:42`), re-exported as
  `opentide::analysis::LanguageId` (`crates/opentide/src/analysis.rs:14-17`). Adding a variant is a
  major change: `cargo semver-checks` reports `enum_variant_added`.
- `LanguageId::QUERY_LANGUAGES` has the type `[Self; 11]`, so adding a language also changes the
  type of a public constant.
- opentide ships in lockstep, one version for every crate (`crates/CHANGELOG.md`, 1.0.0), so a
  facade major is a product major.
- The add-language skill still says a new variant is "a minor bump while 0.x". That has been stale
  since 1.0.0.

Options for the owner:

| Option | What | Cost |
|---|---|---|
| A | Add `LanguageId::Datadog` in 2.0.0, and take a product major for every later language (add-language names S1QL and Sigma) | A major per language, with a **Breaking** entry each time |
| **B (recommended)** | In the next major, whichever comes first, mark `LanguageId` `#[non_exhaustive]` and make `QUERY_LANGUAGES` a `&'static [LanguageId]`. Datadog then lands in that major or in a later minor. Every language after that is a minor | One major. Downstream `match`es need a wildcard arm once. JSON consumers see a new `language` value, which is additive (`data/output-schemas.json`, the Python `Language` literal and the npm types are updated as add-language step 7 lists) |
| C | Keep Datadog out of `LanguageId`, as a fourth Lucene dialect | Breaks the invariant of §2 (a dialect parameter in Lucene's parser). Rejected by the rule |

Option B is recommended because the cost of A recurs and the cost of B is paid once. The renames in
§5.1 and §5.3 are in `opentide-kql` and `opentide-yara`. Those crates are published at the lockstep
version but carry no stability promise (only the facade does, per `crates/opentide/AGENTS.md`), so
they need a **Breaking** entry in `crates/CHANGELOG.md` and no product major.

### 7. Migration order

Each step is its own pull request. None changes a tree or a corpus.

1. **One map, profiles by position.** Each crate's `for_platform` becomes the only platform →
   dialect map. Tide and analysis call it, and `kql_profile` and the Tide copy go. `analyze_query`
   picks a profile from the file, not the platform (§4), so the `.exabeam` case above passes. The
   owner decides whether a `.cql` file is a correlation rule or a search. The golden cases that run
   `validate query --platform exabeam` or `crowdstrike` on a file are reviewed. The facade's API does
   not change, but `QueryRequest.platform`'s documented meaning does (it names Exabeam's `rule`
   profile today), so the change gets a CHANGELOG entry.
2. **Names.** Rename `opentide_kql::Profile` and `opentide_yara::Profile` to `Dialect`, and
   `opentide_cql::Context { correlation_rule }` to a `Profile` when next touched. Each gets a
   `crates/CHANGELOG.md` entry. The specifications' headings ("Platform profiles" in yara-1.0)
   change in their next revision; until then this ADR is the map between the two wordings.
3. **KQL dialect content** (§5.1):
   - Defender's four functions, with availability;
   - a KQL rule profile with Sentinel's `search *`, `union *` and 10,000-character errors;
   - optionally, the time-column checks.

   Each item ships with regression tests, the CHANGELOG entry and the opentidehq/skills companion
   that root `AGENTS.md` item 5 asks for when a check's codes change.
4. **`LanguageId` non-exhaustive** in the next major (option B). This needs the release manager's
   decision on that major.
5. **Datadog** per its RFC and add-language. It lands in or after step 4's major.

Then the add-language skill's step 0, "Decide what the language is", links this ADR's tests, and its
semver row is corrected. That edit is made once the ADR is accepted.

## Consequences

- A new vendor is classified before any code is written: three tests, in order, and a written
  answer in add-language step 0's issue. Datadog is the first case.
- Dialects become cheap and safe: no facade change, no new corpus gate, fuzz target or editor
  grammar. Adding one is a catalog, a branch in the single walk, and `for_platform`. Languages stay
  expensive, but after option B they no longer cost a product major.
- The grammar of each crate stays one grammar. A future request to "just add `@attr` to Lucene for
  Datadog" is refused by the invariant in §2, not argued case by case.
- Names follow the terms: `Dialect` for products, `Profile` for uses, `Context` for inputs. Today
  two crates call a product a profile and one calls a profile a context. Until the renames land,
  this ADR's §5 table is the map.
- Raw files keep their language's default dialect, in the editor and in `validate query --file`. This
  was decided with the ADR's acceptance ([#1917](https://github.com/opentidehq/opentide/issues/1917),
  not planned). opentide validates Tide objects, where a block's or hunt's position gives the
  platform. Anyone who needs platform-specific checks on raw queries uses the crates or the SDK,
  which already take a platform (`QueryRequest.platform`, `opentide-lsp analyze --platform`). No
  language-server setting or pragma is planned.
- What a dialect may not do is now a review item. A dialect check that branches the lexer or parser,
  or a profile chosen from the platform, is a defect under this ADR.

## Counter-arguments

**"Datadog fits Lucene's flat tree: apply its precedence when reading `BooleanQuery`'s operator list,
and keep one crate."** That would hide a shape difference inside a reading of a flat list (test 1),
and nothing would hold the nesting the checks and ranges need. And `@attr`,
`CIDR()` and `**` still need new tokens and productions. These would be a dialect parameter in
Lucene's lexer and parser, so one grammar would have two corpora: Lucene's `__invalid` fixtures
that Datadog accepts, and the reverse. Structural precedence also shapes selection ranges, hover
targets and where a diagnostic points. And Datadog's reference moves on its own cadence.

**"Sentinel and Defender are different enough to be two languages."** Their differences are real,
but none reaches the tree. Splitting would copy a 99-table and 65-table difference into a second
grammar, and the unified portal now lets Defender query Sentinel tables [^unified]. Catalogs that
already overlap belong in one crate.

**"Call everything a profile; the names do not matter."** The axes are selected from different
places: the platform for a product, the position for a use. §5.3 shows what conflating them did:
choosing a profile from the platform gave a valid `.exabeam` search an error. Separate names keep
the two selections separate.

## Inventory

Where each variation lives today. Line numbers are on `development` at the time of writing.

| Language | Grammar | Catalogs | Diagnostics | Highlight | Hover, completion, signature | Selection |
|---|---|---|---|---|---|---|
| KQL | Shared | `data/catalogs/kql/{core,sentinel,defender,azure-monitor,asim}/`; `Catalog::with_profile`, `cached` (`crates/opentide-kql/src/lib.rs:355-541`) | Unknown table by profile (`lib.rs:1192-1232`); ASIM only in Sentinel (`lib.rs:516-521`, `1111`); datasets per platform (`lib.rs:1090-1095`) | Shared | By profile (`crates/opentide-analysis/src/lib.rs:771`, `855`, `927`) | `kql_profile` (`opentide-analysis/src/lib.rs:734-740`); Tide (`opentide-tide/src/lib.rs:889-893`); raw file Sentinel (`opentide-analysis/src/lib.rs:149`) |
| Lucene | Shared, flat `BooleanQuery` | `data/catalogs/carbon_black/fields.toml` (`src/carbon_black.rs`); Graylog's message fields (`src/graylog.rs:30-60`); ECS only for Elastic (`opentide-tide/src/lib.rs:942-946`) | Branches in the walk (`crates/opentide-lucene/src/lib.rs:139-171`); `graylog.rs`; newline join for Carbon Black (`lib.rs:113-120`) | Shared; skipped when the joined text differs (`lib.rs:147-157`) | By dialect for Carbon Black and Graylog, else ECS (`opentide-analysis/src/lib.rs:780-789`, `857-862`) | `Dialect::for_platform` (`lib.rs:69-80`); raw file Elastic (`opentide-analysis/src/lib.rs:188-190`) |
| YARA | yara-x-parser (superset) | `[profile.harfanglab]`, `[profile.bitdefender]` (`data/catalogs/yara/language.toml:25`, `38`); `data/catalogs/bitdefender/criteria.toml` | Size, ASCII and `yara_x_only_syntax` by profile ([`YARA.md`](../../engine/YARA.md)) | Shared | No profile (`opentide-analysis/src/lib.rs:794`, `878`, `932`) | `Profile::for_platform` (`crates/opentide-yara/src/lib.rs:77-84`); raw file none |
| Exabeam | Shared (verdict parser `check.rs`, CST `cst.rs`) | Shared | `exabeam_advanced_in_rule` in `rule` (`check.rs:1174-1184`) | Shared | No profile | Tide by field path (`opentide-tide/src/lib.rs:1010-1015`); `analyze_query` by platform (`opentide-analysis/src/lib.rs:390-396`) |
| YARA-L | Shared | Function availability by profile (`crates/opentide-yaral/src/lib.rs:64-71`) | By `Context` | Shared | No profile | Tide: sections `SECTIONS`, hunts `SEARCH` (`opentide-tide/src/lib.rs:993-1006`) |
| CQL | Shared | Shared | Correlation-rule restrictions (`crates/opentide-cql/src/lib.rs:40-50`) | Shared | No context | Tide by field path (`opentide-tide/src/lib.rs:969-978`); `analyze_query` by platform (`opentide-analysis/src/lib.rs:384-389`) |
| ES\|QL | Shared | Shared | By stack version (`crates/opentide-esql/src/version.rs:60-63`) | Shared | No version | The block's Elastic tenants (`opentide-tide/src/lib.rs:902-911`) |
| Falco | Shared | Fields by event source | By `Context` (`crates/opentide-falco/src/lib.rs:72-90`) | Shared | By context in Tide (`opentide-analysis/src/lib.rs:755-757`) | The Sysdig block (`opentide-tide/src/lib.rs:955-967`) |
| SPL, EQL, Kibana KQL | Shared | Shared (EQL, Kibana KQL: ECS by indices) | None by platform | Shared | None | None |

## Evidence

- Platforms and their languages: `crates/opentide-schema/src/platforms.rs:143-366`.
- Lucene's dialects: `crates/opentide-lucene/src/lib.rs:51-80`, `111-171`; Graylog verified on 7.2.2
  and 6.3.5 (`crates/testdata/oracles/graylog/`; [`LANGUAGE.md`](../../engine/LANGUAGE.md), Lucene).
- YARA's "not by a second grammar": [`YARA.md`](../../engine/YARA.md).
- The probes behind §5.1 and §5.3 were run with the development build's `opentide validate query
  --json`:
  - `invoke FileProfile(SHA1, 1000)` and `DeviceFromIP(...)` give no finding under either dialect;
  - `SecurityEvent | take 1` gives `kql_unknown_table` (error) under Defender only;
  - `union * | take 1` gives no finding under either dialect;
  - `SELECT DISTINCT user, src_ip WHERE vendor:"Microsoft"` in a `.exabeam` file passes without
    `--platform` and gives `exabeam_advanced_in_rule` with `--platform exabeam`.
- Facade semver: `crates/opentide/AGENTS.md`, "Semver"; 1.0.0 released 2026-11-25 (`CHANGELOG.md`).
- Precedent: [ADR 0012](./0012-pure-rust-parsing.md) (one hand-written grammar per language),
  [ADR 0013](./0013-language-catalogs.md) (catalogs built once per process),
  [ADR 0014](./0014-analysis-performance.md) §5a (one walk for checks and highlight, which dialect
  branches live in).

[^overview]: Microsoft, [Advanced hunting overview](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview), quotas.
[^custom-detections]: Microsoft, [Create and manage custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules).
[^functions]: Microsoft, [FileProfile()](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function), [DeviceFromIP()](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefromip-function), [AssignedIPAddresses()](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-assignedipaddresses-function), [SeenBy()](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-seenby-function).
[^unified]: Microsoft, [Advanced hunting in the Microsoft Defender portal](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-microsoft-defender).
[^sentinel-rules]: Microsoft, [Create a scheduled analytics rule](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules).
[^scheduled]: Microsoft, [Scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview).
