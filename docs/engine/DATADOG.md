---
title: "Datadog search syntax"
description: "How the engine checks the Datadog log search syntax (`crates/opentide-datadog`): the grammar and its precedence, the profiles, the diagnostics, the attribute catalogue, and the conformance results against Datadog's published queries and VRL's grammar."
---

# Datadog search syntax

The Datadog engine (`crates/opentide-datadog`) checks the log search syntax of Datadog: the
queries of Datadog Cloud SIEM detection rules (the API's `event_query`), and raw `.datadog` files.
The language id is `datadog`, the file suffix `.datadog`, the code prefix `datadog_`. The language
has no comment syntax.

The contract is [`docs/internal/rfc-datadog-cloud-siem.md`](../internal/rfc-datadog-cloud-siem.md),
§6 (it moves to opentidehq/specifications as `specs/languages/datadog-1.0.md` in the RFC's phase 0).
Datadog publishes no grammar of its log search syntax, so the grammar is written from its
[Log Search Syntax](https://docs.datadoghq.com/logs/explorer/search_syntax/) page and held to two
references: the queries Datadog itself publishes, and the grammar of VRL, the open-source library
behind Datadog's Observability Pipelines.

| Layer | Source of truth | Engine |
|-------|-----------------|--------|
| Syntax, precedence, profiles, every code | RFC §6.3 to §6.7 | `src/lexer.rs`, `src/parser.rs`, `src/datadog.ungram`, `src/check.rs` |
| Reserved and standard attributes | Datadog's Default Standard Attributes table, DataDog/documentation@12f7b8d3 (BSD-3-Clause), facts only | `data/catalogs/datadog/` (`scripts/engine/sync_datadog_catalog.py`), `src/catalog.rs` |
| Highlighting | RFC §6.8 (existing HighlightSpec captures only) | `src/check.rs` (the same walk as the checks) |
| Accept-or-reject differential | VRL's `src/datadog/search/grammar.pest` at `1e3e2e8a` (MPL-2.0), CI only | `scripts/engine/oracles/datadog/` |

This is phase 1 of the RFC: the language. The `datadog` platform (its Tide block, deploy, the
tenant check and `opentide query`) is phase 2, so no block embeds the language yet, `opentide
validate query` does not take `.datadog` files, and hunts with `system: datadog` wait for the
platform's identifier. The language server (`opentide lsp start`, `opentide-lsp`) reads `.datadog`
files today.

## A new grammar, not a Lucene dialect

The syntax looks like Lucene's, but AND (written or implied) binds tighter than OR, which changes
the tree: `a OR b c` is `a OR (b AND c)`, where Lucene's classic parser reads `a b c` with no
precedence. Fields have three forms (`@attribute.path`, a bare tag or reserved attribute,
`#calculated`), `CIDR()` is a call, `/` is an ordinary character, and there is no regular
expression, fuzzy or boost operator (RFC §6.2).

## Grammar

```text
query       = or_expr?
or_expr     = and_expr ( OR and_expr )*
and_expr    = unary ( AND? unary )*
unary       = ( "-" | "+" | "NOT" )? primary          // one modifier
primary     = "(" or_expr ")" | "*:*" | cidr_call | field ":" value | field ":" "(" value_expr ")" | value
value       = PHRASE | comparison | range | TERM
value_expr  = value_and ( OR value_and )*             // a value group: values only, no fields
value_and   = value_unary ( AND? value_unary )*
value_unary = ( "-" | "NOT" )? ( "(" value_expr ")" | value )
```

`datadog.ungram` states the tree (`cargo xtask codegen` writes the typed AST from it). A run of ANDs
and a run of ORs is each one flat node, so a 20,000-term chain is not 20,000 levels deep; only a
group is a level of the parser's `MAX_DEPTH` (1,000, `deep_queries`' `NESTING_CEILING`).

The lexer cuts small pieces and the parser glues the ones that touch: a term is whatever touches
(`web-*`, `waiting\ un*`, `system:serviceaccount:x` in a value), a field is everything before the
first unescaped `:` that touches it (`@user.first\ name:x`), a CIDR block runs to `,` or `)`
(`fc00::/7`), and a range bound runs to whitespace or a closing bracket. `AND`, `OR`, `NOT` and
`TO` are operators in upper case only (a lower-case `to` in a range is read as `TO` and reported);
`&&` and `||` standing alone are read as AND and OR, as VRL reads them, and reported. A space may
follow a field's colon (`env: prod`). A word that is a number, with an optional duration unit
(`100ms`, `5m`, `2days`), is a number where it is a whole value.

## Profiles

| Profile | Used for | Difference |
|---------|----------|------------|
| `rule` | a detection rule's `queries[].query` (phase 2); `analyze_query` with `platform: datadog` | `*:term` (`datadog_full_text_in_rule`) and `#name` (`datadog_calculated_field_in_rule`) are warnings |
| `search` | `.datadog` files; `system: datadog` hunts and `opentide query` (phase 2); `analyze_query` without a platform | everything the syntax allows |

## Diagnostics

A query that does not parse gets its first syntax error and nothing else: advice on a tree that
recovery rebuilt is noise. A fault inside a range is `datadog_range`, every other one
`datadog_parse_error`.

| Code | Severity | Fires on |
|------|----------|----------|
| `datadog_parse_error` | error | an unbalanced bracket, a dangling operator, an empty group, a field with no value, two modifiers, an unclosed phrase, nesting past 1,000 groups |
| `datadog_unescaped_special` | error | an unescaped `!`, `<` or `>` in a term; a value (right after `:`) starting with an unescaped `-` |
| `datadog_regex` | error | `~` or `^` in a term |
| `datadog_cidr` | error | `CIDR` without an `@attribute` first, without a block, or with an argument that is not an IPv4 or IPv6 address with an optional prefix length in range |
| `datadog_range` | error; warning for mixed bounds | a malformed range or a lower-case `to`; `[ … }` or `{ … ]` |
| `datadog_mixed_boolean` | warning | an OR beside an AND, written or implied, without parentheses; the message names the precedence it assumes |
| `datadog_lowercase_operator` | warning | `and`, `or`, `not` in a lower-case spelling between two clauses that are not free text, or in a value group |
| `datadog_curly_quote` | warning | `“` or `”` |
| `datadog_wildcard_in_phrase` | warning | `*` or `?` next to a letter or digit inside quotes |
| `datadog_unescaped_colon` | warning | an unescaped `:` in a value, but in a value of `tags`, whose values are `key:value` by definition |
| `datadog_symbol_operator` | warning | `&&` or `\|\|` between clauses |
| `datadog_detached_operator` | warning | `-` followed by a space |
| `datadog_full_text_in_rule` | warning | `*:term` in profile `rule` |
| `datadog_calculated_field_in_rule` | warning | `#name` in profile `rule` |
| `datadog_pipelines_only` | warning | `_exists_:`, `_missing_:`, a quoted field name |
| `datadog_unknown_attribute` | hint | a dotted bare key (`evt.name:x`), searched as a tag where an attribute was probably meant |

Each code has an explain page (`opentide explain <code>`, `src/opentide/data/diagnostics/`).

**Precedence is unverified on Cloud SIEM** (RFC open question 2). The model follows VRL: AND binds
tighter than OR. `datadog_mixed_boolean` stays a warning and says so in its message until a tenant
probe settles it.

## Highlighting

The captures of RFC §6.8, with no capture added to `highlights/spec.toml`: an attribute, tag key or
reserved attribute is `property`, a calculated field `variable`, `:`, comparisons, the exclusion and
wildcards `operator`, `AND`, `OR`, `NOT` and `TO` `keyword`, `CIDR` `function.builtin`, a CIDR block
and an escape `constant`, a phrase `string`, a number `number`, brackets and the comma of `CIDR`
punctuation, an error node `error`. A term's text is `string`, as Lucene colours its terms (the
RFC's table does not list terms; without it the TextMate grammar left 36% of the published
queries' words uncoloured, against the 30% bound `highlights/test` holds every language to).

The checks and the highlight are one preorder walk of the tree (ADR 0014 §5a): `src/tests.rs`
holds the walk's element visits to the tree's element count.

## Catalogue

`data/catalogs/datadog/attributes.toml` holds the 9 reserved attributes (searched by their bare
name: `host`, `device`, `source`, `status`, `service`, `trace_id`, `message`, `env`, `version`) and
199 standard attributes (searched as `@<name>`), each with its type, group and products, from the
"Default Standard Attributes" table of DataDog/documentation. Facts only: Datadog's descriptions are
not copied, and hover is written from the facts. The catalogue serves hover and completion; it
never makes a finding, because a team's pipelines remap attributes (RFC §14).

The source-pipeline catalogue of RFC §6.9 (integrations-core's 408 pipelines: `source:` values and
each source's attributes) and the template-variable catalogue are follow-ups: they serve completion
and an `@attribute` arm of `datadog_unknown_attribute`, which waits for them.

## Conformance results

| Suite | Queries | Result | Harness |
|-------|---------|--------|---------|
| Datadog's published queries (`crates/testdata/conformance/external/datadog/published.jsonl`: docs, integrations, API clients; BSD-3-Clause and Apache-2.0) | 2,895 | no error but the 4 reasoned exceptions of `EXCEPTIONS.toml`; the count of each code pinned (below) | `crates/opentide-datadog/tests/published.rs` |
| Twins of published queries with one injected fault each (`broken.jsonl`, 12 fault kinds) | 12 | each original clean, each twin exactly its fault's code | `crates/opentide-analysis/tests/external_datadog.rs` |
| The same, against VRL's grammar (accept or reject) | 2,895 | 2,883 agree; the 12 others are the RFC's expected disagreements (below) | `scripts/engine/oracles/datadog/oracle.py` |
| The corpus, against VRL's grammar | 44 | 38 agree; 6 departures on purpose (below) | the same |
| Datadog's default rules as the Terraform provider's cassettes record them (measured, not vendored: MPL-2.0 files of Datadog's own content) | 199 rules, 153 distinct queries | 0 errors; 153 / 153 agree with VRL; one warning, `datadog_mixed_boolean` on the Microsoft 365 rule of RFC §11.3 | `scripts/engine/oracles/datadog/default_rules.py` |
| Grammar productions | 22, one valid and one invalid fixture each | 22 / 22 | `crates/opentide-analysis/tests/corpus_gate.rs` |
| `.ungram` shape | every corpus and published query that parses | conforms | `crates/opentide-datadog/tests/ast_conformance.rs` |

### Datadog's published queries

Each query runs under profile `rule` (profile `search` for an Observability Pipelines example,
`context: op`). Measured on 2026-11-26:

| Code | Findings | Queries | Prototype (RFC §11, 3,229 queries) |
|------|---------:|--------:|-----------------------------------:|
| `datadog_unknown_attribute` (hint) | 50 | 49 | 58 |
| `datadog_full_text_in_rule` | 5 | 5 | 5 |
| `datadog_pipelines_only` | 3 | 3 | 3 |
| `datadog_wildcard_in_phrase` | 3 | 3 | 3 |
| `datadog_unescaped_special` (error) | 2 | 2 | 3 |
| `datadog_unescaped_colon` | 1 | 1 | 4 |
| `datadog_curly_quote` | 1 | 1 | 1 |
| `datadog_range` (error) | 1 | 1 | 1 |
| `datadog_parse_error` (error) | 1 | 1 | 1 |
| `datadog_mixed_boolean` | 0 | 0 | 5 |
| `datadog_lowercase_operator` | 0 | 0 | 1 |
| `datadog_detached_operator` | 0 | 0 | 1 |

The four errors are the RFC's expected rejections that are in the vendored set, each an entry of
`EXCEPTIONS.toml` with its reason: `rule:[A-Invalid` (a deliberately invalid query from the API
clients' examples: a range never closed, so `datadog_range`), `message:*!*` and `tags:*\:!*.`
(Observability Pipelines only), and `@session.view.count :> 3 OR …` (a RUM docs example with a
space before the colon, which makes the field free text and leaves `:` where no clause starts, so
`datadog_parse_error`). The RFC's fifth, `models.litellm[.]cloud` from a Security Labs article, is
measured, not vendored.

**Why the counts differ from the prototype's.** The prototype ran on 3,229 queries; 334 of them are
not vendored (the Terraform provider's 95 docs and test queries, MPL-2.0, and 239 from the blog and
Security Labs, under Datadog's site terms), so every count the prototype found there is absent here:

- `datadog_mixed_boolean` 5 → 0, `datadog_lowercase_operator` 1 → 0, `datadog_detached_operator`
  1 → 0: RFC §11.3 places four of the five mixed-boolean queries and both other findings in
  non-vendored sources (two blog queries, the Security Labs Salesforce guide's
  `- @login_type:(k OR n or E)`). The default-rule finding of §11.3 is in the cassettes, measured
  above. The RFC does not name the fifth mixed-boolean query; the engine finds none in the
  vendored set.
- `datadog_unescaped_colon` 4 → 1: the RUM docs example (`@http.url:https:\/\/*`) is the one here;
  the two blog posts are not vendored; and the engine leaves out a value of `tags`
  (`tags:(security-group:sg-123 AND role:common-node)`, a docs example), whose values are
  `key:value` pairs by definition, which the token-level prototype flagged.
- `datadog_unescaped_special` 3 and `datadog_parse_error` 1 → 2 and 1, with `datadog_range` 1 → 1:
  the same rejections, coded as the tree sees them. The engine reports a fault inside a range as
  `datadog_range` (RFC §6.7: "a malformed range"), so `rule:[A-Invalid` is `datadog_range` and
  `models.litellm[.]cloud` (not vendored) would be too; `field :> 3` is a parse error, not an
  unescaped `>`.
- `datadog_unknown_attribute` 58 → 50: the engine counts each dotted bare key (50 findings in 49
  queries); the other 8 of the prototype's are in the 334 queries not vendored. That split cannot
  be checked here without them.
- The other codes agree.

### Against VRL's grammar

VRL's grammar is the Observability Pipelines dialect, so agreement means only that both accept or
both refuse a query. Every disagreement is a `[[datadog]]` entry of
`crates/testdata/oracles/exceptions.toml`:

| Disagreement | Published | Corpus | Why |
|--------------|----------:|-------:|-----|
| `CIDR(…, fc00::/7)` | 3 | 1 | VRL reads `CIDR(…)` as text and a group, and its terms cannot hold `:`; the engine parses the call and checks its blocks |
| `*:term` | 4 | 1 | Datadog documents it; VRL has only `*:*` |
| A value starting with `+` | 2 | 0 | Datadog's docs write it; VRL refuses a leading `+` |
| An unescaped `:` in a value | 1 | 0 | VRL refuses it; the engine warns, as Datadog's own content writes it |
| Observability Pipelines forms (a quoted field name, a term glued to a phrase) | 2 | 1 | VRL refuses its own examples; the engine warns on the first and accepts the second |
| `CIDR` arguments checked (no `@`, `10.0.0.300`) | 0 | 2 | VRL accepts any text; the engine refuses (`datadog_cidr`) |
| Stacked modifiers (`NOT NOT a`) | 0 | 1 | VRL accepts them; the engine refuses, as VRL refuses `--a` |

The RFC (§11.2) expected 14 disagreements on its 3,229 queries, each a query Datadog publishes and
VRL refuses: the 12 above, and two blog posts with an unescaped `:` that are not vendored.

### Depth and length

Every token class at 1,000,000 characters on a 1 MB stack (`tests/parser_depth.rs`), the chain and
nesting floors and the precedence ladder in `crates/opentide-analysis/tests/deep_queries.rs`
(1,000 levels clean, one error past them), and linear growth on broken input
(`tests/long_runs.rs`). A word is scanned by a callback, not a repeated regex class: logos
recursed once per multi-byte character of a repeated class, and a run of byte-order marks
overflowed a 1 MB stack before the change.

## Open

- **Precedence** (RFC open question 2): a tenant probe (`POST /rules/test`) settles whether Cloud
  SIEM binds AND tighter than OR, and whether `&&`, `||` and `!` are operators.
- **What each accepted-but-undocumented form does** (RFC open question 6): `*:term`, `_exists_`,
  open or mixed range bounds, an unescaped `:` and a space after `:` in rule queries.
- **The language id** (RFC open question 1): `datadog`, as the draft picks.
