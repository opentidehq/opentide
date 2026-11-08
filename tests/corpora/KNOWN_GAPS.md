# Known gaps

Faults the oracle (opentide 0.23.0) misses, or reports in a way that surprises: what the
architecture review found, and what building the fault catalogue found. Each entry has a fault kind
in [`faults.toml`](faults.toml) (its `gap` key names the entry) that pins what 0.23.0 does today, so
the Rust engine is compared with the same behaviour until a decision changes it. **UC-2.2 decides
each entry**; an intended change then goes in `tests/golden/APPROVED_DIFFS.toml` with its reason,
issue and changelog entry, and the kind's expectation changes with it.

A kind with `codes = []` pins a silence: the oracle reports nothing for that fault.

| Id | Gap | Fault kinds |
|----|-----|-------------|
| KG-01 | Sentinel `frequency` that is not an ISO 8601 duration | `compile-invalid-rule-frequency` |
| KG-02 | `metadata.reviewed`: what is checked and what is not | `gap-reviewed-in-future`, `reviewed-impossible-date`, `schema-validation-reviewed-word`, `schema-validation-reviewed-on-1-0` |
| KG-03 | `filename_mismatch` (lint) and `filename_slug` (engine) disagree | `lint-filename-mismatch`, `lint-filename-mismatch-prefix` |
| KG-04 | Invalid and duplicate UUIDs: how many findings, on which file | `uuid-invalid-rule`, `uuid-invalid-threat`, `uuid-duplicate-rule`, `uuid-duplicate-invalid` |
| KG-05 | Metadata recommendation codes | `lint-metadata-recommended`, `lint-metadata-recommended-organisation` |
| KG-06 | Configuration files that stop the run, or vanish without a finding | `gap-extra-configuration-file`, `config-retired-file`, `config-parse-visibility` |
| KG-07 | `opentide lint` ignores `paths.toml` | none: reproduced by the `custom` layout (below) |
| KG-08 | KQL `*` in `union` and `search in`: lint and validate disagree | `kql-unscoped-union`, `kql-wildcard-table`, `kql-wildcard-union-validate` |
| KG-09 | Elastic `severity.default` without `mapping` crashes the compile check | `compile-failed-elastic-severity` |
| KG-10 | The compile check runs only when the whole run is otherwise clean | `compile-invalid-value-suppression`, `compile-missing-field-grouping`, `compile-empty-block-response` |
| KG-11 | A rule block naming an undeclared tenant | `gap-unknown-block-tenant` |
| KG-12 | Configuration findings carry no file or position | `config-*` kinds (`per_target = false`) |
| KG-13 | `sharing.toml` treats `$VAR` as a literal key | `gap-sharing-dollar-variable` |
| KG-14 | An unknown key in `paths.toml` crashes `validate` | none: the run fails with `internal` (below) |
| KG-15 | The rule-level `status` is never checked | `gap-rule-status-unchecked` |

## KG-01: Sentinel `frequency`

The review found `frequency: hourly` in a Sentinel block missed by both implementations. The oracle
does report it, as `compile_invalid_rule` (error, "Duration 'hourly' is not an ISO 8601
duration"), but only from the compile check, which runs only when the run has no other issue
anywhere in the workspace, Sentinel is enabled and the block's status compiles (KG-10). With any
unrelated finding elsewhere (`tlp: clearr` in another file) it is silent; with `status: DESIGN` it
is silent; `lint` never reports it. The engine has no Sentinel duration check.
Options: a schema-level duration check (always reported, `schema_validation` or a new code); or
keep it in the compile check and make that check independent of other findings.

## KG-02: `metadata.reviewed`

The engine has no `reviewed` check. In the oracle, on `rule::1.1`: a word (`yesterday`) or a
datetime without an offset is `schema_validation`; an impossible date (`2026-02-30`) is
`yaml_parse` (PyYAML refuses it before the model sees it), from `validate` and `lint`; a date in
the future (`2099-01-01`) is accepted silently. On `rule::1.0` the key is `schema_validation`
("Extra inputs are not permitted"). Options: report a future review (warning); decide whether an
impossible date stays a parse error or becomes the field's own finding with its path.

## KG-03: `filename_mismatch` and `filename_slug`

`filename_mismatch` (lint, warning) fires on any stem that is not exactly `slugify(name)`; for a
second object with the same name it expects `<slug>-<uuid[:8]>`. The engine's `filename_slug`
accepts any stem that starts with `<slug>-` (so `name-v2.yaml` passes the engine and fails lint),
and the CLI never shows `filename_slug`: lint keeps only engine findings with a query prefix, so it
is language-server only. The two can disagree on the same file in the editor and in CI.
Options: one rule and one code for both; or document the editor's looser rule.

## KG-04: Invalid and duplicate UUIDs

- An invalid UUID gives exactly one `invalid_uuid`; uppercase hexadecimal is accepted.
- A UUID shared by several files gives one `duplicate_id` per extra file (two files: one; three:
  two), on the file indexed later, naming the first: `uuid-duplicate-rule` sets `per_target =
  false` for that reason.
- Five files sharing one invalid UUID (`uuid-duplicate-invalid`): four `duplicate_id` (on the
  files indexed after the first, each naming it as "already used by") and one `invalid_uuid`,
  which lands on one of those four; the first file, the one the others name, gets no finding at
  all, and the other files' `invalid_uuid` is hidden because the index keys objects by UUID.

The kinds pin these numbers with `counts`.
Options: report `invalid_uuid` on every file that carries one; report a duplicate on every file of
the group, or once per group.

## KG-05: Metadata recommendation codes

`validate` reports none. `lint` reports `metadata_recommended` (info, one per object, listing the
missing keys of `[metadata] required` in `lint.toml`: `author`, `organisation`). The engine's
`missing_author`, `missing_organisation` and `recommended_field_missing` are language-server only:
lint keeps no engine finding without a query prefix. `organisation: ACME` (a string) satisfies
lint but fails `validate` with `schema_validation`; the `{name, uuid}` form satisfies both.
Options: one set of codes for the CLI and the editor.

## KG-06: Configuration files that stop the run, or vanish without a finding

- A `.toml` under `.opentide/configurations/` that opentide does not know (`colours.toml`) is
  ignored without a word; `not_a_configuration_file` exists but no CLI path emits it.
- A retired file (`global.toml`) makes every command stop before validating (`failure.code:
  retired_configuration_file`, exit 1): the finding, with its path, is in the failure document's
  `diagnostics`, not in `report`, and no other check runs (`config-retired-file`).
- Invalid TOML in `deployment.toml`, `visibility.toml` or `resources.toml` stops `validate` and
  `lint` the same way (`failure.code: config_parse`, the finding under `diagnostics`;
  `config-parse-visibility`); in `sharing.toml` it is an ordinary `config_parse` finding of
  `validate --check sharing-config`.
Options: report unknown files (warning); keep validating the rest of the workspace when one
configuration file cannot be read, as an unreadable object file does.

## KG-07: `opentide lint` ignores `paths.toml`

`cli/services/lint.py` hard-codes `objects/<family>`: with `[paths.objects]` moving the objects
(`cargo xtask corpus generate --layout custom`), `validate` checks all 220 objects and `lint`
checks 0 files and passes. Reproduce:

```bash
cargo xtask corpus generate --seed 7 --scale 0.2 --layout custom --out /tmp/custom
opentide --json --repo /tmp/custom lint      # summary.files == 0
```

Options: lint reads the object folders from `paths.toml`, as validate does.

## KG-08: KQL `*` in `union` and `search in`

The vendored KQL grammar does not parse `union *` or `search in (T, *)`. `lint` reports the
advisories (`kql_unscoped_union`, `kql_wildcard_table`, warnings); `validate` reports
`kql_parse_error` (error) for the same query, so a query the lint advises on fails validation.
Options: the grammar parses the wildcard forms (they are valid KQL).

## KG-09: Elastic `severity.default` without `mapping`

`severity: {default: high}` passes the schema, then the compile check fails with `compile_failed`
"Elastic cannot compile this rule: 'mapping'" (`platforms/elastic/compile.py` reads
`block["severity"]["mapping"]`, a KeyError). The generator writes a mapping with every default for
that reason. Options: treat a missing mapping as none (the documented shape allows it).

## KG-10: The compile check runs only when the run is otherwise clean

`compile_invalid_rule`, `compile_invalid_value`, `compile_missing_field` and `compile_empty_block`
appear only when the workspace has no other finding (and the platform is enabled, and the block's
status compiles). One unrelated error hides every compile finding, so fixing one problem can reveal
others. Their kinds are `isolated` (left out of the combined fault workspace). These codes are not
in `VALIDATION_CODES` either (`codes.toml` takes them from their explain pages, group `compile`).
`compile_empty_block` needs both an empty `response` and no `alert.severity` in the Sentinel block
("`response` is empty, so Sentinel cannot read `alert_severity`"). Options: run the compile check
independently of other findings, and list its codes.

## KG-11: A rule block naming an undeclared tenant

`tenants: [no-such-tenant]` in a Sentinel block, where `sentinel.toml` declares other tenants, is
not reported by `validate` or `lint`; the rule then deploys to no tenant. Options:
`config_enum_unknown` (as an unknown status is).

## KG-12: Configuration findings carry no file or position

Configuration findings (`unknown_key`, `missing_field`, `schema_validation`,
`promotion_target_unknown`, `asset_unknown`) have `path: null` and no line in `validate --json`;
the file is only named inside the message (`platforms/splunk.toml.platform.colour: unknown key`).
SARIF and Code Quality reports cannot place them. Options: the configuration file's path and the
key's position, as object findings have.

## KG-13: `sharing.toml` treats `$VAR` as a literal key

`api_key = "$MISP_API_KEY"` is `api_key_literal` (warning); `api_key = "${MISP_API_KEY}"` is not.
Platform tenants take the `$VAR` form (every shipped template uses it). Options: accept both forms
in both places.

## KG-14: An unknown key in `paths.toml` crashes `validate`

An unknown key in `paths.toml` makes `validate` fail with `failure.code: internal` (a
ConfigurationError and a crash log), where the same mistake in another configuration file is a
clean `unknown_key` finding. No kind: the runner needs a JSON report to compare, and the crash
gives none. Options: an `unknown_key` finding.

## KG-15: The rule-level `status` is never checked

A rule's top-level `status` (`NOPE`) is not reported: no command reads it (the model says so); each
platform block's `status` is what deploys and what `config_enum_unknown` checks. Options: check it
against the statuses, or deprecate it.
