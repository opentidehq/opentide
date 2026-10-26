---
title: Diagnostic codes
description: What each opentide diagnostic code means, an example, and how to fix it.
---

<!-- Generated from src/opentide/data/diagnostics/ by
     scripts/build/render_diagnostics_docs.py. Edit the pages there. -->

# Diagnostic codes

Every finding `opentide validate` and `opentide lint` report carries a stable `code`, and every command that fails sets a `failure.code` ([JSON output](./json-output.md#failure-codes)). `opentide explain <code>` prints the page for either; this reference collects them all. `opentide explain` with no code lists the codes.

| Code | Meaning |
|------|---------|
| [`api_key_literal`](#api_key_literal) | A `sharing.toml` block holds its API key as a literal. |
| [`api_key_unset`](#api_key_unset) | An enabled sharing target has no API key. |
| [`chaining_relation_unknown`](#chaining_relation_unknown) | A threat's chaining relation is not a known relation. |
| [`changed_diff`](#changed_diff) | `share push --changed` could not calculate which objects changed. |
| [`changed_on_pull_request`](#changed_on_pull_request) | `share push --changed` does not run on a pull request. |
| [`changed_outside_ci`](#changed_outside_ci) | `share push --changed` runs only in CI, where the diff it shares is known. |
| [`command_failed`](#command_failed) | The command failed for a reason no more specific code covers. |
| [`config_enum_unknown`](#config_enum_unknown) | A value is not one of those your deployment configuration declares. |
| [`config_parse`](#config_parse) | A configuration file could not be read as TOML. |
| [`cve_lookup_unavailable`](#cve_lookup_unavailable) | A threat lists CVE identifiers, but Vulnerability-Lookup could not be reached to check them. |
| [`deployment_state_platform`](#deployment_state_platform) | A deployment state shard names a platform that stores no external ids. |
| [`deployment_state_shape`](#deployment_state_shape) | A deployment state shard is not the JSON shape opentide writes. |
| [`deployment_state_uuid_mismatch`](#deployment_state_uuid_mismatch) | A deployment state shard's file name and contents name different rules. |
| [`deprecated_field`](#deprecated_field) | An object uses a field its schema marks as deprecated. |
| [`duplicate_id`](#duplicate_id) | Two object files carry the same UUID. |
| [`duplicate_name`](#duplicate_name) | Two `sharing.toml` blocks share a name. |
| [`external_id_in_rule`](#external_id_in_rule) | A rule still carries a vendor rule id key, which belongs in deployment state. |
| [`external_id_shape`](#external_id_shape) | A vendor rule id in deployment state has the wrong form. |
| [`filename_mismatch`](#filename_mismatch) | An object file's name is not `slugify(name)`. |
| [`invalid_cve`](#invalid_cve) | A threat lists CVE identifiers Vulnerability-Lookup does not know. |
| [`invalid_ref`](#invalid_ref) | A reference names an object that does not exist. |
| [`invalid_uuid`](#invalid_uuid) | An object's `metadata.uuid` is not a UUID v4. |
| [`invalid_value`](#invalid_value) | A `sharing.toml` value has the wrong type. |
| [`issues_found`](#issues_found) | The command ran and failed on what it found. |
| [`max_tlp_unknown`](#max_tlp_unknown) | A `sharing.toml` block's `max_tlp` is not a TLP value. |
| [`metadata_recommended`](#metadata_recommended) | An object has no `metadata.author` or `metadata.organisation`. |
| [`missing_field`](#missing_field) | A `sharing.toml` block is missing a required field. |
| [`missing_uuid`](#missing_uuid) | An object file has no UUID, so it cannot be indexed. |
| [`name_invalid`](#name_invalid) | A `sharing.toml` block name is not 1-64 lowercase letters, digits, `-` or `_`. |
| [`name_missing`](#name_missing) | An object has no `name`, so lint cannot derive its file name. |
| [`needs_human_decision`](#needs_human_decision) | `migrate vocab-scope` left values that only a person can place. |
| [`no_tenant_reached`](#no_tenant_reached) | `validate query --live` sent no query, because no configured tenant takes the rules. |
| [`not_implemented`](#not_implemented) | The command is reserved and does nothing yet. |
| [`not_run`](#not_run) | The command was skipped, and says why in its message. |
| [`object_type_unknown`](#object_type_unknown) | A `sharing.toml` block lists an object type opentide cannot share. |
| [`organisation_uuid_invalid`](#organisation_uuid_invalid) | A `sharing.toml` block's `organisation_uuid` is not a UUID. |
| [`organisation_uuid_mismatch`](#organisation_uuid_mismatch) | The organisation configured for a sharing target is not the one its API key belongs to. |
| [`platform_not_enabled`](#platform_not_enabled) | A rule has a block for a platform this workspace has not enabled, so it will not deploy there. |
| [`retract_unconfirmed`](#retract_unconfirmed) | `share retract` would delete a remote event, and was not confirmed. |
| [`rule_status_unknown`](#rule_status_unknown) | A `sharing.toml` block lists a rule status your configuration does not declare. |
| [`schema_missing`](#schema_missing) | An object has no `metadata.schema`, so no schema can check it. |
| [`schema_validation`](#schema_validation) | An object does not match the schema its `metadata.schema` names. |
| [`scope_no_match`](#scope_no_match) | A `--file`, `--uuid` or `--type` selection matched no object, so nothing was validated. |
| [`share_failed`](#share_failed) | `share` reached the destination, and every object failed. |
| [`share_partial`](#share_partial) | `share` shared some objects, and others failed. |
| [`share_unreachable`](#share_unreachable) | `share` could not authenticate to, or reach, any destination. |
| [`sharing_config`](#sharing_config) | `sharing.toml` failed validation, so `share` did not run. |
| [`sharing_directory`](#sharing_directory) | A `sharing/` configuration directory exists; sharing is configured in one `sharing.toml` file. |
| [`unknown_integration`](#unknown_integration) | `sharing.toml` names a sharing integration opentide does not have; it was skipped. |
| [`unknown_key`](#unknown_key) | `sharing.toml` has a key opentide does not read. |
| [`url_invalid`](#url_invalid) | A `sharing.toml` block's `url` is not an http(s) URL. |
| [`usage_error`](#usage_error) | The command line cannot be used as written, for a reason no other usage code covers. |
| [`usage_invalid_choice`](#usage_invalid_choice) | An option or argument has a value outside the ones it accepts. |
| [`usage_invalid_value`](#usage_invalid_value) | An option has a value that cannot be used, although it is spelled correctly. |
| [`usage_missing_option`](#usage_missing_option) | A required option or argument is missing. |
| [`usage_needs_input`](#usage_needs_input) | The command would ask a question, but nobody can answer it. |
| [`usage_unknown_command`](#usage_unknown_command) | The command line names a command that does not exist. |
| [`usage_unknown_option`](#usage_unknown_option) | The command line passes an option the command does not take. |
| [`vocab_unknown`](#vocab_unknown) | A value is not in the vocabulary its field uses. |
| [`yaml_parse`](#yaml_parse) | An object file is not valid YAML, or not one mapping, so it could not be loaded. |

## api_key_literal

A `sharing.toml` block holds its API key as a literal.

Severity: warning. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
api_key = "8f4c…"
```

### How to fix

Reference an environment variable instead, `api_key = "${MISP_API_KEY}"`, and set it in your shell or CI secrets. opentide never prints the literal.

## api_key_unset

An enabled sharing target has no API key.

Exit 1, as `failure.code` and `preflight`. Nothing was sent.

### Example

```text
opentide share push --target misp-prod
```

### How to fix

Set the environment variable the target's `api_key` names in `sharing.toml`.

## chaining_relation_unknown

A threat's chaining relation is not a known relation.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```yaml
threat:
  chaining:
    - relation: succeds
      vector: 00000000-0000-4000-8001-000000000002
```

### How to fix

Use a relation from the `chaining_relations` vocabulary. `help` names the closest one.

## changed_diff

`share push --changed` could not calculate which objects changed.

Exit 1, as `failure.code` and `preflight`. The message says why.

### Example

```text
opentide share push --changed
```

### How to fix

Fetch enough history for the diff (`fetch-depth: 0` in GitHub Actions), or select objects with `--uuid`, `--type` or `--file`.

## changed_on_pull_request

`share push --changed` does not run on a pull request.

Exit 1, as `failure.code` and `preflight`. Objects are shared once they are merged.

### Example

```text
opentide share push --changed
```

### How to fix

Run it on the default branch after the merge.

## changed_outside_ci

`share push --changed` runs only in CI, where the diff it shares is known.

Exit 1, as `failure.code` and `preflight`.

### Example

```text
opentide share push --changed
```

### How to fix

Run it in GitHub Actions, GitLab CI or Azure Pipelines, or select objects with `--uuid`, `--type` or `--file`.

## command_failed

The command failed for a reason no more specific code covers.

Exit 1, as `failure.code`. `message` and `error` say what went wrong.

### Example

```text
opentide deploy --strategy PREVIEW --all --platform sentinel
```

### How to fix

Read `message`. Run the command again with `--debug` to see the log lines that led to it.

## config_enum_unknown

A value is not one of those your deployment configuration declares.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```yaml
response:
  responders: Night Shift   # not declared under [[responders]]
```

### How to fix

Use one of the values the `expected` note lists, or declare the value in the matching `[[...]]` block (such as `[[responders]]`) of `deployment.toml` under `.opentide/configurations/`.

## config_parse

A configuration file could not be read as TOML.

Severity: error. Reported for `sharing.toml` by `opentide validate --check sharing-config` and `opentide share`, and for the platform files and `deployment.toml` under `.opentide/configurations/` by every command that reads them (`validate`, `info`, `deploy`, …), which then stops with exit 1 and `failure.code` `config_parse`.

### Example

```toml
[[tenants]
name = "prod"
```

### How to fix

Open the file at the line and column the diagnostic names and fix the TOML syntax there: an unclosed `[[` header, a missing quote, or a key written twice. Then run the command again.

## cve_lookup_unavailable

A threat lists CVE identifiers, but Vulnerability-Lookup could not be reached to check them.

Severity: warning. Reported by `opentide validate --check cve`; fails `--strict`.

### Example

```yaml
threat:
  cve: [CVE-2024-3094]   # checked while the lookup service is unreachable
```

### How to fix

Check network access to https://vulnerability.circl.lu (or the configured lookup URL and any proxy), then run `opentide validate --check cve` again. The identifiers themselves were not judged: the check failed open.

## deployment_state_platform

A deployment state shard names a platform that stores no external ids.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```json
{"object_uuid": "…", "platforms": {"splunk": {"prod": "…"}}}
```

### How to fix

Remove that platform from the shard. Only the platforms the message lists keep vendor ids in deployment state.

## deployment_state_shape

A deployment state shard is not the JSON shape opentide writes.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```json
{"object_uuid": "00000000-0000-4000-8003-000000000001"}   # no platforms object
```

### How to fix

Restore the shard from version control, or delete it and let the next deploy write it again. A shard is `.opentide/states/deployment/<uuid>.json` with `object_uuid` and a `platforms` object of tenant to vendor id.

## deployment_state_uuid_mismatch

A deployment state shard's file name and contents name different rules.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```text
.opentide/states/deployment/00000000-0000-4000-8003-00000000000A.json   # not lowercase
```

### How to fix

Name each shard `<uuid>.json` with the rule's lowercase canonical UUID, keep one shard per rule, and make `object_uuid` inside it match the file name.

## deprecated_field

An object uses a field its schema marks as deprecated.

Severity: warning. Reported by `opentide validate` (schema check); fails `--strict`.

### Example

```yaml
metadata:
  old_field: value       # deprecated: use new_field
```

### How to fix

Move the value to the field the message names, then remove the deprecated one.

## duplicate_id

Two object files carry the same UUID.

Severity: error. Reported by `opentide validate` (id-uniqueness check).

### Example

```text
objects/rules/a.yaml     metadata.uuid: 00000000-0000-4000-8003-000000000001
objects/rules/a-copy.yaml metadata.uuid: 00000000-0000-4000-8003-000000000001
```

### How to fix

Give the copy a fresh UUID v4. A copied file is the usual cause. Keep the UUID on the object that is already deployed or referenced, since references and deployment state follow the UUID.

## duplicate_name

Two `sharing.toml` blocks share a name.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
[[misp]]
name = "misp-prod"

[[misp]]
name = "misp-prod"
```

### How to fix

Give each block a unique `name`; `share --target` selects blocks by it.

## external_id_in_rule

A rule still carries a vendor rule id key, which belongs in deployment state.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```yaml
configurations:
  sentinel:
    rule_id: 3f2a…           # not a key of the platform block
```

### How to fix

Run `opentide deploy migrate-state` and commit the rule together with `.opentide/states/deployment/`. Vendor ids live in one shard per rule there.

## external_id_shape

A vendor rule id in deployment state has the wrong form.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```json
{"object_uuid": "…", "platforms": {"defender_for_endpoint": {"prod": "-12"}}}
```

### How to fix

Write the id the platform returned. Defender and SentinelOne ids are canonical decimal integers (no sign, no leading zeroes); an id is never empty. A deploy writes these shards; edit them by hand only to repair one.

## filename_mismatch

An object file's name is not `slugify(name)`.

Severity: warning. Reported by `opentide lint` (filenames check).

### Example

```text
objects/threats/Simulated Actor.yaml   # name: Simulated Actor → simulated-actor.yaml
```

### How to fix

Run `opentide lint --fix`, which renames the file. When another file already has the expected name, the object gets the first eight characters of its UUID as a suffix.

## invalid_cve

A threat lists CVE identifiers Vulnerability-Lookup does not know.

Severity: error. Reported by `opentide validate --check cve`.

### Example

```yaml
threat:
  cve: [CVE-2024-99999999]
```

### How to fix

Check each identifier on https://vulnerability.circl.lu and correct or remove the ones it does not find. The check needs network access to the lookup service.

## invalid_ref

A reference names an object that does not exist.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```yaml
detection_model: 00000000-0000-4000-8002-DEADBEEF0000   # no such objective
```

### How to fix

Point the field at an object that exists: `detection_model` takes an objective or signal UUID (`opentide info objectives`), `objective.threats` and `threat.chaining[].vector` take threat UUIDs (`opentide info threats`). When the value is close to the name of an object, `help` names that object's UUID. A reference field is also a vocabulary field, but a dangling value is reported once, under this code.

## invalid_uuid

An object's `metadata.uuid` is not a UUID v4.

Severity: error. Reported by `opentide validate` (uuid-format check).

### Example

```yaml
metadata:
  uuid: 1234-abcd
```

### How to fix

Replace it with a UUID v4. If other objects already point at the old value, update those references in the same change.

## invalid_value

A `sharing.toml` value has the wrong type.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
enabled = "yes"           # must be a boolean
```

### How to fix

Use the type the message names: `true`/`false` for flags, a list of strings for lists.

## issues_found

The command ran and failed on what it found.

Exit 1, as `failure.code`. Set by `validate` (errors, or warnings under `--strict`), `lint --strict` (findings) and `info --strict` (load errors). The findings are in the same document, each with its own code.

### Example

```text
opentide validate
```

### How to fix

Fix the findings the command printed. Each one names its code: `opentide explain <code>` says how to fix it. Then run the command again.

## max_tlp_unknown

A `sharing.toml` block's `max_tlp` is not a TLP value.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
max_tlp = "white"
```

### How to fix

Use a value of the TLP vocabulary: `clear`, `green`, `amber`, `amber+strict` or `red`.

## metadata_recommended

An object has no `metadata.author` or `metadata.organisation`.

Severity: note. Reported by `opentide lint` (metadata check).

### Example

```yaml
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  # author and organisation are missing
```

### How to fix

Add the missing keys under `metadata`. They are recommended, not required: lint fails only with `--strict`.

## missing_field

A `sharing.toml` block is missing a required field.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
[[misp]]
name = "misp-prod"
# url, max_tlp and api_key are required
```

### How to fix

Add the field the message names to the block.

## missing_uuid

An object file has no UUID, so it cannot be indexed.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```yaml
name: Sentinel KQL Rule
metadata:
  schema: rule::1.0
  # uuid: is missing
```

### How to fix

Add `metadata.uuid` with a fresh UUID v4 (`python -c "import uuid; print(uuid.uuid4())"`). Never reuse the UUID of another object: references and deployment state follow it.

## name_invalid

A `sharing.toml` block name is not 1-64 lowercase letters, digits, `-` or `_`.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
[[misp]]
name = "MISP Prod"
```

### How to fix

Rename the block, for example `misp-prod`.

## name_missing

An object has no `name`, so lint cannot derive its file name.

Severity: error. Reported by `opentide lint` (filenames check).

### Example

```yaml
name: ""
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
```

### How to fix

Give the object a `name`. The file name is derived from it.

## needs_human_decision

`migrate vocab-scope` left values that only a person can place.

Exit 2, as `failure.code`. The document lists the values.

### Example

```text
opentide migrate vocab-scope
```

### How to fix

Edit each listed value by hand, then run the migration again.

## no_tenant_reached

`validate query --live` sent no query, because no configured tenant takes the rules.

Exit 2, as `failure.code`.

### Example

```text
opentide validate query --live --platform sentinel
```

### How to fix

Add a tenant for the platform in `.opentide/configurations/platforms/<platform>.toml`, or pass the `--strategy` the tenants deploy.

## not_implemented

The command is reserved and does nothing yet.

Exit 2, as `failure.code`.

### Example

```text
opentide deploy metadata --platform sentinel
```

### How to fix

Use the command the message names instead, if any.

## not_run

The command was skipped, and says why in its message.

Exit non-zero, as `failure.code`. Nothing was changed.

### Example

The document of a skipped run, trimmed to the keys that say so:

```json illustrative
{"status": "skipped", "exit_code": 2, "failure": {"code": "not_run", "message": "…"}}
```

### How to fix

Read `message`: it names what the command needed to run.

## object_type_unknown

A `sharing.toml` block lists an object type opentide cannot share.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
object_types = ["rule", "detection"]
```

### How to fix

List object families opentide shares: `threat`, `objective` and `rule`.

## organisation_uuid_invalid

A `sharing.toml` block's `organisation_uuid` is not a UUID.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
organisation_uuid = "acme"
```

### How to fix

Use the UUID of the MISP organisation, as MISP shows it.

## organisation_uuid_mismatch

The organisation configured for a sharing target is not the one its API key belongs to.

Exit 1, as `failure.code` and `preflight`. Nothing was sent.

### Example

```text
opentide share push --target misp-prod
```

### How to fix

Set the target's organisation UUID in `sharing.toml` to the one the API key belongs to, or use that organisation's key.

## platform_not_enabled

A rule has a block for a platform this workspace has not enabled, so it will not deploy there.

Severity: warning. Reported by `opentide validate` (schema check); does not fail `--strict`.

### Example

```yaml
configurations:
  splunk:               # splunk is disabled in this workspace
    enabled: true
```

### How to fix

Enable the platform with the command the message names (`opentide setup platforms --<platform>`) when this workspace should deploy there. Otherwise leave the block: it is still validated and travels with the rule.

## retract_unconfirmed

`share retract` would delete a remote event, and was not confirmed.

Exit 1, as `failure.code` and `preflight`. Nothing was deleted.

### Example

```text
opentide share retract --uuid 00000000-0000-4000-8003-000000000001
```

### How to fix

Pass `--yes` to delete the remote event.

## rule_status_unknown

A `sharing.toml` block lists a rule status your configuration does not declare.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
rule_statuses = ["PRODUCTON"]
```

### How to fix

Use a status from your deployment configuration's statuses.

## schema_missing

An object has no `metadata.schema`, so no schema can check it.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```yaml
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  # schema: rule::1.0 is missing
```

### How to fix

Add `metadata.schema` with the identifier of the revision the object follows, for example `rule::1.0`, `threat::1.0` or `objective::1.0`. opentide does not fall back to the newest revision.

## schema_validation

An object does not match the schema its `metadata.schema` names.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```yaml
metadata:
  schema: rule::1.0
severity: 3          # must be one of the severity names
```

### How to fix

The message is the schema's own (a missing required field, a wrong type, an unknown key). The location points at the field, or at the mapping it belongs in when the field is missing. Compare the object with the template under `.opentide/templates/`, or let your editor validate it against the generated JSON schema (`opentide setup vscode`). A `metadata.schema` that names no registered revision, or another object type, is reported with this code as well.

## scope_no_match

A `--file`, `--uuid` or `--type` selection matched no object, so nothing was validated.

Severity: error. Reported by `opentide validate`. `opentide share` also sets it as `failure.code` and `preflight` when no sharing target matches `--target` or none is enabled.

### Example

```text
opentide validate --file objects/rules/sentinel-kql-rul.yaml
```

### How to fix

Fix the path, file name or UUID. A path matches only that file; a bare file name matches every object file with that name. Every `--file` target must match. For `share`, name a target `opentide share targets` lists, and enable it in `sharing.toml`.

## share_failed

`share` reached the destination, and every object failed.

Exit 1, as `failure.code`. Each record in the document says why its object failed.

### Example

```text
opentide share push
```

### How to fix

Read the failed records, fix the objects or the target configuration, then share again.

## share_partial

`share` shared some objects, and others failed.

Exit 3, as `failure.code`. Each record in the document says what happened to its object.

### Example

```text
opentide share push
```

### How to fix

Fix the failed records, then share again: objects already shared are updated, not duplicated.

## share_unreachable

`share` could not authenticate to, or reach, any destination.

Exit 2, as `failure.code`.

### Example

```text
opentide share push
```

### How to fix

Check the API key, the URL and the network path (proxy, `NO_PROXY`) of the target in `sharing.toml`.

## sharing_config

`sharing.toml` failed validation, so `share` did not run.

Exit 1, as `failure.code` and `preflight`. The document lists the issues.

### Example

```text
opentide share push
```

### How to fix

Run `opentide validate --check sharing-config`: each issue has its own code and page.

## sharing_directory

A `sharing/` configuration directory exists; sharing is configured in one `sharing.toml` file.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```text
.opentide/configurations/sharing/misp.toml
```

### How to fix

Move the blocks into `.opentide/configurations/sharing.toml` and remove the directory.

## unknown_integration

`sharing.toml` names a sharing integration opentide does not have; it was skipped.

Severity: warning. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
[[opencti]]
name = "cti"
```

### How to fix

Remove the block. The only sharing integration is `[[misp]]`.

## unknown_key

`sharing.toml` has a key opentide does not read.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
[[misp]]
name = "misp-prod"
verify_tls = false     # the key is verify_ssl
```

### How to fix

Remove the key or correct its spelling. The only sharing integration is `[[misp]]`.

## url_invalid

A `sharing.toml` block's `url` is not an http(s) URL.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
url = "misp.example.org"
```

### How to fix

Write the full URL, scheme included: `https://misp.example.org`.

## usage_error

The command line cannot be used as written, for a reason no other usage code covers.

Exit 2, as `failure.code`. For example, options that cannot be combined.

### Example

```text
opentide generate docs --changed --rules
```

### How to fix

Read the message, then run `opentide <command> --help` for the options and how they combine.

## usage_invalid_choice

An option or argument has a value outside the ones it accepts.

Exit 2, as `failure.code`. Raised for `--platform`, `--type`, `--target`, `--strategy`, an `info` section and a `generate` phase. `failure.suggestion` names the closest valid value.

### Example

```text
opentide validate --type rulez
```

### How to fix

Use one of the values the message lists.

## usage_invalid_value

An option has a value that cannot be used, although it is spelled correctly.

Exit 2, as `failure.code`. The message says why, for example a removed option such as `--plan`.

### Example

```text
opentide deploy --plan plan.json
```

### How to fix

Do what the message says: drop the option, or pass the replacement it names.

## usage_missing_option

A required option or argument is missing.

Exit 2, as `failure.code`. `failure.argument` names it (`--platform`, `--strategy`, `--technique`).

### Example

```text
opentide info coverage
```

### How to fix

Add the option the message names. `opentide <command> --help` shows what it takes.

## usage_needs_input

The command would ask a question, but nobody can answer it.

Exit 2, as `failure.code`. Raised under `--json`, without a terminal, or when a coding agent runs the command.

### Example

```text
opentide --json setup
```

### How to fix

Pass the flags the message names, which answer the prompt, or run the command in a terminal.

## usage_unknown_command

The command line names a command that does not exist.

Exit 2, as `failure.code`. `failure.suggestion` names the closest command.

### Example

```text
opentide valdiate
```

### How to fix

Run the command `did you mean` names, or `opentide --help` for the list. In an agent, `opentide commands --json` prints the whole command tree.

## usage_unknown_option

The command line passes an option the command does not take.

Exit 2, as `failure.code`. `failure.argument` is the option; `failure.suggestion` the closest one.

### Example

```text
opentide validate --strictt
```

### How to fix

Fix the spelling, or run `opentide <command> --help` to see the options the command takes.

## vocab_unknown

A value is not in the vocabulary its field uses.

Severity: error. Reported by `opentide validate` (schema check).

### Example

```yaml
metadata:
  tlp: clearr          # tlp::1.0 has clear, green, amber, amber+strict, red
```

### How to fix

Use a value from the vocabulary the label names. When a close value exists, `help` names it and `fix` carries the edit; the edit is marked `safe` only when the two spell the same word (they differ in case, spaces, `-` or `_`) and hold no digit, so an ATT&CK id is never replaced unreviewed. Your editor completes vocabulary values from the generated schemas (`opentide setup vscode`).

## yaml_parse

An object file is not valid YAML, or not one mapping, so it could not be loaded.

Severity: error. Reported by `opentide validate` (schema and id-uniqueness checks) and `opentide lint`. `opentide deploy` stops on a rule file whose YAML is a list or a single value, with exit 1 and `failure.code` `yaml_parse`.

### Example

```yaml
metadata:
  tlp: [clear        # the flow list is never closed
  author: Tutorial Author
```

### How to fix

Open the file at the line and column the diagnostic names. The note says what the parser was reading when it gave up, and where that started: an unclosed `[` or `{`, a missing quote, a tab used for indentation, or a key indented under a scalar. A key repeated in the same mapping is reported here too. A file whose top level is a list (`- name: …`) or a single value is reported as "expected a mapping at the top of the file": an object file is one mapping of keys such as `name`, `metadata` and `description`. The file is not indexed until it parses, so no other check can see it.
