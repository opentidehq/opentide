---
title: Diagnostic codes
description: What each opentide diagnostic code means, an example, and how to fix it.
---

<!-- Generated from src/opentide/data/diagnostics/ by
     scripts/build/render_diagnostics_docs.py. Edit the pages there. -->

# Diagnostic codes

Every finding `opentide validate` and `opentide lint` report carries a stable `code`. `opentide explain <code>` prints the page for it; this reference collects them all. `opentide explain` with no code lists the codes.

| Code | Meaning |
|------|---------|
| [`api_key_literal`](#api_key_literal) | A `sharing.toml` block holds its API key as a literal. |
| [`chaining_relation_unknown`](#chaining_relation_unknown) | A threat's chaining relation is not a known relation. |
| [`config_enum_unknown`](#config_enum_unknown) | A value is not one of those your deployment configuration declares. |
| [`config_parse`](#config_parse) | `sharing.toml` could not be read as TOML. |
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
| [`max_tlp_unknown`](#max_tlp_unknown) | A `sharing.toml` block's `max_tlp` is not a TLP value. |
| [`metadata_recommended`](#metadata_recommended) | An object has no `metadata.author` or `metadata.organisation`. |
| [`missing_field`](#missing_field) | A `sharing.toml` block is missing a required field. |
| [`missing_uuid`](#missing_uuid) | An object file has no UUID, so it cannot be indexed. |
| [`name_invalid`](#name_invalid) | A `sharing.toml` block name is not 1-64 lowercase letters, digits, `-` or `_`. |
| [`name_missing`](#name_missing) | An object has no `name`, so lint cannot derive its file name. |
| [`object_type_unknown`](#object_type_unknown) | A `sharing.toml` block lists an object type opentide cannot share. |
| [`organisation_uuid_invalid`](#organisation_uuid_invalid) | A `sharing.toml` block's `organisation_uuid` is not a UUID. |
| [`platform_not_enabled`](#platform_not_enabled) | A rule has a block for a platform this workspace has not enabled, so it will not deploy there. |
| [`rule_status_unknown`](#rule_status_unknown) | A `sharing.toml` block lists a rule status your configuration does not declare. |
| [`schema_missing`](#schema_missing) | An object has no `metadata.schema`, so no schema can check it. |
| [`schema_validation`](#schema_validation) | An object does not match the schema its `metadata.schema` names. |
| [`scope_no_match`](#scope_no_match) | A `--file`, `--uuid` or `--type` selection matched no object, so nothing was validated. |
| [`sharing_directory`](#sharing_directory) | A `sharing/` configuration directory exists; sharing is configured in one `sharing.toml` file. |
| [`unknown_integration`](#unknown_integration) | `sharing.toml` names a sharing integration opentide does not have; it was skipped. |
| [`unknown_key`](#unknown_key) | `sharing.toml` has a key opentide does not read. |
| [`url_invalid`](#url_invalid) | A `sharing.toml` block's `url` is not an http(s) URL. |
| [`vocab_unknown`](#vocab_unknown) | A value is not in the vocabulary its field uses. |
| [`yaml_parse`](#yaml_parse) | An object file is not valid YAML, so it could not be loaded. |

## api_key_literal

A `sharing.toml` block holds its API key as a literal.

Severity: warning. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
api_key = "8f4c…"
```

### How to fix

Reference an environment variable instead, `api_key = "${MISP_API_KEY}"`, and set it in your shell or CI secrets. opentide never prints the literal.

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

`sharing.toml` could not be read as TOML.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
[[misp]
name = "misp-prod"
```

### How to fix

Fix the TOML syntax error the message names.

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

Severity: error. Reported by `opentide validate`.

### Example

```text
opentide validate --file objects/rules/sentinel-kql-rul.yaml
```

### How to fix

Fix the path, file name or UUID. A path matches only that file; a bare file name matches every object file with that name. Every `--file` target must match.

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

An object file is not valid YAML, so it could not be loaded.

Severity: error. Reported by `opentide validate` (schema and id-uniqueness checks) and `opentide lint`.

### Example

```yaml
metadata:
  tlp: [clear        # the flow list is never closed
  author: Tutorial Author
```

### How to fix

Open the file at the line and column the diagnostic names. The note says what the parser was reading when it gave up, and where that started: an unclosed `[` or `{`, a missing quote, a tab used for indentation, or a key indented under a scalar. A key repeated in the same mapping is reported here too. The file is not indexed until it parses, so no other check can see it.
