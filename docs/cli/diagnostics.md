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
| [`analysis_engine`](#analysis_engine) | The analysis engine imports: the compiled `opentide-analysis` package behind `opentide validate query`, `opentide validate --deep` and `opentide lsp`. |
| [`api_key_literal`](#api_key_literal) | A `sharing.toml` block holds its API key as a literal. |
| [`api_key_unset`](#api_key_unset) | An enabled sharing target has no API key. |
| [`asset_unknown`](#asset_unknown) | A `visibility.toml` log source or detector names an asset that `[[assets]]` does not declare. |
| [`chaining_relation_unknown`](#chaining_relation_unknown) | A threat's chaining relation is not a known relation. |
| [`changed_diff`](#changed_diff) | `share push --changed` could not calculate which objects changed. |
| [`changed_on_pull_request`](#changed_on_pull_request) | `share push --changed` does not run on a pull request. |
| [`changed_outside_ci`](#changed_outside_ci) | `share push --changed` runs only in CI, where the diff it shares is known. |
| [`command_failed`](#command_failed) | The command failed for a reason no more specific code covers. |
| [`compile_empty_block`](#compile_empty_block) | A block the rule needs is present but empty, so the platform cannot read a value from it. |
| [`compile_failed`](#compile_failed) | The platform's compiler rejected the rule for a reason opentide cannot name more precisely. |
| [`compile_invalid_rule`](#compile_invalid_rule) | The rule does not load as a detection rule the platform can compile. |
| [`compile_invalid_value`](#compile_invalid_value) | A setting in the rule's platform block holds a value the platform cannot use. |
| [`compile_missing_field`](#compile_missing_field) | A rule's Sentinel block lacks a setting Sentinel needs to build the alert rule. |
| [`config_enum_unknown`](#config_enum_unknown) | A value is not one of those your deployment configuration declares. |
| [`config_parse`](#config_parse) | A configuration file could not be read as TOML. |
| [`configuration`](#configuration) | The workspace configuration files under `.opentide/configurations/` load. |
| [`credentials`](#credentials) | Per configured tenant, whether every `$VARIABLE` its setup names is set. |
| [`crowdstrike_unsupported`](#crowdstrike_unsupported) | CrowdStrike queries are not validated; the engine never fakes it. |
| [`cve_lookup_unavailable`](#cve_lookup_unavailable) | A threat lists CVE identifiers, but Vulnerability-Lookup could not be reached to check them. |
| [`defender_output_columns`](#defender_output_columns) | A Defender custom detection must return the columns Defender requires. |
| [`deployment_state_platform`](#deployment_state_platform) | A deployment state shard names a platform that stores no external ids. |
| [`deployment_state_shape`](#deployment_state_shape) | A deployment state shard is not the JSON shape opentide writes. |
| [`deployment_state_uuid_mismatch`](#deployment_state_uuid_mismatch) | A deployment state shard's file name and contents name different rules. |
| [`deprecated_field`](#deprecated_field) | An object uses a field its schema marks as deprecated. |
| [`doctor_checks_failed`](#doctor_checks_failed) | At least one `opentide doctor` check failed. |
| [`duplicate_id`](#duplicate_id) | Two object files carry the same UUID. |
| [`duplicate_name`](#duplicate_name) | Two `sharing.toml` blocks share a name. |
| [`engine_unavailable`](#engine_unavailable) | The analysis engine (the `opentide-analysis` package) does not import, so the command cannot check queries or serve the language server. |
| [`eql_argument_type`](#eql_argument_type) | A literal has a type the EQL verifier rejects in this position. |
| [`eql_case_sensitive`](#eql_case_sensitive) | The comparison is case-sensitive; the case-insensitive form may be meant. |
| [`eql_expression_depth`](#eql_expression_depth) | The expression nests deeper than Elasticsearch accepts. |
| [`eql_field_comparison`](#eql_field_comparison) | Both sides of a comparison read fields, which EQL does not support. |
| [`eql_function_arity`](#eql_function_arity) | An EQL function is called with the wrong number of arguments. |
| [`eql_literal_wildcard`](#eql_literal_wildcard) | A wildcard character is compared literally; use : or like for a pattern. |
| [`eql_maxspan_lookback`](#eql_maxspan_lookback) | A sequence maxspan is longer than the rule's lookback. |
| [`eql_maxspan_missing`](#eql_maxspan_missing) | A sequence has no maxspan, so partial sequences are held until they expire. |
| [`eql_maxspan_unit`](#eql_maxspan_unit) | A sequence maxspan uses a unit Elasticsearch does not accept. |
| [`eql_maxspan_window`](#eql_maxspan_window) | A sequence maxspan is longer than the rule's interval plus lookback, so the rule cannot see whole sequences. |
| [`eql_nested_comment`](#eql_nested_comment) | Elasticsearch nests /* */ comments; the comment ends later than it looks. |
| [`eql_not_boolean`](#eql_not_boolean) | A string or number literal is used as a condition. |
| [`eql_parse_error`](#eql_parse_error) | The EQL query does not parse. |
| [`eql_regex`](#eql_regex) | The regular expression trips a Lucene RegExp pitfall. |
| [`eql_runs_ignored`](#eql_runs_ignored) | A decimal runs count is truncated by Elasticsearch. |
| [`eql_unknown_function`](#eql_unknown_function) | The EQL function is not in the Elasticsearch function catalog. |
| [`eql_unsupported`](#eql_unsupported) | Elasticsearch EQL does not support this construct (pipes, relationships, ...). |
| [`eql_until_term`](#eql_until_term) | runs or a missing-event term ![ ] is not allowed on until. |
| [`esql_expression_depth`](#esql_expression_depth) | The expression nests deeper than Elasticsearch accepts. |
| [`esql_group_by_column`](#esql_group_by_column) | A suppression group_by field is not a column the ES|QL query returns. |
| [`esql_metadata_id`](#esql_metadata_id) | A non-aggregating ES|QL rule query has no METADATA _id, so alerts cannot be deduplicated. |
| [`esql_parse_error`](#esql_parse_error) | The ES|QL query does not parse. |
| [`esql_pattern`](#esql_pattern) | A LIKE or RLIKE pattern escapes or matches differently than it reads. |
| [`esql_unavailable`](#esql_unavailable) | The command, function or form is missing or in preview on a targeted stack version. |
| [`esql_unknown_command`](#esql_unknown_command) | The ES|QL command is not one Elasticsearch knows. |
| [`esql_unknown_function`](#esql_unknown_function) | The ES|QL function is not in the Elasticsearch function catalog. |
| [`esql_unknown_type`](#esql_unknown_type) | The ::type cast names a type no Elasticsearch release can cast to. |
| [`external_id_in_rule`](#external_id_in_rule) | A rule still carries a vendor rule id key, which belongs in deployment state. |
| [`external_id_shape`](#external_id_shape) | A vendor rule id in deployment state has the wrong form. |
| [`filename_mismatch`](#filename_mismatch) | An object file's name is not `slugify(name)`. |
| [`filename_slug`](#filename_slug) | The file name is not the slug of the object's name. |
| [`git`](#git) | git is on `PATH`. |
| [`git_repository`](#git_repository) | The workspace is in a git repository, and its default branch (`origin/HEAD`). |
| [`identifier_mismatch`](#identifier_mismatch) | A platform file's `[platform] identifier` differs from its file name. |
| [`internal`](#internal) | opentide stopped on an exception it did not handle: a bug in opentide, not in your input. |
| [`invalid_cve`](#invalid_cve) | A threat lists CVE identifiers Vulnerability-Lookup does not know. |
| [`invalid_ref`](#invalid_ref) | A reference names an object that does not exist. |
| [`invalid_uuid`](#invalid_uuid) | An object's `metadata.uuid` is not a UUID v4. |
| [`invalid_value`](#invalid_value) | A `sharing.toml` value has the wrong type. |
| [`issues_found`](#issues_found) | The command ran and failed on what it found. |
| [`kql_control_command_unsupported`](#kql_control_command_unsupported) | A KQL control command (.show, .create, ...) is not a detection query; rules cannot run it. |
| [`kql_deprecated_function`](#kql_deprecated_function) | The KQL function is a deprecated alias; Microsoft Learn names its replacement. |
| [`kql_join_summarize_before_project`](#kql_join_summarize_before_project) | join or summarize runs before project, so it carries every column. |
| [`kql_parse_error`](#kql_parse_error) | The KQL query does not parse. |
| [`kql_render_not_valid`](#kql_render_not_valid) | render draws a chart; it has no effect in a detection rule. |
| [`kql_unknown_function`](#kql_unknown_function) | The KQL function is not in the Kusto function catalog. |
| [`kql_unknown_operator`](#kql_unknown_operator) | The KQL tabular operator is not one Kusto knows. |
| [`kql_unknown_table`](#kql_unknown_table) | The table is not in the platform's KQL schema (Sentinel or Defender). |
| [`kql_unscoped_search`](#kql_unscoped_search) | search without a table scans every table in the workspace. |
| [`kql_unscoped_union`](#kql_unscoped_union) | union * or an unscoped union reads every table. |
| [`kql_where_not_first`](#kql_where_not_first) | A filter comes after a more expensive operator; filtering first scans fewer rows. |
| [`kql_wildcard_table`](#kql_wildcard_table) | A wildcard table name reads every matching table. |
| [`kuery_escape`](#kuery_escape) | A character needs escaping in Kibana KQL (kuery). |
| [`kuery_free_text`](#kuery_free_text) | A value with no field searches every field. |
| [`kuery_looks_like_lucene`](#kuery_looks_like_lucene) | The query reads like Lucene; language: lucene may be meant. |
| [`kuery_lucene_syntax`](#kuery_lucene_syntax) | Lucene syntax inside a Kibana KQL (kuery) query. |
| [`kuery_parse_error`](#kuery_parse_error) | The Kibana KQL (kuery) query does not parse. |
| [`kuery_question_mark`](#kuery_question_mark) | ? is a literal in Kibana KQL (kuery), not a single-character wildcard. |
| [`kuery_quoted_wildcard`](#kuery_quoted_wildcard) | A wildcard inside quotes is a literal * in Kibana KQL (kuery). |
| [`kuery_range_type`](#kuery_range_type) | A range compares a value of the wrong type. |
| [`lookback_long`](#lookback_long) | The Elastic rule's lookback exceeds an hour; it is added to the interval, not the whole window. |
| [`lookback_zero`](#lookback_zero) | The Elastic rule's lookback is zero, so events that arrive late are missed. |
| [`lsp_catalog`](#lsp_catalog) | opentide can generate the language server's catalog for this workspace, and a committed copy is current. |
| [`lucene_bare_term`](#lucene_bare_term) | A term with no field searches every field. |
| [`lucene_elasticsearch_only`](#lucene_elasticsearch_only) | The syntax works in Elasticsearch but not in Carbon Black Cloud. |
| [`lucene_escape`](#lucene_escape) | A character needs escaping in Lucene. |
| [`lucene_fuzzy`](#lucene_fuzzy) | Elasticsearch accepts only 0, 1, 2 or AUTO as a fuzziness. |
| [`lucene_kuery_syntax`](#lucene_kuery_syntax) | Kibana KQL (kuery) syntax inside a Lucene query. |
| [`lucene_looks_like_kuery`](#lucene_looks_like_kuery) | The query reads like Kibana KQL (kuery); language: kuery may be meant. |
| [`lucene_lowercase_operator`](#lucene_lowercase_operator) | Lucene operators are upper case; lowercase and/or/not are search terms. |
| [`lucene_mixed_operators`](#lucene_mixed_operators) | AND and OR mixed without parentheses do not bind as they read. |
| [`lucene_parse_error`](#lucene_parse_error) | The Lucene query does not parse. |
| [`lucene_range_operator`](#lucene_range_operator) | f:> 10 searches f for the text >; the value must follow the operator. |
| [`lucene_regexp`](#lucene_regexp) | The /regexp/ body is rejected by, or too costly for, Lucene's RegExp. |
| [`lucene_unescaped_slash`](#lucene_unescaped_slash) | An unescaped / starts a regular expression. |
| [`max_tlp_unknown`](#max_tlp_unknown) | A `sharing.toml` block's `max_tlp` is not a TLP value. |
| [`mcp_config`](#mcp_config) | An MCP configuration from `opentide setup mcp` runs `opentide mcp start`. |
| [`metadata_recommended`](#metadata_recommended) | An object has no `metadata.author` or `metadata.organisation`. |
| [`missing_author`](#missing_author) | The recommended metadata.author field is missing. |
| [`missing_field`](#missing_field) | A configuration file is missing a required key, once it is merged with the bundled file and the parent instance. |
| [`missing_organisation`](#missing_organisation) | The recommended metadata.organisation field is missing. |
| [`missing_uuid`](#missing_uuid) | An object file has no UUID, so it cannot be indexed. |
| [`name_invalid`](#name_invalid) | A `sharing.toml` block name is not 1-64 lowercase letters, digits, `-` or `_`. |
| [`name_missing`](#name_missing) | An object has no `name`, so lint cannot derive its file name. |
| [`needs_human_decision`](#needs_human_decision) | `migrate vocab-scope` left values that only a person can place. |
| [`nested_object_file`](#nested_object_file) | A YAML file sits in a subfolder of an object folder, so it is not an object and no command reads it. |
| [`no_tenant_reached`](#no_tenant_reached) | `validate query --live` sent no query, because no configured tenant takes the rules. |
| [`not_a_configuration_file`](#not_a_configuration_file) | The file is not one opentide reads as configuration, or it has no configuration model to check it against. |
| [`not_implemented`](#not_implemented) | The command is reserved and does nothing yet. |
| [`not_run`](#not_run) | The command was skipped, and says why in its message. |
| [`object_type_unknown`](#object_type_unknown) | A `sharing.toml` block lists an object type opentide cannot share. |
| [`opentide_latest`](#opentide_latest) | Whether PyPI has a newer opentide release than the one installed. |
| [`opentide_version`](#opentide_version) | The installed opentide version. |
| [`organisation_uuid_invalid`](#organisation_uuid_invalid) | A `sharing.toml` block's `organisation_uuid` is not a UUID. |
| [`organisation_uuid_mismatch`](#organisation_uuid_mismatch) | The organisation configured for a sharing target is not the one its API key belongs to. |
| [`path_exists`](#path_exists) | `opentide new` would write a file that already exists, and it never overwrites one. |
| [`path_not_writable`](#path_not_writable) | `opentide new` could not create the folder or the file it scaffolds, because the operating system refused the write: a read-only checkout, a folder another user owns, or a full disk. |
| [`placeholder`](#placeholder) | A value still holds the stand-in `opentide new` wrote for a required field nobody chose yet. |
| [`platform_not_enabled`](#platform_not_enabled) | A rule has a block for a platform this workspace has not enabled, so it will not deploy there. |
| [`platform_sdk`](#platform_sdk) | Each enabled platform's SDK imports. |
| [`platforms_enabled`](#platforms_enabled) | Which platforms the workspace enables. |
| [`promotion_target_unknown`](#promotion_target_unknown) | `deployment.toml` `[promotion] promotion_target` is not the name of a `[[statuses]]` entry. |
| [`proxy`](#proxy) | The proxy in `--proxy`, `OPENTIDE_PROXY` or `HTTPS_PROXY` accepts a connection. |
| [`python_version`](#python_version) | The Python interpreter running opentide. |
| [`reference_not_found`](#reference_not_found) | `--objective` or `--threat` names a UUID that no object in the catalogue carries. |
| [`retract_unconfirmed`](#retract_unconfirmed) | `share retract` would delete a remote event, and was not confirmed. |
| [`risk_band`](#risk_band) | The risk score is outside the band of the rule's severity. |
| [`rule_status_unknown`](#rule_status_unknown) | A `sharing.toml` block lists a rule status your configuration does not declare. |
| [`schema_missing`](#schema_missing) | An object has no `metadata.schema`, so no schema can check it. |
| [`schema_validation`](#schema_validation) | An object does not match the schema its `metadata.schema` names. |
| [`schemas_fresh`](#schemas_fresh) | Every JSON schema this opentide version generates exists. |
| [`scope_no_match`](#scope_no_match) | A `--file`, `--uuid` or `--type` selection matched no object, so nothing was validated. |
| [`share_failed`](#share_failed) | `share` reached the destination, and every object failed. |
| [`share_partial`](#share_partial) | `share` shared some objects, and others failed. |
| [`share_unreachable`](#share_unreachable) | `share` could not authenticate to, or reach, any destination. |
| [`sharing_config`](#sharing_config) | `sharing.toml` failed validation, so `share` did not run. |
| [`sharing_directory`](#sharing_directory) | A `sharing/` configuration directory exists; sharing is configured in one `sharing.toml` file. |
| [`spl_leading_not`](#spl_leading_not) | A search that starts with NOT scans every event before excluding any. |
| [`spl_parse_error`](#spl_parse_error) | The SPL search does not parse. |
| [`spl_subsearch_truncation`](#spl_subsearch_truncation) | A subsearch is silently truncated at its result or time limit. |
| [`spl_unknown_command`](#spl_unknown_command) | The SPL command is not in the Splunk Search Reference. |
| [`spl_wildcard`](#spl_wildcard) | A leading or mid-token wildcard cannot use the index and scans every event. |
| [`technique_not_enterprise`](#technique_not_enterprise) | The ATT&CK technique is not in the Enterprise matrix that Elastic maps. |
| [`template_missing`](#template_missing) | `opentide new` found no generated template or schema for the object type it was asked for. |
| [`templates_fresh`](#templates_fresh) | Every template this opentide version generates exists and matches what it would write. |
| [`threshold_lookback`](#threshold_lookback) | A threshold rule's lookback exceeds its interval, so windows overlap and alerts repeat. |
| [`unknown_connector`](#unknown_connector) | `sharing.toml` has a top-level array that names a sharing connector opentide does not have; it was skipped. |
| [`unknown_key`](#unknown_key) | A configuration file has a key opentide does not read, usually a misspelling. |
| [`url_invalid`](#url_invalid) | A `sharing.toml` block's `url` is not an http(s) URL. |
| [`usage_error`](#usage_error) | The command line cannot be used as written, for a reason no other usage code covers. |
| [`usage_invalid_choice`](#usage_invalid_choice) | An option or argument has a value outside the ones it accepts. |
| [`usage_invalid_value`](#usage_invalid_value) | An option has a value that cannot be used, although it is spelled correctly. |
| [`usage_missing_option`](#usage_missing_option) | A required option or argument is missing. |
| [`usage_needs_input`](#usage_needs_input) | The command would ask a question, but nobody can answer it. |
| [`usage_tui_needs_tty`](#usage_tui_needs_tty) | `opentide tui` ran where it cannot draw: it needs a person at a terminal. |
| [`usage_unknown_command`](#usage_unknown_command) | The command line names a command that does not exist. |
| [`usage_unknown_option`](#usage_unknown_option) | The command line passes an option the command does not take. |
| [`usage_watch_needs_tty`](#usage_watch_needs_tty) | `validate --watch` ran where nobody can watch it. |
| [`vocab_unknown`](#vocab_unknown) | A value is not in the vocabulary its field uses. |
| [`vscode_settings`](#vscode_settings) | `.vscode/settings.json` maps the object folders to the generated schemas. |
| [`vscode_snippets`](#vscode_snippets) | The editor snippet file `opentide generate snippets` writes exists. |
| [`workspace`](#workspace) | Where the workspace is, and how it was found. |
| [`workspace_not_found`](#workspace_not_found) | `opentide new` ran outside a workspace: neither `.opentide/` nor `objects/` is there. |
| [`yaml_parse`](#yaml_parse) | An object file is not valid YAML, or not one mapping, so it could not be loaded. |

## analysis_engine

The analysis engine imports: the compiled `opentide-analysis` package behind `opentide validate query`, `opentide validate --deep` and `opentide lsp`.

Reported by `opentide doctor`, with the package's and the Rust engine's versions. Fails when the engine does not import (`engine_unavailable`).

### Example

```text illustrative
✗ The opentide analysis engine does not load: No module named 'opentide_analysis' · analysis_engine
  → pip install --force-reinstall opentide
```

### How to fix

Reinstall opentide with the command it prints. `opentide-analysis` is a dependency of opentide with a prebuilt wheel for each supported platform, so a failed import means a broken or mixed environment, or a platform with no wheel: see `opentide explain engine_unavailable`.

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

## asset_unknown

A `visibility.toml` log source or detector names an asset that `[[assets]]` does not declare.

Severity: warning. Reported by `opentide validate` (check `configuration`); the loaders log it and go on.

### Example

```toml
[[assets]]
name = "domain-controllers"
description = "Active Directory"
criticality = "high"

[[logsources]]
name = "Security events"
description = "Windows security log"
system = "splunk"
assets = ["domain-controller"]   # declared as domain-controllers
```

### How to fix

Correct the asset name, or declare the asset under `[[assets]]`.

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

## compile_empty_block

A block the rule needs is present but empty, so the platform cannot read a value from it.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1. An empty YAML block (`response:` with nothing under it) loads as nothing.

### Example

```text illustrative
error[compile_empty_block]: 'response' is empty, so Sentinel cannot read 'alert_severity'
  ╭─▶ objects/rules/sentinel-kql-rule.yaml
  ╰─ help: set response.alert_severity, or configurations.sentinel.alert.severity
```

### How to fix

Fill the block with the keys the help names, or delete it when the platform block sets the value itself (`configurations.sentinel.alert.severity`).

## compile_failed

The platform's compiler rejected the rule for a reason opentide cannot name more precisely.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1. The message quotes what the compiler said.

### Example

```text illustrative
error[compile_failed]: Sentinel cannot compile this rule: …
  ╰─▶ objects/rules/lsass-access.yaml
```

### How to fix

Read the quoted reason and fix the rule's platform block. Run `opentide validate --file <path>` first; if the rule validates and still fails here, add `--debug` and open an issue.

## compile_invalid_rule

The rule does not load as a detection rule the platform can compile.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1. The message is the data model's own error.

### Example

```text illustrative
error[compile_invalid_rule]: …
  ╰─▶ objects/rules/lsass-access.yaml
```

### How to fix

Run `opentide validate --file <path>` on the rule: it reports the same problem as a code frame at the line, with a fix when one is safe.

## compile_invalid_value

A setting in the rule's platform block holds a value the platform cannot use.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1.

### Example

```text illustrative
error[compile_invalid_value]: configurations.sentinel.alert.suppression is true
  ╭─▶ objects/rules/lsass-access.yaml
  ╰─ help: set it to false or a duration such as PT1H
```

### How to fix

Set the value the help names. Durations are ISO 8601 (`PT1H`, `P1D`).

## compile_missing_field

A rule's Sentinel block lacks a setting Sentinel needs to build the alert rule.

Severity: error. Reported by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed and exits 1. The message names the key (`configurations.sentinel.grouping.alert is missing`) and the help says when it is required.

### Example

```text illustrative
error[compile_missing_field]: configurations.sentinel.scheduling.frequency is missing
  ╭─▶ objects/rules/lsass-access.yaml
  ╰─ help: required unless scheduling.nrt is true
```

### How to fix

Add the key under `configurations.sentinel` in the rule. The generated rule template, and a rule from `opentide new rule --platform sentinel`, show each one with its default.

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

## configuration

The workspace configuration files under `.opentide/configurations/` load.

Reported by `opentide doctor`. Fails when one does not parse; the message names the file and line. The checks that read the configuration are then skipped, so the broken file is reported once.

### Example

```text illustrative
✗ .opentide/configurations/platforms/sentinel.toml is not valid TOML: Expected '=' after a key (at line 4, column 9) · configuration
```

### How to fix

Fix the TOML at the line it names. `opentide explain config_parse` shows the common mistakes.

## credentials

Per configured tenant, whether every `$VARIABLE` its setup names is set.

Reported by `opentide doctor`. Warns when a variable is unset or empty, with `subject` as `platform/tenant`; skipped when the platform has no tenant. It never prints a value.

### Example

```text illustrative
! sentinel/prod: 1 of 2 variables unset: AZURE_CLIENT_SECRET · credentials
  → set AZURE_CLIENT_SECRET in the environment (or a .env file you load)
```

### How to fix

Set the variables it names in the environment the deploy runs in (a CI secret, or a `.env` file you load). Never write the value into the TOML.

## crowdstrike_unsupported

CrowdStrike queries are not validated; the engine never fakes it.

Reported by the analysis engine for an object file: `opentide lsp check` and an editor running `opentide lsp start` show it. `opentide validate` and `opentide lint` are the authority for objects and may name the same problem with their own code.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the file where the frame points, then run `opentide lsp check` again.

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

## defender_output_columns

A Defender custom detection must return the columns Defender requires.

Reported by the analysis engine for an object file: `opentide lsp check` and an editor running `opentide lsp start` show it. `opentide validate` and `opentide lint` are the authority for objects and may name the same problem with their own code.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the file where the frame points, then run `opentide lsp check` again.

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

```text illustrative
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

## doctor_checks_failed

At least one `opentide doctor` check failed.

Exit 1, as `failure.code`. Warnings and skipped checks never change the exit code. Under `--json`, `checks` lists every check with its `code`, `status`, `message` and `fix`.

### Example

```text
opentide --json doctor
```

### How to fix

Run the fix printed under each `✗` line (or read each failed check's `fix` in JSON), then run `opentide doctor` again. `opentide explain <check code>` describes each check.

## duplicate_id

Two object files carry the same UUID.

Severity: error. Reported by `opentide validate` (id-uniqueness check).

### Example

```text illustrative
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

## engine_unavailable

The analysis engine (the `opentide-analysis` package) does not import, so the command cannot check queries or serve the language server.

Exit 1, as `failure.code`, from `opentide validate query` (offline), `opentide lsp check` and `opentide lsp start`; an error issue of the `queries` check in `opentide validate --deep`; and the `analysis_engine` check of `opentide doctor`. The check is never skipped: a missing engine fails the command.

### Example

```text illustrative
error: The opentide analysis engine does not load: No module named 'opentide_analysis._native'
  help: reinstall opentide: pip install --force-reinstall opentide
```

### How to fix

The engine is a dependency of opentide, compiled for each platform: `pip install opentide` installs it, and there is no extra to add. Reinstall opentide with the command it prints, in a clean environment (`uv tool install --reinstall opentide` for a uv tool install). When pip builds `opentide-analysis` from source instead of downloading a wheel, your platform has no prebuilt wheel: install a Rust toolchain (https://rustup.rs) and reinstall, or report the platform at https://github.com/opentidehq/opentide/issues.

## eql_argument_type

A literal has a type the EQL verifier rejects in this position.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_case_sensitive

The comparison is case-sensitive; the case-insensitive form may be meant.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_expression_depth

The expression nests deeper than Elasticsearch accepts.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_field_comparison

Both sides of a comparison read fields, which EQL does not support.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_function_arity

An EQL function is called with the wrong number of arguments.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_literal_wildcard

A wildcard character is compared literally; use : or like for a pattern.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_maxspan_lookback

A sequence maxspan is longer than the rule's lookback.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_maxspan_missing

A sequence has no maxspan, so partial sequences are held until they expire.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_maxspan_unit

A sequence maxspan uses a unit Elasticsearch does not accept.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_maxspan_window

A sequence maxspan is longer than the rule's interval plus lookback, so the rule cannot see whole sequences.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_nested_comment

Elasticsearch nests /* */ comments; the comment ends later than it looks.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_not_boolean

A string or number literal is used as a condition.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_parse_error

The EQL query does not parse.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_regex

The regular expression trips a Lucene RegExp pitfall.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_runs_ignored

A decimal runs count is truncated by Elasticsearch.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_unknown_function

The EQL function is not in the Elasticsearch function catalog.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_unsupported

Elasticsearch EQL does not support this construct (pipes, relationships, ...).

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_until_term

runs or a missing-event term ![ ] is not allowed on until.

Reported by the analysis engine in a EQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## esql_expression_depth

The expression nests deeper than Elasticsearch accepts.

Reported by the analysis engine in a ES|QL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_group_by_column

A suppression group_by field is not a column the ES|QL query returns.

Reported by the analysis engine in a ES|QL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_metadata_id

A non-aggregating ES|QL rule query has no METADATA _id, so alerts cannot be deduplicated.

Reported by the analysis engine in a ES|QL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_parse_error

The ES|QL query does not parse.

Reported by the analysis engine in a ES|QL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_pattern

A LIKE or RLIKE pattern escapes or matches differently than it reads.

Reported by the analysis engine in a ES|QL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_unavailable

The command, function or form is missing or in preview on a targeted stack version.

Reported by the analysis engine in a ES|QL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_unknown_command

The ES|QL command is not one Elasticsearch knows.

Reported by the analysis engine in a ES|QL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_unknown_function

The ES|QL function is not in the Elasticsearch function catalog.

Reported by the analysis engine in a ES|QL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_unknown_type

The ::type cast names a type no Elasticsearch release can cast to.

Reported by the analysis engine in a ES|QL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

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

```text illustrative
objects/threats/Simulated Actor.yaml   # name: Simulated Actor → simulated-actor.yaml
```

### How to fix

Run `opentide lint --fix`, which renames the file. When another file already has the expected name, the object gets the first eight characters of its UUID as a suffix.

## filename_slug

The file name is not the slug of the object's name.

Reported by the analysis engine for a Tide object: `opentide lsp check` and an editor running `opentide lsp start` show it. `opentide validate` and `opentide lint` are the authority for objects and may name the same problem with their own code.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the file where the frame points, then run `opentide lsp check` again.

## git

git is on `PATH`.

Reported by `opentide doctor`. Warns when it is missing: `--changed`, the default branch and the CI setup need it.

### Example

```text illustrative
✓ git 2.43.0 · git
```

### How to fix

Install git from your package manager or https://git-scm.com.

## git_repository

The workspace is in a git repository, and its default branch (`origin/HEAD`).

Reported by `opentide doctor`. Warns when it is not a repository, or `origin/HEAD` is not set.

### Example

```text illustrative
! ./ is not in a git repository · git_repository
  → git init ./
```

### How to fix

Run the command it prints: `git init` for a new repository, or `git remote set-head origin --auto` when `origin/HEAD` is unset.

## identifier_mismatch

A platform file's `[platform] identifier` differs from its file name.

Severity: error. Reported for `platforms/<id>.toml` by the configuration file check an editor runs (`configuration_file_issues`).

### Example

```toml
# platforms/sentinel.toml
[platform]
identifier = "splunk"
```

### How to fix

Make `identifier` match the file name stem, or remove it: the file name is used when it is absent.

## internal

opentide stopped on an exception it did not handle: a bug in opentide, not in your input.

Exit 1, as `failure.code`. Under `--json` the document also carries `failure.crash_log`, the path of a redacted crash log. On stderr, `error[internal]: <Type>: <message>` is followed by that path and a link that opens a pre-filled GitHub issue. Under `opentide mcp start` nothing is written to stdout.

### Example

```text illustrative
error[internal]: RuntimeError: index exploded
  note: crash log, with credentials and tenant names redacted: ~/.local/state/opentide/crash-20261023T110335102704Z-648.log
  help: this is a bug in opentide; report it: https://github.com/opentidehq/opentide/issues/new?…
  help: add --debug to see the traceback
```

### How to fix

Open the issue from the link, and attach the crash log after reading it: opentide removes the secrets and tenant names it recognises, but not a value it cannot tell is one. Add `--debug` (or `OPENTIDE_DEBUG=1`) to print the traceback on stderr too. See [Troubleshooting](../usage/troubleshooting.md#opentide-stops-with-errorinternal).

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

## kql_control_command_unsupported

A KQL control command (.show, .create, ...) is not a detection query; rules cannot run it.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_deprecated_function

The KQL function is a deprecated alias; Microsoft Learn names its replacement.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_join_summarize_before_project

join or summarize runs before project, so it carries every column.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_parse_error

The KQL query does not parse.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_render_not_valid

render draws a chart; it has no effect in a detection rule.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unknown_function

The KQL function is not in the Kusto function catalog.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unknown_operator

The KQL tabular operator is not one Kusto knows.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unknown_table

The table is not in the platform's KQL schema (Sentinel or Defender).

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unscoped_search

search without a table scans every table in the workspace.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unscoped_union

union * or an unscoped union reads every table.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_where_not_first

A filter comes after a more expensive operator; filtering first scans fewer rows.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_wildcard_table

A wildcard table name reads every matching table.

Reported by the analysis engine in a KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kuery_escape

A character needs escaping in Kibana KQL (kuery).

Reported by the analysis engine in a Kibana KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_free_text

A value with no field searches every field.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_looks_like_lucene

The query reads like Lucene; language: lucene may be meant.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_lucene_syntax

Lucene syntax inside a Kibana KQL (kuery) query.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_parse_error

The Kibana KQL (kuery) query does not parse.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_question_mark

? is a literal in Kibana KQL (kuery), not a single-character wildcard.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_quoted_wildcard

A wildcard inside quotes is a literal * in Kibana KQL (kuery).

Reported by the analysis engine in a Kibana KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_range_type

A range compares a value of the wrong type.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## lookback_long

The Elastic rule's lookback exceeds an hour; it is added to the interval, not the whole window.

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lsp check` and an editor running `opentide lsp start` show it, and `opentide validate query --platform elastic --live` checks the same settings.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the block's setting the frame points at, then run `opentide lsp check` again.

## lookback_zero

The Elastic rule's lookback is zero, so events that arrive late are missed.

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lsp check` and an editor running `opentide lsp start` show it, and `opentide validate query --platform elastic --live` checks the same settings.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the block's setting the frame points at, then run `opentide lsp check` again.

## lsp_catalog

opentide can generate the language server's catalog for this workspace, and a committed copy is current.

Reported by `opentide doctor`. `opentide lsp start`, `opentide lsp check` and `opentide tui` check objects with the catalog this opentide generates from its models and the workspace's configuration, cached under the user cache directory (`OPENTIDE_CACHE_DIR` overrides it). The copy `opentide generate schemas` writes to `.opentide/lsp/catalogs/generated/` is read only by editors that run the `opentide-lsp` binary on its own, and when generation fails. Warns when the catalog cannot be generated, or when a committed copy does not parse or comes from another opentide version.

### Example

```text illustrative
! The language-server catalog committed in .opentide/lsp/catalogs/generated is from opentide 0.18.0, not 0.19.0: editors that run opentide-lsp on their own use it · lsp_catalog
  → opentide generate schemas
```

### How to fix

For a committed copy, run `opentide generate schemas` (or `opentide generate`) and commit the files it writes, so editors that run `opentide-lsp` on its own use the same catalog. When the catalog cannot be generated, `opentide doctor --debug` shows why; until then objects are checked with the committed or the bundled catalog.

## lucene_bare_term

A term with no field searches every field.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_elasticsearch_only

The syntax works in Elasticsearch but not in Carbon Black Cloud.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_escape

A character needs escaping in Lucene.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_fuzzy

Elasticsearch accepts only 0, 1, 2 or AUTO as a fuzziness.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_kuery_syntax

Kibana KQL (kuery) syntax inside a Lucene query.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_looks_like_kuery

The query reads like Kibana KQL (kuery); language: kuery may be meant.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_lowercase_operator

Lucene operators are upper case; lowercase and/or/not are search terms.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_mixed_operators

AND and OR mixed without parentheses do not bind as they read.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_parse_error

The Lucene query does not parse.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_range_operator

f:> 10 searches f for the text >; the value must follow the operator.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_regexp

The /regexp/ body is rejected by, or too costly for, Lucene's RegExp.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_unescaped_slash

An unescaped / starts a regular expression.

Reported by the analysis engine in a Lucene query string query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## max_tlp_unknown

A `sharing.toml` block's `max_tlp` is not a TLP value.

Severity: error. Reported by `opentide validate --check sharing-config` and `opentide share`.

### Example

```toml
max_tlp = "white"
```

### How to fix

Use a value of the TLP vocabulary: `clear`, `green`, `amber`, `amber+strict` or `red`.

## mcp_config

An MCP configuration from `opentide setup mcp` runs `opentide mcp start`.

Reported by `opentide doctor`. Warns when no configuration has such a server, or its command is not on `PATH`; skipped when there is no configuration.

### Example

```text illustrative
○ No MCP configuration: agents in editors cannot call opentide tools · mcp_config
  → opentide setup mcp --vscode (or --cursor, --claude-code, --generic)
```

### How to fix

Run `opentide setup mcp` with your editor's flag.

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

## missing_author

The recommended metadata.author field is missing.

Reported by the analysis engine for a Tide object: `opentide lsp check` and an editor running `opentide lsp start` show it. `opentide validate` and `opentide lint` are the authority for objects and may name the same problem with their own code.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the file where the frame points, then run `opentide lsp check` again.

## missing_field

A configuration file is missing a required key, once it is merged with the bundled file and the parent instance.

Severity: error. Reported by `opentide validate` (check `configuration`) for the files under `.opentide/configurations/`, and by `opentide validate --check sharing-config` and `opentide share` for a `sharing.toml` block. A file that only overrides some keys is not reported for the keys it inherits.

### Example

```toml
[[misp]]
name = "misp-prod"
# url, max_tlp and api_key are required
```

### How to fix

Add the key the message names. `context.file` names the file and `field_path` the table it belongs to.

## missing_organisation

The recommended metadata.organisation field is missing.

Reported by the analysis engine for a Tide object: `opentide lsp check` and an editor running `opentide lsp start` show it. `opentide validate` and `opentide lint` are the authority for objects and may name the same problem with their own code.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the file where the frame points, then run `opentide lsp check` again.

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

## nested_object_file

A YAML file sits in a subfolder of an object folder, so it is not an object and no command reads it.

Severity: warning. Reported by `opentide validate` and `opentide lint`, and named in the `warnings` of `share`, `generate docs` and `export`. `validate --strict` and `lint --strict` fail on it. Only files placed directly in `objects/rules/`, `objects/threats/` and `objects/objectives/` (or the configured folders) are objects: a file one folder down is not indexed, validated, shared, documented or deployed ([#584](https://github.com/opentidehq/opentide/issues/584)).

### Example

```text illustrative
objects/rules/team-a/rule.yaml is in a subfolder of objects/rules and is not an object instance
```

### How to fix

Move the file up into its object folder (`git mv objects/rules/team-a/rule.yaml objects/rules/`), or delete it if it is a stale copy.

## no_tenant_reached

`validate query --live` sent no query, because no configured tenant takes the rules.

Exit 2, as `failure.code`.

### Example

```text
opentide validate query --live --platform sentinel
```

### How to fix

Add a tenant for the platform in `.opentide/configurations/platforms/<platform>.toml`, or pass the `--strategy` the tenants deploy.

## not_a_configuration_file

The file is not one opentide reads as configuration, or it has no configuration model to check it against.

Severity: warning. Reported by the configuration file check an editor runs (`configuration_file_issues`) for a file under `.opentide/configurations/` that no model covers, such as `resources.toml` or `lint.toml` (which `opentide lint` checks itself), and for a file under `.opentide/schemas/`, which holds generated artifacts.

### Example

```text illustrative
.opentide/configurations/deployement.toml   # misspelt: opentide reads deployment.toml
```

### How to fix

Rename a misspelt file to the name opentide reads. A file opentide does not read can be removed.

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

## opentide_latest

Whether PyPI has a newer opentide release than the one installed.

Reported by `opentide doctor`. Warns when a newer release exists or PyPI did not answer (3-second timeout, through the proxy); skipped with `--offline`.

### Example

```text illustrative
! opentide 0.19.0 is available; 0.18.0 is installed · opentide_latest
  → pip install --upgrade opentide
```

### How to fix

Upgrade with the command it prints (or `uv tool upgrade opentide` for a uv tool install). Read the changelog first: a release can rename or deprecate a key.

## opentide_version

The installed opentide version.

Reported by `opentide doctor`. Always passes: it records the version the other checks ran with.

### Example

```text illustrative
✓ opentide 0.18.0 · opentide_version
```

### How to fix

Nothing to fix. Quote it when you report a problem.

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

## path_exists

`opentide new` would write a file that already exists, and it never overwrites one.

Exit 1, as `failure.code`. Raised when `--path` names an existing file, or when a file appears at the chosen path while `new` runs.

### Example

```text
opentide new threat --name "Credential Dumping" --path objects/threats/credential-dumping.yaml
```

### How to fix

Pass another `--path`, or leave `--path` out: without it, `new` appends `-<uuid[:8]>` to the file name when the name is taken. To start over, delete or move the existing file first.

## path_not_writable

`opentide new` could not create the folder or the file it scaffolds, because the operating system refused the write: a read-only checkout, a folder another user owns, or a full disk.

Exit 1, as `failure.code`. The message names the file and the system's reason (`Permission denied`, `Read-only file system`).

### Example

```text illustrative
error: Could not write objects/threats/credential-dumping.yaml: Permission denied
```

### How to fix

Make the folder writable (`ls -ld objects/threats` shows its owner and mode), run `opentide new` from a checkout you can write, or pass `--path` to write the file somewhere you can and move it later.

## placeholder

A value still holds the stand-in `opentide new` wrote for a required field nobody chose yet.

Severity: warning. Reported by `opentide lint` (placeholders check).

### Example

```yaml
threat:
  mitre_attack:
    - T1548  # opentide:placeholder
  description: |  # opentide:placeholder
    ...
```

### How to fix

Replace the value with the real one, then delete the `# opentide:placeholder` comment on that line. The object validates with the stand-in, so only `lint` notices it; `lint --strict` fails until every marker is gone.

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

When the platform file sets a misspelling of `enabled` (`enabeld = true`, `Enabled = true`), the platform reads as disabled and the message names the file and the key instead: rename the key to `enabled`.

## platform_sdk

Each enabled platform's SDK imports.

Reported by `opentide doctor`. Fails when it does not, with `subject` naming the platform.

### Example

```text illustrative
✗ splunk: cannot import splunklib (ModuleNotFoundError) · platform_sdk
  → pip install --force-reinstall opentide
```

### How to fix

Reinstall opentide with the command it prints, in a clean environment (`uv tool install --reinstall opentide` for a uv tool install). The platform SDKs are dependencies of opentide, so a failed import means a broken or mixed environment.

## platforms_enabled

Which platforms the workspace enables.

Reported by `opentide doctor`. Warns when none is: rules validate but nothing deploys.

### Example

```text illustrative
✓ Enabled: sentinel · platforms_enabled
```

### How to fix

Enable one with `opentide setup platforms --<platform>` (`--sentinel`, `--splunk`, …).

## promotion_target_unknown

`deployment.toml` `[promotion] promotion_target` is not the name of a `[[statuses]]` entry.

Severity: error. Reported by `opentide validate` (check `configuration`).

### Example

```toml
[promotion]
enabled = true
promotion_target = "LIVE"   # no [[statuses]] entry is named LIVE
```

### How to fix

Set `promotion_target` to a status name declared in the merged `deployment.toml`, or declare the status.

## proxy

The proxy in `--proxy`, `OPENTIDE_PROXY` or `HTTPS_PROXY` accepts a connection.

Reported by `opentide doctor`. Fails when it does not (3-second timeout); skipped when no proxy is set or with `--offline`. The proxy is shown without its user and password.

### Example

```text illustrative
✗ Cannot connect to proxy http://proxy.example:3128 (ConnectionRefusedError) · proxy
  → check --proxy, OPENTIDE_PROXY or HTTPS_PROXY, and that the proxy is up
```

### How to fix

Check the host and port, and that the proxy is reachable from this machine. Hosts in `NO_PROXY` are reached directly.

## python_version

The Python interpreter running opentide.

Reported by `opentide doctor`. Fails when it is older than 3.10.

### Example

```text illustrative
✓ Python 3.13.16 · python_version
```

### How to fix

Install Python 3.10 or later and reinstall opentide with it (`uv tool install opentide`, or `pipx install --python python3.12 opentide`).

## reference_not_found

`--objective` or `--threat` names a UUID that no object in the catalogue carries.

Exit 2, as `failure.code`, with `failure.argument` naming the option. `opentide new` checks the reference before it writes anything; a malformed UUID is `usage_invalid_value` instead.

### Example

```text
opentide new rule --name "LSASS Access" --objective 00000000-0000-4000-8000-000000000000
```

### How to fix

Copy the UUID from the object's `metadata.uuid`, or create that objective or threat first with `opentide new objective` or `opentide new threat`. `opentide info` lists the catalogue.

## retract_unconfirmed

`share retract` would delete a remote event, and was not confirmed.

Exit 1, as `failure.code` and `preflight`. Nothing was deleted.

### Example

```text
opentide share retract --uuid 00000000-0000-4000-8003-000000000001
```

### How to fix

Pass `--yes` to delete the remote event.

## risk_band

The risk score is outside the band of the rule's severity.

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lsp check` and an editor running `opentide lsp start` show it, and `opentide validate query --platform elastic --live` checks the same settings.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the block's setting the frame points at, then run `opentide lsp check` again.

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

## schemas_fresh

Every JSON schema this opentide version generates exists.

Reported by `opentide doctor`. Warns when one is missing. Schemas carry no version stamp, so only presence is checked.

### Example

```text illustrative
! 1 schema(s) this version generates are missing: rule · schemas_fresh
  → opentide generate schemas
```

### How to fix

Run `opentide generate schemas`.

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

```text illustrative
.opentide/configurations/sharing/misp.toml
```

### How to fix

Move the blocks into `.opentide/configurations/sharing.toml` and remove the directory.

## spl_leading_not

A search that starts with NOT scans every event before excluding any.

Reported by the analysis engine in a SPL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_parse_error

The SPL search does not parse.

Reported by the analysis engine in a SPL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_subsearch_truncation

A subsearch is silently truncated at its result or time limit.

Reported by the analysis engine in a SPL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_unknown_command

The SPL command is not in the Splunk Search Reference.

Reported by the analysis engine in a SPL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_wildcard

A leading or mid-token wildcard cannot use the index and scans every event.

Reported by the analysis engine in a SPL query, at the place in the query: `opentide validate query`, `opentide validate --deep`, `opentide lsp check` and an editor running `opentide lsp start` show it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` again (`--file` for one rule). The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## technique_not_enterprise

The ATT&CK technique is not in the Enterprise matrix that Elastic maps.

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lsp check` and an editor running `opentide lsp start` show it, and `opentide validate query --platform elastic --live` checks the same settings.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the block's setting the frame points at, then run `opentide lsp check` again.

## template_missing

`opentide new` found no generated template or schema for the object type it was asked for.

Exit 1, as `failure.code`. `new` runs the generation it needs first when the workspace has no template; this code means that run wrote none for the family either.

### Example

```text
opentide new threat --name "Credential Dumping"
```

### How to fix

Run `opentide generate templates schemas` and read its output for the failing phase, then run `opentide new` again. `opentide doctor` reports a missing template as `templates_fresh`.

## templates_fresh

Every template this opentide version generates exists and matches what it would write.

Reported by `opentide doctor`. Warns when a template is missing or differs, usually after an upgrade.

### Example

```text illustrative
! 2 template(s) differ from what this version generates: rule, threat · templates_fresh
  → opentide generate templates
```

### How to fix

Run `opentide generate templates`.

## threshold_lookback

A threshold rule's lookback exceeds its interval, so windows overlap and alerts repeat.

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lsp check` and an editor running `opentide lsp start` show it, and `opentide validate query --platform elastic --live` checks the same settings.

### Example

```text
opentide lsp check objects/rules
```

### How to fix

Change the block's setting the frame points at, then run `opentide lsp check` again.

## unknown_connector

`sharing.toml` has a top-level array that names a sharing connector opentide does not have; it was skipped.

Severity: warning. Reported by `opentide validate --check sharing-config` and `opentide share`. The exported `sharing.toml` schema accepts the array, so an editor does not flag it as an error.

### Example

```toml
[[opencti]]
name = "cti"
```

### How to fix

Remove the block. The only sharing connector is `[[misp]]`.

## unknown_key

A configuration file has a key opentide does not read, usually a misspelling.

Severity: error. Reported by `opentide validate` (check `configuration`) for the files under `.opentide/configurations/`, by every command that reads the file, and by `opentide validate --check sharing-config` and `opentide share` for `sharing.toml`. The message names the file and the key, never its value.

### Example

```toml
# deployment.toml
[promotion]
enabeld = false        # the key is enabled
```

### How to fix

Remove the key or correct its spelling. The JSON Schema of each file (`python -m opentide.generation.configuration_schemas <dir>`) lists the keys it takes.

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

Exit 2, as `failure.code`. Raised for `--platform`, `--type`, `--target`, `--strategy`, an `info` section, an `info vocab` name and a `generate` phase. `failure.suggestion` names the closest valid value.

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

## usage_tui_needs_tty

`opentide tui` ran where it cannot draw: it needs a person at a terminal.

Exit 2, as `failure.code`. Raised under `--json`, in a pipe, in CI, under a coding agent, and at a terminal whose settings select `plain` output (`NO_COLOR`, `--no-color`, `TERM=dumb`); the error names the setting.

### Example

```text
opentide --json tui
```

### How to fix

Run `opentide tui` in an interactive terminal. When a `plain` setting such as `NO_COLOR` refused it, set `OPENTIDE_OUTPUT=human` to open it anyway. For a script, run the commands the UI runs (`opentide validate`, `opentide generate`, `opentide deploy --dry-run`) directly, with `--json`.

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

## usage_watch_needs_tty

`validate --watch` ran where nobody can watch it.

Exit 2, as `failure.code`. Raised under `--json`, when a coding agent runs the command, or with `OPENTIDE_OUTPUT=agent`: the watch redraws a terminal until Ctrl-C.

### Example

```text
opentide --json validate --watch
```

### How to fix

Run `opentide validate --watch` in a terminal, or run `opentide validate` once (with `--json` for a document).

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

## vscode_settings

`.vscode/settings.json` maps the object folders to the generated schemas.

Reported by `opentide doctor`. Warns when it maps something else or is not valid JSON; skipped when the file does not exist.

### Example

```text illustrative
○ No .vscode/settings.json: editors get no schema completion · vscode_settings
  → opentide setup vscode
```

### How to fix

Run `opentide setup vscode`.

## vscode_snippets

The editor snippet file `opentide generate snippets` writes exists.

Reported by `opentide doctor`. Skipped when it does not.

### Example

```text illustrative
○ No snippets at .vscode/model-templates.code-snippets · vscode_snippets
  → opentide generate snippets
```

### How to fix

Run `opentide generate snippets`.

## workspace

Where the workspace is, and how it was found.

Reported by `opentide doctor`. Fails when neither `.opentide/` nor `objects/` is in the folder; warns when there is `objects/` without `.opentide/`.

### Example

```text illustrative
✓ Workspace ./ has .opentide/ (found from the current directory) · workspace
```

### How to fix

Run `opentide doctor` from inside your detection repository, or pass `--repo`. Run `opentide setup` to create `.opentide/` in a new or legacy repository.

## workspace_not_found

`opentide new` ran outside a workspace: neither `.opentide/` nor `objects/` is there.

Exit 1, as `failure.code`. `new` writes only into a workspace, the folder `--repo` names or the one discovery finds, so a stray run in your home directory cannot make it a workspace that every folder below it would discover.

### Example

```text illustrative
cd ~ && opentide new threat --name "Credential Dumping"
```

### How to fix

Run it from inside your detection repository, or pass `--repo path/to/detections`. To start a new one, run `opentide setup`. `opentide doctor` applies the same test as its `workspace` check.

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
