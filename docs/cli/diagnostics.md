---
title: Diagnostic codes
description: What each opentide diagnostic code means, an example, and how to fix it.
---

<!-- Generated from src/opentide/data/diagnostics/ and the analysis engine's codes by
     `cargo xtask codegen`. Edit the pages there. -->

# Diagnostic codes

Every finding `opentide validate` and `opentide lint` report carries a stable `code`, and every command that fails sets a `failure.code` ([JSON output](./json-output.md#failure-codes)). `opentide explain <code>` prints the page for either; this reference collects them all. `opentide explain` with no code lists the codes.

| Code | Meaning |
|------|---------|
| [`analysis_engine`](#analysis_engine) | The analysis engine loads: the Rust module compiled into opentide (`opentide._native`) behind the `queries` checks of `opentide validate` and `opentide lint`, `opentide validate query` and `opentide lsp`. |
| [`api_key_literal`](#api_key_literal) | A `sharing.toml` block holds its API key as a literal. |
| [`api_key_unset`](#api_key_unset) | An enabled sharing target has no API key. |
| [`asset_unknown`](#asset_unknown) | A `visibility.toml` log source or detector names an asset that `[[assets]]` does not declare. |
| [`bitdefender_action_scope`](#bitdefender_action_scope) | An automatic action is not allowed for the rule's kind or target. |
| [`bitdefender_actions_unsupported`](#bitdefender_actions_unsupported) | The block sets `actions`, and the tenant's subscription has no automatic actions. |
| [`bitdefender_contains_no_wildcard`](#bitdefender_contains_no_wildcard) | A `contains` criterion has neither `*` nor `?`, so GravityZone matches the value as written. |
| [`bitdefender_create_no_id`](#bitdefender_create_no_id) | A GravityZone create answered something other than a 24-hex rule id. |
| [`bitdefender_create_unconfirmed`](#bitdefender_create_unconfirmed) | A GravityZone create got no answer, and its retry found the name already taken. |
| [`bitdefender_criteria_combination`](#bitdefender_criteria_combination) | The criteria combine fields or values GravityZone does not allow together. |
| [`bitdefender_criterion_field`](#bitdefender_criterion_field) | A criterion's `field` does not belong to the block's `target`. |
| [`bitdefender_criterion_relation`](#bitdefender_criterion_relation) | A criterion uses a relation its field does not take. |
| [`bitdefender_criterion_shape`](#bitdefender_criterion_shape) | A criterion does not have `field` and exactly one of `is`, `contains` and `any`. |
| [`bitdefender_criterion_value`](#bitdefender_criterion_value) | A criterion's value is not one its field accepts. |
| [`bitdefender_incidents_api_unavailable`](#bitdefender_incidents_api_unavailable) | The tenant has no Incidents API, so it cannot take custom rules. |
| [`bitdefender_kind_changed`](#bitdefender_kind_changed) | An update was refused because the block's kind differs from the GravityZone rule's. |
| [`bitdefender_name_conflict`](#bitdefender_name_conflict) | GravityZone refused a create because a rule with the same name exists in the company. |
| [`bitdefender_name_duplicate`](#bitdefender_name_duplicate) | Two enabled Bitdefender blocks resolve to the same GravityZone rule name. |
| [`bitdefender_registry_full_hive`](#bitdefender_registry_full_hive) | A `Registry.Key` criterion starts with a full hive name, which GravityZone accepts and never matches. |
| [`bitdefender_request_failed`](#bitdefender_request_failed) | GravityZone refused a call for this rule with a JSON-RPC error. |
| [`bitdefender_rule_kind`](#bitdefender_rule_kind) | A Bitdefender block sets both `detection` and `yara`, or neither. |
| [`bitdefender_rule_missing`](#bitdefender_rule_missing) | A rule to disable is gone from GravityZone, so its recorded id was removed. |
| [`bitdefender_rule_recreated`](#bitdefender_rule_recreated) | The recorded GravityZone rule was gone, so deploy created it again. |
| [`bitdefender_severity`](#bitdefender_severity) | The block `severity` is not `Low`, `Medium` or `High`. |
| [`bitdefender_severity_collapsed`](#bitdefender_severity_collapsed) | `response.alert_severity` is `Critical` or `Informational`, which GravityZone sends as `High` or `Low`. |
| [`bitdefender_target`](#bitdefender_target) | The `detection.target` is not a GravityZone detection target. |
| [`bitdefender_target_unknown`](#bitdefender_target_unknown) | A `targets` alias is not in the tenant's `endpoint_tags` or `companies` table. |
| [`bitdefender_targets_shape`](#bitdefender_targets_shape) | `targets` sets both `endpoint_tags` and `companies`, or an empty list. |
| [`bitdefender_tenant_unauthorized`](#bitdefender_tenant_unauthorized) | GravityZone refused the tenant's API key, so no rule deploys to it. |
| [`bitdefender_tenant_unreachable`](#bitdefender_tenant_unreachable) | A call to the GravityZone tenant got no answer, so no further rule deploys to it. |
| [`bitdefender_yara_ascii`](#bitdefender_yara_ascii) | A Bitdefender YARA signature holds a character that is not ASCII. |
| [`bitdefender_yara_size`](#bitdefender_yara_size) | A Bitdefender YARA signature is longer than 30,000 characters. |
| [`cbc_unknown_field`](#cbc_unknown_field) | A field in a Carbon Black Cloud query is one or two letters away from a Carbon Black process search field, and is not that field. |
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
| [`config_check_failed`](#config_check_failed) | opentide could not check this configuration file in the editor; the message says why. Its other findings are missing. |
| [`config_enum_unknown`](#config_enum_unknown) | A value is not one of those your deployment configuration declares. |
| [`config_parse`](#config_parse) | A configuration file could not be read as TOML. |
| [`configuration`](#configuration) | The workspace configuration files under `.opentide/configurations/` load. |
| [`cql_assignment_as`](#cql_assignment_as) | A CQL assignment names the output field and the function's as= parameter names it again. |
| [`cql_correlate_aggregate`](#cql_correlate_aggregate) | A Next-Gen SIEM correlation rule combines correlate() with another aggregate function, which CrowdStrike does not allow. |
| [`cql_correlate_placement`](#cql_correlate_placement) | CQL correlate() stands where its reference forbids: after an aggregate or a source function, inside another function's arguments, or with an aggregate in its queries. |
| [`cql_deprecated_function`](#cql_deprecated_function) | CrowdStrike's reference marks the CQL function deprecated. |
| [`cql_duplicate_parameter`](#cql_duplicate_parameter) | A CQL function parameter is given more than once. |
| [`cql_event_function_after_aggregate`](#cql_event_function_after_aggregate) | A CQL eventSize(), eventInternals() or eventFieldCount() call comes after the first aggregate function, which LogScale refuses since 1.190. |
| [`cql_free_text_after_aggregate`](#cql_free_text_after_aggregate) | A CQL free-text filter comes after the first aggregate function, which LogScale refuses since 1.190. |
| [`cql_link_outside_correlate`](#cql_link_outside_correlate) | The CQL link operator &lt;=> appears outside the queries of correlate(), the only place it links fields. |
| [`cql_match_guard`](#cql_match_guard) | A CQL match guard is an aggregate function; a guard must be a filter. |
| [`cql_missing_parameter`](#cql_missing_parameter) | A CQL function call leaves out a required parameter. |
| [`cql_parameter_value`](#cql_parameter_value) | A literal CQL argument is not one of the parameter's allowed values, or is outside its bounds. |
| [`cql_parse_error`](#cql_parse_error) | The CrowdStrike Query Language (CQL) query does not parse. |
| [`cql_regex_flag`](#cql_regex_flag) | A CQL regex literal has a flag other than d, g, i, m or F. |
| [`cql_regex_group_under_or`](#cql_regex_group_under_or) | A CQL regex with named groups is an operand of or, where LogScale extracts none of its fields. |
| [`cql_removed_function`](#cql_removed_function) | The CQL function was removed from LogScale and Next-Gen SIEM no longer runs it. |
| [`cql_string_escape`](#cql_string_escape) | A CQL string has an escape LogScale does not translate; it keeps the backslash and the character. |
| [`cql_unknown_event`](#cql_unknown_event) | The #event_simpleName value is not a Falcon sensor event the engine knows. |
| [`cql_unknown_function`](#cql_unknown_function) | No CQL function has this name; function names are matched without regard to case. |
| [`cql_unknown_parameter`](#cql_unknown_parameter) | The CQL function has no parameter with this name. |
| [`cql_unnamed_argument`](#cql_unnamed_argument) | A CQL function gets an argument without a name that it cannot take: a second one, or one when every parameter needs its name. |
| [`credentials`](#credentials) | Per configured tenant, whether every `$VARIABLE` its setup names is set. |
| [`crowdstrike_unsupported`](#crowdstrike_unsupported) | Retired in engine 0.12.0; CrowdStrike queries are now checked as CQL: see the `cql_*` codes. |
| [`cve_lookup_unavailable`](#cve_lookup_unavailable) | A threat lists CVE identifiers, but Vulnerability-Lookup could not be reached to check them. |
| [`defender_output_columns`](#defender_output_columns) | A Defender custom detection must return the columns Defender requires. |
| [`deployment_state_platform`](#deployment_state_platform) | A deployment state shard names a platform that stores no external ids. |
| [`deployment_state_shape`](#deployment_state_shape) | A deployment state shard is not the JSON shape opentide writes. |
| [`deployment_state_uuid_mismatch`](#deployment_state_uuid_mismatch) | A deployment state shard's file name and contents name different rules. |
| [`deprecated_field`](#deprecated_field) | An object uses a field its schema marks as deprecated. |
| [`doctor_checks_failed`](#doctor_checks_failed) | At least one `opentide doctor` check failed. |
| [`duplicate_id`](#duplicate_id) | Two object files carry the same UUID. |
| [`duplicate_name`](#duplicate_name) | Two `sharing.toml` blocks share a name. |
| [`ecs_type_mismatch`](#ecs_type_mismatch) | The operation cannot apply to the field's type, from ECS or from the columns visibility.toml declares for the index. |
| [`ecs_unknown_field`](#ecs_unknown_field) | The field is not in the Elastic Common Schema, on indices that use it, nor declared for the index in visibility.toml; ECS allows custom fields. |
| [`elastic_dataset_not_declared`](#elastic_dataset_not_declared) | The index pattern is not one the workspace declares in visibility.toml. |
| [`engine_unavailable`](#engine_unavailable) | The analysis engine (the Rust module compiled into opentide) does not load, so the command cannot check queries or serve the language server. |
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
| [`exabeam_advanced_in_rule`](#exabeam_advanced_in_rule) | A correlation rule sequence query uses Exabeam's advanced operators (SELECT, WHERE, pipes and the rest), which are Search only. |
| [`exabeam_bare_wildcard`](#exabeam_bare_wildcard) | A * alone is not an Exabeam query term. |
| [`exabeam_clause_order`](#exabeam_clause_order) | Exabeam clauses are out of order, or one appears twice in a statement: SELECT, FROM, WHERE, AS, GROUP-BY, ORDER-BY, LIMIT. |
| [`exabeam_context_table_limit`](#exabeam_context_table_limit) | An Exabeam query has more than two context table lookups. |
| [`exabeam_context_table_or`](#exabeam_context_table_or) | An Exabeam context table lookup is under OR; lookups combine with AND or AND NOT only. |
| [`exabeam_context_table_trigger`](#exabeam_context_table_trigger) | An Exabeam sequence whose query looks up a context table has a threshold; Exabeam requires trigger on first match. |
| [`exabeam_correlation`](#exabeam_correlation) | An Exabeam block has two or more sequences without correlation, one sequence with it, or a correlation that is not within and group_by. |
| [`exabeam_correlation_window`](#exabeam_correlation_window) | An Exabeam correlation window is shorter than the longest sequence threshold window. |
| [`exabeam_duration`](#exabeam_duration) | An Exabeam duration is not a whole number and a unit its field allows, or delay is outside 7 to 180 minutes. |
| [`exabeam_email`](#exabeam_email) | An Exabeam email does not have a non-empty list of distinct addresses, or its subject is blank. |
| [`exabeam_foreach_clause`](#exabeam_foreach_clause) | An Exabeam FOREACH sub-query has GROUP-BY or ORDER-BY. |
| [`exabeam_foreach_position`](#exabeam_foreach_position) | An Exabeam FOREACH is the first statement; it runs on the result of a preceding query. |
| [`exabeam_foreach_reference`](#exabeam_foreach_reference) | An Exabeam @field reference is outside a FOREACH sub-query. |
| [`exabeam_free_text_special`](#exabeam_free_text_special) | Unquoted Exabeam free text holds a character other than letters, digits, _, * and ?; put it in double quotes. |
| [`exabeam_function_arity`](#exabeam_function_arity) | An Exabeam function gets the wrong arguments: a filter function takes one string, an aggregation one field (* for COUNT only), RGX_EXTRACT an optional field and a pattern. |
| [`exabeam_group_by`](#exabeam_group_by) | An Exabeam group_by is not a list of one to three distinct non-blank fields (correlation.group_by may be empty). |
| [`exabeam_group_by_column`](#exabeam_group_by_column) | An Exabeam selected column is neither in GROUP-BY nor aggregated. |
| [`exabeam_group_by_select_star`](#exabeam_group_by_select_star) | An Exabeam GROUP-BY is combined with SELECT *. |
| [`exabeam_implicit_and`](#exabeam_implicit_and) | Two Exabeam terms, not both free text, stand side by side and are read as AND; write AND. |
| [`exabeam_implicit_operator`](#exabeam_implicit_operator) | An Exabeam NOT stands between two terms with no AND or OR before it, which Exabeam calls invalid; write AND NOT or OR NOT. |
| [`exabeam_ipv6_range`](#exabeam_ipv6_range) | An Exabeam range or CIDR block holds an IPv6 address; Exabeam ranges are IPv4 only. |
| [`exabeam_keyword_case`](#exabeam_keyword_case) | An Exabeam clause keyword, aggregation or RGX_EXTRACT is in mixed case; write it all upper or all lower case. |
| [`exabeam_leading_slash`](#exabeam_leading_slash) | An Exabeam query cannot start with /. |
| [`exabeam_legacy_regex`](#exabeam_legacy_regex) | An Exabeam value between slashes may be read as a regular expression; write RGX("...") for a pattern, or drop the slashes for a path. |
| [`exabeam_mixed_boolean`](#exabeam_mixed_boolean) | Exabeam AND and OR are mixed at one level without parentheses; Exabeam does not document their precedence. |
| [`exabeam_name_duplicate`](#exabeam_name_duplicate) | Two enabled Exabeam blocks of the workspace resolve to the same rule name, compared without regard to case. |
| [`exabeam_name_length`](#exabeam_name_length) | The Exabeam rule name is longer than 128 characters. |
| [`exabeam_not_equal`](#exabeam_not_equal) | Exabeam filters have no != operator; write NOT field:value. |
| [`exabeam_outcome`](#exabeam_outcome) | An Exabeam outcome is not alert, case or none. |
| [`exabeam_outcome_silent`](#exabeam_outcome_silent) | An Exabeam rule's outcome is none and it sends no email, so it only writes a rule-trigger event. |
| [`exabeam_parse_error`](#exabeam_parse_error) | The Exabeam query does not parse: an unterminated string, an unbalanced bracket, a missing operand, an empty sequence query, or a comparison with a non-number. |
| [`exabeam_pipe_limit`](#exabeam_pipe_limit) | An Exabeam query has more than five pipes. |
| [`exabeam_pipe_misuse`](#exabeam_pipe_misuse) | An Exabeam statement after a pipe follows no SELECT or uses none of its columns; write one query with AND or WHERE. |
| [`exabeam_range`](#exabeam_range) | The Exabeam range or CIDR block is invalid: a bound that is not a number, IPv4 address, datetime or *, mixed kinds, low above high, two open bounds, mismatched brackets, or a bad network. |
| [`exabeam_regex`](#exabeam_regex) | The Exabeam regular expression is not valid RE2: a syntax error, a back-reference, look-around, an atomic group or a possessive quantifier. |
| [`exabeam_reserved_alias`](#exabeam_reserved_alias) | An Exabeam AS name is one of the Search guide's reserved words. |
| [`exabeam_rgx_extract_limit`](#exabeam_rgx_extract_limit) | An Exabeam query has more than three RGX_EXTRACT calls. |
| [`exabeam_schedule`](#exabeam_schedule) | An Exabeam schedule recurrence has an unknown every, a from or to that is not HH:MMZ, or day keys its every does not take. |
| [`exabeam_sequences`](#exabeam_sequences) | An Exabeam block's sequences is not a non-empty list of sequences, each with a non-blank query. |
| [`exabeam_severity`](#exabeam_severity) | An Exabeam severity is not none, low, medium, high or critical. |
| [`exabeam_single_group`](#exabeam_single_group) | Parentheses hold a single Exabeam expression, which the Search guide calls an error; drop them. |
| [`exabeam_string_field_number`](#exabeam_string_field_number) | An unquoted number is matched against a field the Exabeam Common Information Model types as a string; Exabeam requires the number in double quotes. |
| [`exabeam_threshold_function`](#exabeam_threshold_function) | An Exabeam threshold function is not count, unique_count, value, max, min, sum or average, or its field is blank or missing. |
| [`exabeam_threshold_operator`](#exabeam_threshold_operator) | An Exabeam threshold operator is not allowed with its function: more_than or less_than, in or not_in for value. |
| [`exabeam_threshold_value`](#exabeam_threshold_value) | An Exabeam threshold value does not have the shape its operator takes, or count and unique_count compare with a non-integer. |
| [`exabeam_time_exact`](#exabeam_time_exact) | An Exabeam time field (time, approxLogTime, ingest_time, raw_log_time) is matched with an exact value; Search matches time with a range only. |
| [`exabeam_unknown_field`](#exabeam_unknown_field) | The field is not in Exabeam's Common Information Model, a platform field, a c_ or m_ field, or an AS name defined earlier in the query; a tenant's parsers may still define it. |
| [`exabeam_unknown_function`](#exabeam_unknown_function) | The call is not an Exabeam function: RGX, RGXi, WLD and WLDi in a filter, an aggregation or RGX_EXTRACT in SELECT. |
| [`exabeam_unknown_value`](#exabeam_unknown_value) | An Exabeam activity_type, subject or outcome value is not one the Common Information Model lists; a tenant's parsers may still emit it. |
| [`exabeam_unquoted_value`](#exabeam_unquoted_value) | An Exabeam field value is a bare word that is not a number, boolean, null, IP address or @field; Exabeam documents string values in double quotes. |
| [`exabeam_wildcard_in_phrase`](#exabeam_wildcard_in_phrase) | A quoted Exabeam value with a space holds * or ?, which Exabeam does not expand inside a phrase. |
| [`external_id_in_rule`](#external_id_in_rule) | A rule still carries a vendor rule id key, which belongs in deployment state. |
| [`external_id_shape`](#external_id_shape) | A vendor rule id in deployment state has the wrong form. |
| [`falco_append_condition`](#falco_append_condition) | A tuning's condition is appended to the tuned rule's condition and must start with `and` or `or`; a new rule's condition must not. |
| [`falco_deprecated_field`](#falco_deprecated_field) | A field Falco deprecates (`evt.dir`, `evt.latency`): it no longer carries the value it used to. |
| [`falco_exception`](#falco_exception) | A rule exception Falco refuses: comparison operators, field and value counts, or a value the field's type cannot hold. |
| [`falco_field_argument`](#falco_field_argument) | A known Falco field is used with an argument it refuses, or without one it requires (libsinsp's field rules: `proc.aname[N]` takes an index, `evt.arg.NAME` an event argument). |
| [`falco_field_as_value`](#falco_field_as_value) | A constant value that is a field name: compare with `val(field)` to read the field. |
| [`falco_invalid_regex`](#falco_invalid_regex) | The `regex` pattern does not compile. |
| [`falco_misplaced_list`](#falco_misplaced_list) | A list is used where its expansion breaks the condition: as a macro, or as a single value; a list belongs inside a value list, `in (name)`. |
| [`falco_newer_syntax`](#falco_newer_syntax) | Syntax that only recent libsinsp releases parse (operator modifiers, `join`, `concat`, `getopt`, transformer arguments); an older Falco or Sysdig agent refuses the rule. |
| [`falco_no_evttype`](#falco_no_evttype) | The rule cannot be narrowed to a few event types (`evt.type`), so it runs on every event; Falco and Sysdig warn about the performance penalty. |
| [`falco_operator_type`](#falco_operator_type) | The operator does not apply to the field's type (libsinsp `flt_is_comparable`); Falco refuses to load the rule. |
| [`falco_output_syntax`](#falco_output_syntax) | The output template does not format: a `%` at the end, a length with no field, or a token that is no field or transformer. |
| [`falco_parse_error`](#falco_parse_error) | The Falco condition does not parse. |
| [`falco_regex_simple`](#falco_regex_simple) | A `regex` check a plain operator (`=`, `contains`, `startswith`, `endswith`) could make, which libsinsp warns about: regex is the slowest check. |
| [`falco_rhs_field`](#falco_rhs_field) | A field cannot be compared with another field here (`val(...)` or a transformer on the right): not with `pmatch` or `regex`, not on networks, not on fields that refuse it, and only between fields of the same type. |
| [`falco_transformer`](#falco_transformer) | A field transformer cannot apply here: the field's type, a field that refuses transformers, or the arguments of `join`, `concat`, or `getopt`. |
| [`falco_transformer_as_value`](#falco_transformer_as_value) | A constant value that looks like a transformer call, compared as text. |
| [`falco_unknown_event`](#falco_unknown_event) | The event type is not in the driver's event table nor a syscall name; libsinsp refuses it. |
| [`falco_unknown_field`](#falco_unknown_field) | The field is not one Falco or its plugins define for the rule's event source; a plugin the engine does not know may add it. |
| [`falco_unknown_list`](#falco_unknown_list) | The name after a list operator, without parentheses, is not a list of the block or of the Falco default rules, so it is compared as a single value. |
| [`falco_unknown_macro`](#falco_unknown_macro) | The name is not a macro of the block or of the Falco default rules; the tenant may define it, as Sysdig does for its managed macros. |
| [`falco_unknown_rule`](#falco_unknown_rule) | A tuning (`append_to_rule`) names a rule the Falco default rules do not define: Falco refuses the append, and on Sysdig the tenant must have that rule. |
| [`falco_unknown_source`](#falco_unknown_source) | The event source is not one Falco or its published plugins define, so its fields are not checked. |
| [`falco_unsafe_na_check`](#falco_unsafe_na_check) | A `ka.` or `jevt.` field compared with `<NA>`, which Falco warns about: the field may hold that text. |
| [`falco_value_type`](#falco_value_type) | The value cannot be parsed as the field's type (a number, `true` or `false`, an IP address or network, a hex string for `bcontains`); Falco refuses to load the rule. |
| [`filename_mismatch`](#filename_mismatch) | An object file's name is not the stem `lint.toml` `[filenames].style` (or its kind's `[filenames.<kind>].style`) asks for: `slugify(name)` by default. |
| [`filename_pattern`](#filename_pattern) | An object file's name does not match the regular expression `lint.toml` sets for it. |
| [`filename_slug`](#filename_slug) | Retired in opentide 0.24.0; `opentide lint` reports a file name that is not the object's as `filename_mismatch`. |
| [`git`](#git) | git is on `PATH`. |
| [`git_repository`](#git_repository) | The workspace is in a git repository, and its default branch (`origin/HEAD`). |
| [`google_secops_compile_error`](#google_secops_compile_error) | Google SecOps's compiler refuses a rule in a live query check. |
| [`google_secops_compile_warning`](#google_secops_compile_warning) | Google SecOps's compiler accepts a rule with a warning in a live query check. |
| [`google_secops_create_no_id`](#google_secops_create_no_id) | A Google SecOps create answered without a rule id. |
| [`google_secops_create_unconfirmed`](#google_secops_create_unconfirmed) | A Google SecOps create got no answer or a server error, so the rule may exist without a binding. |
| [`google_secops_credentials_missing`](#google_secops_credentials_missing) | opentide has no usable Google credentials for a Google SecOps tenant. |
| [`google_secops_delete_refused`](#google_secops_delete_refused) | Google SecOps refused to delete a rule, so deploy archived it. |
| [`google_secops_deployment_failed`](#google_secops_deployment_failed) | A Google SecOps rule exists, but its run state could not be set. |
| [`google_secops_live_frequency_unavailable`](#google_secops_live_frequency_unavailable) | A Google SecOps rule with two or more event variables asks for `run_frequency: LIVE`. |
| [`google_secops_meta_key`](#google_secops_meta_key) | A Google SecOps block's `meta` holds a key deploy cannot write. |
| [`google_secops_name_duplicate`](#google_secops_name_duplicate) | Two enabled Google SecOps blocks resolve to one YARA-L rule name. |
| [`google_secops_request_failed`](#google_secops_request_failed) | A Chronicle API request for one Google SecOps rule failed. |
| [`google_secops_risk_score_missing`](#google_secops_risk_score_missing) | A Google SecOps rule's `outcome` assigns no `$risk_score`. |
| [`google_secops_rule_compilation_failed`](#google_secops_rule_compilation_failed) | Google reports that a deployed Google SecOps rule no longer compiles. |
| [`google_secops_rule_conflict`](#google_secops_rule_conflict) | A Google SecOps rule changed between deploy's read and its update. |
| [`google_secops_rule_execution_limited`](#google_secops_rule_execution_limited) | Google reports that it limits or pauses a Google SecOps rule's runs. |
| [`google_secops_rule_id_literal`](#google_secops_rule_id_literal) | A Google SecOps rule matches a producer rule by a literal `ru_…` id. |
| [`google_secops_rule_missing`](#google_secops_rule_missing) | The Google SecOps rule a binding names no longer exists, and the rule is being retired. |
| [`google_secops_rule_name`](#google_secops_rule_name) | A Google SecOps block's `name` is not a YARA-L rule name. |
| [`google_secops_rule_recreated`](#google_secops_rule_recreated) | The Google SecOps rule a binding names no longer exists, so deploy created it again. |
| [`google_secops_run_frequency`](#google_secops_run_frequency) | A Google SecOps block's `run_frequency` is not one opentide deploys. |
| [`google_secops_run_frequency_not_allowed`](#google_secops_run_frequency_not_allowed) | A Google SecOps block's `run_frequency` is not one Google allows for the rule. |
| [`google_secops_schedule`](#google_secops_schedule) | A Google SecOps block's `schedule` cannot be sent with its run frequency, or holds a duration that is not one. |
| [`google_secops_severity`](#google_secops_severity) | A Google SecOps block's `severity` or `priority` is not one of Google's values. |
| [`google_secops_tenant_unauthorized`](#google_secops_tenant_unauthorized) | A Google SecOps instance refused opentide's credentials. |
| [`google_secops_tenant_unreachable`](#google_secops_tenant_unreachable) | A Google SecOps instance did not answer, so no rule was deployed to it. |
| [`google_secops_verify_failed`](#google_secops_verify_failed) | Google SecOps does not compile a rule, so deploy neither creates nor updates it. |
| [`graylog_aggregation`](#graylog_aggregation) | A Graylog `aggregation.condition` is missing, does not parse under the condition grammar, or calls a function with the wrong arguments. |
| [`graylog_analyzed_field`](#graylog_analyzed_field) | A regex, wildcard, or range applies to Graylog's analysed `message` or `full_message` field, so it matches single lower-cased tokens, never the whole value. |
| [`graylog_double_backslash`](#graylog_double_backslash) | A Graylog query holds four backslashes in a row: `\\` is already one literal backslash, so `\\\\` matches two. |
| [`graylog_event_field`](#graylog_event_field) | A Graylog event field name is not `[A-Za-z0-9_.@-]+`, or its value is not a field name, a `${…}` template, `{template}`, or `{lookup}`. |
| [`graylog_event_key`](#graylog_event_key) | A Graylog `event_key` item is not an `event_fields` name. |
| [`graylog_event_limit`](#graylog_event_limit) | A Graylog `event_limit` is not an integer from 1 to 1,000, or is set on an aggregation. |
| [`graylog_field_name`](#graylog_field_name) | A Graylog `aggregation.group_by` item is not a field name (`[A-Za-z0-9_.@-]+`). |
| [`graylog_leading_wildcard`](#graylog_leading_wildcard) | A Graylog query term starts with `*` or `?`: Graylog refuses leading wildcards unless the server allows them; a regex with a leading `.*` is the portable form. |
| [`graylog_list_shape`](#graylog_list_shape) | A Graylog list field is not one string or a list of distinct non-blank strings. |
| [`graylog_open_range`](#graylog_open_range) | A Graylog range has `*` as a bound (`[1 TO *]`, `{* TO 5}`). Graylog's query validator refuses it, so deploy cannot save the definition: write `field:>=1` or `field:<5`. |
| [`graylog_overlapping_window`](#graylog_overlapping_window) | A Graylog filter searches a `window` longer than it runs `every`, so each message alerts once per overlapping run. |
| [`graylog_priority`](#graylog_priority) | A Graylog `priority` is not `Informational`, `Low`, `Medium`, `High`, or `Critical`. |
| [`graylog_query_blank`](#graylog_query_blank) | A Graylog block's `query` is missing or blank. |
| [`graylog_regex_operator`](#graylog_regex_operator) | A Graylog regex holds an unescaped `#`, `&`, `@`, `~`, `<`, or `>`, which Lucene reads as a regex operator, not the character. |
| [`graylog_regex_quote`](#graylog_regex_quote) | A Graylog regex holds an unescaped `"`, which Lucene reads as a quoted literal, not the character: escape it as `\"`. |
| [`graylog_regex_unsupported`](#graylog_regex_unsupported) | A Graylog regex uses an inline flag, a `(?…)` group, `\b`, `\B`, a lookaround, or a backreference, which Lucene's regex engine does not have: Graylog matches nothing or rejects the query. |
| [`graylog_schedule`](#graylog_schedule) | A Graylog `schedule` sets both `every` and `cron`, a duration that is not greater than zero, a cron that is not a 6- or 7-field Quartz expression, an unknown time zone, or `cron` without `window`. |
| [`harfanglab_rule_kind`](#harfanglab_rule_kind) | A HarfangLab block sets both sigma and yara; a block is one kind. |
| [`harfanglab_yara_context`](#harfanglab_yara_context) | A HarfangLab YARA rule's meta `context` is not a comma-joined list of the scan contexts HarfangLab uses. |
| [`harfanglab_yara_form`](#harfanglab_yara_form) | A HarfangLab yara object sets signature together with decomposed keys (meta, strings, condition or imports). |
| [`harfanglab_yara_import`](#harfanglab_yara_import) | A decomposed HarfangLab YARA imports entry is not a module the YARA language knows. |
| [`harfanglab_yara_rule_name`](#harfanglab_yara_rule_name) | The YARA rule name deploy derives from the rule name is a YARA keyword or keeps a character other than an ASCII letter, digit or underscore. |
| [`harfanglab_yara_section_header`](#harfanglab_yara_section_header) | A decomposed HarfangLab YARA fragment contains a strings:, condition: or rule header, which deploy writes itself. |
| [`internal`](#internal) | opentide stopped on an exception it did not handle: a bug in opentide, not in your input. |
| [`interrupted`](#interrupted) | The command was stopped before it finished: an `opentide serve` client cancelled the run. |
| [`invalid_cve`](#invalid_cve) | A threat lists CVE identifiers Vulnerability-Lookup does not know. |
| [`invalid_ref`](#invalid_ref) | A reference names an object that does not exist. |
| [`invalid_uuid`](#invalid_uuid) | An object's `metadata.uuid` is not a UUID v4. |
| [`invalid_value`](#invalid_value) | A `sharing.toml` value has the wrong type. |
| [`issues_found`](#issues_found) | The command ran and failed on what it found. |
| [`kql_control_command_unsupported`](#kql_control_command_unsupported) | A KQL control command (.show, .create, ...) is not a detection query; rules cannot run it. |
| [`kql_deprecated_function`](#kql_deprecated_function) | The KQL function is a deprecated alias; Microsoft Learn names its replacement. |
| [`kql_deprecated_operator`](#kql_deprecated_operator) | The KQL scalar operator is a legacy spelling (containscs); use the current name (contains_cs). |
| [`kql_join_summarize_before_project`](#kql_join_summarize_before_project) | join or summarize runs before project, so it carries every column. |
| [`kql_parse_error`](#kql_parse_error) | The KQL query does not parse. |
| [`kql_render_not_valid`](#kql_render_not_valid) | render draws a chart; it has no effect in a detection rule. |
| [`kql_table_not_declared`](#kql_table_not_declared) | The table is one the engine knows for the platform, but no log source of the workspace declares it in visibility.toml. |
| [`kql_type_mismatch`](#kql_type_mismatch) | The operator cannot apply to the column's documented or declared type. |
| [`kql_unknown_column`](#kql_unknown_column) | The column is not in the documented schema of the table or ASIM parser it comes from, or in the columns visibility.toml declares for the table. |
| [`kql_unknown_function`](#kql_unknown_function) | The KQL function is not in the Kusto function catalog. |
| [`kql_unknown_operator`](#kql_unknown_operator) | The KQL tabular operator is not one Kusto knows. |
| [`kql_unknown_table`](#kql_unknown_table) | The table is neither one the engine knows for the platform nor one the workspace declares in visibility.toml: a warning under Sentinel, whose workspaces hold tables no catalog lists; an error under Defender's advanced hunting schema. Declaring it in visibility.toml makes it known. |
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
| [`missing_author`](#missing_author) | Retired in opentide 0.24.0; `opentide lint` reports a missing recommended metadata field as `metadata_recommended`. |
| [`missing_field`](#missing_field) | A configuration file is missing a required key, once it is merged with the bundled file and the parent instance. |
| [`missing_organisation`](#missing_organisation) | Retired in opentide 0.24.0; `opentide lint` reports a missing recommended metadata field as `metadata_recommended`. |
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
| [`query_check_timeout`](#query_check_timeout) | `validate query --live` failed because a tenant did not answer a query's check within the check timeout. |
| [`recommended_field_missing`](#recommended_field_missing) | A field the templates ask for is missing; `opentide validate` accepts the object without it. |
| [`reference_not_found`](#reference_not_found) | `--objective` or `--threat` names a UUID that no object in the catalogue carries. |
| [`retired_configuration_file`](#retired_configuration_file) | A file or folder under `.opentide/configurations/` that opentide does not read. |
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
| [`spl_command_without_pipe`](#spl_command_without_pipe) | The query starts with a command name but no |, so Splunk searches for the word instead of running the command. |
| [`spl_dataset_not_declared`](#spl_dataset_not_declared) | The sourcetype is not one the workspace declares in visibility.toml. |
| [`spl_empty_command`](#spl_empty_command) | A command with no arguments: Splunk runs it, but it does nothing, returns no results, or fails at run time. |
| [`spl_empty_stage`](#spl_empty_stage) | A trailing | with no command; Splunk ignores it. |
| [`spl_leading_not`](#spl_leading_not) | A base search that starts with NOT scans every event before excluding any. |
| [`spl_parse_error`](#spl_parse_error) | The SPL search does not parse. |
| [`spl_search_operator`](#spl_search_operator) | A search clause compares with an operator search does not have (`==`, `<>`, `=>`, `=<`, `!~`): Splunk accepts it but the comparison never matches, or `=~`, which compares with a value that starts with `~`. |
| [`spl_subsearch_truncation`](#spl_subsearch_truncation) | A subsearch is silently truncated at its result or time limit. |
| [`spl_unknown_command`](#spl_unknown_command) | The SPL command is not in the Splunk Search Reference or a catalogued app such as MLTK: a warning, since an app on the search head can add commands, or an error when the name is one edit from a known command. |
| [`spl_unknown_datamodel`](#spl_unknown_datamodel) | The CIM data model or dataset is not one Splunk CIM defines. |
| [`spl_unknown_datamodel_field`](#spl_unknown_datamodel_field) | The field is not in the CIM data model the search reads. |
| [`spl_wildcard`](#spl_wildcard) | A leading or mid-token wildcard in a base search that nothing else narrows (no index, sourcetype, source, host, TERM() or macro) cannot use the index and scans every event. |
| [`sysdig_definition_duplicate`](#sysdig_definition_duplicate) | A name is defined more than once across the block's macros and lists. |
| [`sysdig_definition_name`](#sysdig_definition_name) | A block macro or list name is not `[A-Za-z_][A-Za-z0-9_]*`, or is a Falco operator or keyword. |
| [`sysdig_definition_order`](#sysdig_definition_order) | A block macro uses itself or a macro defined after it: Falco gives a macro no view of itself or later macros, and refuses it as an undefined macro. |
| [`sysdig_exception_shape`](#sysdig_exception_shape) | An exception's fields, comps, and values do not have a shape Falco's rule loader accepts (`validate_exception_info`). |
| [`sysdig_list_in_value`](#sysdig_list_in_value) | A block list name appears in an exception value where Falco's expansion would not produce a value list. |
| [`sysdig_list_self_reference`](#sysdig_list_self_reference) | A block list names itself as one of its items, so its own name stays in the expanded condition. |
| [`sysdig_priority`](#sysdig_priority) | `priority` is not one of Falco's eight priorities (or `INFO`), compared case-insensitively. |
| [`sysdig_rule_shape`](#sysdig_rule_shape) | A Sysdig block is a new rule with a non-blank `condition`, or a tuning (`append_to_rule`) that appends a condition, exceptions, or both. |
| [`sysdig_source`](#sysdig_source) | `source` is not an event source name (`[a-z][a-z0-9_]*`). |
| [`sysdig_tuning_keys`](#sysdig_tuning_keys) | A tuning (`append_to_rule`) inherits `output`, `priority`, `policies`, `source`, and `name` from the rule it tunes, so it must not set them. |
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
| [`vscode_settings`](#vscode_settings) | The workspace recommends the opentide VS Code extension (`opentidehq.opentide`) in `.vscode/extensions.json`, and `.vscode/settings.json` maps no object files to opentide's JSON schemas in `yaml.schemas`. |
| [`vscode_snippets`](#vscode_snippets) | The editor snippet file `opentide generate snippets` writes exists. |
| [`workspace`](#workspace) | Where the workspace is, and how it was found. |
| [`workspace_not_found`](#workspace_not_found) | `opentide new` ran outside a workspace: neither `.opentide/` nor `objects/` is there. Or the MCP server was started in an Agent Plugin's directory, which is not a workspace, and nothing named one. |
| [`yaml_parse`](#yaml_parse) | An object file is not valid YAML, or not one mapping, so it could not be loaded. |
| [`yara_duplicate_rule`](#yara_duplicate_rule) | Two YARA rules in one signature have the same name. |
| [`yara_duplicate_string`](#yara_duplicate_string) | Two strings of one YARA rule have the same identifier. |
| [`yara_duplicate_tag`](#yara_duplicate_tag) | A YARA rule repeats a tag. |
| [`yara_empty_signature`](#yara_empty_signature) | The YARA signature has no rule, or only private or global rules. |
| [`yara_entrypoint_deprecated`](#yara_entrypoint_deprecated) | entrypoint is deprecated in libyara and refused by YARA-X; use pe.entry_point or elf.entry_point. |
| [`yara_hex_string`](#yara_hex_string) | A YARA hex string is invalid: an odd number of nibbles, a bad jump, or unbalanced alternatives. |
| [`yara_include`](#yara_include) | A YARA signature uses an include directive, which no platform resolves: each API takes one text with no file system behind it. |
| [`yara_meta_missing`](#yara_meta_missing) | A HarfangLab YARA rule has no meta `context`, which the HarfangLab profile recommends on every rule that is not private. |
| [`yara_module_not_imported`](#yara_module_not_imported) | A YARA module field or function is used without importing its module. |
| [`yara_module_unconfirmed`](#yara_module_unconfirmed) | The YARA module is known but not confirmed on the platform's agents. |
| [`yara_number_out_of_range`](#yara_number_out_of_range) | A YARA integer, size suffix, jump bound or string index is outside the range libyara accepts. |
| [`yara_parse_error`](#yara_parse_error) | The YARA signature does not parse as libyara 4.5 reads it. |
| [`yara_regexp`](#yara_regexp) | A YARA regular expression is invalid. |
| [`yara_rule_identifier_conflict`](#yara_rule_identifier_conflict) | A YARA rule is named like a keyword, or matches a rule wildcard an earlier condition uses; a rule named like an imported module is yara_x_incompatible. |
| [`yara_signature_alias`](#yara_signature_alias) | A `yara.signature` is a YAML alias of text anchored elsewhere in the file instead of YARA written in the block. |
| [`yara_slow_pattern`](#yara_slow_pattern) | libyara warns that this YARA string or loop may slow scanning down. |
| [`yara_string_modifier`](#yara_string_modifier) | libyara refuses this combination of YARA string modifiers, or an xor or base64 argument is out of range. |
| [`yara_suspicious_expression`](#yara_suspicious_expression) | A YARA condition is invariant, unsatisfiable or not boolean, or compares an integer with a boolean. |
| [`yara_type`](#yara_type) | A YARA operator or function is applied to a value of the wrong type. |
| [`yara_undefined_identifier`](#yara_undefined_identifier) | A YARA identifier is neither a rule defined earlier in the signature nor an imported module, or is used as libyara refuses: a module field called as a function, a module function named without a call, or a loop variable a loop already binds. |
| [`yara_undefined_string`](#yara_undefined_string) | A YARA condition names a string ($id, #id, @id, !id or $prefix*) that the rule does not define. |
| [`yara_unknown_module`](#yara_unknown_module) | A YARA import names a module libyara does not ship. |
| [`yara_unknown_module_member`](#yara_unknown_module_member) | The YARA module has no such field or function, or the function takes other arguments. |
| [`yara_unreferenced_string`](#yara_unreferenced_string) | A YARA string is never used in the condition, which libyara refuses unless the condition uses them. |
| [`yara_x_incompatible`](#yara_x_incompatible) | libyara 4.5 compiles this YARA but YARA-X 1.x refuses it. |
| [`yaral_condition_shape`](#yaral_condition_shape) | The condition is not one Google compiles: `not` or a comma on event terms, `or` across too many event variables or in an unbounded condition, or non-existence without a window and a bounded event. |
| [`yaral_deprecated_field`](#yaral_deprecated_field) | The UDM field is deprecated. |
| [`yaral_enum_value`](#yaral_enum_value) | The value is not one of the enumerated UDM field's values. |
| [`yaral_export_value`](#yaral_export_value) | An `export` `write_row` value is not an outcome variable: Google exports outcome variables only. |
| [`yaral_function_unavailable`](#yaral_function_unavailable) | The function exists, but not in this profile (rules or search). |
| [`yaral_leading_wildcard_regex`](#yaral_leading_wildcard_regex) | The regular expression starts with `.*` without an anchor: RE2 matches anywhere already, and the prefix only costs time. |
| [`yaral_match_shape`](#yaral_match_shape) | The `match` block is not a YaraLMatch: `group_by` and `window`, and `pivot` and `direction` exactly when `type` is `sliding`. |
| [`yaral_match_variable`](#yaral_match_variable) | A `match` name is not a placeholder bound in `events`. |
| [`yaral_match_window`](#yaral_match_window) | The match window is outside its bounds (hop and sliding 1m to 14d in a rule, 1m to 48h in a search; tumbling 1m to 72h) or has a unit other than m, h or d. |
| [`yaral_meta_duplicate`](#yaral_meta_duplicate) | A meta key appears twice, or a meta value is not a double-quoted string. |
| [`yaral_multi_event_match`](#yaral_multi_event_match) | A rule with two or more event variables has no `match` section. |
| [`yaral_nocase_on_enum`](#yaral_nocase_on_enum) | `nocase` is applied to a comparison with an enumerated UDM field. |
| [`yaral_option`](#yaral_option) | An unknown option, or an option value of the wrong kind. |
| [`yaral_outcome_aggregation`](#yaral_outcome_aggregation) | With `match`, an outcome reads an event field, or a placeholder that is not a `match` variable, outside an aggregation; or it aggregates an outcome variable. |
| [`yaral_outcome_limit`](#yaral_outcome_limit) | A rule or search assigns more than 20 outcome variables. |
| [`yaral_parse_error`](#yaral_parse_error) | The YARA-L text does not parse, or a text holds a second rule. |
| [`yaral_reference_list_deprecated`](#yaral_reference_list_deprecated) | Reference lists are deprecated from May 2027 and migrate to data tables by July 2027: use a data table (`%table.column`). |
| [`yaral_reference_list_limit`](#yaral_reference_list_limit) | More `in` statements than the profile allows (rules: 10, 5 with regex, 5 with cidr; search: 7, 4, 2). |
| [`yaral_regex`](#yaral_regex) | The regular expression is not valid RE2. |
| [`yaral_reserved_identifier`](#yaral_reserved_identifier) | A YARA-L keyword is used as a rule name, meta key or variable, or a variable is named `$window_start` or `$window_end`. |
| [`yaral_section_alias`](#yaral_section_alias) | A YARA-L section key is a YAML alias: write the section out in the block, so the block shows what it deploys. |
| [`yaral_section_empty`](#yaral_section_empty) | A YARA-L section key has no text. A plain YAML scalar that starts with `#` is a YAML comment, so it loads as null: write the text as a block scalar (`|`). |
| [`yaral_section_header`](#yaral_section_header) | A `google_secops` section text holds a section label, a `rule` header, or braces around a rule: deploy writes those, so each key holds its section's body only. |
| [`yaral_section_missing`](#yaral_section_missing) | A required YARA-L section is absent: `meta` in a rule file, `events` and `condition` in every rule. |
| [`yaral_section_order`](#yaral_section_order) | A YARA-L section is repeated or out of order (meta, setup, events, match, outcome, condition, options, export). |
| [`yaral_section_unavailable`](#yaral_section_unavailable) | The section is not part of this profile: `dedup`, `order`, `limit`, `select` and `unselect` are search sections; `meta`, `setup` and `options` are rule sections. |
| [`yaral_string_escape`](#yaral_string_escape) | A double-quoted string holds an escape Google does not document (only backslash, double quote, n, r and t); the tenant decides whether it compiles. |
| [`yaral_type`](#yaral_type) | An operator or function is applied to a value of the wrong type: a count compared with a string, `any` or `all` on a map key, `nocase` on a number. |
| [`yaral_undefined_variable`](#yaral_undefined_variable) | A variable in `match`, `outcome` or `condition` is not defined by `events` or `outcome`, or an event variable of `events` is absent from `condition`. |
| [`yaral_unfiltered_event`](#yaral_unfiltered_event) | An event variable has no equality on `metadata.event_type`, `metadata.log_type` or `metadata.product_name`, so the rule scans every event. |
| [`yaral_unknown_function`](#yaral_unknown_function) | The function is not in Google's YARA-L function list, or it takes a different number of arguments. |
| [`yaral_unknown_udm_field`](#yaral_unknown_udm_field) | The field path is not in the Unified Data Model. |
| [`yaral_window_bound`](#yaral_window_bound) | `window_start` or `window_end` is used in `events`, or in a rule or search with no `match` window. |

## analysis_engine

The analysis engine loads: the Rust module compiled into opentide (`opentide._native`) behind the `queries` checks of `opentide validate` and `opentide lint`, `opentide validate query` and `opentide lsp`.

Reported by `opentide doctor`, with the version of the language-server crates compiled in. Fails when the engine does not load (`engine_unavailable`).

### Example

```text illustrative
✗ The opentide analysis engine does not load: cannot import name '_native' from 'opentide' · analysis_engine
  → pip install --force-reinstall opentide
```

### How to fix

Reinstall opentide with the command it prints. The engine is part of the opentide package, in the wheel for each supported platform, so a failed import means a broken or mixed environment, or an install from source that did not compile it: see `opentide explain engine_unavailable`.

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

## bitdefender_action_scope

An automatic action is not allowed for the rule's kind or target.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). `kill_process` is for Basic rules only. `sandbox`, `kill_process` and `quarantine` need a `process` or `file` target or a `*.CreatedBy.*` criterion; a YARA rule takes `sandbox` and `quarantine`.

### Example

```yaml
configurations:
  bitdefender:
    actions:
      kill_process: true
    yara:
      signature: |
        rule A { condition: true }
```

### How to fix

Remove the action, or use one the kind and target allow (`isolate`, `collect_investigation_package`, `antimalware_scan`, `risk_scan` are allowed everywhere).

## bitdefender_actions_unsupported

The block sets `actions`, and the tenant's subscription has no automatic actions.

Severity: warning. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). With `automatic_actions = false` in the tenant setup, deploy omits `automaticActions` and the rule deploys without them.

### Example

```yaml
configurations:
  bitdefender:
    actions:
      isolate: true   # tenant: automatic_actions = false
```

### How to fix

Remove the block's `actions`, or set `automatic_actions = true` once the subscription includes them.

## bitdefender_contains_no_wildcard

A `contains` criterion has neither `*` nor `?`, so GravityZone matches the value as written.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on a `bitdefender` block (bitdefender-1.0). It is an advisory: GravityZone's `contains` relation compares the whole value with `*` and `?` as wildcards, so a value without one is an exact match, and the author most likely meant a substring.

### Example

```yaml
configurations:
  bitdefender:
    detection:
      target: process
      criteria:
        - field: Process.CommandLine
          contains: -enc
```

### How to fix

Add the wildcards you mean (`contains: "*-enc*"`), or use `is` for an exact match.

## bitdefender_create_no_id

A GravityZone create answered something other than a 24-hex rule id.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). Deploy sends `returnRuleId: true` and records the id it gets back. Without one the rule may exist on the tenant with no binding in `.opentide/states/deployment/`.

### Example

```text illustrative
bitdefender_create_no_id: createCustomRule for 'Encoded PowerShell' answered True
```

### How to fix

Find the rule by name in the GravityZone console and record its id in the rule's deployment state shard, or delete it and deploy again.

## bitdefender_create_unconfirmed

A GravityZone create got no answer, and its retry found the name already taken.

Severity: error. Reported by `opentide deploy` on a `bitdefender` tenant. The first `createCustomRule` got no answer (a timeout, a reset or a cut-off response), so deploy sent it once more; the retry got no answer either, or GravityZone refused it because a rule of that name exists. The first create may have succeeded, but its rule id never reached opentide, so nothing was recorded in `.opentide/states/deployment/`. Deploy never lists rules to find the id.

### Example

```text illustrative
bitdefender_create_unconfirmed: the first create of 'Office application spawns encoded PowerShell'
got no answer and the retry found the name taken
```

### How to fix

Find the rule by its name in the GravityZone console (Incidents, Custom rules). Delete it and deploy again, or record its 24-hex id under `platforms.bitdefender.<tenant>` in the rule's `.opentide/states/deployment/<uuid>.json` and commit it.

## bitdefender_criteria_combination

The criteria combine fields or values GravityZone does not allow together.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). EDR-only and XDR-only fields or values are not mixed (`File.CreatedBy.*` with `File.MD5`, `rename` with `downloaded`). `File.Certificate*` needs `File.Name` or `File.FullPathName`. `Connection.Protocol` needs `Connection.Domain`. An XDR detection uses `alert` or an operation criterion, not both.

### Example

```yaml
configurations:
  bitdefender:
    detection:
      target: connection
      criteria:
        - field: Connection.Protocol
          is: smb
```

### How to fix

Add the field the pairing needs (`Connection.Domain`), or split EDR and XDR conditions into two rules.

## bitdefender_criterion_field

A criterion's `field` does not belong to the block's `target`.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). Each target has its own fields in Bitdefender's criteria catalogue: `process` has `Process.*`, `file` has `File.*`, `connection` has `Connection.*` and `registry` has `Registry.*`. A field the catalogue does not list for any other target is a warning. The alert filter (`detection`) is never a criterion, on any target: write it as the block's `alert`.

### Example

```yaml
configurations:
  bitdefender:
    detection:
      target: process
      criteria:
        - field: Process.Hash
          is: 44d88612fea8a8f36de82e1278abb02f
```

### How to fix

Use a field of the target, as the catalogue spells it (`Process.MD5`), or change the target.

## bitdefender_criterion_relation

A criterion uses a relation its field does not take.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). Enum fields (`File.Operation`, `Registry.Operation`, `Registry.DataType`, `Connection.Protocol`, ...) take `is` or `any` only, and `*.MD5` and `*.SHA2` do not take `contains`.

### Example

```yaml
configurations:
  bitdefender:
    detection:
      target: registry
      criteria:
        - field: Registry.Operation
          contains: key_*
```

### How to fix

Use `is` with one value or `any` with several: `any: [key_created, key_renamed]`.

## bitdefender_criterion_shape

A criterion does not have `field` and exactly one of `is`, `contains` and `any`.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). `is` takes a string or an integer, `contains` a string, and `any` a non-empty list of strings or integers.

### Example

```yaml
configurations:
  bitdefender:
    detection:
      target: process
      criteria:
        - field: Process.Name
          is: powershell.exe
          contains: "*shell*"
```

### How to fix

Keep one relation per criterion. Two conditions on one field are two criteria, which must both match.

## bitdefender_criterion_value

A criterion's value is not one its field accepts.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). An enum field takes only its catalogue values (`Registry.Operation`: `key_created`, `key_deleted`, ...), and a port is an integer from 0 to 65535.

### Example

```yaml
configurations:
  bitdefender:
    detection:
      target: connection
      criteria:
        - field: Connection.DestinationPort
          any: [443, 70000]
```

### How to fix

Use a catalogue value, or a port in range written as a number.

## bitdefender_incidents_api_unavailable

The tenant has no Incidents API, so it cannot take custom rules.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). GravityZone answered `-32601` (method not found). On-premises GravityZone has no Incidents API.

### Example

```toml
url = "https://gravityzone.example.internal/api"   # on-premises
```

### How to fix

Use a GravityZone cloud or partner console URL, ending in `/api`.

## bitdefender_kind_changed

An update was refused because the block's kind differs from the GravityZone rule's.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). GravityZone cannot turn a YARA rule into a Basic rule or back, and `updateCustomRule` takes no `subtype`.

### Example

```yaml
configurations:
  bitdefender:
    # deployed as yara, now a detection block
    detection:
      target: process
```

### How to fix

Deploy the rule with a `DELETION` status first, then deploy it again with the new kind.

## bitdefender_name_conflict

GravityZone refused a create because a rule with the same name exists in the company.

Severity: error. Reported by `opentide deploy` on a `bitdefender` tenant. GravityZone names are unique per company, and deploy never adopts a rule it did not create: it has no id for it in `.opentide/states/deployment/`. `opentide validate` reports two opentide rules with one GravityZone name as `bitdefender_name_duplicate`; this code is a rule created outside opentide, or by another workspace.

### Example

```yaml
name: Office application spawns encoded PowerShell   # a console rule has this name
configurations:
  bitdefender:
    status: PRODUCTION
```

### How to fix

Set a distinct `configurations.bitdefender.name`, or delete the other rule in the console. To take over a rule opentide created and lost track of, record its id in the rule's deployment state shard.

## bitdefender_name_duplicate

Two enabled Bitdefender blocks resolve to the same GravityZone rule name.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). The GravityZone name is the block's `name`, else the rule's `name`, normalised and cut at 128 characters. GravityZone refuses a second rule with one name in a company, so the second deploy would fail with `bitdefender_name_conflict`.

### Example

```yaml
# rule-a.yaml and rule-b.yaml, both:
name: Office application spawns encoded PowerShell
configurations:
  bitdefender:
    enabled: true
```

### How to fix

Give one of the blocks its own `configurations.bitdefender.name`, or rename one of the rules.

## bitdefender_registry_full_hive

A `Registry.Key` criterion starts with a full hive name, which GravityZone accepts and never matches.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on a `bitdefender` block (bitdefender-1.0). It is an advisory: the rule validates and deploys, but GravityZone stores registry keys under the short hive names, so `HKEY_LOCAL_MACHINE\…` never triggers.

### Example

```yaml
configurations:
  bitdefender:
    detection:
      target: registry
      criteria:
        - field: Registry.Key
          contains: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run*
```

### How to fix

Write the short hive name, as in `HKLM\Software\Microsoft\Windows\CurrentVersion\Run*`: `HKLM`, `HKCU`, `HKCR` or `HKCC`; `HKU` for a user's hive, `HKEY_USERS\<SID>…`; and `HKLU` for any other `HKEY_USERS\…` key. The hive name is compared case-insensitively.

## bitdefender_request_failed

GravityZone refused a call for this rule with a JSON-RPC error.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). A response with an `error` member is a failure even with HTTP 200; the message carries its code and `error.data.details`. Other rules on the tenant carry on.

### Example

```text illustrative
bitdefender_request_failed: updateCustomRule: error -32602: Invalid params (Invalid value for parameter settings.criteriaList)
```

### How to fix

Read `error.data.details` in the message, fix the block it points at, and deploy again. `opentide validate` catches most refusals before any call.

## bitdefender_rule_kind

A Bitdefender block sets both `detection` and `yara`, or neither.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). A GravityZone custom rule is one kind: a Basic rule (`detection`, a list of criteria) or a YARA rule (`yara`, a signature). An `exclusion` key is unknown: GravityZone exclusion rules are not opentide rules, and deploy never creates, updates or deletes one.

### Example

```yaml
configurations:
  bitdefender:
    status: STAGING
    detection:
      target: process
      criteria:
        - field: Process.Name
          is: mshta.exe
    yara:
      signature: |
        rule A { condition: filesize < 10 }
```

### How to fix

Keep one kind per rule. Split a Basic rule and a YARA rule into two opentide rules; manage exclusions in the GravityZone console.

## bitdefender_rule_missing

A rule to disable is gone from GravityZone, so its recorded id was removed.

Severity: warning. Reported by `opentide deploy` under `DISABLEMENT` on a `bitdefender` block (bitdefender-1.0). `updateCustomRule` answered `-32002`. Nothing exists to disable, so deploy creates nothing and forgets the binding.

### Example

```text illustrative
bitdefender_rule_missing: the recorded rule no longer exists on the tenant; its id is removed
```

### How to fix

Commit the updated deployment state.

## bitdefender_rule_recreated

The recorded GravityZone rule was gone, so deploy created it again.

Severity: warning. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). `updateCustomRule` answered `-32002` (resource not found): someone deleted the rule in the console. Deploy creates it again and replaces the id in `.opentide/states/deployment/`.

### Example

```text illustrative
bitdefender_rule_recreated: the recorded rule no longer exists on the tenant; creating it again
```

### How to fix

Commit the updated deployment state. Delete rules through a `DELETION` status, not in the console.

## bitdefender_severity

The block `severity` is not `Low`, `Medium` or `High`.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). GravityZone has three severities, spelled with a capital letter. Without `severity`, deploy derives it from `response.alert_severity`.

### Example

```yaml
configurations:
  bitdefender:
    severity: Critical
```

### How to fix

Use `Low`, `Medium` or `High`, or remove the key.

## bitdefender_severity_collapsed

`response.alert_severity` is `Critical` or `Informational`, which GravityZone sends as `High` or `Low`.

Severity: warning. Reported by `opentide validate` and `opentide lint` (its `queries` check) on a rule with a `bitdefender` block that sets no `severity` (bitdefender-1.0). GravityZone has three severities: deploy sends `Critical` as `High` and `Informational` as `Low`. It is an advisory: the rule validates and deploys.

### Example

```yaml
response:
  alert_severity: Critical
configurations:
  bitdefender:
    status: PRODUCTION
```

### How to fix

Set `configurations.bitdefender.severity` to `Low`, `Medium` or `High` to choose the GravityZone level, or accept the mapping.

## bitdefender_target

The `detection.target` is not a GravityZone detection target.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). The target must be spelled as the API spells it: `process`, `file`, `connection`, `registry`, `user connection`, `email`, `application`, `key vault`, `role`, `policy`, `sharing link`, `url`, `ssh key`, `launch template`, `service principal`, `user group`, `automation account`, `automation account hook`, `certificate authority`, `api`, `bucket`, `jira project` or `confluence page`. The exclusion-only targets `flow` and `bitbucket repository` are refused.

### Example

```yaml
configurations:
  bitdefender:
    detection:
      target: flow
      criteria:
        - field: Flow.Source
          is: 10.0.0.1
```

### How to fix

Use one of the detection targets, in lower case with spaces, such as `process`.

## bitdefender_target_unknown

A `targets` alias is not in the tenant's `endpoint_tags` or `companies` table.

Severity: error. Reported by `opentide deploy`, before any call for the rule on a `bitdefender` block (bitdefender-1.0). A rule file carries aliases, because GravityZone ids differ per tenant; each tenant maps them in `platforms/bitdefender.toml`.

### Example

```yaml
configurations:
  bitdefender:
    targets:
      endpoint_tags: [tier0-servers]   # the tenant has no tier0-servers
```

### How to fix

Add the alias to the tenant's `[tenants.setup.endpoint_tags]` (or `companies`) table, or change the block's `targets`.

## bitdefender_targets_shape

`targets` sets both `endpoint_tags` and `companies`, or an empty list.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). A rule applies to endpoint tags or, on a partner tenant, to companies; neither means the whole company. Each list names aliases from the tenant's tables.

### Example

```yaml
configurations:
  bitdefender:
    targets:
      endpoint_tags: [tier0-servers]
      companies: [acme]
```

### How to fix

Keep one of the two lists, with at least one alias, or remove `targets`.

## bitdefender_tenant_unauthorized

GravityZone refused the tenant's API key, so no rule deploys to it.

Severity: error. Reported by `opentide deploy` on a `bitdefender` block (bitdefender-1.0). A `-32001` answer, HTTP 401 or HTTP 403 stops the tenant. The key must be valid and have the Incidents API enabled.

### Example

```text illustrative
bitdefender_tenant_unauthorized: tenant gravityzone-eu refused the API key: API Key is not allowed to access the selected API: Incidents
```

### How to fix

Check the variable `api_key` names, and enable the Incidents API for the key in GravityZone (My Account, API keys). `key_type` must match the key: `personal` or `service`.

## bitdefender_tenant_unreachable

A call to the GravityZone tenant got no answer, so no further rule deploys to it.

Severity: error. Reported by `opentide deploy` on a `bitdefender` tenant (bitdefender-1.0). A timeout or a connection error on an update or a delete stops the tenant. A create with no answer is retried once instead; a retry with no answer, or one refused because the name is taken, is `bitdefender_create_unconfirmed` for that rule, and the tenant goes on.

### Example

```text illustrative
bitdefender_tenant_unreachable: HTTPSConnectionPool(host='cloudgz.gravityzone.bitdefender.com', port=443): Read timed out
```

### How to fix

Check the tenant `url` (it ends in `/api`), the network path to it, and the tenant's `ssl` setting, then deploy again.

## bitdefender_yara_ascii

A Bitdefender YARA signature holds a character that is not ASCII.

Severity: error. Reported by `opentide validate` on a `bitdefender` block's `yara.signature` (bitdefender-1.0): GravityZone takes ASCII only. The analysis engine checks the signature under its Bitdefender profile and places the finding on the character; without the engine, `opentide validate` still reports it on `yara.signature`. `opentide validate query --platform bitdefender` reports it in a `.yar` file. Deploy refuses the rule.

### Example

```yaml
configurations:
  bitdefender:
    yara:
      signature: |
        rule Loader {
          meta:
            description = "Stage-1 loader — config blob"
          condition:
            true
        }
```

### How to fix

Replace the character with ASCII (`-` for `—`), or match it as a hex string (`{ E2 80 94 }`), then run `opentide validate` again.

## bitdefender_yara_size

A Bitdefender YARA signature is longer than 30,000 characters.

Severity: error. Reported by `opentide validate` on a `bitdefender` block's `yara.signature` (bitdefender-1.0): GravityZone takes at most 30,000 characters. The analysis engine checks the signature under its Bitdefender profile; without the engine, `opentide validate` still reports it on `yara.signature`. `opentide validate query --platform bitdefender` reports it in a `.yar` file. Deploy refuses the rule.

### Example

```yaml
configurations:
  bitdefender:
    yara:
      signature: |
        rule Loader {
          strings:
            $a01 = "..."   # thousands of strings, 30,001 characters in all
          condition:
            any of them
        }
```

### How to fix

Shorten the signature: drop comments and unused strings, or split its rules across several Tide rules, then run `opentide validate` again.

## cbc_unknown_field

A field in a Carbon Black Cloud query is one or two letters away from a Carbon Black process search field, and is not that field.

Severity: warning. Reported by the query checks and the language server on `configurations.carbon_black_cloud.query`, and on hunts whose `system` is `carbon_black_cloud`, at the field name, with the field it is close to as the suggestion. The field list is the engine's Carbon Black process search catalog. A field far from every catalog field is not reported, because the catalog may not list it.

### Example

```text illustrative
`process_nmae` is not a Carbon Black Cloud process search field; did you mean `process_name`?
```

### How to fix

Use the suggested field (`process_name:cmd.exe`). If the field is right and Carbon Black accepts it, `opentide validate query --live` confirms it against the tenant; report the missing field to the language server's catalog (`catalogs/carbon_black/fields.toml`).

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

Severity: error. Reported by `opentide validate` (the `schema` check compiles each rule a deploy would send) and by `opentide deploy --dry-run` (and a real deploy) for one rule on one platform; the dry run lists the rule as failed, and both exit 1. The message names the key (`configurations.sentinel.grouping.alert is missing`) and the help says when it is required.

### Example

```text illustrative
error[compile_missing_field]: configurations.sentinel.scheduling.frequency is missing
  ╭─▶ objects/rules/lsass-access.yaml
  ╰─ help: required unless scheduling.nrt is true
```

### How to fix

Add the key under `configurations.sentinel` in the rule. The generated rule template, and a rule from `opentide new rule --platform sentinel`, show each one with its default.

## config_check_failed

opentide could not check this configuration file in the editor; the message says why. Its other findings are missing.

Severity: warning. Reported by the language server (`opentide lsp start`) on the first line of a file under `.opentide/configurations/` when the configuration check itself fails, for example because opentide raised an error while reading the parent instance's file. Nothing about the file is reported until the check runs again, so the file may still have problems `opentide validate` finds.

### Example

```text
opentide could not check this file: ImportError: cannot import name 'configuration_buffer_issues'
```

### How to fix

Run `opentide validate` in the workspace to see the file's findings and any error behind this one. If the message names an import or version error, the editor runs a different opentide than the one you installed: point the editor at it, or reinstall with `pip install --force-reinstall opentide`. Then edit the file or restart the language server to check it again.

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

## cql_assignment_as

A CQL assignment names the output field and the function's as= parameter names it again.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_correlate_aggregate

A Next-Gen SIEM correlation rule combines correlate() with another aggregate function, which CrowdStrike does not allow.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_correlate_placement

CQL correlate() stands where its reference forbids: after an aggregate or a source function, inside another function's arguments, or with an aggregate in its queries.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_deprecated_function

CrowdStrike's reference marks the CQL function deprecated.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_duplicate_parameter

A CQL function parameter is given more than once.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_event_function_after_aggregate

A CQL eventSize(), eventInternals() or eventFieldCount() call comes after the first aggregate function, which LogScale refuses since 1.190.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_free_text_after_aggregate

A CQL free-text filter comes after the first aggregate function, which LogScale refuses since 1.190.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_link_outside_correlate

The CQL link operator &lt;=> appears outside the queries of correlate(), the only place it links fields.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_match_guard

A CQL match guard is an aggregate function; a guard must be a filter.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_missing_parameter

A CQL function call leaves out a required parameter.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_parameter_value

A literal CQL argument is not one of the parameter's allowed values, or is outside its bounds.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_parse_error

The CrowdStrike Query Language (CQL) query does not parse.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_regex_flag

A CQL regex literal has a flag other than d, g, i, m or F.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_regex_group_under_or

A CQL regex with named groups is an operand of or, where LogScale extracts none of its fields.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_removed_function

The CQL function was removed from LogScale and Next-Gen SIEM no longer runs it.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_string_escape

A CQL string has an escape LogScale does not translate; it keeps the backslash and the character.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_unknown_event

The #event_simpleName value is not a Falcon sensor event the engine knows.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_unknown_function

No CQL function has this name; function names are matched without regard to case.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_unknown_parameter

The CQL function has no parameter with this name.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

## cql_unnamed_argument

A CQL function gets an argument without a name that it cannot take: a second one, or one when every parameter needs its name.

Reported by the analysis engine in a CQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [CQL reference](https://library.humio.com/crowdstrike-query-language/) describes the syntax and the commands the engine checks against.

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

Retired in engine 0.12.0; CrowdStrike queries are now checked as CQL: see the `cql_*` codes.

Severity: warning, while it was reported. CrowdStrike queries were not validated, and the engine said so rather than fake it.

Until engine 0.12.0, the analysis engine reported it as a warning on a CrowdStrike rule's `crowdstrike` block: an editor running `opentide lsp start` and `opentide tui` showed it. Engine 0.12.0 checks the query as the CrowdStrike Query Language (CQL) instead, and reports what it finds with the `cql_*` codes (`opentide explain` lists them). No command reports `crowdstrike_unsupported` now.

### Example

```text
opentide explain cql_unknown_function
```

### How to fix

Nothing to fix: no command reports this code any more. A suppression list or SARIF baseline that names it can drop it.

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

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

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

## ecs_type_mismatch

The operation cannot apply to the field's type, from ECS or from the columns visibility.toml declares for the index.

Reported by the analysis engine in an ECS field query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) describes the syntax and the commands the engine checks against.

## ecs_unknown_field

The field is not in the Elastic Common Schema, on indices that use it, nor declared for the index in visibility.toml; ECS allows custom fields.

Reported by the analysis engine in an ECS field query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference) describes the syntax and the commands the engine checks against.

## elastic_dataset_not_declared

The index pattern is not one the workspace declares in visibility.toml.

Severity: warning. Reported by the analysis engine on an Elastic rule (`elastic`): its `index`, a threat match's `index`, or an ES|QL `FROM`. `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it, with the query's findings; `opentide validate` does not fail on it. It is opt-in: only a workspace whose `visibility.toml` has at least one `elastic` log source gets it, for an index pattern no log source names, whether or not the engine knows it otherwise. An Elastic log source's `name` is its index pattern or data stream; data views are not declared. A declared pattern covers the patterns inside it: `logs-*` covers `logs-azure.*`.

### Example

```toml
[[logsources]]
name = "logs-endpoint.events.*"
description = "Elastic Defend endpoint data."
system = "elastic"
```

```yaml
configurations:
  elastic:
    index:
      - winlogbeat-*   # not declared for elastic
```

### How to fix

Correct the pattern, or declare it: add an `elastic` log source whose `name` is the index pattern in `visibility.toml`. The editor applies the change as you type it; the CLI reads the file on its next run. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).

```toml
[[logsources]]
name = "winlogbeat-*"
description = "Windows event logs shipped by Winlogbeat."
system = "elastic"
```

## engine_unavailable

The analysis engine (the Rust module compiled into opentide) does not load, so the command cannot check queries or serve the language server.

Exit 1, as `failure.code`, from `opentide validate query` (offline), `opentide lint` (its `queries` check) and `opentide lsp start`; an error issue of the `queries` check in `opentide validate`, whatever `--queries` says but `off`; and the `analysis_engine` check of `opentide doctor`. The check is never skipped: a missing engine fails the command.

### Example

```text illustrative
error: The opentide analysis engine does not load: cannot import name '_native' from 'opentide'
  help: reinstall opentide: pip install --force-reinstall opentide
```

### How to fix

The engine is part of the opentide package: each opentide wheel carries it, compiled for its platform, and there is nothing else to install. Reinstall opentide with the command it prints, in a clean environment (`uv tool install --reinstall opentide` for a uv tool install). When pip builds opentide from source instead of downloading a wheel, your platform has no prebuilt wheel and the build compiles the engine: install a Rust toolchain (https://rustup.rs) and reinstall, or report the platform at https://github.com/opentidehq/opentide/issues.

## eql_argument_type

A literal has a type the EQL verifier rejects in this position.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_case_sensitive

The comparison is case-sensitive; the case-insensitive form may be meant.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_expression_depth

The expression nests deeper than Elasticsearch accepts.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_field_comparison

Both sides of a comparison read fields, which EQL does not support.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_function_arity

An EQL function is called with the wrong number of arguments.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_literal_wildcard

A wildcard character is compared literally; use : or like for a pattern.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_maxspan_lookback

A sequence maxspan is longer than the rule's lookback.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_maxspan_missing

A sequence has no maxspan, so partial sequences are held until they expire.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_maxspan_unit

A sequence maxspan uses a unit Elasticsearch does not accept.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_maxspan_window

A sequence maxspan is longer than the rule's interval plus lookback, so the rule cannot see whole sequences.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_nested_comment

Elasticsearch nests /* */ comments; the comment ends later than it looks.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_not_boolean

A string or number literal is used as a condition.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_parse_error

The EQL query does not parse.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_regex

The regular expression trips a Lucene RegExp pitfall.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_runs_ignored

A decimal runs count is truncated by Elasticsearch.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_unknown_function

The EQL function is not in the Elasticsearch function catalog.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_unsupported

Elasticsearch EQL does not support this construct (pipes, relationships, ...).

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## eql_until_term

runs or a missing-event term ![ ] is not allowed on until.

Reported by the analysis engine in an EQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [EQL reference](https://www.elastic.co/docs/reference/query-languages/eql) describes the syntax and the commands the engine checks against.

## esql_expression_depth

The expression nests deeper than Elasticsearch accepts.

Reported by the analysis engine in an ES|QL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_group_by_column

A suppression group_by field is not a column the ES|QL query returns.

Reported by the analysis engine in an ES|QL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_metadata_id

A non-aggregating ES|QL rule query has no METADATA _id, so alerts cannot be deduplicated.

Reported by the analysis engine in an ES|QL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_parse_error

The ES|QL query does not parse.

Reported by the analysis engine in an ES|QL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_pattern

A LIKE or RLIKE pattern escapes or matches differently than it reads.

Reported by the analysis engine in an ES|QL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_unavailable

The command, function or form is missing or in preview on a targeted stack version.

Reported by the analysis engine in an ES|QL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_unknown_command

The ES|QL command is not one Elasticsearch knows.

Reported by the analysis engine in an ES|QL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_unknown_function

The ES|QL function is not in the Elasticsearch function catalog.

Reported by the analysis engine in an ES|QL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## esql_unknown_type

The ::type cast names a type no Elasticsearch release can cast to.

Reported by the analysis engine in an ES|QL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [ES|QL reference](https://www.elastic.co/docs/reference/query-languages/esql) describes the syntax and the commands the engine checks against.

## exabeam_advanced_in_rule

A correlation rule sequence query uses Exabeam's advanced operators (SELECT, WHERE, pipes and the rest), which are Search only.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_bare_wildcard

A * alone is not an Exabeam query term.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_clause_order

Exabeam clauses are out of order, or one appears twice in a statement: SELECT, FROM, WHERE, AS, GROUP-BY, ORDER-BY, LIMIT.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_context_table_limit

An Exabeam query has more than two context table lookups.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_context_table_or

An Exabeam context table lookup is under OR; lookups combine with AND or AND NOT only.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_context_table_trigger

An Exabeam sequence whose query looks up a context table has a threshold; Exabeam requires trigger on first match.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_correlation

An Exabeam block has two or more sequences without correlation, one sequence with it, or a correlation that is not within and group_by.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_correlation_window

An Exabeam correlation window is shorter than the longest sequence threshold window.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_duration

An Exabeam duration is not a whole number and a unit its field allows, or delay is outside 7 to 180 minutes.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_email

An Exabeam email does not have a non-empty list of distinct addresses, or its subject is blank.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_foreach_clause

An Exabeam FOREACH sub-query has GROUP-BY or ORDER-BY.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_foreach_position

An Exabeam FOREACH is the first statement; it runs on the result of a preceding query.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_foreach_reference

An Exabeam @field reference is outside a FOREACH sub-query.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_free_text_special

Unquoted Exabeam free text holds a character other than letters, digits, _, * and ?; put it in double quotes.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_function_arity

An Exabeam function gets the wrong arguments: a filter function takes one string, an aggregation one field (* for COUNT only), RGX_EXTRACT an optional field and a pattern.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_group_by

An Exabeam group_by is not a list of one to three distinct non-blank fields (correlation.group_by may be empty).

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_group_by_column

An Exabeam selected column is neither in GROUP-BY nor aggregated.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_group_by_select_star

An Exabeam GROUP-BY is combined with SELECT *.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_implicit_and

Two Exabeam terms, not both free text, stand side by side and are read as AND; write AND.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_implicit_operator

An Exabeam NOT stands between two terms with no AND or OR before it, which Exabeam calls invalid; write AND NOT or OR NOT.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_ipv6_range

An Exabeam range or CIDR block holds an IPv6 address; Exabeam ranges are IPv4 only.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_keyword_case

An Exabeam clause keyword, aggregation or RGX_EXTRACT is in mixed case; write it all upper or all lower case.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_leading_slash

An Exabeam query cannot start with /.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_legacy_regex

An Exabeam value between slashes may be read as a regular expression; write RGX("...") for a pattern, or drop the slashes for a path.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_mixed_boolean

Exabeam AND and OR are mixed at one level without parentheses; Exabeam does not document their precedence.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_name_duplicate

Two enabled Exabeam blocks of the workspace resolve to the same rule name, compared without regard to case.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_name_length

The Exabeam rule name is longer than 128 characters.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_not_equal

Exabeam filters have no != operator; write NOT field:value.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_outcome

An Exabeam outcome is not alert, case or none.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_outcome_silent

An Exabeam rule's outcome is none and it sends no email, so it only writes a rule-trigger event.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_parse_error

The Exabeam query does not parse: an unterminated string, an unbalanced bracket, a missing operand, an empty sequence query, or a comparison with a non-number.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_pipe_limit

An Exabeam query has more than five pipes.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_pipe_misuse

An Exabeam statement after a pipe follows no SELECT or uses none of its columns; write one query with AND or WHERE.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_range

The Exabeam range or CIDR block is invalid: a bound that is not a number, IPv4 address, datetime or *, mixed kinds, low above high, two open bounds, mismatched brackets, or a bad network.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_regex

The Exabeam regular expression is not valid RE2: a syntax error, a back-reference, look-around, an atomic group or a possessive quantifier.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_reserved_alias

An Exabeam AS name is one of the Search guide's reserved words.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_rgx_extract_limit

An Exabeam query has more than three RGX_EXTRACT calls.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_schedule

An Exabeam schedule recurrence has an unknown every, a from or to that is not HH:MMZ, or day keys its every does not take.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_sequences

An Exabeam block's sequences is not a non-empty list of sequences, each with a non-blank query.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_severity

An Exabeam severity is not none, low, medium, high or critical.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_single_group

Parentheses hold a single Exabeam expression, which the Search guide calls an error; drop them.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_string_field_number

An unquoted number is matched against a field the Exabeam Common Information Model types as a string; Exabeam requires the number in double quotes.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_threshold_function

An Exabeam threshold function is not count, unique_count, value, max, min, sum or average, or its field is blank or missing.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_threshold_operator

An Exabeam threshold operator is not allowed with its function: more_than or less_than, in or not_in for value.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_threshold_value

An Exabeam threshold value does not have the shape its operator takes, or count and unique_count compare with a non-integer.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_time_exact

An Exabeam time field (time, approxLogTime, ingest_time, raw_log_time) is matched with an exact value; Search matches time with a range only.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_unknown_field

The field is not in Exabeam's Common Information Model, a platform field, a c_ or m_ field, or an AS name defined earlier in the query; a tenant's parsers may still define it.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_unknown_function

The call is not an Exabeam function: RGX, RGXi, WLD and WLDi in a filter, an aggregation or RGX_EXTRACT in SELECT.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_unknown_value

An Exabeam activity_type, subject or outcome value is not one the Common Information Model lists; a tenant's parsers may still emit it.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_unquoted_value

An Exabeam field value is a bare word that is not a number, boolean, null, IP address or @field; Exabeam documents string values in double quotes.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## exabeam_wildcard_in_phrase

A quoted Exabeam value with a space holds * or ?, which Exabeam does not expand inside a phrase.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

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

## falco_append_condition

A tuning's condition is appended to the tuned rule's condition and must start with `and` or `or`; a new rule's condition must not.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_deprecated_field

A field Falco deprecates (`evt.dir`, `evt.latency`): it no longer carries the value it used to.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_exception

A rule exception Falco refuses: comparison operators, field and value counts, or a value the field's type cannot hold.

Reported by the analysis engine on the Sysdig block's `exceptions`, with the condition's findings, since Falco appends them to the condition when it loads the rule: as an error, an exception Falco would reject, by `opentide validate` (its `queries` check); as a warning, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both. An exception whose shape the model refuses (fields, comps and values that do not align) is `sysdig_exception_shape` instead, which `validate` names in its `schema_validation` finding: Falco's checks leave that exception to it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_field_argument

A known Falco field is used with an argument it refuses, or without one it requires (libsinsp's field rules: `proc.aname[N]` takes an index, `evt.arg.NAME` an event argument).

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_field_as_value

A constant value that is a field name: compare with `val(field)` to read the field.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_invalid_regex

The `regex` pattern does not compile.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_misplaced_list

A list is used where its expansion breaks the condition: as a macro, or as a single value; a list belongs inside a value list, `in (name)`.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_newer_syntax

Syntax that only recent libsinsp releases parse (operator modifiers, `join`, `concat`, `getopt`, transformer arguments); an older Falco or Sysdig agent refuses the rule.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_no_evttype

The rule cannot be narrowed to a few event types (`evt.type`), so it runs on every event; Falco and Sysdig warn about the performance penalty.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_operator_type

The operator does not apply to the field's type (libsinsp `flt_is_comparable`); Falco refuses to load the rule.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_output_syntax

The output template does not format: a `%` at the end, a length with no field, or a token that is no field or transformer.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_parse_error

The Falco condition does not parse.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_regex_simple

A `regex` check a plain operator (`=`, `contains`, `startswith`, `endswith`) could make, which libsinsp warns about: regex is the slowest check.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_rhs_field

A field cannot be compared with another field here (`val(...)` or a transformer on the right): not with `pmatch` or `regex`, not on networks, not on fields that refuse it, and only between fields of the same type.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_transformer

A field transformer cannot apply here: the field's type, a field that refuses transformers, or the arguments of `join`, `concat`, or `getopt`.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_transformer_as_value

A constant value that looks like a transformer call, compared as text.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_unknown_event

The event type is not in the driver's event table nor a syscall name; libsinsp refuses it.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_unknown_field

The field is not one Falco or its plugins define for the rule's event source; a plugin the engine does not know may add it.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_unknown_list

The name after a list operator, without parentheses, is not a list of the block or of the Falco default rules, so it is compared as a single value.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_unknown_macro

The name is not a macro of the block or of the Falco default rules; the tenant may define it, as Sysdig does for its managed macros.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_unknown_rule

A tuning (`append_to_rule`) names a rule the Falco default rules do not define: Falco refuses the append, and on Sysdig the tenant must have that rule.

Reported by the analysis engine on the Sysdig block's `append_to_rule`, as a warning: `opentide lint` (its `queries` check) shows it. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_unknown_source

The event source is not one Falco or its published plugins define, so its fields are not checked.

Reported by the analysis engine on the Sysdig block's `source`, as a warning, with the condition's findings (its fields go unchecked): `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_unsafe_na_check

A `ka.` or `jevt.` field compared with `<NA>`, which Falco warns about: the field may hold that text.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## falco_value_type

The value cannot be parsed as the field's type (a number, `true` or `false`, an IP address or network, a hex string for `bcontains`); Falco refuses to load the rule.

Reported by the analysis engine in a Falco condition query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Falco condition reference](https://falco.org/docs/concepts/rules/conditions/) describes the syntax and the commands the engine checks against.

## filename_mismatch

An object file's name is not the stem `lint.toml` `[filenames].style` (or its kind's `[filenames.<kind>].style`) asks for: `slugify(name)` by default.

Severity: warning. Reported by `opentide lint` (filenames check).

### Example

```text illustrative
objects/threats/Simulated Actor.yaml   # name: Simulated Actor → simulated-actor.yaml
```

With `style = "name"` the stem is the name, less the characters a file name cannot hold (`< > : " / \ | ? *`, control characters, and spaces or dots at either end):

```text illustrative
objects/threats/actor.yaml   # name: Simulated Actor → Simulated Actor.yaml
```

### How to fix

Run `opentide lint --fix`, which renames the file. When another file already has the expected name (compared without regard to case), the object gets the first eight characters of its UUID as a suffix.

If the catalogue keeps another convention, set `style` in `.opentide/configurations/lint.toml`: `"name"` for the object's name as the file name, `"none"` to stop comparing the stem with the name. `pattern` checks the stem against a regular expression (`opentide explain filename_pattern`). `[filenames.threats]`, `[filenames.objectives]` and `[filenames.rules]` set either key for one kind of object.

## filename_pattern

An object file's name does not match the regular expression `lint.toml` sets for it.

Severity: warning, or the severity `[filenames]` sets. Reported by `opentide lint` (filenames check), only when `[filenames].pattern`, or the object kind's `[filenames.<kind>].pattern`, is set.

### Example

```toml
# .opentide/configurations/lint.toml
[filenames]
style = "name"
pattern = '^\[(SEN|XDR)\]\[[^\]]+\].+\[[^\]]+\]$'
```

```text illustrative
objects/rules/Some rule.yaml   # the stem is not [PLATFORM][GROUP]name[TENANT]
```

### How to fix

The pattern is matched against the whole file name without its extension (`re.fullmatch`), whatever `style` is. `lint --fix` cannot rename the file, because no name derives from a pattern: rename it so the stem matches, or change `pattern` in `.opentide/configurations/lint.toml` if the convention changed.

`pattern` applies together with `style`. When `style` asks for a stem and `lint --fix` renames the file to it, the pattern is checked against the new name. With `style = "name"` the stem is the object's `name`, so a stem that fails the pattern after `--fix` means the `name` itself does not fit it: change the name. With `style = "none"` only the pattern is checked.

## filename_slug

Retired in opentide 0.24.0; `opentide lint` reports a file name that is not the object's as `filename_mismatch`.

Severity: warning, while it was reported. The file name was not the one `lint.toml`'s `[filenames]` style derives from the object's name.

Until opentide 0.24.0, the language server reported it as a warning on an object's `name`, with a looser rule than `opentide lint` (any stem that started with the slug passed). The editor now reports what `opentide validate` reports, and `opentide lint` keeps the one file-name rule, `filename_mismatch` (KG-03).

### Example

```text
opentide lint --check filenames
```

### How to fix

Nothing to fix: no command reports this code any more. A suppression list or SARIF baseline that names it can drop it.

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

## google_secops_compile_error

Google SecOps's compiler refuses a rule in a live query check.

Severity: error. Reported by `opentide validate query --platform google_secops --live` (google-secops-1.0). The rule's assembled text is compiled by `verifyRuleText`, which resolves the instance's reference lists and data tables and creates nothing. Each `ERROR` diagnostic is placed on the section key and line it falls in, with Google's message and documentation link.

### Example

```text illustrative
google_secops_compile_error: configurations.google_secops.condition line 1, column 1: event variable $success is not used
```

### How to fix

Fix the section and line the finding names, then run the check again.

## google_secops_compile_warning

Google SecOps's compiler accepts a rule with a warning in a live query check.

Severity: warning. Reported by `opentide validate query --platform google_secops --live`, and logged by `opentide deploy` (google-secops-1.0): `verifyRuleText` answered `success` with a `WARNING` diagnostic, placed on the section key and line it falls in. The rule still deploys.

### Example

```text illustrative
google_secops_compile_warning: configurations.google_secops.events line 2, column 5: reference lists are deprecated
```

### How to fix

Read Google's message and its documentation link; change the section when the warning applies.

## google_secops_create_no_id

A Google SecOps create answered without a rule id.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Google answered 2xx with a `name` that does not end in a rule id, or with a body that is not JSON. The `name` of the created rule must end in `rules/ru_<uuid>`, the id deploy records in `.opentide/states/deployment/`. Without it the rule may exist on the instance with no binding.

### Example

```text illustrative
google_secops_create_no_id: rules.create for password_spray answered name None, which does not end in a rule id
```

### How to fix

Find the rule in Google SecOps (Detection, Rules) by its name. Delete it, or record its `ru_` id under `platforms.google_secops.<tenant>` in the rule's `.opentide/states/deployment/<uuid>.json` and commit it.

## google_secops_create_unconfirmed

A Google SecOps create got no answer or a server error, so the rule may exist without a binding.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). The `rules.create` request timed out, its connection was reset, or Google answered a 5xx (`503` included), which can come after the rule was written. Google may have created the rule, but its id never reached opentide, so nothing was recorded, and deploy does not send the create again: a second rule with the same name would follow.

### Example

```text illustrative
google_secops_create_unconfirmed: the create of rule password_spray got no answer (read timed out)
```

### How to fix

Find the rule in Google SecOps (Detection, Rules) by its name. Delete it and deploy again, or record its `ru_` id under `platforms.google_secops.<tenant>` in the rule's `.opentide/states/deployment/<uuid>.json` and commit it.

## google_secops_credentials_missing

opentide has no usable Google credentials for a Google SecOps tenant.

Severity: error. Reported by `opentide deploy`, `opentide validate query --live` and `opentide query` on a `google_secops` tenant (google-secops-1.0). The tenant's `credentials` variable is unset, names no file, or holds no service-account key; or the tenant names no `credentials` and Application Default Credentials are not set up.

### Example

```text illustrative
google_secops_credentials_missing: the credentials variable GOOGLE_SECOPS_CREDENTIALS is not set
```

### How to fix

Set the variable to a service-account key (its JSON, or the path to the file), or leave `credentials` out and set up Application Default Credentials (`gcloud auth application-default login`, or workload identity in CI).

## google_secops_delete_refused

Google SecOps refused to delete a rule, so deploy archived it.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant with `deletion = "delete"` (google-secops-1.0). `DELETE` without `force` fails when the rule has detections or retrohunts. Google does not document the status it answers, so any 4xx but 401, 403, 404 and 429 counts as a refusal, and the warning carries Google's message. opentide never sends `force=true`, which deletes the detections too. The rule was disabled and archived instead, and its binding kept.

### Example

```text illustrative
google_secops_delete_refused: Google refused to delete rule ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1 because it has detections or retrohunts; it is archived instead
```

### How to fix

Nothing to do: an archived rule keeps its detections as the audit trail of what it found. Delete it in the console when they are no longer needed.

## google_secops_deployment_failed

A Google SecOps rule exists, but its run state could not be set.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). The rule text was created or updated and its id is recorded, but the update of its deployment (`enabled`, `alerting`, `runFrequency`, `archived`) failed. The binding is kept: the next deploy repairs the run state.

### Example

```text illustrative
google_secops_deployment_failed: rule ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1 is bound, but its run state could not be set
```

### How to fix

Read Google's error in the message (a permission such as `chronicle.ruleDeployments.update`, a run frequency) and deploy again.

## google_secops_live_frequency_unavailable

A Google SecOps rule with two or more event variables asks for `run_frequency: LIVE`.

Severity: warning (an advisory). Reported by `opentide validate` and `opentide lint` on a `google_secops` block (google-secops-1.0). Google allows `LIVE` for single-event rules only: `verifyRuleText` does not list it for this rule, so deploy refuses it with `google_secops_run_frequency_not_allowed` before writing anything. Google also counts a single event variable with `match` and a count or outcome condition as multi-event; the advisory does not try to decide that, and deploy still refuses.

### Example

```yaml
configurations:
  google_secops:
    run_frequency: LIVE
    events: |
      $fail.metadata.event_type = "USER_LOGIN"
      $success.metadata.event_type = "USER_LOGIN"
```

### How to fix

Write `run_frequency: LIVE_CUSTOMIZABLE`, or remove `run_frequency`: deploy then sends none, and Google gives the rule its default frequency.

## google_secops_meta_key

A Google SecOps block's `meta` holds a key deploy cannot write.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). Each extra meta key is written after the derived meta as `key = "value"`: it must be an identifier that is not a YARA-L keyword, it must not be a key deploy derives (`author`, `description`, `severity`, `priority`, `technique`, `opentide_uuid`, `opentide_version`), and its value is a string. The finding is on `meta.<key>`.

### Example

```yaml
configurations:
  google_secops:
    meta:
      severity: Low        # deploy writes severity itself
      data_source: Okta
```

### How to fix

Remove the derived key (set `severity` on the block instead) or rename it; quote a value YAML would read as a number or a boolean.

## google_secops_name_duplicate

Two enabled Google SecOps blocks resolve to one YARA-L rule name.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). The rule name is the block's `name`, else the rule's title lower-cased with runs of other characters as `_`. Names are compared case-insensitively: a composite rule that matches a producer by `detection.detection.rule_name` would match both, and Google's own tooling treats names as unique regardless of case.

### Example

```yaml
# rule-a.yaml: name: Password spray
# rule-b.yaml:
configurations:
  google_secops:
    name: PASSWORD_SPRAY
```

### How to fix

Give one of the blocks its own `configurations.google_secops.name`, or rename one of the rules.

## google_secops_request_failed

A Chronicle API request for one Google SecOps rule failed.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Google answered an error other than the ones deploy handles itself, or stayed rate limited (`RESOURCE_EXHAUSTED` or HTTP 503) after three waits: `Retry-After` (at most 300 seconds), else the `RetryInfo` delay Google names, else 5, 15 and 60 seconds. The message carries Google's `error.status` and `error.message`. The other rules still deploy.

### Example

```text illustrative
google_secops_request_failed: INVALID_ARGUMENT: the rule text is too long
```

### How to fix

Read Google's status and message; deploy again once the cause is fixed.

## google_secops_risk_score_missing

A Google SecOps rule's `outcome` assigns no `$risk_score`.

Severity: warning (an advisory: the rule still validates and deploys). Reported by `opentide validate` and `opentide lint` (its `queries` check) on a `google_secops` block (google-secops-1.0). Without `$risk_score`, Google gives every detection of the rule the instance's default score, 40 for an alert and 15 otherwise unless the instance's settings change them, whatever it detects.

### Example

```yaml
configurations:
  google_secops:
    outcome: |
      $host = $e.principal.hostname
```

### How to fix

Add a `$risk_score` line to `outcome`, an integer from 0 to 100 (`$risk_score = 70`), or an aggregation in a rule with `match` (`$risk_score = max(70)`).

## google_secops_rule_compilation_failed

Google reports that a deployed Google SecOps rule no longer compiles.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0), from the rule it reads before an update. `compilationState` `FAILED` happens after a backwards-incompatible change to Google's compiler, or when a reference list or data table the rule uses is gone; the rule then does not run. Deploy goes on: a changed text is verified and sent as usual.

### Example

```text illustrative
google_secops_rule_compilation_failed: Google reports the rule's compilation as FAILED
```

### How to fix

Run `opentide validate query --platform google_secops --live` to see Google's diagnostics for the rule, fix the sections they name, and deploy again.

## google_secops_rule_conflict

A Google SecOps rule changed between deploy's read and its update.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). The text update carried the `etag` of the rule deploy had just read, and Google refused it (HTTP 409, `ABORTED`): someone or something changed the rule in between. Nothing was written, and deploy does not retry in the same run.

### Example

```text illustrative
google_secops_rule_conflict: rule ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1 changed between its read and the update (etag mismatch)
```

### How to fix

Deploy again. When it keeps happening, find what else edits the rule in Google SecOps.

## google_secops_rule_execution_limited

Google reports that it limits or pauses a Google SecOps rule's runs.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0), from the rule deployment it reads before an update. `executionState` `LIMITED` means Google does not guarantee the rule's runs, usually because it is expensive or produces too many detections; `PAUSED` means Google does not run it at all. Deploy goes on: the text and run state are still updated.

### Example

```text illustrative
google_secops_rule_execution_limited: Google reports the rule's execution as PAUSED: it is not run at all
```

### How to fix

Open the rule in Google SecOps (Detection, Rules) to see why. Narrow `events` (filter on `metadata.event_type` or `metadata.log_type`), shorten the `match` window, or reduce the detections it produces, then deploy again.

## google_secops_rule_id_literal

A Google SecOps rule matches a producer rule by a literal `ru_…` id.

Severity: warning (an advisory). Reported by `opentide validate` and `opentide lint` on a `google_secops` block (google-secops-1.0). A rule id differs on every instance and changes when the rule is recreated, so a composite rule that compares `detection.detection.rule_id` with a literal stops matching after a redeploy or on another tenant.

### Example

```yaml
configurations:
  google_secops:
    events: |
      $d.detection.detection.rule_id = "ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1"
```

### How to fix

Match the producer by its name, which opentide derives the same way on every instance: `$d.detection.detection.rule_name = "password_spray_then_success"`.

## google_secops_rule_missing

The Google SecOps rule a binding names no longer exists, and the rule is being retired.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Under `DISABLEMENT` or `DELETION`, reading or updating the recorded rule answered 404. Deploy created nothing and removed the binding.

### Example

```text illustrative
google_secops_rule_missing: the recorded rule no longer exists on the instance; its id is removed
```

### How to fix

Nothing to do: commit `.opentide/states/deployment/`.

## google_secops_rule_name

A Google SecOps block's `name` is not a YARA-L rule name.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). The name is written as `rule <name> {`: it must be an identifier, `[A-Za-z_][A-Za-z0-9_]*`, and not a YARA-L keyword such as `match` or `rule`. An empty `name` is derived from the rule's title instead.

### Example

```yaml
configurations:
  google_secops:
    name: password-spray   # a hyphen is not allowed
```

### How to fix

Write the name with letters, digits and underscores (`password_spray`), or remove `name` to use the one derived from the rule's title.

## google_secops_rule_recreated

The Google SecOps rule a binding names no longer exists, so deploy created it again.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Reading or updating the recorded rule answered 404. Deploy verified and created the rule again and replaced the binding with the new id. Detections of the old rule are not carried over.

### Example

```text illustrative
google_secops_rule_recreated: the recorded rule no longer exists on the instance; creating it again
```

### How to fix

Nothing to do: commit `.opentide/states/deployment/` with the new id. Find out who deleted the rule if that was not intended.

## google_secops_run_frequency

A Google SecOps block's `run_frequency` is not one opentide deploys.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). `run_frequency` is `LIVE`, `LIVE_CUSTOMIZABLE`, `HOURLY_CUSTOMIZABLE` or `DAILY`. Google's legacy `HOURLY` is refused: Google remaps it, so the stored rule would never match the block.

### Example

```yaml
configurations:
  google_secops:
    run_frequency: HOURLY
```

### How to fix

Write `HOURLY_CUSTOMIZABLE` (or another of the four values), or remove `run_frequency`: deploy then sends none, and Google keeps the rule's frequency, or gives a new rule its default.

## google_secops_run_frequency_not_allowed

A Google SecOps block's `run_frequency` is not one Google allows for the rule.

Severity: error. Reported by `opentide deploy` before any write, and by `opentide validate query --platform google_secops --live` (google-secops-1.0). `verifyRuleText` answers the frequencies the rule can run at (`allowedRunFrequencies`): `LIVE` is for single-event rules, `LIVE_CUSTOMIZABLE` for multi-event windows under an hour, `HOURLY_CUSTOMIZABLE` up to two days, `DAILY` beyond.

### Example

```text illustrative
google_secops_run_frequency_not_allowed: run_frequency LIVE is not one Google allows for this rule (LIVE_CUSTOMIZABLE, HOURLY_CUSTOMIZABLE, DAILY); nothing was written
```

### How to fix

Set `run_frequency` to one of the frequencies the message lists, or remove it: deploy then sends no `runFrequency`, and Google keeps the rule's frequency, or gives a new rule its default.

## google_secops_schedule

A Google SecOps block's `schedule` cannot be sent with its run frequency, or holds a duration that is not one.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). Schedule customizations apply to `LIVE_CUSTOMIZABLE` and `HOURLY_CUSTOMIZABLE` rules only, and `late_arriving_data_adjustment` is a positive duration with unit `s`, `m`, `h` or `d` (`30m`, `2h`). The finding is on `schedule`, or on `schedule.late_arriving_data_adjustment`.

### Example

```yaml
configurations:
  google_secops:
    run_frequency: LIVE
    schedule:
      late_arriving_data_adjustment: half an hour
```

### How to fix

Set `run_frequency` to `LIVE_CUSTOMIZABLE` or `HOURLY_CUSTOMIZABLE`, or remove `schedule`; write the adjustment as a duration such as `30m`.

## google_secops_severity

A Google SecOps block's `severity` or `priority` is not one of Google's values.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). Both are written into the rule's meta and must be `Info`, `Low`, `Medium`, `High` or `Critical`, Google's community spelling. `Informational` is opentide's alert severity, not Google's.

### Example

```yaml
configurations:
  google_secops:
    severity: Informational
```

### How to fix

Use `Info`, `Low`, `Medium`, `High` or `Critical`, or remove the key: `severity` is derived from `response.alert_severity`, and `priority` defaults to the severity.

## google_secops_tenant_unauthorized

A Google SecOps instance refused opentide's credentials.

Severity: error. Reported by `opentide deploy` and `opentide validate query --live` on a `google_secops` tenant (google-secops-1.0). The instance answered HTTP 401 or 403, or no access token could be obtained (Google refused the credentials, or its token endpoint did not answer): no rule on that tenant is deployed or checked. A token failure happens before the request is sent, so it is never an unanswered create. User credentials from Application Default Credentials send their quota project (`x-goog-user-project`); Google refuses them without one.

### Example

```text illustrative
google_secops_tenant_unauthorized: tenant secops-eu refused the request (HTTP 403 PERMISSION_DENIED): Permission 'chronicle.rules.create' denied
```

### How to fix

Give the service account (or the Application Default Credentials principal) the permissions on the instance: `chronicle.rules.verifyRuleText`, `.create`, `.get`, `.update`, `.delete`, `chronicle.ruleDeployments.get`, `.update`, and `chronicle.events.udmSearch` for `opentide query`. Check `project`, `location` and `instance` in `platforms/google_secops.toml`. With user Application Default Credentials, set a quota project: `gcloud auth application-default set-quota-project <project>`.

## google_secops_tenant_unreachable

A Google SecOps instance did not answer, so no rule was deployed to it.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). A request to the instance's endpoint failed in transit (DNS, TLS, a refused or reset connection, a timeout). The tenant stops; the others go on.

### Example

```text illustrative
google_secops_tenant_unreachable: HTTPSConnectionPool(host='eu-chronicle.googleapis.com', port=443): Read timed out
```

### How to fix

Check the tenant's `location` (or `endpoint`), the network and proxy between the runner and Google, and `ssl`; then deploy again.

## google_secops_verify_failed

Google SecOps does not compile a rule, so deploy neither creates nor updates it.

Severity: error. Reported by `opentide deploy` on a `google_secops` tenant (google-secops-1.0). Deploy sends the assembled rule to `verifyRuleText` before every create and every text update. Each of Google's diagnostics is reported at the section key and line it falls in (`configurations.google_secops.events line 3, column 5`), or on the block when it falls in the generated header or meta.

### Example

```text illustrative
google_secops_verify_failed: Google SecOps does not compile rule password_spray: configurations.google_secops.events line 3, column 5: field principal.nope does not exist
```

### How to fix

Fix the section the diagnostic names and run `opentide validate query --platform google_secops --live`, which asks the same compiler without deploying.

## graylog_aggregation

A Graylog `aggregation.condition` is missing, does not parse under the condition grammar, or calls a function with the wrong arguments.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_analyzed_field

A regex, wildcard, or range applies to Graylog's analysed `message` or `full_message` field, so it matches single lower-cased tokens, never the whole value.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_double_backslash

A Graylog query holds four backslashes in a row: `\\` is already one literal backslash, so `\\\\` matches two.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_event_field

A Graylog event field name is not `[A-Za-z0-9_.@-]+`, or its value is not a field name, a `${…}` template, `{template}`, or `{lookup}`.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_event_key

A Graylog `event_key` item is not an `event_fields` name.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_event_limit

A Graylog `event_limit` is not an integer from 1 to 1,000, or is set on an aggregation.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_field_name

A Graylog `aggregation.group_by` item is not a field name (`[A-Za-z0-9_.@-]+`).

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_leading_wildcard

A Graylog query term starts with `*` or `?`: Graylog refuses leading wildcards unless the server allows them; a regex with a leading `.*` is the portable form.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_list_shape

A Graylog list field is not one string or a list of distinct non-blank strings.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_open_range

A Graylog range has `*` as a bound (`[1 TO *]`, `{* TO 5}`). Graylog's query validator refuses it, so deploy cannot save the definition: write `field:>=1` or `field:<5`.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_overlapping_window

A Graylog filter searches a `window` longer than it runs `every`, so each message alerts once per overlapping run.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_priority

A Graylog `priority` is not `Informational`, `Low`, `Medium`, `High`, or `Critical`.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_query_blank

A Graylog block's `query` is missing or blank.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_regex_operator

A Graylog regex holds an unescaped `#`, `&`, `@`, `~`, `<`, or `>`, which Lucene reads as a regex operator, not the character.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_regex_quote

A Graylog regex holds an unescaped `"`, which Lucene reads as a quoted literal, not the character: escape it as `\"`.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_regex_unsupported

A Graylog regex uses an inline flag, a `(?…)` group, `\b`, `\B`, a lookaround, or a backreference, which Lucene's regex engine does not have: Graylog matches nothing or rejects the query.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## graylog_schedule

A Graylog `schedule` sets both `every` and `cron`, a duration that is not greater than zero, a cron that is not a 6- or 7-field Quartz expression, an unknown time zone, or `cron` without `window`.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## harfanglab_rule_kind

A HarfangLab block sets both sigma and yara; a block is one kind.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## harfanglab_yara_context

A HarfangLab YARA rule's meta `context` is not a comma-joined list of the scan contexts HarfangLab uses.

Severity: warning. Reported by `opentide lint` (its `queries` check) on a HarfangLab rule (`harfanglab`). In the signature form, a rule that is not `private` sets meta `context` to something other than a comma-joined list, without blanks, of `file`, `memory`, `file.pe`, `file.elf`, and `file.macho` (`file,memory` and `file.pe,memory` are lists), or to a value that is not a string (`context = 1`). In the decomposed form, the `context` deploy writes from `meta.context` and `meta.os` is checked the same way. `opentide validate` does not fail on it. `file`, `memory`, and `file,memory` are the values HarfangLab's published rules use; `file.pe`, `file.elf`, and `file.macho` are what the decomposed form writes for `file`. No HarfangLab document defines the key, so another value may be accepted and never scanned.

### Example

```yaml
configurations:
  harfanglab:
    yara:
      signature: |
        rule Cmd_String {
          meta:
            context = "disk"   # not a HarfangLab context
          strings:
            $a = "cmd.exe" ascii
          condition:
            $a
        }
```

### How to fix

Set `context` to where the agent should scan: `file`, `memory`, or both (`file,memory`), or a file type (`file.pe`, `file.elf`, `file.macho`), joined with commas and no spaces. In the decomposed form, list them under `meta.context`. Then run `opentide lint --check queries` again.

```yaml
          meta:
            context = "file,memory"
```

## harfanglab_yara_form

A HarfangLab yara object sets signature together with decomposed keys (meta, strings, condition or imports).

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## harfanglab_yara_import

A decomposed HarfangLab YARA imports entry is not a module the YARA language knows.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## harfanglab_yara_rule_name

The YARA rule name deploy derives from the rule name is a YARA keyword or keeps a character other than an ASCII letter, digit or underscore.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## harfanglab_yara_section_header

A decomposed HarfangLab YARA fragment contains a strings:, condition: or rule header, which deploy writes itself.

Reported by the analysis engine for an object file: an editor running `opentide lsp start` shows it. `opentide validate` and `opentide lint` are the authority for objects and name the same problem with their own code.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

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

## interrupted

The command was stopped before it finished: an `opentide serve` client cancelled the run.

Exit 130, as Ctrl-C at a terminal exits. The command's own cleanup ran first (an open search is stopped, a file being written is not left half-written), so whatever it had not done yet was not done. A command stopped this way prints no document of its own, so `opentide serve` answers with one that carries this code.

### Example

```json
{"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": 7}}
```

### How to fix

Nothing is broken. Run the command again when you need its result; a `validate` or `lint` that was cancelled wrote nothing.

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

Exit 1, as `failure.code`. Set by `validate` (errors, or warnings under `--strict`), `lint --strict` (findings), `info --strict` (load errors) and `deploy` (a rule the platform refused). The findings are in the same document, each with its own code; a `deploy` lists every rule in `results` with its `status`, the platform's message in `error`, and the rules it never reached as `not_attempted`.

### Example

```text
opentide validate
```

### How to fix

Fix the findings the command printed. Each one names its code: `opentide explain <code>` says how to fix it. After a failed `deploy`, fix the rule on the `✗ failed` line, or the tenant it names, then run the command again: the rules before it were deployed, and the ones marked `not attempted` were not sent.

## kql_control_command_unsupported

A KQL control command (.show, .create, ...) is not a detection query; rules cannot run it.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_deprecated_function

The KQL function is a deprecated alias; Microsoft Learn names its replacement.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_deprecated_operator

The KQL scalar operator is a legacy spelling (containscs); use the current name (contains_cs).

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_join_summarize_before_project

join or summarize runs before project, so it carries every column.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_parse_error

The KQL query does not parse.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_render_not_valid

render draws a chart; it has no effect in a detection rule.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_table_not_declared

The table is one the engine knows for the platform, but no log source of the workspace declares it in visibility.toml.

Severity: warning. Reported by the analysis engine on a KQL query (`sentinel`, `defender_for_endpoint`): `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. It is opt-in per system: only a workspace whose `visibility.toml` has at least one log source for that platform gets it. It applies to a table the engine's catalog knows (a built-in table such as `SigninLogs`) that no log source names; a table the catalog does not know and no log source names is `kql_unknown_table` instead. Every name a query reads from counts (a pipeline's first source, a `union` leg, a `join` or `lookup` right side), whatever its case, except a `let` binding, a query parameter or a function the engine knows, so a workspace function is declared as a log source too. `*` in a declared name matches any run of characters.

### Example

```toml
[[logsources]]
name = "NTANetAnalytics"
description = "Traffic analytics on the production VNet flow logs."
system = "sentinel"
```

```kusto
NTAIpDetails   // known to the engine, not declared for sentinel
| where FlowType == "MaliciousFlow"
```

### How to fix

Correct the table name, or declare it: add a log source whose `name` is the table (or a pattern such as `*_CL` that covers it) in `visibility.toml`. The editor applies the change as you type it; the CLI reads the file on its next run. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).

```toml
[[logsources]]
name = "NTAIpDetails"
description = "IP details from traffic analytics."
system = "sentinel"
```

## kql_type_mismatch

The operator cannot apply to the column's documented or declared type.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unknown_column

The column is not in the documented schema of the table or ASIM parser it comes from, or in the columns visibility.toml declares for the table.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unknown_function

The KQL function is not in the Kusto function catalog.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unknown_operator

The KQL tabular operator is not one Kusto knows.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unknown_table

The table is neither one the engine knows for the platform nor one the workspace declares in visibility.toml: a warning under Sentinel, whose workspaces hold tables no catalog lists; an error under Defender's advanced hunting schema. Declaring it in visibility.toml makes it known.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unscoped_search

search without a table scans every table in the workspace.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_unscoped_union

union * or an unscoped union reads every table.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_where_not_first

A filter comes after a more expensive operator; filtering first scans fewer rows.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kql_wildcard_table

A wildcard table name reads every matching table.

Reported by the analysis engine in a KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [KQL reference](https://learn.microsoft.com/kusto/query/) describes the syntax and the commands the engine checks against.

## kuery_escape

A character needs escaping in Kibana KQL (kuery).

Reported by the analysis engine in a Kibana KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_free_text

A value with no field searches every field.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_looks_like_lucene

The query reads like Lucene; language: lucene may be meant.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_lucene_syntax

Lucene syntax inside a Kibana KQL (kuery) query.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_parse_error

The Kibana KQL (kuery) query does not parse.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_question_mark

? is a literal in Kibana KQL (kuery), not a single-character wildcard.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_quoted_wildcard

A wildcard inside quotes is a literal * in Kibana KQL (kuery).

Reported by the analysis engine in a Kibana KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## kuery_range_type

A range compares a value of the wrong type.

Reported by the analysis engine in a Kibana KQL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Kibana KQL reference](https://www.elastic.co/docs/reference/query-languages/kql) describes the syntax and the commands the engine checks against.

## lookback_long

The Elastic rule's lookback exceeds an hour; it is added to the interval, not the whole window.

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.

### Example

```text
opentide lint --check queries
```

### How to fix

Change the block's setting the frame points at, then run `opentide lint --check queries` again.

## lookback_zero

The Elastic rule's lookback is zero, so events that arrive late are missed.

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.

### Example

```text
opentide lint --check queries
```

### How to fix

Change the block's setting the frame points at, then run `opentide lint --check queries` again.

## lsp_catalog

opentide can generate the language server's catalog for this workspace, and a committed copy is current.

Reported by `opentide doctor`. `opentide lsp start` and `opentide tui` check objects with the catalog this opentide generates from its models and the workspace's configuration, cached under the user cache directory (`OPENTIDE_CACHE_DIR` overrides it). The copy `opentide generate schemas` writes to `.opentide/lsp/catalogs/generated/` is read only by editors that run the `opentide-lsp` binary on its own, and when generation fails. Warns when the catalog cannot be generated, or when a committed copy does not parse or comes from another opentide version.

### Example

```text illustrative
! The language-server catalog committed in .opentide/lsp/catalogs/generated is from opentide 0.18.0, not 0.19.0: editors that run opentide-lsp on their own use it · lsp_catalog
  → opentide generate schemas
```

### How to fix

For a committed copy, run `opentide generate schemas` (or `opentide generate`) and commit the files it writes, so editors that run `opentide-lsp` on its own use the same catalog. When the catalog cannot be generated, `opentide doctor --debug` shows why; until then objects are checked with the committed or the bundled catalog.

## lucene_bare_term

A term with no field searches every field.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_elasticsearch_only

The syntax works in Elasticsearch but not in Carbon Black Cloud.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_escape

A character needs escaping in Lucene.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_fuzzy

Elasticsearch accepts only 0, 1, 2 or AUTO as a fuzziness.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_kuery_syntax

Kibana KQL (kuery) syntax inside a Lucene query.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_looks_like_kuery

The query reads like Kibana KQL (kuery); language: kuery may be meant.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_lowercase_operator

Lucene operators are upper case; lowercase and/or/not are search terms.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_mixed_operators

AND and OR mixed without parentheses do not bind as they read.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_parse_error

The Lucene query does not parse.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_range_operator

f:> 10 searches f for the text >; the value must follow the operator.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_regexp

The /regexp/ body is rejected by, or too costly for, Lucene's RegExp.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

## lucene_unescaped_slash

An unescaped / starts a regular expression.

Reported by the analysis engine in a Lucene query string query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [Lucene query string reference](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-query-string-query) describes the syntax and the commands the engine checks against.

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

Reported by `opentide doctor`. Warns when no configuration has such a server, or its command is not on `PATH`; skipped when there is no configuration. Passes without one when `.vscode/extensions.json` recommends the opentide VS Code extension (`opentidehq.opentide`), which provides the opentide MCP server to VS Code; with both, the message says so, since `.vscode/mcp.json` then serves teammates without the extension.

### Example

```text illustrative
○ No MCP configuration: agents in editors cannot call opentide tools · mcp_config
  → opentide setup mcp --vscode (or --cursor, --claude-code, --generic)
```

### How to fix

Run `opentide setup mcp` with your editor's flag.

## metadata_recommended

An object has no `metadata.author` or `metadata.organisation`.

Severity: note. Reported by `opentide lint` (metadata check). The editor (`opentide lsp start`) and `opentide tui` report the same finding, at the severity `[metadata]` sets.

### Example

```yaml
metadata:
  uuid: 00000000-0000-4000-8001-000000000001
  # author and organisation are missing
```

### How to fix

Add the missing keys under `metadata`. They are optional, so the note never fails a run, `lint --strict` included, and prints only with `--verbose`. To require them, set `severity = "warning"` or `"error"` under `[metadata]` in `.opentide/configurations/lint.toml`; to stop asking for them, set `required = []`.

## missing_author

Retired in opentide 0.24.0; `opentide lint` reports a missing recommended metadata field as `metadata_recommended`.

Severity: warning, while it was reported. The recommended `metadata.author` field was missing.

Until opentide 0.24.0, the language server reported it as a warning on every object without an author, where `opentide validate` reported nothing and `opentide lint` reported `metadata_recommended` (KG-05).

### Example

```text
opentide lint --check metadata
```

### How to fix

Nothing to fix: no command reports this code any more. A suppression list or SARIF baseline that names it can drop it.

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

Retired in opentide 0.24.0; `opentide lint` reports a missing recommended metadata field as `metadata_recommended`.

Severity: warning, while it was reported. The recommended `metadata.organisation` field was missing.

Until opentide 0.24.0, the language server reported it as a warning on every object without an organisation, where `opentide validate` reported nothing and `opentide lint` reported `metadata_recommended` (KG-05).

### Example

```text
opentide lint --check metadata
```

### How to fix

Nothing to fix: no command reports this code any more. A suppression list or SARIF baseline that names it can drop it.

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

Replace the value with the real one, then delete the `# opentide:placeholder` comment on that line. The object validates with the stand-in, so only `lint` notices it; `lint --strict` fails until every marker is gone. A placeholder query (`...`) is not sent to the analysis engine either: `validate`'s and `validate query`'s queries checks skip it, and `lint`'s `queries` check leaves it to this one.

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

## query_check_timeout

`validate query --live` failed because a tenant did not answer a query's check within the check timeout.

Exit 1, as `failure.code` when every failed check timed out; as the `code` of each entry under `timed_out` otherwise. Only that rule's check fails: the other rules are still checked. A tenant is reported unreachable only after 3 queries in a row get no answer.

A read timeout, a gateway or proxy's HTTP 502, 503 or 504 page, or a SentinelOne PowerQuery still running at the deadline all count. The default timeout is 120 seconds.

### Example

A live check of 403 Splunk rules where one parse took longer than 120 seconds, trimmed to the keys that say so (illustrative: it needs a tenant):

```json illustrative
{"status": "failed", "exit_code": 1, "message": "Queries rejected on splunk · 403 checked on 1 tenant · 1 with no answer within 120s", "check_timeout": 120.0, "timed_out": [{"code": "query_check_timeout", "…": "…"}], "failure": {"code": "query_check_timeout", "message": "…"}}
```

### How to fix

Raise the timeout with `--check-timeout SECONDS` or `OPENTIDE_QUERY_CHECK_TIMEOUT`, or make the query cheaper. When a gateway answered (HTTP 504), its own timeout may be shorter than the check's: raise the gateway's timeout too.

## recommended_field_missing

A field the templates ask for is missing; `opentide validate` accepts the object without it.

Severity: note. Reported by `opentide lint` (recommended check). Today it is a rule's `configurations` or `response`. The editor (`opentide lsp start`) and `opentide tui` report the same finding, at the severity `[recommended]` sets.

### Example

```yaml
name: Suspicious sign-in
metadata:
  uuid: 00000000-0000-4000-8001-000000000002
  schema: rule::1.0
# no configurations: nothing to deploy yet
# no response: no alert guidance for the analyst
```

### How to fix

Add the field when the rule is ready for it: `configurations` with a block per platform to deploy to, `response` with the alert guidance. The note never fails a run, `lint --strict` included, and prints only with `--verbose`. To require them in `opentide lint`, set `severity = "warning"` or `"error"` under `[recommended]` in `.opentide/configurations/lint.toml`; to stop reporting them, set `enabled = false`.

## reference_not_found

`--objective` or `--threat` names a UUID that no object in the catalogue carries.

Exit 2, as `failure.code`, with `failure.argument` naming the option. `opentide new` checks the reference before it writes anything; a malformed UUID is `usage_invalid_value` instead.

### Example

```text
opentide new rule --name "LSASS Access" --objective 00000000-0000-4000-8000-000000000000
```

### How to fix

Copy the UUID from the object's `metadata.uuid`, or create that objective or threat first with `opentide new objective` or `opentide new threat`. `opentide info` lists the catalogue.

## retired_configuration_file

A file or folder under `.opentide/configurations/` that opentide does not read.

Severity: error. Reported by every command that reads the configuration (`validate`, `deploy`, `generate`, …), which then stops with exit 1 and `failure.code` `retired_configuration_file`, for these entries of the workspace's (or the parent instance's) `.opentide/configurations/`:

| Entry | What replaces it |
|-------|------------------|
| `global.toml` | `paths.toml`: workspace paths and artifact names |
| `schema.toml` | Nothing: template defaults are not configurable, and vocabularies are not extended locally |
| `systems/` | `platforms/<platform>.toml` |

Loading such a file and ignoring it would leave the workspace believing it is configured by settings that have no effect.

### Example

```text illustrative
.opentide/configurations/
├── global.toml
└── systems/
    └── splunk.toml
```

### How to fix

Move the settings you need into the file the diagnostic names (`paths.toml`, `platforms/<platform>.toml`), in its current format, then delete the retired file or folder. `opentide validate --check configuration` then checks what you moved.

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

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.

### Example

```text
opentide lint --check queries
```

### How to fix

Change the block's setting the frame points at, then run `opentide lint --check queries` again.

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

The message is the schema's own (a missing required field, a wrong type, an unknown key). The location points at the field, or at the mapping it belongs in when the field is missing. Compare the object with the template under `.opentide/templates/`, or let the opentide VS Code extension check it as you type (`opentide setup vscode` recommends it). A `metadata.schema` that names no registered revision, or another object type, is reported with this code as well.

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

## spl_command_without_pipe

The query starts with a command name but no |, so Splunk searches for the word instead of running the command.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_dataset_not_declared

The sourcetype is not one the workspace declares in visibility.toml.

Severity: warning. Reported by the analysis engine on an SPL search (`splunk`): `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it; `opentide validate` does not fail on it. It is opt-in: only a workspace whose `visibility.toml` has at least one `splunk` log source gets it, for a sourcetype no log source names, whether or not the engine knows it otherwise. A Splunk log source's `name` is its sourcetype; indexes and macros are not declared. Names match regardless of case, and `*` matches any run of characters.

### Example

```toml
[[logsources]]
name = "WinEventLog:Security"
description = "Security event log of the domain controllers."
system = "splunk"
```

```text illustrative
sourcetype=XmlWinEventLog:Security EventCode=4688   # not declared
```

### How to fix

Correct the sourcetype, or declare it: add a `splunk` log source whose `name` is the sourcetype (or a pattern that covers it) in `visibility.toml`. The editor applies the change as you type it; the CLI reads the file on its next run. See [The datasets a log source fills](../usage/configuration.md#the-datasets-a-log-source-fills).

```toml
[[logsources]]
name = "XmlWinEventLog:Security"
description = "Security event log, XML rendering."
system = "splunk"
```

## spl_empty_command

A command with no arguments: Splunk runs it, but it does nothing, returns no results, or fails at run time.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_empty_stage

A trailing | with no command; Splunk ignores it.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_leading_not

A base search that starts with NOT scans every event before excluding any.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_parse_error

The SPL search does not parse.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_search_operator

A search clause compares with an operator search does not have (`==`, `<>`, `=>`, `=<`, `!~`): Splunk accepts it but the comparison never matches, or `=~`, which compares with a value that starts with `~`.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_subsearch_truncation

A subsearch is silently truncated at its result or time limit.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_unknown_command

The SPL command is not in the Splunk Search Reference or a catalogued app such as MLTK: a warning, since an app on the search head can add commands, or an error when the name is one edit from a known command.

Reported by the analysis engine in an SPL query (`splunk`), at the place in the query. One edit from a known command (`stas` for `stats`), it is an error, a query the platform would reject: `opentide validate` (its `queries` check) and `opentide validate query` fail on it, and the help names the command. Further from every known command, it is a warning: a command an app on the search head provides (`decrypt`, `mispsearch`) looks the same, so `validate` passes and `opentide lint` (its `queries` check) reports it. An editor running `opentide lsp start` shows both.

opentide has no setting that declares a search head's app commands yet: neither `visibility.toml` nor `platforms/splunk.toml` takes a list of them, so the warning stays for every query that uses one. Through 0.20.1 the CLI's message asked to declare the command, which nothing could do; an editor running `opentide lsp start` still shows the engine's own wording, which does.

### Example

```text illustrative
index=main sourcetype=misp | mispsearch value=evil.example | table value
```

### How to fix

When the name is a typo, correct it. When an app on the search head provides the command, the warning is expected and the query deploys as written. `opentide lint --strict` fails on any finding, so a catalogue that gates on it and uses app commands narrows the gate to the files a change touches (`opentide lint --strict --changed`), or turns the `queries` check off in `lint.toml` (`[queries] enabled = false`), which drops every other query style finding too.

## spl_unknown_datamodel

The CIM data model or dataset is not one Splunk CIM defines.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_unknown_datamodel_field

The field is not in the CIM data model the search reads.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## spl_wildcard

A leading or mid-token wildcard in a base search that nothing else narrows (no index, sourcetype, source, host, TERM() or macro) cannot use the index and scans every event.

Reported by the analysis engine in a SPL query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [SPL reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference) describes the syntax and the commands the engine checks against.

## sysdig_definition_duplicate

A name is defined more than once across the block's macros and lists.

Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## sysdig_definition_name

A block macro or list name is not `[A-Za-z_][A-Za-z0-9_]*`, or is a Falco operator or keyword.

Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## sysdig_definition_order

A block macro uses itself or a macro defined after it: Falco gives a macro no view of itself or later macros, and refuses it as an undefined macro.

Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## sysdig_exception_shape

An exception's fields, comps, and values do not have a shape Falco's rule loader accepts (`validate_exception_info`).

Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## sysdig_list_in_value

A block list name appears in an exception value where Falco's expansion would not produce a value list.

Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## sysdig_list_self_reference

A block list names itself as one of its items, so its own name stays in the expanded condition.

Severity: warning. Reported by the analysis engine on a Sysdig rule (`sysdig`): an item of one of the block's `lists` is that list's own name. `opentide lint` (its `queries` check) shows it; `opentide validate` does not fail on it, and since UC-2.6 an editor running `opentide lsp start` does not show it either: the editor publishes what `opentide validate` reports on the object, and the block's advisories are lint's. Falco loads the rule: it flattens a list with the lists defined before it only, and its `resolve_list` pass never re-scans the items it has just inserted, so the name is left in the text as a literal value. On Sysdig Secure that literal then resolves against any tenant list of the same name, or matches the bare string. A list naming a later block list is not this advisory: the later list's own pass expands it, as Falco does.

### Example

```yaml
configurations:
  sysdig:
    condition: spawned_process and proc.name in (shells)
    lists:
      - name: shells
        items: [bash, zsh, shells]   # deploys as proc.name in ( bash, zsh, shells )
```

### How to fix

Remove the item, or name the other list you meant. To extend a list with another, define that list before it in the block, or after it if you prefer: both expand.

```yaml
    lists:
      - name: more_shells
        items: [fish, ksh]
      - name: shells
        items: [bash, zsh, more_shells]   # deploys as proc.name in ( bash, zsh, fish, ksh )
```

## sysdig_priority

`priority` is not one of Falco's eight priorities (or `INFO`), compared case-insensitively.

Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## sysdig_rule_shape

A Sysdig block is a new rule with a non-blank `condition`, or a tuning (`append_to_rule`) that appends a condition, exceptions, or both.

Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## sysdig_source

`source` is not an event source name (`[a-z][a-z0-9_]*`).

Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## sysdig_tuning_keys

A tuning (`append_to_rule`) inherits `output`, `priority`, `policies`, `source`, and `name` from the rule it tunes, so it must not set them.

Named by `opentide validate`: the Sysdig block's model check reports a `schema_validation` finding on the object whose message lists the codes it broke (`SysdigConfig validation failed with code(s): ...`), and an editor running `opentide lsp start` shows that finding. The analysis engine reported it a second time until UC-2.6; `opentide validate` is the one authority for the block's constraints.

### Example

```text
opentide validate
```

### How to fix

Change the file where the frame points, then run `opentide validate` again.

## technique_not_enterprise

The ATT&CK technique is not in the Enterprise matrix that Elastic maps.

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.

### Example

```text
opentide lint --check queries
```

### How to fix

Change the block's setting the frame points at, then run `opentide lint --check queries` again.

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

Reported by `opentide doctor`. Warns when a template is missing or differs, usually after an upgrade. The comparison renders the `metadata` keys `lint.toml` requires (`[metadata].required`) as live keys, as `opentide generate templates` does. It also warns, naming the key, when `lint.toml` parses but holds a value opentide rejects: the templates cannot be compared until it is fixed.

### Example

```text illustrative
! 2 template(s) differ from what this version generates: rule, threat · templates_fresh
  → opentide generate templates
```

### How to fix

Run `opentide generate templates`. When the warning names a `lint.toml` key, fix that key first: `generate` fails on the same file, so regenerating does not clear it. A `lint.toml` that is not valid TOML is reported by the `configuration` check instead, and this check is skipped.

## threshold_lookback

A threshold rule's lookback exceeds its interval, so windows overlap and alerts repeat.

Reported by the analysis engine on an Elastic rule block (elastic-1.0): `opentide lint` (its `queries` check) shows it, and `opentide validate query --platform elastic --live` checks the same settings. Since UC-2.6 an editor running `opentide lsp start` does not: it publishes what `opentide validate` reports on the object, and the block's advisories are lint's.

### Example

```text
opentide lint --check queries
```

### How to fix

Change the block's setting the frame points at, then run `opentide lint --check queries` again.

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

Use a value from the vocabulary the label names. When a close value exists, `help` names it and `fix` carries the edit; the edit is marked `safe` only when the two spell the same word (they differ in case, spaces, `-` or `_`) and hold no digit, so an ATT&CK id is never replaced unreviewed. The opentide VS Code extension completes vocabulary values (`opentide setup vscode` recommends it).

## vscode_settings

The workspace recommends the opentide VS Code extension (`opentidehq.opentide`) in `.vscode/extensions.json`, and `.vscode/settings.json` maps no object files to opentide's JSON schemas in `yaml.schemas`.

The extension's language server checks object files. A `yaml.schemas` mapping to `.opentide/schemas/opentide.schema.json`, which earlier releases wrote, makes a YAML extension report the same problems a second time.

Reported by `opentide doctor`. Warns when `settings.json` maps objects to opentide's schemas (the globs written as a string or as a list, as the YAML extension accepts both), when `extensions.json` does not recommend the extension, or when either file is not valid JSON; skipped when there is no `.vscode/extensions.json`.

### Example

```text illustrative
! .vscode/settings.json maps objects to .opentide/schemas/opentide.schema.json in yaml.schemas: a YAML extension would report what the opentide extension already does · vscode_settings
  → opentide setup vscode
```

### How to fix

Run `opentide setup vscode`. It recommends the extension and removes opentide's `yaml.schemas` entries, keeping your other settings.

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

`opentide new` ran outside a workspace: neither `.opentide/` nor `objects/` is there. Or the MCP server was started in an Agent Plugin's directory, which is not a workspace, and nothing named one.

Exit 1, as `failure.code`. `new` writes only into a workspace, the folder `--repo` names or the one discovery finds, so a stray run in your home directory cannot make it a workspace that every folder below it would discover.

The MCP server reports it as an error from every tool and resource that reads the catalogue (`search`, `validation_report`, `deploy_rule`, `opentide://rules`, ...). An Agent Plugins client starts a plugin's server in the plugin's directory; the server never serves that directory, such as the opentidehq/skills package, as the catalogue. `explain` and offline `validate_query` still answer.

### Example

```text illustrative
cd ~ && opentide new threat --name "Credential Dumping"
```

### How to fix

Run it from inside your detection repository, or pass `--repo path/to/detections`. To start a new one, run `opentide setup`. `opentide doctor` applies the same test as its `workspace` check.

For the MCP server, set `OPENTIDE_REPO_ROOT` to the detection repository in the host's settings for the `opentide` server, or start the host from inside the repository, so its `PWD` (or Claude Code's `CLAUDE_PROJECT_DIR`) lies in it. `opentide setup mcp`, run in the repository, writes the host's MCP file with the project directory filled in.

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

## yara_duplicate_rule

Two YARA rules in one signature have the same name.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_duplicate_string

Two strings of one YARA rule have the same identifier.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_duplicate_tag

A YARA rule repeats a tag.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_empty_signature

The YARA signature has no rule, or only private or global rules.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_entrypoint_deprecated

entrypoint is deprecated in libyara and refused by YARA-X; use pe.entry_point or elf.entry_point.

Reported by the analysis engine in a YARA rule query, at the place in the query, always as a warning: the platform takes the rule, so `opentide validate` does not fail on it, and `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it.

### Example

```text
opentide lint --check queries
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_hex_string

A YARA hex string is invalid: an odd number of nibbles, a bad jump, or unbalanced alternatives.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_include

A YARA signature uses an include directive, which no platform resolves: each API takes one text with no file system behind it.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_meta_missing

A HarfangLab YARA rule has no meta `context`, which the HarfangLab profile recommends on every rule that is not private.

Severity: warning. Reported by `opentide lint` (its `queries` check) on a HarfangLab rule (`harfanglab`). In the signature form, a rule that is not `private` has no `meta:` section, or one without `context`. `opentide validate` does not fail on it. Deploy sends the signature verbatim and adds no meta, so the agent receives the rule without saying where to scan. In the decomposed form, an empty `meta.context: []` is the same finding: deploy then writes the rule with no `context` line.

### Example

```yaml
configurations:
  harfanglab:
    yara:
      signature: |
        rule Cmd_String {
          strings:
            $a = "cmd.exe" ascii
          condition:
            $a
        }
```

### How to fix

Add a `meta:` section with `context` to the rule (`file`, `memory`, or `file,memory`), then run `opentide lint --check queries` again. A `private` helper rule needs none.

```yaml
        rule Cmd_String {
          meta:
            context = "file"
          strings:
            $a = "cmd.exe" ascii
          condition:
            $a
        }
```

## yara_module_not_imported

A YARA module field or function is used without importing its module.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_module_unconfirmed

The YARA module is known but not confirmed on the platform's agents.

Reported by the analysis engine in a YARA rule query, at the place in the query, always as a warning: the platform takes the rule, so `opentide validate` does not fail on it, and `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it.

### Example

```text
opentide lint --check queries
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_number_out_of_range

A YARA integer, size suffix, jump bound or string index is outside the range libyara accepts.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_parse_error

The YARA signature does not parse as libyara 4.5 reads it.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_regexp

A YARA regular expression is invalid.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_rule_identifier_conflict

A YARA rule is named like a keyword, or matches a rule wildcard an earlier condition uses; a rule named like an imported module is yara_x_incompatible.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_signature_alias

A `yara.signature` is a YAML alias of text anchored elsewhere in the file instead of YARA written in the block.

Severity: error. Reported by `opentide validate` (its `schema` check) on a rule whose `configurations.harfanglab.yara.signature` or `configurations.bitdefender.yara.signature` is `*name` (yara-1.0). What a block deploys must be readable in the block: an alias makes a change to the anchored text, under any other key, change the deployed rule too, and a signature in two platform blocks is checked once under each platform's profile. The YAML loader cannot tell an alias from text written in place, so `opentide validate` reads the file's node graph.

### Example

```yaml
configurations:
  harfanglab:
    yara:
      signature: &shared_yara |
        rule Cmd_String { condition: true }
  bitdefender:
    yara:
      signature: *shared_yara
```

### How to fix

Write the YARA text under each `signature` with a block scalar (`|`), then run `opentide validate` again.

```yaml
configurations:
  bitdefender:
    yara:
      signature: |
        rule Cmd_String {
          condition:
            true
        }
```

## yara_slow_pattern

libyara warns that this YARA string or loop may slow scanning down.

Reported by the analysis engine in a YARA rule query, at the place in the query, always as a warning: the platform takes the rule, so `opentide validate` does not fail on it, and `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it.

### Example

```text
opentide lint --check queries
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_string_modifier

libyara refuses this combination of YARA string modifiers, or an xor or base64 argument is out of range.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_suspicious_expression

A YARA condition is invariant, unsatisfiable or not boolean, or compares an integer with a boolean.

Reported by the analysis engine in a YARA rule query, at the place in the query, always as a warning: the platform takes the rule, so `opentide validate` does not fail on it, and `opentide lint` (its `queries` check) and an editor running `opentide lsp start` show it.

### Example

```text
opentide lint --check queries
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_type

A YARA operator or function is applied to a value of the wrong type.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_undefined_identifier

A YARA identifier is neither a rule defined earlier in the signature nor an imported module, or is used as libyara refuses: a module field called as a function, a module function named without a call, or a loop variable a loop already binds.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_undefined_string

A YARA condition names a string ($id, #id, @id, !id or $prefix*) that the rule does not define.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_unknown_module

A YARA import names a module libyara does not ship.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_unknown_module_member

The YARA module has no such field or function, or the function takes other arguments.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_unreferenced_string

A YARA string is never used in the condition, which libyara refuses unless the condition uses them.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yara_x_incompatible

libyara 4.5 compiles this YARA but YARA-X 1.x refuses it.

Reported by the analysis engine in a YARA rule query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA rule reference](https://yara.readthedocs.io/en/v4.5.2/writingrules.html) describes the syntax and the commands the engine checks against.

## yaral_condition_shape

The condition is not one Google compiles: `not` or a comma on event terms, `or` across too many event variables or in an unbounded condition, or non-existence without a window and a bounded event.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_deprecated_field

The UDM field is deprecated.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_enum_value

The value is not one of the enumerated UDM field's values.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_export_value

An `export` `write_row` value is not an outcome variable: Google exports outcome variables only.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_function_unavailable

The function exists, but not in this profile (rules or search).

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_leading_wildcard_regex

The regular expression starts with `.*` without an anchor: RE2 matches anywhere already, and the prefix only costs time.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_match_shape

The `match` block is not a YaraLMatch: `group_by` and `window`, and `pivot` and `direction` exactly when `type` is `sliding`.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_match_variable

A `match` name is not a placeholder bound in `events`.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_match_window

The match window is outside its bounds (hop and sliding 1m to 14d in a rule, 1m to 48h in a search; tumbling 1m to 72h) or has a unit other than m, h or d.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_meta_duplicate

A meta key appears twice, or a meta value is not a double-quoted string.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_multi_event_match

A rule with two or more event variables has no `match` section.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_nocase_on_enum

`nocase` is applied to a comparison with an enumerated UDM field.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_option

An unknown option, or an option value of the wrong kind.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_outcome_aggregation

With `match`, an outcome reads an event field, or a placeholder that is not a `match` variable, outside an aggregation; or it aggregates an outcome variable.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_outcome_limit

A rule or search assigns more than 20 outcome variables.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_parse_error

The YARA-L text does not parse, or a text holds a second rule.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_reference_list_deprecated

Reference lists are deprecated from May 2027 and migrate to data tables by July 2027: use a data table (`%table.column`).

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_reference_list_limit

More `in` statements than the profile allows (rules: 10, 5 with regex, 5 with cidr; search: 7, 4, 2).

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_regex

The regular expression is not valid RE2.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_reserved_identifier

A YARA-L keyword is used as a rule name, meta key or variable, or a variable is named `$window_start` or `$window_end`.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_section_alias

A YARA-L section key is a YAML alias: write the section out in the block, so the block shows what it deploys.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_section_empty

A YARA-L section key has no text. A plain YAML scalar that starts with `#` is a YAML comment, so it loads as null: write the text as a block scalar (`|`).

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_section_header

A `google_secops` section text holds a section label, a `rule` header, or braces around a rule: deploy writes those, so each key holds its section's body only.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_section_missing

A required YARA-L section is absent: `meta` in a rule file, `events` and `condition` in every rule.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_section_order

A YARA-L section is repeated or out of order (meta, setup, events, match, outcome, condition, options, export).

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_section_unavailable

The section is not part of this profile: `dedup`, `order`, `limit`, `select` and `unselect` are search sections; `meta`, `setup` and `options` are rule sections.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_string_escape

A double-quoted string holds an escape Google does not document (only backslash, double quote, n, r and t); the tenant decides whether it compiles.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_type

An operator or function is applied to a value of the wrong type: a count compared with a string, `any` or `all` on a map key, `nocase` on a number.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_undefined_variable

A variable in `match`, `outcome` or `condition` is not defined by `events` or `outcome`, or an event variable of `events` is absent from `condition`.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_unfiltered_event

An event variable has no equality on `metadata.event_type`, `metadata.log_type` or `metadata.product_name`, so the rule scans every event.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_unknown_function

The function is not in Google's YARA-L function list, or it takes a different number of arguments.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_unknown_udm_field

The field path is not in the Unified Data Model.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.

## yaral_window_bound

`window_start` or `window_end` is used in `events`, or in a rule or search with no `match` window.

Reported by the analysis engine in a YARA-L 2.0 query, at the place in the query: as an error, a query the platform would reject, by `opentide validate` (its `queries` check) and `opentide validate query`; as a warning or a note, style, by `opentide lint` (its `queries` check). An editor running `opentide lsp start` shows both.

### Example

```text
opentide validate query
```

### How to fix

Change the query where the frame points, then run `opentide validate query` (`--file` for one rule or query file) or `opentide lint --check queries` again. The [YARA-L 2.0 reference](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax) describes the syntax and the commands the engine checks against.
