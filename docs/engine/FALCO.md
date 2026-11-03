# Falco conformance

The Falco language engine (`crates/opentide-falco`) checks a Sysdig Secure / Falco rule (`configurations.sysdig`, sysdig-1.0) against the sources Falco itself runs, not against documentation:

| Layer | Source of truth | Engine |
|-------|-----------------|--------|
| Syntax | falcosecurity/libs `userspace/libsinsp/filter/parser.{h,cpp}`, `escaping.cpp` | `parser.rs`, a step-for-step port |
| Compile checks | libs `filter.cpp`, `filter_compare.cpp`, `value_parser.cpp`, `sinsp_filtercheck*.cpp`, `plugin_filtercheck.cpp`, `sinsp_filter_transformers/`, `sinsp_filtercheck_multivalue_transformer.cpp`, `filter/ppm_codes.cpp` | `compile.rs` |
| Rule loading | falcosecurity/falco `userspace/engine/rule_loader_{reader,collector,compiler}.cpp`, `filter_warning_resolver.cpp`, `falco_load_result.cpp`, `falco_common.cpp` | `lib.rs`, `exceptions.rs` |
| Fields, events | libs field tables, `driver/event_table.c`, `driver/ppm_events_public.h`; plugin READMEs | `catalogs/falco/` (`scripts/sync_falco_catalog.py`) |

Pinned revisions: libs `f13bc241815d463be433e947b90f42713df1abf9`, falco `b3c37fe82155ce58b6c4fb440b2a72559bb7453f`, plugins `9064e9d620538aebf32912fa00f6b9ef95d46a37`, rules `e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428`.

## Conformance results

| Suite | Fixtures | Agreement | Harness |
|-------|----------|-----------|---------|
| libs parser tests (`filter_parser.ut.cpp`) | 571 expressions (376 accepted, each also padded, with line breaks, with tabs; 195 rejected; 4 exact messages; 7 printed ASTs) + the recursion-limit case | 100 % | `tests/libsinsp_parser.rs` |
| libs compiler tests (`filter_compiler.ut.cpp`) | 326 filters (153 refused, 15 warnings) | 100 % | `tests/libsinsp_compiler.rs` |
| **real Falco 0.45.2** (`falco --validate`, libs 0.26.1, the three default rules files loaded) | 358 cases: the 166 of `testdata/oracles/falco/cases.yaml` (every row of this page) and the 192 default-rule conditions and broken twins; Falco loads 205, refuses 153 | 358 / 358: 353 identical, 5 documented differences (3 Sysdig-managed names, 2 stricter by spec), 0 disagreements | `scripts/oracles/falco/oracle.py`, `oracle.yml` → Falco |
| Falco default rules (`falcosecurity/rules`, plugin rules) | 241 conditions across six sources, unmodified | 241 / 241 clean (no finding), every broken twin a parse error | `crates/opentide-analysis/tests/external_falco.rs` |
| Public rules converted to opentide (`testdata/workspaces/falco/`) | 9 rules (syscall, k8s_audit, aws_cloudtrail, a tuning) | clean end to end, every injected fault reported where it is written | `crates/opentide-analysis/tests/falco_rules.rs` |
| tree-sitter grammar (highlighting) | the 376 accepted libs inputs | 375 / 376 (`test.op existsand macro`, below) | `tests/tree_sitter_agreement.rs` |

Both harnesses were checked to fail when the engine is wrong (a reordered list-operator table, a numeric operator table that allows everything).

## Grammar productions (`parser.h`)

| Production | Status | Proven by |
|------------|--------|-----------|
| `Expr ::= OrExpr`; `OrExpr ::= AndExpr ('or' OrExprTail)*`; `OrExprTail ::= ' ' AndExpr \| '(' Expr ')'` (`or(`) | yes | parser.json `parse_smoke_test`, `expr_parenthesis` |
| `AndExpr`, `AndExprTail` (`and(`) | yes | parser.json |
| `NotExpr ::= ('not ')* NotExprTail`; `NotExprTail ::= 'not(' Expr ')' \| Check`; `not` + POSIX `[[:space:]]+`; double negation cancels | yes | `expr_multi_negation`; `parser.rs` `precedence_and_ast_strings` |
| `Check ::= Field Condition \| FieldTransformer Condition \| Identifier \| '(' Expr ')'` | yes | parser.json |
| `FieldTransformer`, `FieldTransformerTail` with a trailing `[FieldArg]` | yes | `parse_transformer_with_arg`, `transformer_arg_optional` |
| `FieldTransformerArg ::= FieldTransformer \| Field \| QuotedStr \| NumValue \| TransformerList` | yes | `parse_transformer_list_*` |
| `TransformerList ::= '(' (TransformerListArg (',' ...)*)? ')'` (empty allowed) | yes | `parse_transformer_list_empty`, `_invalid` |
| `FieldTransformerOrVal ::= FieldTransformer \| 'val(' Field ')'` (+ `[arg]`, refused at compile) | yes | `parse_transformers_right_hand`; compiler.json `val(...)[x]` |
| `Condition`: unary, numeric (number or transformer only), string (value or transformer), string + modifier + list, list (list, identifier, transformer) | yes | `parse_operators`, `parse_str_op_modifier_*` |
| `ListValue ::= '(' StrValue (',' StrValue)* ')' \| Identifier` | yes | `parse_lists` |
| `Field ::= FieldName ('[' FieldArg ']')?`, `FieldArg ::= QuotedStr \| FieldArgBareStr` | yes | `parse_shared_field_arg_*`, `filtercheck_arg_optional` |
| Partial parse (`parse_field_or_transformer`, output templates) | yes | `lib.rs` `output_fields_are_checked` |
| Recursion limit 100 (`exceeded max depth limit of 100`) | yes | `libsinsp_parser.rs` `the_recursion_limit_matches_libsinsp` |

## Tokens and lexing

| Rule | Status | Note |
|------|--------|------|
| `Identifier ::= [a-zA-Z]+[a-zA-Z0-9_]*` (a macro starts with a letter) | yes | |
| `FieldName ::= Identifier(\.Identifier)+` | yes | `evt.type.is.3` is `evt.type.is` then a parse error, as in libs |
| `FieldArgBareStr ::= [^][\"'[:space:]]+` | yes | |
| `HexNumber ::= 0[xX][0-9a-fA-F]+`; `Number ::= [+-]?[0-9]+\.?[0-9]*([eE][+-][0-9]+)?` | yes | an exponent needs a sign, as in libs |
| `QuotedStr`, both quote styles; a quote after a backslash never closes | yes | `parse_str` |
| Escapes `\b \f \n \r \t \\ \/ \" \' \xHH`, legacy `\ `; the wrong quote escape and unknown escapes refused | yes | `parse_str`; `parser.rs` `unescape_str` |
| `BareStr ::= [^()\"'[:space:]=,]+` (`evt.dir = <` compares with `<`) | yes | |
| Blanks: space, tab, `\b`, `\r`, `\n` | yes | |
| Keywords matched as prefixes (`and`, `or`), word operators need a blank after them, `in`/`intersects`/`pmatch`/`exists` do not | yes | `parse_operators`; `libs_quirks` |
| A list's first element that fails to lex leaves the list empty (libs' `catch`) | yes | `libs_quirks` |
| An operator modifier only when a list or a list name follows and no `and`/`or`/`not` (`= anyof` alone is a value) | yes | `parse_str_op_modifier_accept`/`_reject` |
| Error messages | libs' text, `(libsinsp)` appended in diagnostics | `test_reject_msg` cases |

## Operators and modifiers

| Operator | Types (`flt_is_comparable`) | Status |
|----------|-----------------------------|--------|
| `exists` | every type | yes |
| `=`, `==`, `!=` | numeric, bool, IP/network, string, buffer | yes |
| `<`, `<=`, `>`, `>=` | numeric, string (a number value) | yes |
| `contains` | string, buffer | yes |
| `icontains`, `startswith`, `endswith`, `glob`, `iglob`, `pmatch`, `regex` | string (`startswith`, `endswith` also buffer) | yes |
| `bcontains`, `bstartswith` | buffer; values are an even number of hex digits | yes |
| `in`, `intersects` | every non-list type; the only operators (with `exists`) for list fields; list fields only for `CHARBUF`, `UINT64`, `RELTIME`, `ABSTIME`, `BOOL`, `IPADDR`, `IPNET` | yes |
| modifiers `oneof`, `anyof`, `allof` | after string operators; on IP fields only with `=`, `!=` | yes; `falco_newer_syntax` (libs 0.25.0) |

All proven by `compiler.json` (each operator against `CHARBUF`, `BYTEBUF`, `BOOL`, numeric, `IPADDR`, `IPNET`, list fields) and `compile.rs` `operators_values_and_transformers`.

## Fields

| Rule | Status | Proven by |
|------|--------|-----------|
| Catalogue from libsinsp's field tables: type, list-ness, `EPF_ARG_REQUIRED`/`ALLOWED`/`INDEX`/`KEY`, `EPF_NO_RHS`, `EPF_NO_TRANSFORMER`, `EPF_FILTER_ONLY`, `EPF_PRINT_ONLY`, `EPF_DEPRECATED` | yes | `scripts/sync_falco_catalog.py --check` |
| Resolution class by class in libsinsp's order (`gen_event`, `event`, `thread`, `user`, `group`, `fd`, `fspath`, `utils`, `fdlist`, then plugins); the first class that knows a prefix decides, and only the whole name resolves | yes | `compile.rs` `fields_resolve_with_their_arguments` |
| `evt.arg[N]`, `evt.arg.NAME` (longest event argument), `evt.rawarg.NAME` (the argument's type), `evt.around[N]` (`=` only), `evt.abspath[.src\|.dst]`, `evt.type.is.NAME\|N` | yes | same; compiler.json |
| `proc.apid`, `proc.aname`, `proc.aexe`, `proc.aexepath`, `proc.acmdline`, `proc.aargs`, `proc.args` `[N]`; `proc.env`, `proc.aenv` `[KEY]`; `thread.cgroup.NAME`; `fd.types[N]` | yes | same |
| Plugin fields: `Index` (digits, no leading zero), `Key`, `Required`, argument on a field that takes none | yes | same (`ka.uri.param`) |
| `gen_event` fields on every source; other libsinsp classes on `syscall` only; plugin fields on their source (`container`, `k8smeta` on `syscall`; `json` on plugin sources) | yes | `fields_are_checked_for_the_source` |
| Unknown field of a catalogued source: error (`falco_unknown_field`), with a near miss, in conditions, `val()`, transformers, exception `fields`, and output templates. Falco refuses it (`filter_check called with nonexistent field`) | yes | real Falco oracle (`field-unknown`, `out-unknown-field`, `exc-unknown-field`, `rhs-val-unknown-field`) |
| Known field, bad argument: error (`falco_field_argument`) | yes | `operators_and_values_follow_the_field_type` |
| Deprecated fields (`evt.dir`, `evt.latency*`, `evt.wait_latency`): warning, Falco's text | yes | `falco_loader_warnings` |

## Values (`string_to_rawval`)

| Type | Rule | Status |
|------|------|--------|
| `INT*`, `UINT*`, `FLAGS*`, `ENUMFLAGS*`, `MODE`, `UID`, `GID`, `FD`, `PID`, `ERRNO`, `RELTIME`, `ABSTIME`, `DOUBLE`, `L4PROTO` | a decimal integer, as `sscanf("%d%c")` (so `0x10` parses as a number and is refused as a value) | yes |
| `PORT` | digits, or a service name | yes; a name outside the common services is a warning (the agent's host resolves it) |
| `BOOL` | `true` or `false` | yes |
| `IPADDR`, `IPV4ADDR`, `IPV6ADDR` | an address | yes |
| `IPNET`, `IPV4NET`, `IPV6NET` | `address/len`, IPv4 mask 0–32 | yes; IPv6 mask 0–128 |
| `CHARBUF`, `FSPATH`, `FSRELPATH`, `BYTEBUF` | anything without a NUL byte | yes |
| `regex` | the pattern compiles | yes, with an RE2-compatible engine (Rust `regex`) |
| `evt.type` values | a name of the event table or a syscall name (`unknown event type`) | yes, error |

## Transformers

| Transformer | Rule | Status |
|-------------|------|--------|
| `tolower`, `toupper`, `basename` | `CHARBUF`, `FSPATH`, `FSRELPATH`; type unchanged | yes |
| `b64` | `CHARBUF`, `BYTEBUF` | yes |
| `len` | `CHARBUF`, `BYTEBUF`, `FSPATH`, `FSRELPATH`, or any list; becomes `UINT64`, not a list | yes |
| `join(sep, list)` | exactly 2 arguments; the first a single value, the second a list | yes; `falco_newer_syntax` (0.24.0) |
| `concat(a, b, ...)` | 2 or more single strings | yes; `falco_newer_syntax` (0.24.0) |
| `getopt(args, "opts")[c]` | a list and a single value, both strings; `[c]` one character; a list without `[c]` | yes; `falco_newer_syntax` (0.25.0) |
| a single-argument call of `join`/`concat`/`getopt`, a multi-argument call of the others | refused | yes |
| a transformer on an `EPF_NO_TRANSFORMER` field (`proc.aname`) | refused | yes |
| `[arg]` on a transformer other than `getopt`, on `val` | refused | yes |
| multivalue arguments read their untransformed type (`get_field_info`) | yes | |

## Right-hand side fields

| Rule | Status |
|------|--------|
| `val(field)` or a transformer on the right; not with `pmatch` or `regex` | yes |
| not when the left side is a network | yes |
| not when either side is `EPF_NO_RHS` | yes |
| same type and list-ness on both sides, after transformers | yes |

## Compile warnings (libsinsp)

| Warning | Code | Status |
|---------|------|--------|
| a `regex` a plain operator could do | `falco_regex_simple` | yes, libs' heuristic and text |
| a value that is a field name | `falco_field_as_value` | yes |
| a value that looks like a transformer call | `falco_transformer_as_value` | yes |

Counts agree with all 15 warnings of `compiler.json`.

## Output templates (`eventformatter.cpp`)

| Rule | Status |
|------|--------|
| a leading `*` | yes |
| `%` then an optional length, then the longest text that parses as a field or transformer and compiles (`%proc.namex` is `proc.name` then `x`) | yes |
| a template ending with `%` or with a length | error, libs' text |
| a filter-only field | error |
| `%container.info` | warning, Falco's deprecation text |
| transformers in output (`%tolower(proc.name)`) | yes |

## Rule loading (Falco)

| Rule | Status | Proven by |
|------|--------|-----------|
| lists expand as text before the parse (`resolve_list`: between delimiters, items quoted when they hold a space, an empty list drops a comma), the block's lists over the default rules' | yes | `lists_expand_as_falco_expands_them` |
| a list where its expansion breaks the condition (a macro, a single value, `in name` with several items) | error `falco_misplaced_list` | same |
| macros resolve by name: the block's, then the default rules'; an unknown name is a warning (Sysdig manages macros; Falco OSS refuses it, a documented difference) | yes | `macros_and_lists_resolve_through_the_block`; oracle `def-unknown-macro` |
| default macros, lists, and rules come from the first file that defines them: `falco_rules.yaml`, then `falco-incubating_rules.yaml`, then `falco-sandbox_rules.yaml` (what a deployment loads by default); a differing later definition is kept as `also` and shown on hover | yes | `default_definitions_follow_the_stable_rules_file`; `falco_hover_over_stdio` |
| an empty condition: error (`falco_parse_error`), as Falco's rules schema (`Value must be non-empty`); in Tide, `sysdig_rule_shape` | yes | `an_empty_condition_is_refused`; oracle `bool-empty` |
| a tuning of a default rule is judged on the rule's condition with the tuning appended, as Falco appends it: `or …` loses event-type scoping (`falco_no_evttype`) | yes | `a_tuning_is_judged_on_the_tuned_rule_with_it_appended`; oracle `app-or` |
| a tuning of a rule the defaults do not have: warning `falco_unknown_rule` (Sysdig may manage it; Falco OSS refuses it, a documented difference) | yes | oracle `app-unknown-rule` |
| the block's constraint codes (`sysdig_rule_shape`, `sysdig_tuning_keys`, `sysdig_priority`, `sysdig_source`, `sysdig_exception_shape`, `sysdig_definition_name`, `sysdig_definition_duplicate`, `sysdig_definition_order`, `sysdig_list_in_value`), as opentide reports them, each on its field | yes | `crates/opentide-tide/src/sysdig.rs` tests |
| a tuning's condition is appended to the tuned rule's (`<rule> <condition>`), so it starts with `and` or `or` | yes | `tunings_append_with_and_or_or` |
| exceptions: tuple form (default `=`, equal lengths, operators or modifier operators, a row per value), single-field form (default `in`; `in`, `pmatch`, `intersects`, or a modifier operator), fields known, then the text Falco writes compiled | yes | `exceptions.rs` tests; `falco_rules.rs` |
| `<NA>` checks on `ka.` / `jevt.` fields | warning | `falco_loader_warnings` |
| event types (`ppm_event_codes`, with macros resolved): a syscall rule over more than 100 event types | warning `falco_no_evttype`, as Falco's `LOAD_NO_EVTTYPE` and Sysdig's backend | `falco_loader_warnings` |
| `priority` (`EMERGENCY` ... `DEBUG`, case-insensitive, `INFO` for `INFORMATIONAL`) | opentide's model (`sysdig_priority`), matching `falco_common::parse_priority` | opentide |
| `source` | known sources are checked; others are `falco_unknown_source` (warning) | `falco_rules.rs` |

## Known differences

- The tree-sitter grammar lexes `existsand` as one word; libsinsp reads `exists` then `and`. Only highlighting differs; the verdict comes from the port.
- Plugin READMEs do not list `EPF_NO_RHS` or `EPF_NO_TRANSFORMER`, so plugin fields accept both. The plugin's own field definitions would.
- `regex` patterns compile with Rust's `regex`, close to RE2 but not identical in every corner (RE2's POSIX mode and some Unicode classes).
- A port given as a service name is a warning: whether it resolves depends on the agent host's `/etc/services`.
- Lists expand in name order with the block's last; Falco expands in load order with list visibility. Items are expanded through other lists either way.
- Not reported: unused macros and lists (`LOAD_UNUSED_*`), `skip-if-unknown-filter`, `warn_evttypes`: the block has no keys for them.
- Fields the Sysdig agent adds beyond libsinsp and the published plugins are unknown: an error, as on Falco OSS.
- **Documented differences from Falco OSS**, the only ones the oracle allows: an undefined macro or list, and a tuning of a rule the default rules do not have. Falco OSS refuses them; on a Sysdig tenant either may be one Sysdig manages, so the engine warns (`falco_unknown_macro`, `falco_unknown_list`, `falco_unknown_rule`). Stricter by spec: a list item naming a later list or its own list, which Falco loads as a literal string, is `sysdig_definition_order` (sysdig-1.0, as opentide).
