# CrowdStrike Query Language (CQL)

The CQL engine (`crates/opentide-cql`) checks CrowdStrike Falcon Next-Gen SIEM correlation rules (`configurations.crowdstrike.query`, `platform::crowdstrike::1.0`), CrowdStrike threat hunts (`system: crowdstrike`), and raw `.cql` files. CQL is the language of Falcon LogScale (formerly Humio, whose docs called it LQL); CrowdStrike now publishes it as the "CrowdStrike Query Language". One language serves self-hosted LogScale and Next-Gen SIEM: what differs between them is which functions, saved searches, lookup files and repositories a tenant offers, not the syntax.

CQL is closed source. There is no reference parser to port (Falco has libsinsp) and no free reference build to run in CI (LogScale self-hosted needs a licence key and Kafka; Community Edition sign-up closed in 2024). So the engine follows CrowdStrike's published grammar and reference pages, measured against real public queries:

| Layer | Source of truth | Engine |
|-------|-----------------|--------|
| Syntax | CrowdStrike's "CQL Grammar Subset" (library.humio.com, `lql-grammar/syntax-grammar-guide-subset`) and its appendices (quirks, character table), the operator, filter, expression, conditional, comment, regular-expression and array pages, and the release notes 1.90–1.265 | `grammars/tree-sitter-opentide-cql` (tree-sitter, with an external scanner for context-dependent tokens) |
| Functions | the CQL function reference (one page per function: parameters, types, required, default, the omittable parameter, allowed values, bounds, availability, deprecation) | `catalogs/cql/functions.toml` (`scripts/sync_cql_catalog.py`) |
| Data | LogScale built-in fields and tags; Falcon sensor events and fields from redistributable sources only; CrowdStrike Parsing Standard (CPS, ECS-based) fields | `catalogs/cql/events.toml`, `catalogs/cql/fields.toml` |
| Correlation rules | the Next-Gen SIEM correlation-rule API (FalconPy, gofalcon, the CrowdStrike Terraform provider) and the `correlate()` reference | `crates/opentide-cql/src/correlation.rs` |

CrowdStrike's grammar text is cited, not copied: the grammar is re-derived in `grammar.js`, and catalog summaries are written for this repository. Facts (names, parameter names, types, defaults, enums) are generated.

## Language

### Two modes

CQL lexes by position. Pipeline steps and filter right-hand sides are *filter* mode; function arguments, `:=` right-hand sides and `test()` are *expression* mode. The same character means different things in each:

| Text | Meaning |
|------|---------|
| `https://www.example.com/` | free text: one unquoted pattern containing slashes |
| `https: //www.example.com/` | free text `https:`, then a `//` comment |
| `https://` | error: an unquoted pattern cannot end in `//` |
| `/fisk/i` (a step) | regex over every field, case-insensitive |
| `foo=m/fisk/i` | `foo` equals the pattern `m/fisk/i` |
| `a := m/fisk/i` | `a := m / fisk / i`, division of three fields |
| `a := /fisk/i` | error: there are no regex literals in expressions |

The grammar keeps filter and expression constructs as different node types, so highlighting and checks can tell a field name from a value.

### Filters and precedence

`or` binds tighter than `and`, the reverse of most languages ("OR binds closer than AND"). Juxtaposition is `and`, and `|` is the loosest of all: `A B` ≡ `A and B` ≡ `A | B`. `not` and `!` are prefixes and repeat.

| Level (tightest first) | Operators |
|------------------------|-----------|
| 4 | `not`, `!` |
| 3 | `or` |
| 2 | `and`, juxtaposition |
| 1 | `\|` |

`foo or not bar and baz` is `(foo or (not bar)) and baz`. `and`, `or` and `not` are case-insensitive. Function calls cannot be combined with `and` or `or`; they are pipeline steps, optionally negated (`!cidr(...)`, `not in(...)`).

A filter's left-hand side is always a field name, even when quoted: `"user name" = abrown` tests the field `user name`. `=`/`!=` right-hand sides are anchored patterns (`*` is a wildcard that cannot be escaped), regexes, or `?parameters`, never fields. `like` takes an unanchored pattern. `<`, `<=`, `>`, `>=` take a number. Free text is an unanchored pattern over the raw event; a bare regex searches every field.

### Expressions

Expressions have arithmetic and comparisons but no `and`/`or`:

| Level (tightest first) | Operators |
|------------------------|-----------|
| 5 | unary `-`, `!` |
| 4 | `*` `/` `%` |
| 3 | `+` `-` |
| 2 | `==` `!=` `<` `<=` `>` `>=` `<=>` (left-associative) |
| 1 | attributes `name: expr` (correlate() subqueries, 1.192+) |

A bare word in an expression is a field reference (or a number); a quoted string is a string value.

### Steps

| Step | Form |
|------|------|
| filter | `#event_simpleName=ProcessRollup2 CommandLine=/whoami/i` |
| function call | `groupBy([aid, ComputerName], function=count())` |
| negated call | `!cidr(RemoteAddressIP4, subnet=["10.0.0.0/8"])` |
| assignment | `ratio := bytes / packets`, `host := lower(ComputerName)` |
| field shorthand | `status =~ in(values=["500", "502"])` (adds `field=status`) |
| stats shorthand | `[count(), avg(duration)]` |
| case | `case { a=1 | x := "one"; a=2 | x := "two"; * }` |
| match | `kind match { "a" => x := 1; /b+/ => x := 2; * => * }` |
| saved search | `$falcon/helper:enrich(field=UserIsAdmin)`, `$"name with spaces"()` |
| parameter | `ComputerName=?host`, `?{host=*}` |

A function name must be followed immediately by `(` (`rdns (ip)` is free text `rdns` and a parenthesised filter). Since 1.224 function names are not reserved words. Function names are matched without regard to case (`groupby(` is common in CrowdStrike's own packages). A function takes named arguments `name=value` in any order and at most one argument without a name, which binds the function's omittable parameter. Arguments can be arrays, nested calls, subqueries `{ ... }`, bare function names (`function=count`) and parameters.

### Lexical

- Comments: `//` to end of line and `/* ... */`, wherever a token may start.
- Strings: `"..."` on one line; `\"`, `\\`, `\n`, `\t` are escapes. LogScale keeps other `\x` sequences verbatim (they reach regex arguments) and warns about them.
- Regex literals: `/.../flags` with flags `d` (dot matches newline), `g`, `i`, `m`, `F` (regex engine v2), in any order. `\/` escapes a slash. The body goes to the regex engine and is not CQL.
- Field names: letters, digits, `#` `%` `&` `.` `@` `\` `^` `_` `~`, Latin-1 letters, and JSON array indexes (`users[0].name`). Tags are field names starting with `#` (`#repo`, `#event_simpleName`). `host-name` is not a field name; quote it.
- Unquoted patterns add `*` `+` `-` `:` `/`.
- Numbers: integers, decimals, scientific notation. No hex. `true`/`false` lower case.

## Diagnostics

Every diagnostic has a stable code (`opentide_core::codes`) and a test that fails without it.

| Code | Severity | When |
|------|----------|------|
| `cql_parse_error` | error | the query does not parse |
| `cql_unknown_function` | error | no CQL function has this name (case-insensitive); a near match is suggested |
| `cql_removed_function` | error | the function was removed from CQL (`rdns`, `holtwinters`, `lookup`) |
| `cql_deprecated_function` | warning | the reference marks the function deprecated |
| `cql_unknown_parameter` | error | the function has no parameter with this name |
| `cql_duplicate_parameter` | error | a parameter is given twice, by name or once by name and once without |
| `cql_unnamed_argument` | error | more than one argument without a name, or one given to a function whose every parameter needs its name |
| `cql_missing_parameter` | error | a required parameter is missing |
| `cql_parameter_value` | error | a literal argument is not one of the parameter's allowed values, or is outside its bounds |
| `cql_regex_flag` | error | a regex literal has a flag other than `d`, `g`, `i`, `m`, `F` |
| `cql_string_escape` | warning | a string has an escape other than `\"`, `\\`, `\n`, `\t`; LogScale keeps it verbatim |
| `cql_free_text_after_aggregate` | error | free text after the first aggregate function (an error since 1.190) |
| `cql_assignment_as` | error | `x := f(..., as=y)`: the assignment already names the output |
| `cql_unknown_event` | warning | `#event_simpleName` compared with a literal no Falcon event has; a near match is suggested |
| `cql_correlate_aggregate` | error | a Next-Gen SIEM correlation rule combines `correlate()` with another aggregate function |

Not checked, on purpose:

- **Field existence.** A LogScale event has whatever fields its parser produced; an unknown field is never a finding.
- **Saved searches, lookup files, repositories and views** (`$falcon/...()`, `match(file=...)`, `readFile()`, `#repo`). They live in the tenant. They are completed and highlighted, not resolved.
- **The Next-Gen SIEM function allow-list** (language version `xdr1`). CrowdStrike does not publish it; it is only readable from a tenant (GraphQL `languageRestrictions`). The catalog records `ngsiem = true` only where CrowdStrike's own published queries use the function.
- **Regex bodies.** LogScale's engines (JitRex, and regex engine v2 since 1.236) are not Rust's `regex`; a body is highlighted, not compiled.
- **Correlation-rule fields** (`details.trigger`, `details.outcome`, `schedule.frequency`, `schedule.lookback`). They are Tide object fields, which the opentide models check; the language server places those findings.

## Hover, completion, signature help

- Hover on a function shows its signature, the summary written for this catalog, its category, whether it aggregates, and a link to CrowdStrike's page. Hover on a parameter shows its type, default and allowed values. Hover on a tag, a known field or an event name shows its layer (LogScale, Falcon, CPS) and summary.
- Completion offers functions at the start of a step and in argument values, parameter names inside a call (the ones not yet given), allowed values after `name=`, Falcon event names after `#event_simpleName=`, and known tags and fields where a field name may start.
- Signature help tracks the active parameter by name, or the omittable parameter for an argument without a name.

## Tide injection

| Field path | Language |
|------------|----------|
| `configurations.crowdstrike.query` | CQL, with Next-Gen SIEM correlation checks |
| hunts `searches[].query` with `system: crowdstrike` | CQL |
| raw `*.cql` | CQL |

Diagnostics map back onto the YAML (block scalar indent stripped), with `field_path` set to the injected key.

## Corpus and oracle

- `testdata/corpus/cql/`: one valid and one invalid fixture per grammar production (`crates/opentide-syntax/tests/corpus_gate.rs`).
- `testdata/conformance/external/cql/`: public CrowdStrike queries, unmodified, from the Unlicense parts of `CrowdStrike/logscale-community-content`, each with a `.broken.cql` twin carrying one injected fault (`SOURCES.md`).
- Oracle: none runs in CI. See `scripts/oracles/README.md`. A tenant's GraphQL `validateQuery` (LogScale) or a failed query job (Next-Gen SIEM, HTTP 400) is the only reference, and it needs credentials.

## Known differences

- The grammar follows the published grammar where CrowdStrike's pages disagree with each other (`like` with a regex, saved searches inside composite functions, an empty `match` guard in one example).
- Mixed-case `case`, `match` and `like` (`CASE {`) are not documented anywhere and parse as errors.
