---
title: "YARA conformance"
description: "How the engine checks YARA signatures (`crates/opentide-yara`): YARA-X 1.x as the language, the portability check of the HarfangLab and Bitdefender profiles, the module catalogue, with their sources."
---

# YARA

The YARA engine (`crates/opentide-yara`) checks YARA signatures as YARA-X 1.x compiles them ([#1225](https://github.com/opentidehq/opentide/issues/1225); the spec change from yara-1.0 1.1's "what libyara 4.5 compiles" is [opentidehq/specifications#93](https://github.com/opentidehq/specifications/issues/93)): what YARA-X refuses is an error, and syntax only YARA-X has is refused by a platform profile that does not take it (`yara_x_only_syntax`). libyara's quirks that YARA-X refuses are errors now; `yara_x_incompatible`, which warned about them, is retired. Design and work packages: [RFC 0015 §6](https://github.com/opentidehq/specifications/blob/main/rfcs/0015-yara-language.md#6-analysis-engine-language-server). Tracking: [#165](https://github.com/opentidehq/language-server/issues/165).

Language id `yara` (`.yar`, `.yara`). Platforms: HarfangLab (`configurations.harfanglab.yara`, harfanglab-1.0 1.3) and Bitdefender GravityZone (`configurations.bitdefender.yara`, bitdefender-1.0).

## Parsers

| Role | Parser | Where |
|------|--------|-------|
| Verdicts (diagnostics) | VirusTotal `yara-x-parser` 1.23.0 (BSD-3-Clause): pure Rust, logos + rowan, a lossless CST with byte spans, error recovery | `opentide-yara` |
| Formatting of `.yar` files | `yara-x-fmt` 1.23.0 (BSD-3-Clause) | `opentide_yara::format` |
| Oracle, never shipped | the `yara-x` 1.23.0 wheel | `scripts/engine/oracles` |

The `yara-x` compiler crate is not a dependency: it brings wasmtime, breaks the WASI build and reports one error per compile. The `yara-x-*` crates need Rust 1.95, which `rust-toolchain.toml` pins.

## Pipeline

1. **Profile text checks**: `bitdefender_yara_ascii` and `bitdefender_yara_size` on the raw text.
2. **yara-x-parser** on the text: each error, classified (`errors.rs`: a syntax error inside a hex string or a jump bound past 2^32 − 1 is `yara_hex_string`, an `xor` bound `yara_string_modifier`, an integer overflow `yara_number_out_of_range`), with YARA-X's own message. A rule wildcard in `of` (`any of (base*)`), which libyara took and YARA-X reads as an unfinished product, gets a hint naming the fix: list the rules.
3. **Semantic pass** (`check.rs`) on each rule that parsed: the symbol table (imports, rules defined so far, strings, loop variables), types, module members from `data/catalogs/yara/modules.toml`, and the YARA-X-only syntax yara-x-parser accepts (`with`, digit separators, float meta, `"""` strings, booleans in `of` tuples, hex or octal jump bounds, `.len()`), the 64-bit and float readers (`uint64`, `float32`, ...), `(?` groups and an empty first alternative in a regexp, and two different `base64` alphabets: each the error `yara_x_only_syntax` while the profile's `yara_x_syntax` is `refused` (below), and nothing when it is `allowed`.

Under a platform profile, YARA-X-only syntax is checked by one setting, `yara_x_syntax: allowed | refused` (`data/catalogs/yara/language.toml`), not by a second grammar. A raw `.yar` file allows it: YARA-X is the language (#1225). Both profiles start at `refused`, because their documentation describes standard YARA and names no engine; flip one to `allowed` once a live deploy confirms the platform takes it. The check is syntactic: it flags constructs only YARA-X parses, not libyara's semantics. A signature YARA-X compiles but libyara refuses for a value or a limit (an unsigned literal above `i64::MAX`, `0% of them`, floats in an enumeration, a shadowed loop variable, an identifier over 128 characters, a jump bound from 2^31 to 2^32 − 1) passes under both profiles, as the one portability check of #1225 intends: the profiles no longer emulate libyara.

YARA-X's matching differences need no diagnostic, since the engine does not scan: `xor` with `fullword` checks word boundaries on the XORed bytes, and `base64` matching has no false positives.

## Codes

Errors are what YARA-X 1.x refuses to compile (each checked against the `yara-x` wheel). **Source** is the libyara 4.5.4 file whose behaviour the check follows where YARA-X keeps it, or YARA-X's differences page where it does not. **Test** names the case in `crates/opentide-yara/tests/codes.rs` (`RAW`, `profiles`, `spec_examples_are_clean`) or the unit test that proves it.

### Errors

| Code | Condition | Source | Test |
|------|-----------|--------|------|
| `yara_parse_error` | Syntax error (with YARA-X's message), among them a repeated rule modifier (`global global`), a rule wildcard in `of` (`any of (base*)`: the message says to list the rules) and an escape in a `base64` alphabet; an empty text string. YARA-X has no identifier length limit | yara-x-parser; `parser.c` `ERROR_EMPTY_STRING` | `RAW`: `true and }`, `global global`, `any of (base*)`, `base64("…\\x09…")`; `identifiers_have_no_length_limit`; `tests/yara.rs` `decomposed_raw_quotes_are_parse_errors_in_their_field`: a `"` in `references`, `tags`, `arch`, `context` or `os`, which deploy writes raw |
| `yara_x_only_syntax` | YARA-X-only syntax (`with`, a digit separator, a float meta value, a `"""` string, a boolean in an `of` tuple, a hex or octal jump bound, `.len()`, a percentage with `at` or `in`, regexp modifiers other than `i`, `s`, `is`, `(?` groups or an empty first alternative in a regexp, a 64-bit or float reader, two different `base64` alphabets) under a profile whose `yara_x_syntax` is `refused`; the message names the construct and the platform | YARA-X's [differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara) | `codes.rs`: `RAW` (the refusing context), `yara_x_syntax_is_taken_when_allowed`, `yara_x_syntax_is_refused_by_both_profiles` |
| `yara_include` | An `include` directive | `lexer.l` `include` | `RAW`: `include "x.yar"` |
| `yara_signature_alias` | `signature` is a YAML alias | yara-1.0 (Tide) | `crates/opentide-tide/tests/yara.rs` `spec_fixtures` |
| `yara_empty_signature` | No rule, or only `private` or `global` rules | yara-1.0 | `RAW`: `private rule a`, `""` |
| `yara_duplicate_rule` | Two rules with one name | `parser.c` `ERROR_DUPLICATED_IDENTIFIER` | `RAW`: `rule a … rule a` |
| `yara_duplicate_string` | Two strings with one identifier (`$` excepted) | `parser.c` `ERROR_DUPLICATED_STRING_IDENTIFIER` | `RAW`: `$a … $a` |
| `yara_duplicate_tag` | A tag repeated on one rule | `parser.c` `ERROR_DUPLICATED_TAG_IDENTIFIER` | `RAW`: `rule a : t t` |
| `yara_undefined_string` | `$id`, `#id`, `@id`, `!id`, `$prefix*` matching no string; `$` outside `for … of`; `them` in a rule with no strings | `parser.c` `ERROR_UNDEFINED_STRING` | `RAW`: `$b`, `#b`, `($c*)`, `$`, `any of them` |
| `yara_unreferenced_string` | A string the condition never uses, without `them` (`$_name` excepted) | `parser.c` `yr_parser_reduce_rule_declaration_phase_2` | `RAW`: `$b` unused; `$_x` clean |
| `yara_undefined_identifier` | A bare name that is neither an earlier rule, a loop or `with` variable, nor a module; a call that is not a module function or a reader; a module field called as a function ("is not a function"); a module function named and not called ("wrong usage of identifier"); `entrypoint` (YARA-X E017). A loop variable an enclosing loop binds shadows it, as in YARA-X | `grammar.y` `identifier` | `RAW`: `b`, `b` defined later, `foo(1)`, `pe.number_of_sections(0)`, `pe.sections[0].name(0)`, `s.name(0)` in a loop, `pe.signatures[0].valid_on`, `pe.imphash and true`, `entrypoint == 0`; nested loops binding one name clean |
| `yara_rule_identifier_conflict` | A rule named like a reserved word or built-in (YARA-X's `with` and readers among them), or like an imported module | `lexer.l`; YARA-X E013 | `RAW`: `rule uint8`, `rule int64`, `import "pe" rule pe` |
| `yara_unknown_module` | `import` of a module outside YARA-X's default modules less `vt` (below); for `magic`, `vt` and YARA-X's experimental modules the message says why | YARA-X's default modules; #1225 | `RAW`: `import "foo"`, `import "magic"`, `import "vt"`; `a_refused_module_says_why` |
| `yara_module_not_imported` | A module member used without its `import`, or above it: the compiler reads the signature top to bottom | `grammar.y` `identifier` | `RAW`: `pe.number_of_sections`, a rule above `import "pe"` |
| `yara_unknown_module_member` | A member YARA-X's module lacks, or arguments no overload takes | `modules/*/*.c` `begin_declarations`; `parser.c` `yr_parser_check_types` | `RAW`: `pe.nonexistent`, `pe.exports(1, 2)`, `math.entropy("a", "b")` |
| `yara_type` | An operator or function on the wrong type; a boolean where YARA wants a `primary_expression`; a module member YARA-X types as boolean where a number is needed (arithmetic, an ordering, `!=`, a comparison with a float, an offset, an index, a range bound, a quantifier, an enumeration among integers, a function argument no overload takes a boolean for), once per comparison; a regexp as a condition; a string index that is a string; an enumeration mixing types | `grammar.y` `check_type`; YARA-X E002, E003 | `RAW`: `filesize contains "a"`, `"a" + 1`, `filesize matches "x"`, `pe.is_dll() > 0`, `1 != pe.is_dll()`, `uint8(pe.is_dll())`, `for all x in (1, 2.0)`; `ranges_cover_the_expression_as_written` |
| `yara_regexp` | An invalid regular expression, among them YARA-X's refusals: an unknown escape (`\\R`), a `{` outside a repetition, a look-around group, a string's regexp that can match the empty string or starts with an arbitrary prefix under `/s` | `re_lexer.l`, `re_grammar.y`; YARA-X E014, E045 | `RAW`: `/a(b/`, `/[z-a]bc/`, `/a{3,1}/`, `/\\Release/`, `/abc{/`, `/(?=abc)/`; `regexp.rs` `libyara_errors`, `yara_x_refusals`, `yara_x_only_forms` |
| `yara_hex_string` | Odd nibbles, `[0]` and `[0-0]`, `[a-b]` with a > b, a bound past 2^32 − 1, unbalanced alternatives (YARA-X takes any jump inside an alternative); one error per jump | `hex_grammar.y`, `hex_lexer.l`; yara-x-parser | `RAW`: `[4-2]`, `[0-0]`, `[0-4294967296]`, `[4294967296]`, `[9223372036854775813]`, `{ 01 0 }`; `( 03 \| [-] 04 )` (a branch cannot start with a jump); `[0-2147483648]`, `[3000000000]`, `( 02 [-] 03 \| 04 )` and `[1-300]` in an alternative clean |
| `yara_string_modifier` | A modifier repeated, on the wrong kind of string, or combined as YARA-X refuses (`xor nocase`, `base64` with `nocase`, `fullword` or `xor`); an `xor` range or `base64` alphabet YARA-X refuses; `base64` on a string under 3 bytes | `grammar.y` `string_modifiers`; `parser.c` `_yr_parser_check_string_modifiers`; YARA-X | `RAW`: `base64 nocase`, `xor nocase`, `wide wide`, hex `xor`, `xor(3-1)`, `xor(300)`, `base64("abc")`, `"ab" base64` |
| `yara_number_out_of_range` | An integer literal over 64 bits; a percentage outside 0-100; a constant sum, difference, product or negation that overflows 64 bits, or that has a literal above 2^63 − 1 (YARA-X reads `0xFFFFFFFFFFFFFFFF` as −1 only in a comparison, a bitwise operation or an argument); such a literal as an offset or range bound; a string index below 1. A division by zero is `undefined`, no error | `lexer.l`; YARA-X E007 | `RAW`: `99999999999999999999`, `150% of them`, `101% of them`, `2 * 4611686018427387904`, `0xFFFFFFFFFFFFFFFF + 1`, `$a at 0xFFFFFFFFFFFFFFFF`, `@a[-1]`; `0% of them`, `1 \\ 0`, `-9223372036854775808 \\ -1` clean |

### Warnings

| Code | Condition | Source | Test |
|------|-----------|--------|------|
| `yara_slow_pattern` | libyara's "string may slow down scanning": no atom of the string scores 38 | `atoms.c` `yr_atoms_heuristic_quality`; `parser.c` | `RAW`: `"a"`, `{ ?? ?? ?? }`, `/a.b/`; `atoms.rs` `libyara_examples` |
| `yara_entrypoint_deprecated` | `entrypoint`, with the error `yara_undefined_identifier` | `grammar.y` | `RAW`: `entrypoint == 0` |
| `yara_suspicious_expression` | libyara's warnings: a literal string in a boolean operation, "expression always false - requesting N of M", "consider using none", "multiple strings at an offset is usually false"; a non-boolean condition or operand of `and`, `or`, `not` or a `for` body, as YARA-X's `non_bool_expr` reads it (a module predicate YARA-X types as boolean, such as `pe.is_dll()` or a `with` name bound to one, is none; the operand of `defined` is no boolean context); yara-1.0's integer or float compared with a boolean, which covers what YARA-X reports as `bool_int_comparison` and more (`pe.is_dll() == pe.number_of_sections`, `#a == pe.is_dll()`, where YARA-X is silent); yara-1.0's invariant or unsatisfiable comparison (two constants, or `filesize` with a constant that decides it) | `grammar.y` `yywarning` | `RAW`: `"abc" and true`, `condition: filesize`, `2 of them`, `0 of them`, `all of them at 0`, `1 == 1`, `filesize < 0`, `true and pe.number_of_sections`, `not pe.number_of_sections`, `true and 1`, `pe.is_dll() or 0`, `for any s in pe.sections : ( s.virtual_size )`, `pe.is_dll() == 1`, `pe.exports("x") == 0`, `pe.is_signed == 1`, `pe.is_dll() == pe.number_of_sections`, `#a == pe.is_dll()`; `defined pe.number_of_sections`, `defined 1` clean |
| `yara_module_unconfirmed` | A known module outside the profile's confirmed set | yara-1.0 profiles | `profiles`: `import "dotnet"` under HarfangLab |
| `yara_meta_missing` | A recommended meta key missing on a non-private rule | yara-1.0 profiles | `profiles`: no `context` under HarfangLab |

### Platform profiles

| Code | Severity | Platform | Condition | Test |
|------|----------|----------|-----------|------|
| `harfanglab_rule_kind` | error | HarfangLab | `sigma` and `yara` both set | `tests/yara.rs` `spec_fixtures` |
| `harfanglab_yara_form` | error | HarfangLab | `signature` with decomposed keys | `tests/yara.rs` `spec_fixtures` |
| `harfanglab_yara_section_header` | error | HarfangLab | A `strings:`, `condition:`, `meta:` or `rule` header in a fragment | `tests/yara.rs` `decomposed_imports_and_headers_and_rule_names` |
| `harfanglab_yara_import` | error | HarfangLab | An `imports` entry that is not a known module | same |
| `harfanglab_yara_rule_name` | error | HarfangLab | The derived rule name is a keyword or keeps a character other than an ASCII letter, digit or `_` | same (`Condition`, `Détection`) |
| `harfanglab_yara_context` | warning | HarfangLab | Meta `context` that is not a comma-joined list, without blanks, of `file`, `memory`, `file.pe`, `file.elf`, `file.macho`, on the unknown value; the decomposed form's `context` too | `profiles`; `tests/yara.rs` `decomposed_unescaped_meta_is_checked_where_it_is_written`, `decomposed_contexts_are_checked_as_deploy_writes_them` |
| `bitdefender_yara_ascii` | error | Bitdefender | A character that is not ASCII | `profiles` |
| `bitdefender_yara_size` | error | Bitdefender | More than 30,000 characters | `profiles` |

The codes are constants in `opentide_core::codes`; `opentide explain <code>` prints each one's sentence. The `harfanglab_*` constraint codes and `yara_signature_alias` need the Tide block around the YARA text: `opentide-tide` checks them (`crates/opentide-tide/src/yara.rs`, tests in `crates/opentide-tide/tests/yara.rs`), as opentide's models will.

## In Tide objects

| Path | Analysed as |
|------|-------------|
| `configurations.harfanglab.yara.signature` | a whole signature, HarfangLab profile |
| `configurations.bitdefender.yara.signature` | a whole signature, Bitdefender profile |
| `configurations.harfanglab.yara.strings`, `.condition`, `.imports` | the one rule deploy assembles, HarfangLab profile: each finding lands in `strings`, `condition` or the `imports` item where it is written |

The decomposed form is assembled exactly as opentide's `compile_yara_deployment` writes it (`tests/yara.rs` `decomposed_assembly_is_what_deploy_writes` compares the two): the imports, `rule <name> {`, every meta line (`id`, `title`, `description`, `author`, `date`, `modified`, `references`, `tags`, `context` with `file` as the os's file context, `os`, `arch`, `classification`, `score`, `confidence`), then the bodies. What deploy escapes is generated text; what it writes as it is (`id`, the dates, `references`, `tags`, `context`, `os`, `arch`) keeps its place in the object, so a `"` in a tag is the parse error the tenant reports, on that tag. No finding is dropped: one inside generated text, such as a condition cut short and found at the closing brace, is reported on the nearest text of its field, or on the field itself when the field wrote nothing (`condition: ""`).

The pinned opentide's catalogue does not have `yara.signature` or the Bitdefender block yet (opentide's HarfangLab `signature` branch and RFC 0016): until it does, the schema check may also report those keys.

## Editor features

In `.yar` files, and in `yara.signature` and HarfangLab's decomposed fragments inside Tide objects (`crates/opentide-yara/src/editor.rs`, mapped through the injection by `crates/opentide-analysis/src/yara.rs`):

| Feature | What it does |
|---------|--------------|
| Hover | Module members (signature, type, documentation), modules, strings (`$a`, `#a`, `@a`, `!a` show the definition), rules, integer readers and built-in words |
| Completion | Modules after `import "`, members after `pe.` (and after `pe.sections[0].`), the rule's strings after `$`, `#`, `@` or `!`, and keywords, readers, imported modules and earlier rules elsewhere |
| Signature help | Each overload of a module function, and the integer readers |
| Symbols | Rules and their strings |
| Folding | Rules, sections, multi-line hex strings and comments |
| Definition, references, highlights | Strings within their rule (a `$a*` set item that covers the string counts), rules across the signature |
| Rename | String identifiers, keeping each sigil; refused for an invalid or taken name, or when a `$prefix*` set would stop matching. In a decomposed HarfangLab block it edits `strings` and `condition` together |
| Formatting | `.yar` files, with `yara-x-fmt`'s defaults; a file that does not parse is left as it is |

## Modules

The modules opentide knows are **YARA-X's documented default module set, less `vt`** (#1225): `console`, `crx`, `cuckoo`, `dex`, `dotnet`, `elf`, `hash`, `lnk`, `macho`, `math`, `pe`, `string`, `time`, `zip`. Importing any other is `yara_unknown_module`:

- `magic` is not one of YARA-X's defaults: YARA-X builds it only with its `magic-module` feature and libmagic, because it can be slow and its output varies across libmagic versions ([YARA-X: magic](https://virustotal.github.io/yara-x/docs/modules/magic/)). A rule that imports it is not portable.
- `vt` is a YARA-X default that opentide refuses on purpose (a maintainer decision): it describes VirusTotal's own scan metadata, which only VirusTotal's scanning fills in. YARA-X compiles `import "vt"`: the `[[yara]]` entry `vt-module-not-supported` records the difference.
- `msi`, `olecf` and `vba` are experimental in YARA-X and off by default.

`data/catalogs/yara/modules.toml` has every member of those modules, by path, generated by `cargo xtask codegen` (`xtask/src/yara_modules.rs`; CI runs `--check`) from `data/catalogs/yara/yara-x-modules.json`, YARA-X 1.23.0's reflection of its default modules (`scripts/engine/yara-modules`; `.agents/skills/catalogs/SKILL.md`). libyara is no input. A member YARA-X types as boolean, a field or a function's return, is checked as YARA-X checks it: compared with `==` to an integer it is taken (YARA-X warns, `yara_suspicious_expression`), in arithmetic, an ordering or `!=` it is `yara_type`. Under a profile, a known module outside the profile's confirmed set is the warning `yara_module_unconfirmed`, `crx` and `zip` included; no other gate applies.

## Verified against the engines

The reference is the `yara-x` 1.23.0 wheel, which never ships (`scripts/engine/oracles/README.md`). libyara (`yara-python` 4.5.4) is no oracle any more; its verdicts recorded in `cases.json` stay as data for the portability check's test.

### In every `cargo test`

- **Conformance cases**: `crates/testdata/conformance/yara/cases.json` holds 1,766 cases with both engines' recorded verdicts. They come from YARA-X's `lib/src/tests/mod.rs` and its compiler `errors`/`warnings` suites, from libyara's `tests/test-rules.c`, and four of opentide's own (`opentide:modules/*`: `magic`, `vt`, `crx`, `zip`), extracted by `scripts/engine/sync_yara_conformance.py`. Verdict pairs (libyara, YARA-X):

  | Pair | Cases |
  |------|-------|
  | ok, ok | 828 |
  | error, error | 507 |
  | error, ok | 225 |
  | warning, ok | 171 |
  | ok, error | 27 |
  | warning, error | 8 |

  `crates/opentide-yara/tests/conformance.rs` checks two things:
  - an error exactly where YARA-X refuses (`agrees_with_yara_x`, every case with a YARA-X verdict);
  - under a context that refuses YARA-X-only syntax, no error on a case both engines compile (`the_portability_check_takes_what_both_engines_compile`).

  The differences are the `[[yara]]` entries of `crates/testdata/oracles/exceptions.toml`. There are three: two YARA-X limits that are not modelled, and one decision:
  - its regexp size limit (nested repetitions);
  - its variable frame limit, about 2,048 variables in one condition (E047);
  - `import "vt"`, which YARA-X compiles and opentide refuses (`vt-module-not-supported`).
- **External corpus**: 50 public files with their `.broken.` twins, under `crates/testdata/conformance/external/yara`. 25 come from ReversingLabs (MIT) and 25 from signature-base (DRL 1.1). `crates/opentide-yara/tests/external_corpus.rs` requires no finding on each file, whether the context allows YARA-X-only syntax or refuses it, and an error on each twin.

### In CI

`oracle.yml` → YARA-X (`scripts/engine/oracles/yara/oracle.py`) re-checks every recorded YARA-X verdict against the live wheel. It also runs every YARA file of the repository (269: the production corpus, the external corpus, YARA-X's parser suite) through the engine and the wheel, which must agree on error or not.

### Local sweeps

Measured while libyara was the language (before #1225); kept as the record of that release.

| Set | Result |
|-----|--------|
| Neo23x0/signature-base (`de3c725`, 754 files) and ReversingLabs/reversinglabs-yara-rules (`e0a0be5`, 309 files) | 1,059 / 1,063 files agree with libyara on error or not, no file libyara refuses is missed; the other 4 have every rule commented out, which yara-1.0 reports as `yara_empty_signature`. YARA-X compiles every file libyara compiles, and the engine warns `yara_x_incompatible` on none |
| 467 one-fault mutations of those rules (a renamed string reference, a dropped import, a duplicated string, a broken hex byte or regexp, an unclosed parenthesis, a bad rule name, `nocase xor`, a 20-digit integer, a repeated tag) | 467 / 467 agree with libyara |
| 400 random short strings, hex strings and regexps | 400 / 400 agree with libyara on "may slow down scanning" |
