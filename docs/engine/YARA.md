# YARA

The YARA engine (`crates/opentide-yara`) checks YARA signatures as [yara-1.0](https://github.com/opentidehq/specifications/blob/main/specs/languages/yara-1.0.md) 1.1 defines them: the language libyara 4.5 compiles, with YARA-X 1.x as a second opinion whose refusals are warnings. Design and work packages: [RFC 0015 §6](https://github.com/opentidehq/specifications/blob/main/rfcs/0015-yara-language.md#6-analysis-engine-language-server). Tracking: [#165](https://github.com/opentidehq/language-server/issues/165).

Language id `yara` (`.yar`, `.yara`). Platforms: HarfangLab (`configurations.harfanglab.yara`, harfanglab-1.0 1.3) and Bitdefender GravityZone (`configurations.bitdefender.yara`, bitdefender-1.0).

## Parsers

| Role | Parser | Where |
|------|--------|-------|
| Verdicts (diagnostics) | VirusTotal `yara-x-parser` 1.23.0 (BSD-3-Clause): pure Rust, logos + rowan, a lossless CST with byte spans, error recovery | `opentide-yara` |
| Formatting of `.yar` files | `yara-x-fmt` 1.23.0 (BSD-3-Clause) | `opentide_yara::format` |
| Oracles, never shipped | `yara-python` 4.5.4 (libyara) and the `yara-x` wheel | `scripts/oracles` |

The `yara-x` compiler crate is not a dependency: it brings wasmtime, breaks the WASI build, reports one error per compile, and would make YARA-X the contract. The `yara-x-*` crates need Rust 1.95, which `rust-toolchain.toml` pins.

## Pipeline

1. **Profile text checks**: `bitdefender_yara_ascii` and `bitdefender_yara_size` on the raw text.
2. **libyara-only forms** (`syntax.rs`): the tree-sitter grammar (libyara's dialect) finds what yara-x-parser refuses and libyara accepts: a repeated rule modifier, a rule wildcard in `of`, an escape in a `base64` alphabet. Each is blanked to text of the same length and reported as `yara_x_incompatible`.
3. **yara-x-parser** on that text: each error, classified (a syntax error inside a hex string is `yara_hex_string`, an `xor` bound `yara_string_modifier`, an integer overflow `yara_number_out_of_range`).
4. **Semantic pass** (`check.rs`) on each rule that parsed: the symbol table (imports, rules defined so far, strings, loop variables), types, module members from `catalogs/yara/modules.toml`, and the YARA-X-only syntax yara-x-parser accepts and libyara refuses (`with`, digit separators, float meta, `"""` strings, booleans in `of` tuples, hex or octal jump bounds), each a `yara_parse_error` naming the feature.

`Dialect::YaraX` accepts YARA-X's syntax and makes `yara_x_incompatible` an error. No profile uses it today.

## Codes

Errors are what libyara 4.5 refuses to compile. **Source** is the libyara 4.5.4 file whose behaviour the check follows. **Test** names the case in `crates/opentide-yara/tests/codes.rs` (`RAW`, `profiles`, `spec_examples_are_clean`) or the unit test that proves it.

### Errors

| Code | Condition | Source | Test |
|------|-----------|--------|------|
| `yara_parse_error` | Syntax error; YARA-X-only syntax, named (`.len()` included); an empty text string; an identifier longer than 128 characters: every one but a string's (`$`, `#`, `@`, `!`), so rule names, tags, meta keys, loop variables and any other bare name or field (YARA-X has no limit) | `grammar.y`, `lexer.l`; `parser.c` `ERROR_EMPTY_STRING` | `RAW`: `true and }`, `with`, `1_000`, `f = 1.5`, `[0x2-0x4]`, `of (true, false)`, `pe.sections.len()`, a 129-character rule name; `identifiers_over_128_characters`: a 129-character loop variable, bare name, field, tag and meta key, and a 129-character string identifier clean; `tests/yara.rs` `decomposed_raw_quotes_are_parse_errors_in_their_field`: a `"` in `references`, `tags`, `arch`, `context` or `os`, which deploy writes raw |
| `yara_include` | An `include` directive | `lexer.l` `include` | `RAW`: `include "x.yar"` |
| `yara_signature_alias` | `signature` is a YAML alias | yara-1.0 (Tide) | `crates/opentide-tide/tests/yara.rs` `spec_fixtures` |
| `yara_empty_signature` | No rule, or only `private` or `global` rules | yara-1.0 | `RAW`: `private rule a`, `""` |
| `yara_duplicate_rule` | Two rules with one name | `parser.c` `ERROR_DUPLICATED_IDENTIFIER` | `RAW`: `rule a … rule a` |
| `yara_duplicate_string` | Two strings with one identifier (`$` excepted) | `parser.c` `ERROR_DUPLICATED_STRING_IDENTIFIER` | `RAW`: `$a … $a` |
| `yara_duplicate_tag` | A tag repeated on one rule | `parser.c` `ERROR_DUPLICATED_TAG_IDENTIFIER` | `RAW`: `rule a : t t` |
| `yara_undefined_string` | `$id`, `#id`, `@id`, `!id`, `$prefix*` matching no string; `$` outside `for … of`; `them` in a rule with no strings | `parser.c` `ERROR_UNDEFINED_STRING` | `RAW`: `$b`, `#b`, `($c*)`, `$`, `any of them` |
| `yara_unreferenced_string` | A string the condition never uses, without `them` (`$_name` excepted) | `parser.c` `yr_parser_reduce_rule_declaration_phase_2` | `RAW`: `$b` unused; `$_x` clean |
| `yara_undefined_identifier` | A bare name that is neither an earlier rule nor a module; a call that is not a module function or integer reader; a rule wildcard matching no earlier rule | `grammar.y` `identifier` | `RAW`: `b`, `b` defined later, `foo(1)` |
| `yara_rule_identifier_conflict` | A rule named like a reserved word, or defined after a rule wildcard an earlier condition uses that matches it. A rule named like an imported module is `yara_x_incompatible`: libyara 4.5 accepts it | `lexer.l`; `parser.c` `ERROR_DUPLICATED_IDENTIFIER` | `RAW`: `rule uint8` |
| `yara_unknown_module` | `import` of a module outside yara-1.0's 13 | `modules/module_list` | `RAW`: `import "foo"` |
| `yara_module_not_imported` | A module member used without its `import`, or above it: libyara reads the signature top to bottom | `grammar.y` `identifier` | `RAW`: `pe.number_of_sections`, a rule above `import "pe"` |
| `yara_unknown_module_member` | A member the module lacks (or only YARA-X has), or arguments no overload takes | `modules/*/*.c` `begin_declarations`; `parser.c` `yr_parser_check_types` | `RAW`: `pe.nonexistent`, `pe.exports(1, 2)`, `math.entropy("a", "b")` |
| `yara_type` | An operator or function on the wrong type; a boolean where libyara wants a `primary_expression` | `grammar.y` `check_type` | `RAW`: `filesize contains "a"`, `"a" + 1`, `filesize matches "x"` |
| `yara_regexp` | An invalid regular expression | `re_lexer.l`, `re_grammar.y` | `RAW`: `/a(b/`, `/[z-a]bc/`, `/a{3,1}/`; `regexp.rs` `libyara_errors` |
| `yara_hex_string` | Odd nibbles, `[0]` (also a bound of 2^32 that libyara wraps to it, `[4294967296]`), `[a-b]` with a > b, a jump bound from 2^31 to 2^32 − 1 (libyara reads it as a negative 32-bit int), a bound of 2^63 or more (libyara's `strtoll` saturates it at 2^63 − 1, which reads as −1), an unbounded or over-200 jump in an alternative, unbalanced alternatives | `hex_grammar.y`, `hex_lexer.l` | `RAW`: `[4-2]`, `[0-2147483648]`, `[4294967296]`, `[9223372036854775813]`, `[18446744073709551621]`, `( 03 \| [-] 04 )`, `[1-300]` in an alternative, `{ 01 0 }` |
| `yara_string_modifier` | A modifier repeated, on the wrong kind of string, or combined as libyara refuses (`xor nocase`, `base64` with `nocase`, `fullword` or `xor`); an `xor` range or `base64` alphabet libyara refuses; two different alphabets | `grammar.y` `string_modifiers`; `parser.c` `_yr_parser_check_string_modifiers` | `RAW`: `base64 nocase`, `xor nocase`, `wide wide`, hex `xor`, `xor(3-1)`, `xor(300)`, `base64("abc")` |
| `yara_number_out_of_range` | An integer literal over 64 bits; a percentage outside 1-100 | `lexer.l`; `grammar.y` `ERROR_INVALID_PERCENTAGE` | `RAW`: `99999999999999999999`, `150% of them` |

### Warnings

| Code | Condition | Source | Test |
|------|-----------|--------|------|
| `yara_x_incompatible` | libyara compiles it, YARA-X 1.x refuses it: unknown regexp escapes, a `{` outside a repetition, `base64` under 3 bytes, a negative string index, a repeated rule modifier, rule wildcards in `of`, escapes in a base64 alphabet, a module member YARA-X lacks, a rule named like an imported module, `[0-0]`, a jump bound of 2^32 or more (libyara reads it modulo 2^32), arithmetic or an ordering on what YARA-X types as a boolean (`pe.is_dll() > 0`, `pe.is_dll() + 1`, `-pe.is_dll()`: libyara declares an integer) | YARA-X's [differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences/) | `RAW`: `/\\Release/`, `/abc{/`, `"ab" base64`, `@a[-1]`, `global global`, `any of (base*)`, `base64("…\\x09…")`, `rule pe`, `[0-0]`, `[0-4294967296]`, `pe.is_dll() > 0`, `pe.is_dll() * 2 > 1`, `pe.is_dll() + 1`, `pe.is_dll() & 1`, `-pe.is_dll()` |
| `yara_slow_pattern` | libyara's "string may slow down scanning": no atom of the string scores 38 | `atoms.c` `yr_atoms_heuristic_quality`; `parser.c` | `RAW`: `"a"`, `{ ?? ?? ?? }`, `/a.b/`; `atoms.rs` `libyara_examples` |
| `yara_entrypoint_deprecated` | `entrypoint` | `grammar.y` | `RAW`: `entrypoint == 0` |
| `yara_suspicious_expression` | libyara's warnings: a literal string in a boolean operation, "expression always false - requesting N of M", "consider using none", "multiple strings at an offset is usually false"; a non-boolean condition or operand of `and`, `or`, `not` or a `for` body, as YARA-X's `non_bool_expr` reads it (a module predicate YARA-X types as boolean, such as `pe.is_dll()`, is none, though libyara declares an integer); an integer compared with a boolean, as YARA-X's `bool_int_comparison`; yara-1.0's invariant or unsatisfiable comparison (two constants, or `filesize` with a constant that decides it) | `grammar.y` `yywarning` | `RAW`: `"abc" and true`, `condition: filesize`, `2 of them`, `0 of them`, `all of them at 0`, `1 == 1`, `filesize < 0`, `true and pe.number_of_sections`, `not pe.number_of_sections`, `true and 1`, `pe.is_dll() or 0`, `for any s in pe.sections : ( s.virtual_size )`, `pe.is_dll() == 1`, `pe.exports("x") == 0`, `pe.is_signed == 1` |
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
| Hover | Module members (signature, type, documentation, which engine has it), modules, strings (`$a`, `#a`, `@a`, `!a` show the definition), rules, integer readers and built-in words |
| Completion | Modules after `import "`, members after `pe.` (and after `pe.sections[0].`), the rule's strings after `$`, `#`, `@` or `!`, and keywords, readers, imported modules and earlier rules elsewhere |
| Signature help | Each overload of a module function, and the integer readers |
| Symbols | Rules and their strings |
| Folding | Rules, sections, multi-line hex strings and comments |
| Definition, references, highlights | Strings within their rule (a `$a*` set item that covers the string counts), rules across the signature |
| Rename | String identifiers, keeping each sigil; refused for an invalid or taken name, or when a `$prefix*` set would stop matching. In a decomposed HarfangLab block it edits `strings` and `condition` together |
| Formatting | `.yar` files, with `yara-x-fmt`'s defaults; a file that does not parse is left as it is |

## Modules

`catalogs/yara/modules.toml` has every member of the 13 modules, generated from libyara 4.5.4's module declarations and YARA-X 1.23.0's module reflection (`skills/catalogs/SKILL.md`). Each row says which engine has it, so a member only one engine knows is reported as above. Where YARA-X types a member differently, the row records it (`yara_x_ret` for a function, `yara_x_kind` for a field). **libyara 4.5.4 ships no `lnk` module**, though yara-1.0 lists it among the 13: importing it is allowed as the spec says, and its members are checked against YARA-X's.

## Verified against the engines

The references are `yara-python` 4.5.4 (libyara) and the `yara-x` 1.23.0 wheel. Neither ships (`scripts/oracles/README.md`).

### In every `cargo test`

- **Conformance cases**: `testdata/conformance/yara/cases.json` holds 1,762 cases with both engines' recorded verdicts. They come from YARA-X's `lib/src/tests/mod.rs` and its compiler `errors`/`warnings` suites, and from libyara's `tests/test-rules.c`, extracted by `scripts/sync_yara_conformance.py`. Verdict pairs (libyara, YARA-X):

  | Pair | Cases |
  |------|-------|
  | ok, ok | 828 |
  | error, error | 506 |
  | error, ok | 222 |
  | warning, ok | 171 |
  | ok, error | 27 |
  | warning, error | 8 |

  `crates/opentide-yara/tests/conformance.rs` checks three things:
  - under the libyara dialect, an error exactly where libyara refuses, and a warning where libyara warns;
  - `yara_x_incompatible` on every case libyara compiles and YARA-X refuses;
  - no `yara_x_incompatible` on a case both compile.

  The differences are the `[[yara]]` entries of `testdata/oracles/exceptions.toml`. There are four:
  - an unterminated `/*`: libyara silently drops the rest of the text, and the engine reports it as YARA-X does;
  - sixteen nested repetitions that libyara runs out of memory on;
  - YARA-X's regexp size limit, which is not modelled;
  - libyara's test-only `tests` module.
- **External corpus**: 50 public files with their `.broken.` twins, under `testdata/conformance/external/yara`. 25 come from ReversingLabs (MIT) and 25 from signature-base (DRL 1.1). `crates/opentide-yara/tests/external_corpus.rs` requires no finding on each file under both dialects, and an error on each twin.

### In CI

`oracle.yml` → libyara and YARA-X (`scripts/oracles/yara/oracle.py`) re-checks every recorded verdict against the live engines. It also runs every YARA file of the repository (269: the production corpus, the external corpus, YARA-X's parser suite) through the engine and both references.

### Local sweeps

| Set | Result |
|-----|--------|
| Neo23x0/signature-base (`de3c725`, 754 files) and ReversingLabs/reversinglabs-yara-rules (`e0a0be5`, 309 files) | 1,059 / 1,063 files agree with libyara on error or not, no file libyara refuses is missed; the other 4 have every rule commented out, which yara-1.0 reports as `yara_empty_signature`. YARA-X compiles every file libyara compiles, and the engine warns `yara_x_incompatible` on none |
| 467 one-fault mutations of those rules (a renamed string reference, a dropped import, a duplicated string, a broken hex byte or regexp, an unclosed parenthesis, a bad rule name, `nocase xor`, a 20-digit integer, a repeated tag) | 467 / 467 agree with libyara |
| 400 random short strings, hex strings and regexps | 400 / 400 agree with libyara on "may slow down scanning" |
