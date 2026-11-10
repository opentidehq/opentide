# YARA

The YARA engine (`crates/opentide-yara`) checks YARA signatures as [yara-1.0](https://github.com/opentidehq/specifications/blob/main/specs/languages/yara-1.0.md) defines them: the language libyara 4.5 compiles, with YARA-X 1.x as a second opinion whose refusals are warnings. Design and work packages: [RFC 0015 §6](https://github.com/opentidehq/specifications/blob/main/rfcs/0015-yara-language.md#6-analysis-engine-language-server). Tracking: [#165](https://github.com/opentidehq/language-server/issues/165).

Language id `yara` (`.yar`, `.yara`). Platforms: HarfangLab (`configurations.harfanglab.yara`, harfanglab-1.0 1.2) and Bitdefender GravityZone (`configurations.bitdefender.yara`, bitdefender-1.0).

## Parsers

| Role | Parser | Where |
|------|--------|-------|
| Verdicts (diagnostics) | VirusTotal `yara-x-parser` 1.23.0 (BSD-3-Clause): pure Rust, logos + rowan, a lossless CST with byte spans, error recovery | `opentide-yara` |
| Formatting of `.yar` files | `yara-x-fmt` 1.23.0 (BSD-3-Clause) | `opentide_yara::format` |
| Oracles, never shipped | `yara-python` 4.5.4 (libyara) and the `yara-x` wheel | `scripts/oracles` |

The `yara-x` compiler crate is not a dependency: it brings wasmtime, breaks the WASI build, reports one error per compile, and would make YARA-X the contract. The `yara-x-*` crates need Rust 1.95, which `rust-toolchain.toml` pins.

## Codes

Errors are what libyara 4.5 refuses to compile. The **Checked** column says what the engine reports today; the rest of the table lands with the semantic pass (#165).

### Errors

| Code | Condition | Checked |
|------|-----------|---------|
| `yara_parse_error` | Syntax error | yes, every error `yara-x-parser` recovers from |
| `yara_include` | An `include` directive | — |
| `yara_signature_alias` | `signature` is a YAML alias | — |
| `yara_empty_signature` | No rule, or only `private` or `global` rules | — |
| `yara_duplicate_rule` | Two rules with one name | — |
| `yara_duplicate_string` | Two strings with one identifier in a rule | — |
| `yara_duplicate_tag` | A rule tag repeated on one rule | — |
| `yara_undefined_string` | `$id`, `#id`, `@id`, `!id`, `$prefix*` matching no string | — |
| `yara_unreferenced_string` | A string the condition never uses, without `them` | — |
| `yara_undefined_identifier` | A bare identifier that is neither an earlier rule nor a module | — |
| `yara_rule_identifier_conflict` | A rule named like an imported module or a keyword | — |
| `yara_unknown_module` | `import` of a module libyara does not ship | — |
| `yara_module_not_imported` | A module member used without its `import` | — |
| `yara_unknown_module_member` | A field or function the module lacks, or the wrong arguments | — |
| `yara_type` | An operator or function on the wrong type | — |
| `yara_regexp` | An invalid regular expression | regexp modifiers only |
| `yara_hex_string` | Odd nibbles, a bad jump, unbalanced alternatives | — |
| `yara_string_modifier` | A modifier combination or argument libyara refuses | — |
| `yara_number_out_of_range` | An integer, size suffix, jump bound or index out of range | integer literals only |

### Warnings

| Code | Condition | Checked |
|------|-----------|---------|
| `yara_x_incompatible` | libyara compiles it, YARA-X 1.x refuses it | — |
| `yara_slow_pattern` | libyara's slow-scanning warnings | — |
| `yara_entrypoint_deprecated` | `entrypoint` | — |
| `yara_suspicious_expression` | Invariant, unsatisfiable or non-boolean condition | — |
| `yara_module_unconfirmed` | A known module outside the profile's confirmed set | — |
| `yara_meta_missing` | A recommended meta key missing on a non-private rule | — |

### Platform profiles

| Code | Severity | Platform | Condition |
|------|----------|----------|-----------|
| `harfanglab_rule_kind` | error | HarfangLab | `sigma` and `yara` both set |
| `harfanglab_yara_form` | error | HarfangLab | `signature` with decomposed keys |
| `harfanglab_yara_section_header` | error | HarfangLab | A `strings:`, `condition:` or `rule` header in a fragment |
| `harfanglab_yara_import` | error | HarfangLab | An `imports` entry that is not a known module |
| `harfanglab_yara_rule_name` | error | HarfangLab | The derived rule name is a keyword or keeps a non-ASCII-word character |
| `harfanglab_yara_context` | warning | HarfangLab | Meta `context` outside `file`, `memory`, `file,memory`, `file.pe`, `file.elf`, `file.macho` |
| `bitdefender_yara_ascii` | error | Bitdefender | A character that is not ASCII |
| `bitdefender_yara_size` | error | Bitdefender | More than 30,000 characters |

The codes are constants in `opentide_core::codes`; `opentide explain <code>` prints each one's sentence.
