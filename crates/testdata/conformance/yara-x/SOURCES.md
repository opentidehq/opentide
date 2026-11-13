# YARA-X conformance fixtures

Copied unchanged from [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x) at tag `v1.23.0` (`afe4585b12f56c698794dc80b3d28ddb87b56c0a`). Copyright The YARA-X Authors, BSD-3-Clause (`LICENSE.BSD-3-Clause.txt`).

| Directory | From | What |
|-----------|------|------|
| `parser/` | `parser/src/parser/tests/testdata/*.in` | yara-x-parser's own parser inputs: valid rules and the `*-error-*` cases it recovers from. YARA-X's golden CST/AST outputs are not copied. |

Harness: `crates/opentide-yara/tests/tree_sitter_agreement.rs` (the tree-sitter grammar against `yara-x-parser`).
