# libsinsp conformance fixtures

Ported from [falcosecurity/libs](https://github.com/falcosecurity/libs) at
`f13bc241815d463be433e947b90f42713df1abf9` by
`scripts/engine/sync_libsinsp_conformance.py` (`--check` in CI keeps them in step).
Copyright The Falco Authors, licensed under the Apache License, Version 2.0
(`../external/LICENSE.Apache-2.0.txt`). The inputs and libs' verdicts are
copied unchanged; only the C++ test scaffolding is dropped.

| File | From | What |
|------|------|------|
| `parser.json` | `userspace/libsinsp/test/filter_parser.ut.cpp` | 571 filter expressions with libs' verdict: 376 accepted (with the padded, line-break and tab variants `test_accept` also tries), 195 rejected; 4 with libs' exact error message, 7 with the AST libs prints (`as_string`). Not ported: `recursion_depth_limit`'s input (a 100,000-`(` string, built in code): `crates/opentide-falco/tests/libsinsp_parser.rs` tests it directly. |
| `compiler.json` | `userspace/libsinsp/test/filter_compiler.ut.cpp` | 326 `test_filter_compile` calls: the filter, whether libs refuses it (153), and its warning count (15 warnings). 22 use the test's mock fields (`c.true`, `c.buffer`, ...), which the harness maps to real fields of the same type. Not ported: `complex_filter` (a filter built in code). |

Harnesses: `crates/opentide-falco/tests/libsinsp_parser.rs`,
`crates/opentide-falco/tests/libsinsp_compiler.rs`,
`crates/opentide-falco/tests/tree_sitter_agreement.rs`.
