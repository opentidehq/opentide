---
title: "Profiles: where the editor's time goes"
description: "Callgrind call-tree summaries and the server's timing trace for the workspace pull, start-up and first requests, behind the 2026-11-21 editor-latency report."
---

# Profiles: where the editor's time goes

Call-tree summaries from `valgrind --tool=callgrind` of the release `opentide-lsp` (line tables kept, LTO as shipped), a scripted session on the 1,200-object workspace (`scripts/perf/lsp-script.mjs`). Inclusive instruction counts (Ir), the biggest frames first; frames that only wrap others (threads, runtime entry points, once-cells) are left out. Instructions are not time (valgrind runs the server 30 to 60 times slower), but their shares are the shares of the CPU time.

A script piped to stdin is one batch, which the server coalesces (twenty queued edits are one analysis), so these sessions show the pulls and the start-up, not per-keystroke costs; those are in the timing trace below.

## Workspace pull before the fix (HEAD of integration/unified-core): two pulls over 1,200 object files

Total: 8,102,834,115 instructions.

| Ir | % | Frame |
|---:|---:|---|
| 4,229,983,912 | 52.20 | `opentide-lsp/src/protocol.rs:opentide_lsp::main` |
| 4,229,979,666 | 52.20 | `opentide-lsp/src/protocol.rs:<opentide_lsp::protocol::Driver>::batch` |
| 4,071,653,573 | 50.25 | `opentide-lsp/src/handlers.rs:opentide_lsp::handlers::request` |
| 3,143,890,503 | 38.80 | `opentide-analysis/src/lib.rs:opentide_analysis::analyze` |
| 2,871,009,888 | 35.43 | `opentide-lsp/src/handlers.rs:<opentide_lsp::handlers::Dispatcher>::on::<lsp_types::request::WorkspaceDiagnosticRequest, opentide_lsp::handlers::handle` |
| 2,246,251,040 | 27.72 | `opentide-tide/src/lib.rs:opentide_tide::analyze_lines` |
| 1,922,583,145 | 23.73 | `opentide-lsp/src/models.rs:opentide_lsp::models::build` |
| 1,870,650,395 | 23.09 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::fields_catalog` |
| 1,631,629,319 | 20.14 | `/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:core::ptr::drop_glue::<serde_json::value::Value>'2` |
| 1,438,920,869 | 17.76 | `opentide-tide/src/lib.rs:opentide_tide::analyze_injections` |
| 1,386,411,560 | 17.11 | `opentide-schema/src/generate/schema.rs:opentide_schema::generate::schema::resolve_node'2` |
| 1,200,249,389 | 14.81 | `opentide-lsp/src/handlers.rs:opentide_lsp::handlers::diagnostics_for` |
| 1,200,228,067 | 14.81 | `opentide-lsp/src/session.rs:<opentide_lsp::session::Session>::analysis` |
| 1,026,086,647 | 12.66 | `/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/alloc/src/collections/btree/map.rs:<alloc::collections::btree::map::BTreeMap<_, _, _> as core:` |
| 987,831,897 | 12.19 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::walk'2` |
| 959,360,955 | 11.84 | `opentide-workspace/src/validate/objects.rs:opentide_workspace::validate::objects::check_object` |
| 920,898,037 | 11.37 | `opentide-core/src/node.rs:opentide_core::node::load` |
| 887,592,531 | 10.95 | `opentide-core/src/node.rs:<opentide_core::node::Builder>::run` |
| 874,687,904 | 10.79 | `./misc/../sysdeps/unix/sysv/linux/x86_64/clone.S:start_thread` |
| 850,155,835 | 10.49 | `opentide-kql/src/lib.rs:<opentide_kql::Catalog>::for_workspace` |
| 817,424,251 | 10.09 | `/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/toml_edit-0.22.27/src/de/mod.rs:<toml_edit::de::Deserializer<&str>>::parse` |
| 794,564,470 | 9.81 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::flatten` |

## Workspace pull after the analysis cache (three pulls): the first analyses every file, the others read it back

Total: 7,345,597,689 instructions.

| Ir | % | Frame |
|---:|---:|---|
| 3,471,968,407 | 47.27 | `opentide-lsp/src/protocol.rs:opentide_lsp::main` |
| 3,471,963,687 | 47.27 | `opentide-lsp/src/protocol.rs:<opentide_lsp::protocol::Driver>::batch` |
| 3,234,617,108 | 44.03 | `opentide-lsp/src/handlers.rs:opentide_lsp::handlers::request` |
| 2,185,229,255 | 29.75 | `opentide-analysis/src/lib.rs:opentide_analysis::analyze` |
| 1,938,426,742 | 26.39 | `opentide-lsp/src/handlers.rs:opentide_lsp::handlers::handle_workspace_diagnostics` |
| 1,921,886,519 | 26.16 | `opentide-lsp/src/models.rs:opentide_lsp::models::build` |
| 1,869,445,372 | 25.45 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::fields_catalog` |
| 1,771,234,503 | 24.11 | `/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:core::ptr::drop_glue::<serde_json::value::Value>'2` |
| 1,735,820,414 | 23.63 | `opentide-tide/src/lib.rs:opentide_tide::analyze_lines` |
| 1,385,617,209 | 18.86 | `opentide-schema/src/generate/schema.rs:opentide_schema::generate::schema::resolve_node'2` |
| 1,333,097,506 | 18.15 | `opentide-tide/src/lib.rs:opentide_tide::analyze_injections` |
| 1,202,321,581 | 16.37 | `opentide-lsp/src/handlers.rs:opentide_lsp::handlers::diagnostics_for` |
| 1,202,300,590 | 16.37 | `opentide-lsp/src/session.rs:<opentide_lsp::session::Session>::analysis` |
| 1,087,354,561 | 14.80 | `/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/alloc/src/collections/btree/map.rs:<alloc::collections::btree::map::BTreeMap<_, _, _> as core:` |
| 986,488,437 | 13.43 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::walk'2` |
| 961,748,238 | 13.09 | `opentide-workspace/src/validate/objects.rs:opentide_workspace::validate::objects::check_object` |
| 897,539,821 | 12.22 | `./misc/../sysdeps/unix/sysv/linux/x86_64/clone.S:start_thread` |
| 849,860,919 | 11.57 | `opentide-kql/src/lib.rs:<opentide_kql::Catalog>::for_workspace` |
| 817,509,951 | 11.13 | `/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/toml_edit-0.22.27/src/de/mod.rs:<toml_edit::de::Deserializer<&str>>::parse` |
| 793,955,041 | 10.81 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::flatten` |
| 793,952,993 | 10.81 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::walk` |
| 780,101,412 | 10.62 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::field_row` |

## Start-up and first requests: where one-time work goes (the cold completion and diagnostics)

Total: 3,248,936,705 instructions.

| Ir | % | Frame |
|---:|---:|---|
| 1,259,984,396 | 38.78 | `opentide-lsp/src/protocol.rs:opentide_lsp::main` |
| 1,259,973,717 | 38.78 | `opentide-lsp/src/protocol.rs:<opentide_lsp::protocol::Driver>::batch` |
| 1,259,453,272 | 38.77 | `opentide-lsp/src/handlers.rs:opentide_lsp::handlers::request` |
| 1,259,060,208 | 38.75 | `opentide-lsp/src/handlers.rs:opentide_lsp::handlers::diagnostics_for` |
| 1,259,038,349 | 38.75 | `opentide-lsp/src/session.rs:<opentide_lsp::session::Session>::analysis` |
| 1,168,261,690 | 35.96 | `opentide-lsp/src/models.rs:opentide_lsp::models::build` |
| 1,142,117,748 | 35.15 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::fields_catalog` |
| 1,114,160,101 | 34.29 | `opentide-schema/src/generate/schema.rs:opentide_schema::generate::schema::resolve_node'2` |
| 958,369,474 | 29.50 | `opentide-analysis/src/lib.rs:opentide_analysis::analyze` |
| 957,961,678 | 29.49 | `opentide-tide/src/lib.rs:opentide_tide::analyze_lines` |
| 956,086,112 | 29.43 | `opentide-tide/src/lib.rs:opentide_tide::analyze_injections` |
| 784,809,139 | 24.16 | `opentide-kql/src/lib.rs:<opentide_kql::Catalog>::for_workspace` |
| 737,705,509 | 22.71 | `opentide-kql/src/lib.rs:<opentide_kql::Catalog>::with_profile` |
| 642,951,758 | 19.79 | `/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/toml_edit-0.22.27/src/de/mod.rs:<toml_edit::de::Deserializer<&str>>::parse` |
| 617,488,184 | 19.01 | `opentide-core/src/catalog.rs:opentide_core::catalog::read_items::<opentide_kql::tables::AzureMonitorTable>::{closure#1}` |
| 610,513,534 | 18.79 | `opentide-core/src/catalog.rs:opentide_core::catalog::batch_of::<opentide_kql::tables::AzureMonitorTable>` |
| 610,246,968 | 18.78 | `/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/toml-0.8.23/src/de.rs:opentide_core::catalog::batch_of::<opentide_kql::tables::AzureMonitor` |
| 610,246,466 | 18.78 | `/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/toml-0.8.23/src/de.rs:<toml::de::Deserializer as serde_core::de::Deserializer>::deserialize` |
| 583,778,622 | 17.97 | `opentide-schema/src/generate/schema.rs:opentide_schema::generate::schema::resolve_node` |
| 582,614,076 | 17.93 | `opentide-schema/src/generate/schema.rs:opentide_schema::generate::schema::resolve_field` |
| 552,188,588 | 17.00 | `/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/toml_edit-0.22.27/src/parser/document.rs:toml_edit::parser::document::parse_keyval` |
| 489,939,458 | 15.08 | `opentide-schema/src/generate/catalog.rs:opentide_schema::generate::catalog::walk'2` |


## The timing trace: per request and per phase (wall time, native, 1,200 objects)

`OPENTIDE_LSP_TIMING=1`, one scripted session of `scripts/perf/lsp-bench.mjs` with VS Code's workspace pull loop (the build before the report cache; `--profile release`, no LTO). Times in ms.

| Span | n | sum | p50 | max |
|---|---:|---:|---:|---:|
| `request workspace/diagnostic` | 10 | 2318 | 226 | 478 |
| `workspace/diagnostic: files` | 10 | 2250 | 221 | 458 |
| closed findings (`validate` of every object, once per generation) | 11,990 | 1638 | 0.0 | 192 |
| analysis of an open document | 7 | 814 | 97 | 211 |
| `request textDocument/diagnostic` | 6 | 738 | 114 | 218 |
| analysis: the object's findings (`validate` and `lint` of the open file, which read every object file) | 7 | 684 | 92 | 121 |
| `request textDocument/completion` | 131 | 227 | 0.8 | 10.1 |
| analysis: the engine (queries of the open object) | 7 | 129 | 0.5 | 126 |
| `request textDocument/semanticTokens/full` | 21 | 88 | 0.1 | 87 |
| `request textDocument/hover` | 42 | 12.7 | 0.2 | 3.6 |

Reading it: a completion or a hover is a millisecond; a workspace pull is a quarter of a second, and 190 ms of that is the one `validate` of the whole workspace each edit makes necessary (the cached lookups in the 11,990 spans cost nothing). The 126 ms engine analysis and the 87 ms token request are the first use after start-up: the catalogs.
