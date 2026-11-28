---
title: "Editor latency, part two: a keystroke, the completion payload and the field catalog (2026-11-21)"
description: "What typing in an object cost the language server after the workspace pull was kept (0.24 s at 500 rules), the incremental check that brings it to 22 ms, the completion list that is labels, and where the field catalog's time goes."
---

# Editor latency, part two (2026-11-21)

[Part one](perf-editor-latency-2026-11-21.md) made the workspace pull cheap when nothing changed and left the cost of a keystroke as its next item: **0.24 s at 500 rules**, because each keystroke validated and linted every object twice, once for the object being edited and once for the workspace pull the editor makes next. This part is that item (#1745), the completion payload, and the profile of the Tide field catalog's generation.

Everything below was measured on the 500-rule benchmark workspace (`cargo xtask bench`'s heavy workspace at scale 1: 1,113 files) or the 600-object corpus workspace of `scripts/perf/make_workspace.py`, on the same 4 vCPU Xeon 2.10 GHz as part one, with release builds without LTO (the build the numbers of part one were made with, so the two parts compare).

## Summary

| | Before | After |
|---|---:|---:|
| `lsp_editor_typing_latency` (the longest completion after a keystroke and its pulls, median of 7) | 0.37 s ¹ | **0.022 s** |
| The open object's diagnostics after a keystroke (`analysis: the object's findings`) | 115–120 ms | 18 ms |
| The workspace pull after a keystroke (`request workspace/diagnostic`) | 145–195 ms | 1.5–2.3 ms |
| ATT&CK technique completion, 370 items (VS Code's capabilities), payload | 141,788 bytes | **19,035 bytes** |
| The same request, cold / warm / after a keystroke | 5.3 / 3.9 / 4.6 ms | 3.1 / 2.6 / 3.2 ms |

¹ Part one's report gives 0.24 s for this scenario; 0.37 s is what the same build of part one's head measures here with the trace on, one run. The gate is the number that matters: it was 0.5 s and is 0.05 s.

## 1. Per-edit validation

### Where a keystroke's time went

A keystroke in an open object (`didChange`), then the editor's two pulls. With the trace on (`OPENTIDE_LSP_TIMING=1`), per keystroke at 500 rules:

| Step | Before | After |
|---|---:|---:|
| `Workspace::invalidate` (re-parse one file, list the folders, assemble the index, compare two indexes) | 13–14 ms | 5.5 ms |
| `validate` on the open file | 5.5 ms | 4.5–4.9 ms |
| `lint` on the open file (the filename check reads every object file) | 40–60 ms | 1 ms |
| the workspace pull: `validate` and `lint` on every object, one report entry per closed file | 140–190 ms | 1.5–2.3 ms |

Callgrind on the editor's checks found, besides the structure (the whole workspace checked twice):

- **`lint`'s filename check** loads a record of every object file to learn the stems the others want. 63% of a run was `recommended_fields`, which generated a model JSON schema again for every run (a pure function of the schema revision: made once for each now); then every record's text was copied and scanned by regular expressions for key lines and placeholders, though only the reported file's are shown; `narrow` resolved every candidate's path against the disk; the folders were listed again.
- **The deprecation walk** (`opentide_schema::objects::platform::deprecation`) copied the schema's JSON at every field of every object: 30% of `validate`'s per-object checks. It borrows now. `validate` of the whole 500-rule workspace is 45 ms before, 33 ms after, for the command line too.
- **`Workspace::invalidate`** listed every object folder again for an edit of a file it already holds, and compared two whole indexes to say which UUIDs were affected.

### The design

`Workspace::invalidate` returns, besides what it did (`full`, `configuration`, `reparsed`):

- `changed`: the files whose cached parse was dropped (re-read, new or gone). For an edit of a file it holds it lists no folder again.
- `identity_changed`: what **other objects' checks read of the objects in `changed`** is not what it was. That is the set the `Graph` of `validate` is built from: an object's family, UUID and name (a reference's `invalid_ref` suggestion compares names), a signal and its owner, a UUID another file now shares, and a file that came or went. A typed line in a rule, an objective or a threat changes none of it. Anything the facts cannot say is taken as `identity_changed` too, so that the checks of every object are made again (`needs_every_check`): any duplicate UUID in the workspace, a path that is a source in one index and not the other (a file that came, went or was renamed: expected file names depend on paths), and a path the index holds as a source or a load error but not as an object (no UUID, a duplicate's displaced file, a file that does not load). The fast path is an ordinary edit inside one file that is an object before and after it, in a workspace with no UUID used twice.
- `cross_changed`: a Graylog, Exabeam or Google SecOps platform block of a rule in `changed` is not what it was. The cross-rule checks (`graylog_title_duplicate`, `exabeam_name_*`, `google_secops_name_duplicate`) read every rule's blocks, and report on the other rule too.
- `affected`: the objects in the changed files, those that reference or are referenced by them, and the signals they own, found from `changed` instead of by comparing the indexes.

`opentide-lsp` (`checks.rs`) keeps the findings of every object (`RootChecks::all_findings`) and, when an edit sets neither flag, checks the files in `changed` alone: a narrowed `validate` and `lint` on them, put in place of the entries those files had. When a flag is set, the configuration changed, the catalogs did (the server's environment epoch), or nothing is kept yet, every object is checked, as it was. The open file's findings are read from the same map, so one keystroke makes one narrowed run.

A workspace pull then needs to build nothing for a file that did not change: each closed file keeps its report entry (`DiskFile::reported`) with the epoch and a **stamp** of the findings it was made from (`RootChecks::stamp_of`, a revision counted at each change to a file's entry), and uses it again while both are the same. A `duplicate_id` entry is not kept: it points at the other file's lines.

`lint` has the same shape (`RecordCache`, in `opentide-workspace`): the light record of each file it does not report on is kept for the document it was made from, the listing of the object folders is kept until the workspace lists them again, and so are the stems each file is expected to have, until an object's name or UUID changes or a file comes or goes (`Invalidation::identity_changed`, a new listing). `editor_lint` names its files as the index does (`LintOptions::selected`) instead of resolving each candidate against the disk.

### What is not claimed

- A client that does not watch files gets nothing kept, as in part one: nothing tells the server what changed on disk.
- An edit that changes an object's name or UUID, or a platform block the cross-rule checks compare, checks every object again (about 35 ms of `validate` and 20 ms of `lint` at 500 rules). Typing in `name:` is that edit on each keystroke.
- A pull that arrives after a configuration change, or the first pull, makes the findings of every object once (about 250 ms at 500 rules, as before).

### Tests

- `kept_findings_equal_a_fresh_run_after_each_kind_of_edit` (`checks.rs`): after each of 40 edits (among them a copy that duplicates a rule's UUID, edited and broken, a file with no UUID whose name changes, the plain-stem holder of a shared name renamed) (a typed line, a severity, a reference to an object that is not there and back, a name and back, the objective deleted and back, a UUID written by a second file and removed, a file renamed and back, YAML broken and mended, two Google SecOps blocks that come to share a name, a name two files want) the kept findings equal a fresh run's, for every file, and the run was partial where only the file's own text changed and full where something other objects read did. It fails without `cross_changed` (the second rule keeps a stale `google_secops_name_duplicate`).
- `a_keystroke_checks_the_file_it_changed_not_every_object` (`tests/protocol.rs`): the first pull checks everything (`validations.full` 1), two typed lines check one file each (`partial` 2), a new name checks everything (`full` 2).
- `invalidation_says_what_other_objects_read_of_the_files_that_changed` (`opentide-workspace`): `changed`, `identity_changed` and `cross_changed` for a typed line, a name, a UUID, a file that stops loading, a platform block, a file that comes, a configuration file.
- The incremental index's property test (`tests/index.rs`) holds the fast path of `invalidate` to a full rebuild.

### The gate

`cargo xtask bench --engine rust --only lsp_editor_latency,lsp_editor_typing_latency` with its own release build (LTO): 0.005 s idle and 0.022 s after a keystroke, median of 7 runs. `lsp_editor_typing_latency` (`tests/bench/budgets.toml`) was 0.5 s and is 0.05 s: twice what it measures here, which the slowest recorded CPU class (1.8 times slower) stays under.

## 2. Completion: labels, with the rest said once

The harness's completion scenarios (`scripts/perf/lsp-bench.mjs`, VS Code's recorded capabilities plus `completionList.itemDefaults` as `vscode-languageclient` 10.1 declares it, `completion.js`: `commitCharacters`, `editRange`, `insertTextFormat`, `insertTextMode`, `data`):

| Scenario | Items | Bytes before | Bytes after | Cold / warm before (ms) | after (ms) |
|---|---:|---:|---:|---:|---:|
| `completion:attack-technique` | 370 | 141,788 | **19,035** | 5.3 / 3.9 | 3.1 / 2.6 |
| `completion:kql-after-where` | 229 | 56,132 | 56,132 | 1.5 / 1.4 | 2.0 / 1.9 |
| `completion:kql-after-pipe` | 54 | 16,143 | 16,143 | 0.5 / 0.4 | 0.7 / 0.7 |

The technique list had no documentation inline already (part one's figure was 138 KiB of repeated structure): each of the 370 items said `{"data": {"field_path", "language", "schema"}, "detail", "filterText", "insertText", "kind", "label", "textEdit": {"newText", "range"}}`, 383 bytes for a label of 5 to 9. For a client that declares `completionList.itemDefaults` with `data` and `editRange` the result is now a list: `itemDefaults` holds the `data` and the range the items share, and an item is `{label, kind}` (`textEditText` when its text is not its label), 51 bytes. The `detail` (`rule::1.0 techniques`, which names the schema and field the item's `data` names) is made when the item is resolved, for a client whose `resolveSupport` lists `detail`. `completionItem/resolve` is unchanged: given the `data` the client puts back from the defaults, it returns the documentation and detail the whole list held (the test compares the first 60).

A client that declares neither gets the array it got. The KQL lists keep their per-item documentation (it is made at completion time by the query engine, which `completionItem/resolve` cannot reproduce from an item's `data`): moving it is the next step if those lists matter.

`the_values_of_a_tide_field_are_listed_by_label_and_say_the_same_once` (`tests/protocol.rs`) holds the payload under 64 bytes an item, and each of the first 60 items' text, range, data, documentation and detail to what a client with no defaults is sent.

Data: `docs/internal/perf/data/completion-before-1745.json`, `completion-after-1745.json` (`lsp-bench.mjs`, 5 runs, 8 warm requests each).

## 3. The field catalog (`models::build`)

`models::build` is what a root's own catalog costs (`fields_catalog`: 140 ms on the warm-up thread's second build, 240 ms when it competes with the start-up threads; `dump` 3 ms; deprecations 0.1 ms). It is off the request loop (a thread), so it is not a request's wait, but the catalog arrives after the first analyses were made against the engine's compiled-in catalogs, and the arrival made every file be analysed again.

Callgrind of `fields_catalog` for the bundled configuration (1,133,476 bytes of JSON):

| Share | Where |
|---:|---|
| 72% | `resolve_node`: every `tide.vocab` of every revision of every object becomes an `enum` with its Markdown dropdowns |
| 32% | …of which `vocabulary_offer` (the dropdown and plain text of each ATT&CK entry, each time a field names the vocabulary) |
| 21% | `catalog::clean_enum` / `array_enum`: the rows read the arrays the previous step wrote |
| 12% | `annotate` (hover texts) |
| 15% | `Json` ↔ `serde_json::Value` conversions |
| 26% | dropping the arrays |

Two changes, both exact (the generator's own tests and the engine's compiled-in catalogs hold the output):

- **`vocabulary_offer` is made once for each reference** (`Vocabularies::memoized`): every revision of every object that names `techniques` asked for the same few hundred dropdowns again. `fields_catalog` goes from 120 ms to 105 ms warm (10%).
- **A root's catalog that equals the installed one is not a catalog that arrived** (`CatalogSightings::saw`): a root with configuration files that change nothing the catalog reads, which is most of them, no longer makes the next pull analyse every file again (about 250 ms of server time at 1,200 objects).

### What is left, and #1743

The remaining time is arrays that are written into a schema, read back into rows and dropped, for fields that offer the bundled vocabularies, whose values do not depend on the workspace. Only the configuration's own enumerations do (`tide.config.statuses`, `responders`, `system.tenants`, the log source names). The way to cut the rest is to generate the rows of the bundled vocabularies once as static data (the offer of each bundled reference is 32% by itself and a function of the bundled documents alone) and resolve only the configuration-driven fields per root.

That is the shape of #1743 (`fix/av-compressed-datasets`), which compresses the embedded datasets and pre-parses the heaviest at build time. It does not touch the Tide field catalogs (`vocab::bundled::load` is 8% of the first, cold build, which its pre-parse removes), so the two do not collide: this change adds `Vocabularies::memoized` and does not touch `bundled.rs`. Once #1743 has merged, the per-reference offers belong in its build-time data (`xtask codegen`), and `memoized` then only serves the vocabularies a workspace brings.

## Review of f2d5f0d6

Five defects, fixed conservatively (the narrowed path is taken only where its assumptions clearly hold):

1. A completion item is resolved (its documentation and detail left to `completionItem/resolve`) only when it names a field of the Tide models and resolving gives back exactly the documentation the list would have said; an ECS value, a Bitdefender target or `configurations.elastic.type`, whose documentation is made elsewhere, keeps its own, and `resolve` never documents an item from another field. Test: `values_outside_the_tide_models_keep_their_documentation_when_resolved`.
2. A narrowed run takes only the entries of the files that changed, and any duplicate UUID makes the run a full one.
3. Kept lint stems are forgotten, and every object checked again, when a changed path holds a source that is not an object (no UUID, a displaced duplicate, a parse error), before or after the edit.
4. A path that is in one index and not the other (a rename) is a change of identity.
5. The findings, and their stamps, of a changed file are kept by its resolved path; the narrowed selection keeps the index's path. Test: `kept_findings_follow_a_symbolic_link_to_an_object_file` (unix).

## The offers as build-time data (#1755)

What `models::build` still spent on the bundled vocabularies' offers (the dropdown and plain text of each entry, for every field that names the vocabulary) is now read from data `opentide-schema`'s build script made once ([`docs/internal/datasets.md`](datasets.md)). A field that names one vocabulary also keeps the keywords it writes (`enum`, the Markdown and plain descriptions) once per reference.

`fields_catalog` for the bundled configuration, 1,133,476 bytes of JSON, release build, this machine (4 vCPU), 12 alternating runs of each build: **cold** (the first build of a process) 259 to 144 ms (median, best 230 to 135), **warm** (the next ones) 139 to 130 ms (best 127 to 104). The language server's first catalog (`OPENTIDE_LSP_TIMING=1`, 1,200 objects, 5 runs each) 283 to 199 ms. What remains warm is the rows read back and dropped (`clean_enum`, `array_enum`), not the offers. `lsp_editor_typing_latency` (7 runs, twice each) 34 and 36 ms before, 39 and 30 ms after: no change. Cold start to the first diagnostics (`scripts/perf/lsp-bench.mjs`, 8 runs, three times each) 113, 113 and 101 ms before, 106, 106 and 104 ms after: the catalog is built off the request loop, so no change. Memory, resident after the first pull: 196 to 191 MiB. Binary: `opentide-lsp` +583 KB (117.49 to 118.07 MB, release with line tables).
