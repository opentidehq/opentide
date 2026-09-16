# OpenTide highlight debug (KQL / SPL / Tide)

Investigation of “mostly white” highlighting (only table names looking cyan).

**Runtime path:** `opentide_syntax::query_captures` runs `highlights/queries/{kql,spl}/highlights.scm` via tree-sitter `QueryCursor::captures` (first pattern wins). Nested overlapping spans are dropped so LSP semantic tokens never overlap. Catalog overlay promotes known functions to `function.builtin` and operators/commands to `keyword`.

**LSP encoding:** VS Code only colors the [standard semantic token types](https://code.visualstudio.com/api/language-extensions/semantic-highlight-guide). Capture names like `operator.pipe` / `function.builtin` / `tide.keyword` are **not** in that set, so `encode_lsp_semantic_tokens` maps them onto `keyword` / `operator` / `function` / `type` / … (`opentide_highlight::LSP_TOKEN_TYPES`). JSON `highlight()` still emits the frozen capture names.

**HTML:** `tokens_to_html` uses high-contrast Dark+ colors (`keyword` magenta, pipes hot-pink, functions yellow, tables teal).

---

## 1. CST dumps

Source: `opentide_syntax::parse` (tree-sitter 0.25).  
Command: `cargo test -p opentide-syntax dump_cst_kql_and_spl_samples -- --nocapture`  
(module: `highlight_cst_dump`)

### KQL — `SecurityEvent | where EventID == 1 | take 1`

```
kind="source_file" named=true children=1 bytes=[0..43]
  kind="query" named=true children=1 bytes=[0..43]
    kind="tabular_expression" named=true children=5 bytes=[0..43]
      kind="tabular_primary" named=true children=1 bytes=[0..13]
        kind="identifier" named=true children=0 bytes=[0..13] text="SecurityEvent"
      kind="|" named=false children=0 bytes=[14..15] text="|"
      kind="tabular_operator" named=true children=1 bytes=[16..34]
        kind="where_operator" named=true children=2 bytes=[16..34]
          kind="where" named=false children=0 bytes=[16..21] text="where"    ← leaf
          kind="expression" …
            … identifier EventID, "==", number 1 …
      kind="|" named=false children=0 bytes=[35..36] text="|"
      kind="tabular_operator" named=true children=1 bytes=[37..43]
        kind="take_operator" named=true children=2 bytes=[37..43]
          kind="take" named=false children=0 bytes=[37..41] text="take"      ← leaf
          kind="number" named=true children=0 bytes=[42..43] text="1"
```

**Keyword focus:** `where` / `take` are **anonymous**, **`named=false`**, **`children=0`**.  
Grammars declare `word: ($) => $.identifier`, but in tree-sitter 0.25 that only reserves keywords from the identifier rule — it does **not** wrap keyword tokens in an `identifier` child.

### SPL — `index=main | stats count by host | head 1`

```
kind="source_file" named=true children=1 bytes=[0..41]
  kind="pipeline" named=true children=5 bytes=[0..41]
    kind="bare_search" …
      kind="field_value" …
        kind="identifier" children=0 text="index"
        kind="=" children=0
        kind="identifier" children=0 text="main"
    kind="|" children=0
    kind="command"
      kind="stats_command" children=4
        kind="stats" named=false children=0 text="stats"   ← leaf
        kind="identifier" text="count"
        kind="by" named=false children=0 text="by"       ← leaf
        kind="identifier" text="host"
    kind="|" children=0
    kind="command"
      kind="head_command" children=2
        kind="head" named=false children=0 text="head"   ← leaf
        kind="number" text="1"
```

Same pattern: `stats` / `by` / `head` are anonymous leaves.

---

## 2. Actual highlight tokens (CST walker)

Runtime path: `collect_highlights` in `crates/opentide-kql` / `crates/opentide-spl` → `tokens_from_spans` / `HighlightSpec`.

### KQL sample

| capture         | span   | text             |
|-----------------|--------|------------------|
| `type`          | 0..13  | `SecurityEvent`  |
| `operator.pipe` | 14..15 | `\|`             |
| `keyword`       | 16..21 | `where`          |
| `variable`      | 22..29 | `EventID`        |
| `operator`      | 30..32 | `==`             |
| `number`        | 33..34 | `1`              |
| `operator.pipe` | 35..36 | `\|`             |
| `keyword`       | 37..41 | `take`           |
| `number`        | 42..43 | `1`              |

### SPL sample

| capture         | span   | text    |
|-----------------|--------|---------|
| `property`      | 0..5   | `index` |
| `operator`      | 5..6   | `=`     |
| `variable`      | 6..10  | `main`  |
| `operator.pipe` | 11..12 | `\|`    |
| `keyword`       | 13..18 | `stats` |
| `variable`      | 19..24 | `count` |
| `keyword`       | 25..27 | `by`    |
| `variable`      | 28..32 | `host`  |
| `operator.pipe` | 33..34 | `\|`    |
| `keyword`       | 35..39 | `head`  |
| `number`        | 40..41 | `1`     |

### Corpus samples (same walker)

```
comment__valid.kql          SecurityEvent | take 1
  => type, operator.pipe, keyword:take, number

distinct_operator__valid.kql  SecurityEvent | distinct Computer
  => type, operator.pipe, keyword:distinct, variable

dedup_command__valid.spl    index=main | dedup host
  => property, operator, variable, operator.pipe, keyword:dedup, variable

eval_command__valid.spl     index=main | eval x=1
  => property, operator, variable, operator.pipe, keyword:eval, variable, operator, number
```

Keywords are present on corpus queries.

### HTML from CLI (`opentide-lsp highlight --html`)

```html
<span class="type">SecurityEvent</span>
<span class="operator-pipe">|</span>
<span class="keyword">where</span>
<span class="variable">EventID</span>
<span class="operator">==</span>
<span class="number">1</span>
…
<span class="keyword">take</span>
```

Regression tests (pass): `crates/opentide-analysis/tests/highlight_keyword_html.rs`
(`kql_keyword_tokens_and_html_spans`, `spl_keyword_tokens_and_html_spans`).

---

## 3. Why the HTML demo looked “uncolored”

`crates/opentide-lsp/src/main.rs` builds HTML with:

```css
body{ … color:#d4d4d4; background:#1e1e1e }
.keyword{color:#569cd6}
.type{color:#4ec9b0}          /* vivid cyan — tables */
.variable{color:#9cdcfe}      /* very pale */
.operator{color:#d4d4d4}      /* SAME as body — invisible */
.operator-pipe{color:#c586c0}
```

Classes are `capture.replace('.', '-')`, so `operator.pipe` → `operator-pipe` (CSS matches).

**Perception:**

1. Table / primary source identifiers use `@type` → strong cyan.
2. `==` / `=` use `@operator` → identical to body → look “white”.
3. Field names / identifiers use `@variable` → near-white pale blue.
4. Keywords are blue (`#569cd6`) and **are** wrapped — but the overall surface still reads washed out next to cyan tables.

So the CLI path is not “missing keywords”; it is **low-contrast for everything except `type` (and pipes)**.

### Other paths that really are uncolored

| Path | Behavior |
|------|----------|
| `highlights/generated/*.tmLanguage.json` | Patterns are **name-only stubs** — no `match` / `begin`. TextMate-only coloring does nothing. |
| `packages/lsp-client` `highlight()` (stdio without bindgen) | Returns **`tokens: []`**. |
| `packages/lsp-worker` stub | Returns **`tokens: []`**. |

Failing test documenting the TextMate stub (intentionally red):  
`opentide_highlight::tm_language_stub_bug::generated_kql_tm_language_has_executable_match_rules`.

---

## 4. `child_count() == 0` guard — does it skip keywords?

```rust
// crates/opentide-kql/src/lib.rs  (opentide-spl is analogous)
"let" | "where" | … | "take" | … => Some("keyword"),
…
if let Some(capture) = capture {
    if node.child_count() == 0 || matches!(kind, "string" | "comment" | "number" | "timespan") {
        out.push((ByteSpan::new(node.start_byte(), node.end_byte()), capture));
    }
}
```

| Node kind | `child_count()` | Skipped? |
|-----------|-----------------|----------|
| `where` / `take` / `stats` / `head` / `by` | **0** | **No** — emitted as keyword |
| `where_operator` / `stats_command` (parents) | >0 | Not matched as keyword (kind ≠ `"where"`) |
| `identifier` under `tabular_primary` | 0 | Emitted as `type` |

**Conclusion:** The guard does **not** drop keywords today. It would only bite if the grammar started wrapping keyword tokens (true `word` wrapper children), or if the walker matched parent operator nodes instead of anonymous keyword leaves.

`highlights.scm` already targets the correct shape, e.g. `(where_operator "where" @keyword)`.

---

## 5. `highlights.scm` is not executed at runtime

- Files exist: `highlights/queries/{kql,spl,tide}/highlights.scm`.
- They are `include_str!`’d in `opentide-highlight` and checked as a **subset of `HighlightSpec`** only.
- Engines use the hand-written CST walk above — **no `Query` / `QueryCursor`**.

Probe (passes): compiling the SCM with tree-sitter 0.25 and running matches **does** capture `where` / `take` / `stats` / `head` as `@keyword`.

```text
cargo test -p opentide-syntax highlights_scm_query_api_emits_keywords -- --nocapture
```

(module: `highlight_cst_dump`)

### Recommended fix — drive highlighting from `.scm` (tree-sitter 0.25.10)

Sketch that compiles against `tree-sitter = "0.25"` (uses `StreamingIterator` for `QueryCursor::matches`):

```rust
use tree_sitter::{Node, Query, QueryCursor, StreamingIterator};
use opentide_core::ByteSpan;
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};

pub fn highlight_with_scm(
    spec: &HighlightSpec,
    language: &tree_sitter::Language,
    source: &str,
    root: Node,
    scm: &str,
) -> Result<Vec<HighlightToken>, opentide_highlight::HighlightError> {
    let query = Query::new(language, scm).expect("highlights.scm must compile");
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, source.as_bytes());
    let mut spans: Vec<(ByteSpan, &str)> = Vec::new();
    // Later captures win for the same byte range (scm puts @variable after @type).
    // Prefer collecting then resolving overlaps, or order scm so specifics come last
    // and keep last-wins when sorting.
    while let Some(m) = matches.next() {
        for capture in m.captures {
            let name = query.capture_names()[capture.index as usize];
            // Only accept names that exist in HighlightSpec (already CI-gated).
            let node = capture.node;
            spans.push((
                ByteSpan::new(node.start_byte(), node.end_byte()),
                // leak-free: use an interned map, or match to &'static str table
                // For a first cut, map known captures:
                match name {
                    "comment" => "comment",
                    "keyword" => "keyword",
                    "operator" => "operator",
                    "operator.pipe" => "operator.pipe",
                    "function" => "function",
                    "type" => "type",
                    "variable" => "variable",
                    "property" => "property",
                    "string" => "string",
                    "number" => "number",
                    "boolean" => "boolean",
                    "constant" => "constant",
                    "punctuation.bracket" => "punctuation.bracket",
                    "punctuation.delimiter" => "punctuation.delimiter",
                    "error" => "error",
                    other => panic!("unexpected capture {other}"),
                },
            ));
        }
    }
    // Resolve overlaps: keep the last capture for an identical span (scm order),
    // or prefer non-variable over variable when spans equal.
    spans.sort_by_key(|(sp, _)| (sp.start, sp.end));
    tokens_from_spans(spec, source, &spans)
}
```

Wire-up:

1. Replace `collect_highlights` + `highlight_tree` in `opentide-kql` / `opentide-spl` with `highlight_with_scm(..., KQL_HIGHLIGHTS_SCM)`.
2. Keep Tide host YAML regex highlighter; keep injection remapping (below).
3. Optionally drop the duplicate CST keyword tables so `.scm` is authoritative.
4. When resolving overlaps, prefer `@type` / `@function` / `@keyword` over the broad `(identifier) @variable` rule (scm currently emits both for table names).

Also fix demo CSS: give `.operator` a distinct color (not `#d4d4d4`), and/or darken `.variable` so the HTML preview is not cyan-primary.

---

## 6. Tide injection remapping

`configurations.sentinel.query` → `LanguageId::Kql`  
`configurations.splunk.query` / `.search` → `LanguageId::Spl`

Flow in `opentide-tide::analyze`:

1. `extract_injections` strips block-scalar indent and builds `host_map` (inner byte → host byte).
2. Inner `opentide_kql::analyze` / `opentide_spl::analyze` produce tokens on **inner** coordinates.
3. `remap_token` → `remap_span` maps each token onto the YAML host document.

Verified: injected KQL/SPL tokens (including `keyword` for `where`/`take`/`stats`/`head`) appear on YAML byte ranges together with `tide.keyword` / `tide.property` host tokens. Existing test: `injected_kql_tokens_land_on_yaml`.

Injection remapping is **not** the white-highlight root cause; it faithfully forwards whatever the inner engines emit (including keywords).

---

## 7. Tests added for this investigation (uncommitted)

| Test | Expectation | Status |
|------|-------------|--------|
| `opentide_syntax::highlight_cst_dump::dump_cst_kql_and_spl_samples` | Prints CST | pass (debug) |
| `opentide_syntax::highlight_cst_dump::highlights_scm_query_api_emits_keywords` | SCM Query yields keywords | pass |
| `highlight_keyword_html::{kql,spl}_keyword_tokens_and_html_spans` | Keyword tokens + `<span class="keyword">` | pass |
| `opentide_highlight::tm_language_stub_bug::generated_kql_tm_language_has_executable_match_rules` | Generated tmLanguage has `match`/`begin` | **FAIL** (documents TextMate stub bug) |

Do **not** commit until the team decides whether to keep the failing TextMate assertion or `#[ignore]` it.

---

## Root cause summary

1. **Not** keyword nodes with children skipped by `child_count() == 0` — keywords are leaves and are tokenized.
2. **`highlights.scm` unused** at runtime (CST walk only) — architectural drift; Query API works and should replace the walk.
3. **Demo CSS** makes operators invisible and variables pale; **`type` (tables) dominates** as cyan.
4. **Generated TextMate grammars are inert stubs**; JS client/worker stubs return empty token lists — editor paths without semantic tokens look fully white.
5. **Tide injection remapping works** for sentinel/splunk query fields.
