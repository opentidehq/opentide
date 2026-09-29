# HighlightSpec

`highlights/spec.toml` is the frozen map from a capture name to TextMate, Monaco, and Helix scopes. `HighlightSpec::load` parses it once and rejects a legend entry that has no `[captures.<name>]` table.

## Versions

`[meta].version` is `0.2.0`. Policy:

- Renaming or removing a capture is a **major** break. Editors and the highlight zip key off the name. Do not rename.
- Adding a capture is a **minor**. Bump the patch or minor in `[meta].version` when you add one (`markdown.*` and `macro` were the 0.2.0 additions). Appending to `legend` is the compatible direction. Inserting in the middle changes semantic-token type indexes, which is a break for clients that cached the legend. Append.

Every legend string has a `[captures."<name>"]` table with `tm`, `monaco`, and `helix`. Dotted names are quoted TOML keys (`[captures."operator.pipe"]`).

## Generated artifacts

`opentide-lsp generate-highlights` writes:

- `highlights/generated/kql.tmLanguage.json`
- `highlights/generated/spl.tmLanguage.json`
- `highlights/generated/tide.tmLanguage.json`
- `highlights/generated/monaco.json`
- `highlights/generated/helix.toml`
- `highlights/generated/legend.json`

CI runs `generate-highlights --check`. After a spec or `.scm` change:

```bash
cargo run -p opentide-lsp -- generate-highlights
cargo run -p opentide-lsp -- generate-highlights --check
```

Commit the generated files. Do not hand-edit them. Editor repos copy the zip produced from these files; they do not author a second grammar.

## Queries

`.scm` captures must be legend members. `opentide-highlight` extracts `@name` from the query files and errors on an unknown name. The syntax crate resolves overlaps: first pattern wins, then a later span that starts inside a previous token is dropped.

A new capture needs all of:

1. A legend entry appended in `spec.toml`.
2. A `[captures."..."]` table with three scopes.
3. A pattern in the right `highlights/queries/<lang>/highlights.scm`, above the broad `(identifier) @variable` pattern.
4. Regenerated files under `highlights/generated/`.
5. A corpus or highlight test that the token is present (`capture == "keyword"` style assertions in `opentide-syntax` and `opentide-analysis`).

## Markdown and Tide

`markdown.heading`, `markdown.emphasis`, `markdown.strong`, `markdown.code`, `markdown.link`, `markdown.list`, `markdown.quote` highlight Tide markdown bodies. They are not tree-sitter Markdown. `tide.keyword`, `tide.property`, `tide.uuid`, and `tide.schema` are the YAML object layer. `macro` is the SPL macro capture.

Do not reuse `keyword` for a Tide YAML key. The Tide scopes exist so editors can theme object structure separately from query keywords.
