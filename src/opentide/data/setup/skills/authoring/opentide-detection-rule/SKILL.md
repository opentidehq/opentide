# Detection rules

Author rules as `rule::1.1` YAML under `objects/rules/`.

## Shape

- `metadata.uuid` is required. `metadata.schema` is `rule::1.1`.
- `detection_model` is the UUID of an objective in `objects/objectives/`.
- Platform query text lives under `configurations.<platform>`, not a legacy `Schemas/` or `Configurations/systems` path.
- Generate a starting file with `opentide generate` and edit the template it writes.

## Check

```bash
opentide --json validate --strict
opentide --json lint --strict
opentide validate query --platform <platform> --live --file <rule file>
opentide deploy --dry-run --strategy PREVIEW --all
```

With `--json`, stdout is one JSON document. Each finding has `code`, `path`, `line`, `column`, `help` and `fix`: apply `fix.edits` (replace the text from (`line`, `column`) up to (`end_line`, `end_column`) with `replacement`; check an edit that is not `safe` against `help`), run `opentide explain <code>` when there is none, and repeat until the exit code is `0`. On a non-zero exit, `failure.code` says why; follow `next_actions`.

`validate` checks schema, UUID, and references. `lint` checks filenames and recommended metadata. Query validation checks the tenant (`--live`) for the platforms that support it; `--file` limits it to the rule you are writing. A bare command refuses.
