# Detection rules

Author rules as `rule::1.0` YAML under `objects/rules/`.

## Shape

- `metadata.uuid` is required. `metadata.schema` is `rule::1.0`.
- `detection_model` is the UUID of an objective in `objects/objectives/`.
- Platform query text lives under `configurations.<platform>`, not a legacy `Schemas/` or `Configurations/systems` path.
- Generate a starting file with `opentide generate` and edit the template it writes.

## Check

```bash
opentide validate --strict
opentide lint --strict
opentide validate query --platform <platform> --live
opentide deploy --dry-run
```

`validate` checks schema, UUID, and references. `lint` checks filenames and recommended metadata. Query validation checks the tenant (`--live`) for the platforms that support it. A bare command refuses.
