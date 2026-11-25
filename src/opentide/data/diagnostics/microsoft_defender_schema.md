# microsoft_defender_schema

A Microsoft Defender block's `schema` names another schema.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `microsoft_defender` block (microsoft-defender-1.0). `schema` may be left out; when set it is `platform::microsoft_defender::1.0`. The finding is on `schema`.

## Example

```yaml
configurations:
  microsoft_defender:
    schema: platform::microsoft_defender::2.0
```

## How to fix

Write `schema: platform::microsoft_defender::1.0`, or remove the key.
