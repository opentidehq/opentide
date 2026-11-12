# google_secops_meta_key

A Google SecOps block's `meta` holds a key deploy cannot write.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). Each extra meta key is written after the derived meta as `key = "value"`: it must be an identifier that is not a YARA-L keyword, it must not be a key deploy derives (`author`, `description`, `severity`, `priority`, `technique`, `opentide_uuid`, `opentide_version`), and its value is a string. The finding is on `meta.<key>`.

## Example

```yaml
configurations:
  google_secops:
    meta:
      severity: Low        # deploy writes severity itself
      data_source: Okta
```

## How to fix

Remove the derived key (set `severity` on the block instead) or rename it; quote a value YAML would read as a number or a boolean.
