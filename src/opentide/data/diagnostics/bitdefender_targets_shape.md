# bitdefender_targets_shape

`targets` sets both `endpoint_tags` and `companies`, or an empty list.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). A rule applies to endpoint tags or, on a partner tenant, to companies; neither means the whole company. Each list names aliases from the tenant's tables.

## Example

```yaml
configurations:
  bitdefender:
    targets:
      endpoint_tags: [tier0-servers]
      companies: [acme]
```

## How to fix

Keep one of the two lists, with at least one alias, or remove `targets`.
