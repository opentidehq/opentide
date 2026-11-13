# exabeam_group_by

A `group_by` is not a list of one to three distinct field names.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). A sequence's and the suppression's `group_by` hold one to three distinct non-blank field names; `correlation.group_by` holds up to three and may be empty. Field names are not checked against a list: they come from the tenant's data.

## Example

```yaml
sequences:
  - query: activity_type:"app-login"
    group_by: [user, src_ip, host, dest_ip]
```

## How to fix

Keep at most three fields, each once, or remove `group_by`.
