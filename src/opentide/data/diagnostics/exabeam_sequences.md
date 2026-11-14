# exabeam_sequences

An Exabeam block has no sequences, or a sequence has no query.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). `sequences` is a non-empty list, and every sequence has a non-blank `query`: a filter in the Exabeam Query Language.

## Example

```yaml
configurations:
  exabeam:
    sequences:
      - name: Failed logins
        query: ""
```

## How to fix

Write the filter in `query`, such as `activity_type:"app-login" AND outcome:"fail"`, or remove the empty sequence.
