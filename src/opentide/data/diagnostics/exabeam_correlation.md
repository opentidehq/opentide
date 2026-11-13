# exabeam_correlation

An Exabeam block with two or more sequences has no `correlation`, or one with a single sequence has one.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). Two or more sequences correlate within a common window, `correlation.within`; one sequence has nothing to correlate with.

## Example

```yaml
configurations:
  exabeam:
    sequences:
      - query: activity_type:"process-create" AND process_name:"mshta.exe"
    correlation:
      within: 10m
```

## How to fix

With one sequence, remove `correlation`. With two or more, set `correlation.within` (`15m`) and, optionally, `correlation.group_by`.
