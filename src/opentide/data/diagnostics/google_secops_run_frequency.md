# google_secops_run_frequency

A Google SecOps block's `run_frequency` is not one opentide deploys.

Severity: error. Reported by `opentide validate` (its `schema` check) on a `google_secops` block (google-secops-1.0). `run_frequency` is `LIVE`, `LIVE_CUSTOMIZABLE`, `HOURLY_CUSTOMIZABLE` or `DAILY`. Google's legacy `HOURLY` is refused: Google remaps it, so the stored rule would never match the block.

## Example

```yaml
configurations:
  google_secops:
    run_frequency: HOURLY
```

## How to fix

Write `HOURLY_CUSTOMIZABLE` (or another of the four values), or remove `run_frequency`: deploy then sends none, and Google keeps the rule's frequency, or gives a new rule its default.
