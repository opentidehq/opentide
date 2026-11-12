# google_secops_delete_refused

Google SecOps refused to delete a rule with detections, so deploy archived it.

Severity: warning. Reported by `opentide deploy` on a `google_secops` tenant with `deletion = "delete"` (google-secops-1.0). `DELETE` without `force` fails (`FAILED_PRECONDITION`) when the rule has detections or retrohunts; opentide never sends `force=true`, which deletes the detections too. The rule was disabled and archived instead, and its binding kept.

## Example

```text
google_secops_delete_refused: Google refused to delete rule ru_cfc80c6b-f918-42ed-8d5c-9518c13586c1 because it has detections or retrohunts; it is archived instead
```

## How to fix

Nothing to do: an archived rule keeps its detections as the audit trail of what it found. Delete it in the console when they are no longer needed.
