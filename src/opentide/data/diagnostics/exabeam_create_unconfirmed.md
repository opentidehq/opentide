# exabeam_create_unconfirmed

An Exabeam create got no answer, or a server error, so it may or may not have happened.

Severity: error. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). The create timed out, the connection was reset, or Exabeam answered `5xx`. Exabeam may have created the rule, but its id never reached opentide. Deploy never sends a create again, because it may not list rules to find the first one.

## Example

```text
exabeam_create_unconfirmed: the create of 'Password spraying from outside the network' got no answer, so Exabeam may have created it with an id opentide does not know
```

## How to fix

Look for the rule by its name in the Exabeam console. Delete it and deploy again, or record its id under `platforms.exabeam.<tenant>` in `.opentide/states/deployment/<uuid>.json` and commit it. If there is none, deploy again.
