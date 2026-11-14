# exabeam_name_conflict

An Exabeam rule with the block's name already exists, so deploy did not create a second one.

Severity: error. Reported by `opentide deploy` on an `exabeam` block (exabeam-1.0). Before a create, deploy lists the rules whose name holds the block's name (`nameContains`) and compares the names case-insensitively. A match fails the rule, naming the existing rule's id. Deploy never adopts it or records its id.

## Example

```text
exabeam_name_conflict: an Exabeam rule named 'Password spraying from outside the network' already exists (id 016dbc1d-a727-43df-a143-9546dcc81a5a); deploy does not adopt it
```

## How to fix

Rename the block (`configurations.exabeam.name`), or delete the old rule in the console. If it is this rule's own earlier create, record its id under `platforms.exabeam.<tenant>` in `.opentide/states/deployment/<uuid>.json` and commit it.
