# reference_not_found

`--objective` or `--threat` names a UUID that no object in the catalogue carries.

Exit 2, as `failure.code`, with `failure.argument` naming the option. `opentide new` checks the reference before it writes anything; a malformed UUID is `usage_invalid_value` instead.

## Example

```text
opentide new rule --name "LSASS Access" --objective 00000000-0000-4000-8000-000000000000
```

## How to fix

Copy the UUID from the object's `metadata.uuid`, or create that objective or threat first with `opentide new objective` or `opentide new threat`. `opentide info` lists the catalogue.
