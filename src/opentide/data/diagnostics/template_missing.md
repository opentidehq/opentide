# template_missing

`opentide new` found no generated template or schema for the object type it was asked for.

Exit 1, as `failure.code`. `new` runs the generation it needs first when the workspace has no template; this code means that run wrote none for the family either.

## Example

```text
opentide new threat --name "Credential Dumping"
```

## How to fix

Run `opentide generate templates schemas` and read its output for the failing phase, then run `opentide new` again. `opentide doctor` reports a missing template as `templates_fresh`.
