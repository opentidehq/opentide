# usage_unknown_option

The command line passes an option the command does not take.

Exit 2, as `failure.code`. `failure.argument` is the option; `failure.suggestion` the closest one.

## Example

```text
opentide validate --strictt
```

## How to fix

Fix the spelling, or run `opentide <command> --help` to see the options the command takes.
