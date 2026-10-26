# usage_error

The command line cannot be used as written, for a reason no other usage code covers.

Exit 2, as `failure.code`. For example, options that cannot be combined.

## Example

```text
opentide generate docs --changed --rules
```

## How to fix

Read the message, then run `opentide <command> --help` for the options and how they combine.
