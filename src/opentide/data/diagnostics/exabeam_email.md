# exabeam_email

The block `email` has no recipients, a recipient that is not an address, a repeated recipient, or a blank subject.

Severity: error. Reported by `opentide validate` on an `exabeam` block (exabeam-1.0). `email.recipients` is a non-empty list of distinct addresses (`local@domain`); `subject`, when set, is non-blank; `attach_csv` is `true` or `false`.

## Example

```yaml
configurations:
  exabeam:
    email:
      recipients: []
```

## How to fix

List at least one address, each once, or remove `email`.
