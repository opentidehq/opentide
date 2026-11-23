# credential_unset

A tenant's setup names an environment variable that is not set, so the command stopped before it called the tenant.

Exit 1, as `failure.code` of `validate query --live`. `message` names the variables (`Splunk credentials are unset ($SPLUNK_TOKEN)`). Nothing is sent to the tenant, and no value is printed.

## Example

```text
opentide validate query --live --platform splunk
```

## How to fix

Set the variables the message names in the environment the command runs in (a CI secret, or a `.env` file you load). Never write the value into the TOML. `opentide doctor` lists the unset variables of every tenant.
