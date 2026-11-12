# google_secops_credentials_missing

opentide has no usable Google credentials for a Google SecOps tenant.

Severity: error. Reported by `opentide deploy`, `opentide validate query --live` and `opentide query` on a `google_secops` tenant (google-secops-1.0). The tenant's `credentials` variable is unset, names no file, or holds no service-account key; or the tenant names no `credentials` and Application Default Credentials are not set up.

## Example

```text
google_secops_credentials_missing: the credentials variable GOOGLE_SECOPS_CREDENTIALS is not set
```

## How to fix

Set the variable to a service-account key (its JSON, or the path to the file), or leave `credentials` out and set up Application Default Credentials (`gcloud auth application-default login`, or workload identity in CI).
