# bitdefender_target

The `detection.target` is not a GravityZone detection target.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). The target must be spelled as the API spells it: `process`, `file`, `connection`, `registry`, `user connection`, `email`, `application`, `key vault`, `role`, `policy`, `sharing link`, `url`, `ssh key`, `launch template`, `service principal`, `user group`, `automation account`, `automation account hook`, `certificate authority`, `api`, `bucket`, `jira project` or `confluence page`. The exclusion-only targets `flow` and `bitbucket repository` are refused.

## Example

```yaml
configurations:
  bitdefender:
    detection:
      target: flow
      criteria:
        - field: Flow.Source
          is: 10.0.0.1
```

## How to fix

Use one of the detection targets, in lower case with spaces, such as `process`.
