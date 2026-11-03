# Public Falco rules, converted to opentide

Each file converts one rule of the public Falco rulesets into an opentide
rule with a `configurations.sysdig` block (`platform::sysdig::1.0`). The
condition, output, priority and tags come from the upstream rule; macros the
upstream file defines and Sysdig or the Falco default rules also ship are left
as references, and the rule-specific `user_known_*` hooks are written as block
macros and lists, which deploy expands.

| File | Upstream rule | Source |
|------|---------------|--------|
| `netcat-remote-code-execution.yaml` | Netcat Remote Code Execution in Container | `falcosecurity/rules`, `rules/falco_rules.yaml` |
| `search-private-keys-or-passwords.yaml` | Search Private Keys or Passwords | `falcosecurity/rules`, `rules/falco_rules.yaml` |
| `k8s-attach-exec-pod.yaml` | Attach/Exec Pod | `falcosecurity/plugins`, `plugins/k8saudit/rules/k8s_audit_rules.yaml` |
| `aws-console-login-without-mfa.yaml` | Console Login Without MFA | `falcosecurity/plugins`, `plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml` |
| `tuning-contact-k8s-api-server.yaml` | tunes Contact K8S API Server From Container | `falcosecurity/rules`, `rules/falco_rules.yaml` |

The upstream rules are Copyright The Falco Authors, licensed under the Apache
License, Version 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>).
