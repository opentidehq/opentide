# cve_lookup_unavailable

A threat lists CVE identifiers, but Vulnerability-Lookup could not be reached to check them.

Severity: warning. Reported by `opentide validate --check cve`; fails `--strict`.

## Example

```yaml
threat:
  cve: [CVE-2024-3094]   # checked while the lookup service is unreachable
```

## How to fix

Check network access to https://vulnerability.circl.lu (or the configured lookup URL and any proxy), then run `opentide validate --check cve` again. The identifiers themselves were not judged: the check failed open.
