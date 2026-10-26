# invalid_cve

A threat lists CVE identifiers Vulnerability-Lookup does not know.

Severity: error. Reported by `opentide validate --check cve`.

## Example

```yaml
threat:
  cve: [CVE-2024-99999999]
```

## How to fix

Check each identifier on https://vulnerability.circl.lu and correct or remove the ones it does not find. The check needs network access to the lookup service.
