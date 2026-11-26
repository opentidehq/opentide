# microsoft_defender_custom_details_limit

A Microsoft Defender block's `alert.custom_details` is past the limits Microsoft documents.

Severity: warning. Reported by `opentide validate` (its `schema` check) and `opentide lint` (its `queries` check) on a `microsoft_defender` block (microsoft-defender-1.0), at `alert.custom_details`, when it has more than 20 details, or when the details' names alone take more than 4 KB (4096 bytes). Microsoft's [custom detection docs](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules) (read 2026-11-26) say: "Each rule is limited to up to 20 key-value pairs of custom details. The combined size limit for all custom details and their values in a single alert is 4 KB. If the custom details array exceeds this limit, the whole custom details array is dropped from the alert." The values are the query's results, known only when the rule runs, so opentide reports the size only when the names fill the limit on their own. Graph's answer to a 21st detail is not documented, so this is an advisory: the rule validates and deploys, and `validate --strict` reports it without failing until a tenant check settles it.

## Example

```yaml
configurations:
  microsoft_defender:
    alert:
      custom_details:
        Detail1: Column1
        # Detail2 to Detail20
        Detail21: Column21
```

## How to fix

Keep the details an analyst needs first, at most 20, and keep their values short: a long command line or a JSON column can push one alert past 4 KB, and then the alert shows no custom detail at all.
