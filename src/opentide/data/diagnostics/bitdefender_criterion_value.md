# bitdefender_criterion_value

A criterion's value is not one its field accepts.

Severity: error. Reported by `opentide validate` on a `bitdefender` block (bitdefender-1.0). An enum field takes only its catalogue values (`Registry.Operation`: `key_created`, `key_deleted`, ...), and a port is an integer from 0 to 65535.

## Example

```yaml
configurations:
  bitdefender:
    detection:
      target: connection
      criteria:
        - field: Connection.DestinationPort
          any: [443, 70000]
```

## How to fix

Use a catalogue value, or a port in range written as a number.
