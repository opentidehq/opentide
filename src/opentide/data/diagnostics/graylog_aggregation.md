# graylog_aggregation

A Graylog aggregation condition does not parse, or a call has the wrong arguments.

Severity: error. Reported by `opentide validate` on a `graylog` block (graylog-1.0), at `aggregation.condition` (or `aggregation` when it has no condition). The condition compares series with numbers: `count() >= 3 OR card(parent_image_lc) >= 2`. The functions are `avg`, `card`, `count`, `latest`, `max`, `min`, `percentage`, `percentile`, `stddev`, `sum`, `sumofsquares` and `variance`; `count` takes no field or one, `percentile` a field and a percentile from above 0 to 100, every other function one field. Operators `AND`, `OR` and `NOT` are upper case. Arguments are separated by one comma (`percentile(bytes, 95)`), and parentheses and `NOT` nest at most 32 deep.

## Example

```yaml
configurations:
  graylog:
    aggregation:
      condition: count() >= 3 or avg() > 1
```

## How to fix

Write the condition in the grammar: `count() >= 3 OR avg(bytes) > 1`.
