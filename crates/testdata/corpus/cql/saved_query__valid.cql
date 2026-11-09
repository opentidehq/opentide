# prod:saved_query valid
$"My Saved Query"() | $filterOutFalsePositive()
| $falcon/helper:enrich(field=LogonType)
| $query://anotherView:saved()
