# prod:subquery valid
defineTable(query={ | value=42 }, include=*, name="")
| join(query={#repo=B session_id=*}, field=session_id, key=session_id)
| groupBy(type, function={ avgFoo := avg(foo) | outFoo := round(avgFoo) })
