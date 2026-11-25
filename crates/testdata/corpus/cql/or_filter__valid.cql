# prod:or_filter valid
statuscode=404 and (method=GET or method=POST)
| foo or not bar and baz
