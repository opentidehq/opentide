# prod:array valid
in(severity, values=["critical", "high"]) | selfJoin(email_id, where=[{from=*peter*}, {to=*anders*}], collect=[from,to]) | rename(field=[[a, b], [c, d]])
