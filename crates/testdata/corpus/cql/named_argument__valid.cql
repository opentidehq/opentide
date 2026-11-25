# prod:named_argument valid
wildcard(field=animal, pattern=*h*rse*, ignoreCase=true)
| eval(a = b, x = y + z)
| format("%s:%s", field=[aid, cid], as="key")
