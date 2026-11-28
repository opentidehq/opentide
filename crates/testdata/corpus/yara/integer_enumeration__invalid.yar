// prod:integer_enumeration invalid
rule r {
  condition:
    for any i in (1, 2,) : ( i == filesize )
}
