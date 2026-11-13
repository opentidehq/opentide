// prod:integer_enumeration valid
rule r {
  condition:
    for any i in (1, 2, 3) : ( i == filesize )
}
