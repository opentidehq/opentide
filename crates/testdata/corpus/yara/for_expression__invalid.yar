// prod:for_expression invalid
rule r {
  strings:
    $a = "abc"
  condition:
    for any i in (1..#a) ( @a[i] < 100 )
}
