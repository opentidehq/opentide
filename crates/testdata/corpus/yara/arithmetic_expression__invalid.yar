// prod:arithmetic_expression invalid
rule r {
  condition:
    filesize * / 2 == 1
}
