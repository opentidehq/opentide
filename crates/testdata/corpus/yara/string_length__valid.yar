// prod:string_length valid
rule r {
  strings:
    $a = "abc"
  condition:
    !a > 2
}
