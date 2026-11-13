// prod:string_length invalid
rule r {
  strings:
    $a = "abc"
  condition:
    !a > > 2
}
