// prod:string_definition invalid
rule r {
  strings:
    $a "abc"
  condition:
    $a
}
