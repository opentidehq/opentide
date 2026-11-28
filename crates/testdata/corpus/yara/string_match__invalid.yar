// prod:string_match invalid
rule r {
  strings:
    $a = "abc"
  condition:
    $a at
}
