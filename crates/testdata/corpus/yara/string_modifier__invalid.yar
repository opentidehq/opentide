// prod:string_modifier invalid
rule r {
  strings:
    $a = "abc" wide,
  condition:
    $a
}
