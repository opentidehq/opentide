// prod:string_wildcard invalid
rule r {
  strings:
    $a1 = "x"
  condition:
    any of ($*a)
}
