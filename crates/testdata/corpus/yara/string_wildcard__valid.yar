// prod:string_wildcard valid
rule r {
  strings:
    $a1 = "x"
  condition:
    any of ($a*)
}
