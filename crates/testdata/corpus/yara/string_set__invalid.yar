// prod:string_set invalid
rule r {
  strings:
    $a = "abc"
  condition:
    all of ($a,)
}
