// prod:string_set valid
rule r {
  strings:
    $a = "a"
    $b1 = "b"
  condition:
    all of ($a, $b*)
}
