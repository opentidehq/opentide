// prod:string_count valid
rule r {
  strings:
    $a = "abc"
  condition:
    #a > 2
}
