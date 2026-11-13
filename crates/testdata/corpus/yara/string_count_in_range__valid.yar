// prod:string_count_in_range valid
rule r {
  strings:
    $a = "abc"
  condition:
    #a in (0..100) == 1
}
