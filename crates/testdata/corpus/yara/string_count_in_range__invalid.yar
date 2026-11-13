// prod:string_count_in_range invalid
rule r {
  strings:
    $a = "abc"
  condition:
    #a in (0..) == 1
}
