// prod:string_offset valid
rule r {
  strings:
    $a = "abc"
  condition:
    @a > 2
}
