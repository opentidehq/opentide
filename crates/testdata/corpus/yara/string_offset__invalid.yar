// prod:string_offset invalid
rule r {
  strings:
    $a = "abc"
  condition:
    @a > > 2
}
