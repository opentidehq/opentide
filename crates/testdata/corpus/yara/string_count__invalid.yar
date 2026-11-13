// prod:string_count invalid
rule r {
  strings:
    $a = "abc"
  condition:
    # > > 2
}
