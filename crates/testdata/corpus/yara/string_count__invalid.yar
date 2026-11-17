// prod:string_count invalid
rule r {
  strings:
    $a = "abc"
  condition:
    #a[1 > 2
}
