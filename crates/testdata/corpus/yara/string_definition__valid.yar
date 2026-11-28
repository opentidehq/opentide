// prod:string_definition valid
rule r {
  strings:
    $a = "abc"
    $ = "anon"
  condition:
    all of them
}
