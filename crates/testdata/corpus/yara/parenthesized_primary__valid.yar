// prod:parenthesized_primary valid
rule r {
  condition:
    (filesize + 1) * 2 > 10
}
