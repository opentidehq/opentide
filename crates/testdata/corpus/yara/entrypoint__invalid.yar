// prod:entrypoint invalid
rule r {
  condition:
    entrypoint[0] == 1
}
