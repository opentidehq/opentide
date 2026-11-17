// prod:filesize invalid
rule r {
  condition:
    filesize[0] > 10
}
