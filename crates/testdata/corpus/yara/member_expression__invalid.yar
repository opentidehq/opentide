// prod:member_expression invalid
import "pe"

rule r {
  condition:
    pe. > 1
}
