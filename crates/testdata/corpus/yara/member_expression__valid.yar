// prod:member_expression valid
import "pe"

rule r {
  condition:
    pe.number_of_sections > 1
}
