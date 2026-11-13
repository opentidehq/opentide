// prod:index_expression valid
import "pe"

rule r {
  condition:
    pe.sections[0].name == ".text"
}
