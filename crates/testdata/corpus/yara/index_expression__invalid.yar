// prod:index_expression invalid
import "pe"

rule r {
  condition:
    pe.sections[0.name == ".text"
}
