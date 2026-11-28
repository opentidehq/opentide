// prod:import valid
import "pe"

rule r {
  condition:
    pe.is_dll()
}
