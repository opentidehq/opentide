// prod:call_expression valid
import "math"

rule r {
  condition:
    uint16(0) == 0x5A4D and math.entropy(0, filesize) > 7.0
}
