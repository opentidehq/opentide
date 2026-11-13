// prod:for_expression valid
import "pe"

rule r {
  strings:
    $a = "abc"
  condition:
    for any i in (1..#a) : ( @a[i] < 100 ) and for all s in pe.sections : ( s.raw_data_size > 0 ) and for any of ($a) : ( $ at 0 )
}
