# prod:binary_expression valid
errortime := if((@ingesttimestamp > @timestamp), then=@timestamp, else=@ingesttimestamp) / 1000
| test(length(userid) == length(method))
| pct := (part * 100) % total
