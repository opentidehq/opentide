$tausight/ephi-risk-posture:Tausight_ePHIStored(HostName=?{HostName=*})

//edit age as number of days to find stale files more than 'age' days old
|age:=30
|case{ not in(field="Activity", values=[Email, "Cloud share"]) | parseTimestamp(as=@timestamp, field=LastAccessed); *|parseTimestamp(as=@timestamp, field=timestamp)}
|eval(curr_age = (now() - @timestamp)/(24*3600*1000))
|test(curr_age >= age)

|groupBy([OwnerName], function=count(field=FileName, as= "Files"), limit=10)
|sort(Files, order=down)

|Files>=1
//Severity:=Medium
