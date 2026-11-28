# prod:saved_query_argument valid
$tausight/ephi-risk-posture:Tausight_ePHIStored(HostName=?{HostName=*})
| $mySavedQuery(mvArgument=["value1", "value2"], path=C:\Windows\*)
