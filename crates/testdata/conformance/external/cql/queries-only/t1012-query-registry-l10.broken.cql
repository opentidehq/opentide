#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/\\reg\.exe/
| ImageFileName=/^//.+//(?<FileName>reg\.exe)/
| FileName:=lower("FileName" 
| ParentBaseFileName:=lower("ParentBaseFileName")
| groupBy([ParentBaseFileName, FileName], function=([count(aid, as=executionCount), count(aid, distinct=true, as=totalEndpoints)]))
| sort(executionCount, order=asc)