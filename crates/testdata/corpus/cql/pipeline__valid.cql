# prod:pipeline valid
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\powershell\.exe$/i
| groupBy([aid, ComputerName], function=count(as=executions))
| sort(executions, order=desc, limit=20)
