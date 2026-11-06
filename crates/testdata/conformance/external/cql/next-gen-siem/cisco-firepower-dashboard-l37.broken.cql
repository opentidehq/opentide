//NST: Falcon Endpoint
#event_simpleName=NetworkConnectIP4
| wildcard(field=LocalAddressIP4, pattern=?SourceIP, ignoreCase=true)
| wildcard(field=RemoteAddressIP4, pattern=?DestinationIP, ignoreCase=true)
| wildcard(field=RPort, pattern=?DestinationPort, ignoreCase=true)
| asn(RemoteAddressIP4)
| ipLocation(RemoteAddressIP4)
| country:=RemoteAddressIP4.country
| join(query={"#event_simpleName" = ProcessRollup2, mode = inner, limit = 200000, field=[aid,ContextProcessId], key=[aid,TargetProcessId], include=[aid,TargetProcessId,FileName, ParentBaseFileName,UserName] )
| falconPID:= ContextProcessId
| format("[Graph Explorer](/graphs/process-explorer/graph?id=pid:%s:%s)", field=["aid", "falconPID"], as="Graph Explorer")
| table([ComputerName,UserName,ParentBaseFileName, FileName, RemoteIP, RemoteAddressIP4.org, country, "Graph Explorer"])
