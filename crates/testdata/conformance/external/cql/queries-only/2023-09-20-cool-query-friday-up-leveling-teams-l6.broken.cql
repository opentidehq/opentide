// Get specific events and provide option to specify host
#event_simpleName=/^(ProcessRollup2|DnsRequest)$/x
// Get details for specific system
| ComputerName=~wildcard(?ComputerName, ignoreCase=true)

// Normalize UPID value
| falconPID:=TargetProcessId 
| falconPID:=ContextProcessId

// Create case statement to manipulate fields based on event type and provide option to specifiy parameters based on file type
| case {
    #event_simpleName=ProcessRollup2 | UserName=~wildcard(?UserName, ignoreCase=true) | FileName=~wildcard(?FileName, ignoreCase=true) | ParentBaseFileName=~wildcard(?ParentBaseFileName, ignoreCase=true) | ExecutionChain:=format(format="%s\n\t└ %s (%s)", field=[ParentBaseFileName, FileName, RawProcessId]);
    #event_simpleName=DnsRequest | DomainName=~wildcard(?DomainName, ignoreCase=true);
}
// Use selfJoin to filter our instances on only one event happening
| selfJoinFilter(field=[aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}])

// Aggregate to include desired fields
| groupBy([aid, falconPID], function=([count(#event_simpleName, as=eventCount, distinct=true), collect([ComputerName, UserName, ExecutionChain, DomainName, CommandLine])]))

// Remove unneeded fields
| drop(eventCount)

// Add link to graph explorer
| format("[Graph Explorer](https://falcon.us-2.crowdstrike.com/graphs/process-explorer/graph?id=pid:%s:%s)", field=["aid", "falconPID"], as="Graph Explorer")