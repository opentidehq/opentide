// Define the repository
#repo="base_sensor"

// Define EDR events to include
| in(#event_simpleName,values=[DnsRequest])

// Match DomainName from lookup file
| match(file="rmm_domains.csv", field=[DomainName], column=rmm_domain, mode=glob, strict=true, include=[rmm_tool])

// Define the list of processes to exclude
//| ContextBaseFileName!=/chrome\.exe|msedge.*\.exe|firefox.*\.exe/iF

// Enrich with IOC lookup
| ioc:lookup(FirstIP4Record, type="ip_address", prefix="ip4_ioc")
| case {
    ip4_ioc.detected!=true | ip4_ioc.detected:=false ;
    * ;
}
| rename("ip4_ioc.detected", as="IP4IOCDetected")
| ioc:lookup(FirstIP6Record, type="ip_address", prefix="ip6_ioc")
| case {
    ip6_ioc.detected!=true | ip6_ioc.detected:=false ;
    * ;
}
| rename("ip6_ioc.detected", as="IP6IOCDetected")

// Define Filters
| ComputerName =~ wildcard(?{ComputerName=*}, ignoreCase=true)
| DomainName =~ wildcard(?{DomainName=*}, ignoreCase=true)
| ContextBaseFileName =~ wildcard(?{ContextBaseFileName=*}, ignoreCase=true)
| rmm_tool =~ wildcard(?{rmm_tool=*}, ignoreCase=true)

// Format timestamp
| Time := formatTime("%FT%TZ", field=@timestamp)

// Create the output table
| groupBy([Time, aid, ComputerName, LocalIP, rmm_tool, ContextBaseFileName, DomainName, FirstIP4Record, IP4IOCDetected, FirstIP6Record, IP6IOCDetected, id])
| sort(Time, order=desc, limit=20000)