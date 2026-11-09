#repo=base_sensor
| !in(#event_simpleName, values=[SensorHeartbeat, EndOfProcess, ChannelVersionRequired, CurrentSystemTags, TerminateProcess, "LFO*", "ObPost*"])
| ComputerName=?ComputerName aid=?aid UserName=?UserName FileName=?FileName #event_simpleName=?events
| case {
    #event_simpleName = "NetworkConnectIP4"
        | DestIP := RemoteAddressIP4;
    *
        | DestIP := RemoteAddressIP6;
}
| format("Local Port: %s;Destination IP: %s;Remote Port: %s;File Name: %s;Target File Name: %s;CommandLine: %s;SHA256: %s;MD5: %s;SHA256: %s;AV Hits: %s;Domain Name: %s;Registry Name: %s;Registry String: %s;Registry Value: %s;Source Thread Module: %s;Target Thread Module: %s;Injected DLL: %s;Volume Drive Letter: %s;Volume File System Device: %s;Volume Real DeviceName: %s;Volume Mount Point: %s;Pattern Id: %s;Tree Id: %s;Logon Time: %s;Logon Domain: %s;Logon Type: %s;PID: %s;Parent ProcessId: %s;AsepWritten Count: %s;DnsRequest Count: %s;NetworkBind Count: %s;NetworkCapableAsepWrite Count: %s;NetworkClose Count: %s;NetworkConnectCount: %s;NetworkListen Count: %s;NetworkRecvAccept Count: %s;NewExecutableWritten Count: %s;SuspectStack Count: %s;", field=[LocalPort, DestIP, RemotePort, ImageFileName, TargetFileName, CommandLine, SHA256HashData, MD5HashData, sha256, detectionCount, DomainName, RegObjectName, RegStringValue, RegValueName, SourceThreadModule, TargetThreadModule, InjectedDll, VolumeDriveLetter, VolumeFileSystemDevice, VolumeRealDeviceName, VolumeMountPoint, PatternId, TreeId, LogonTime, LogonDomain, LogonType, RawProcessId, ParentProcessId, AsepWrittenCount, DnsRequestCount, NetworkBindCount, NetworkCapableAsepWriteCount, NetworkCloseCount, NetworkConnectCount, NetworkListenCount, NetworkRecvAcceptCount, NewExecutableWrittenCount, SuspectStackCount], as=Attributes)
| splitString(Attributes, by=";", as=Attributes)
| split(Attributes)
| Attributes != *null
| case {
    TargetProcessId != *
        | ProcessId := ContextProcessId;
    ContextProcessId != *
        | ProcessId := TargetProcessId;
    *;
}
| rename([ImageFileName], as = FileName)
| groupBy([@timestamp, aid, ComputerName, TreeId, PatternId, ParentProcessId, ProcessId, #event_simpleName, FileName, DomainName, DestIP, TargetFileName, UserSid, UserName], function=[collect([Attributes])], limit=max)
| default(field=[aid, ComputerName, FileName, TreeId, PatternId, ParentProcessId, ProcessId, DomainName, DestIP, TargetFileName, UserSid, UserName, Attributes], value="--", replaceEmpty=true)
| timestamp_UTC_readable := formatTime("%FT%T%z", field=@timestamp)
| table([@timestamp, timestamp_UTC_readable, aid, ComputerName, TreeId, PatternId, ParentProcessId, ProcessId, #event_simpleName, FileName, DomainName, DestIP, TargetFileName, UserSid, UserName, Attributes], sortby=Time, order=desc, limit=5000)