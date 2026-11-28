#Vendor = netskope
and
| source.ip=~wildcard(?Source, ignoreCase=true)
| destination.ip=~wildcard(?Destination, ignoreCase=true)
| Vendor.action=~wildcard(?EventAction, ignoreCase=true)
| Vendor.user=~wildcard(?user, ignoreCase=true)
| cidr(source.ip, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32"])
| default(value="Not Match", field=[ComputerName])
| join({#type=/falcon/i AND #event_simpleName=NetworkConnectIP4}, field=source.ip, key=LocalAddressIP4,limit=200000, mode=left, include=[ComputerName])
| ComputerName="Not Match"
| groupBy([source.ip], function={[collect([source.mac]),count()]})
| sort(_count, order=desc)