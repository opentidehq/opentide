// Fortinet FortiGate parser
// bjorn.graabek@crowdstrike.com
//
// v0.4.0, more detailed/correct parsing based on "action" values
// v0.3.0, initial work on making the parser ECS compliant. The parser keeps the original field names and adds ECS field equivalents
// There are more fields to map to ECS fields. Fortigate log format is described here:
// https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference/357866/log-message-fields
// v0.2.0, timestamps weren't extracted correctly, timestamp extraction corrected. Choice between two different timestamps added
// v0.1.0, initial parser made by ???

// If events are received via syslog, there may be a priority number at the beginning which we have no need for
replace("^\<[\d]+\>", with="") |
kvParse() |

// There are 2 different time stamps in Fortigate events.
// The eventtime field records when the event was triggered.
// the date, time and tz fields record when the event was recorded.
// this parser uses the eventtime field and ignores the date, time and tz fields
// extract @timestamp from eventtime field
// some Fortigate eventtime fields have more digits than others
case {
    regex("^(?<timestamp>.{13})", field=eventtime) | parseTimestamp(field=timestamp, format=unixtimeMillis);
    regex("^(?<timestamp>.{10})", field=eventtime) | parseTimestamp(field=timestamp, format=unixtime);
* } |
drop(timestamp) |

case {
    in(action, values=["deny","blocked"]) | event.type:="denied";
    in(action, values=["perf-stats","trim-disk","update","delete","reseeding","roll-log"]) | event.type:="info";
    action!=* | event.type:="info";
* | event.type:="allowed" } |

// LogScale PaSta fields
Vendor:="fortinet" | logtype:="fortinet-firewall-log" |
// ECS fields
ecs.version:=8.8.0 | event.category:="network" | event.kind:="event" |
destination.address:=dstip | destination.ip:=dstip | destination.port:=dstport | destination.mac:=dstmac | destination.geo.country_name:=dstcountry |
source.address:=srcip | source.ip:=srcip | source.port:=srcport | source.mac:=srcmac | source.geo.country_name:=srccountry |
network.iana_number:=proto | network.application:=lower(app) |
// Computes the Community ID, a standard for hashing network flows. This can be used to easily correlate and join network flows across systems
communityId(proto=network.iana_number,sourceip=source.ip,sourceport=source.port,destinationip=destination.ip,destinationport=destination.por,as=network.community_id) |
source.bytes:=sentbyte | destination.bytes:=rcvdbyte | network.bytes:=source.bytes+destination.bytes |
source.packets:=sentpkt | destination.packets:=rcvdpkt | network.packets:=source.packets+destination.packets |
observer.type:="firewall" | observer.vendor:="Fortinet" |
observer.ingress.interface.name:=srcintf | observer.egress.interface.name:=dstintf |
log.level:=level