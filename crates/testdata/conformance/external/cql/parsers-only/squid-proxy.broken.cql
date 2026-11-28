// Parser for the Squid proxy, http://www.squid-cache.org
// bjorn.graabek@crowdstrike.com
// v0.1.0
//
// The purpose of this parser is mainly to facilitate monitoring of access/denied access via a squid proxy.
// Squid logs contain much other information useful when monitoring squid hierarchies which this parser makes little attempt to extract.
// For more information on the squid log format, see:
// http://wiki.squid-cache.org/Features/LogFormat#squid-native-accesslog-format-in-detail
// https://wiki.squid-cache.org/SquidFaq/SquidLogs

regex("(?<@timestamp>\d{10}\.\d{3})\s+(?<duration>\d+)\s+(?<client.ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s+(?<cacheResultCode>\w+)\/(?<http.response.status_code>\d+)\s(?<responseSize>\d+)\s(?<http.request.method>\w+)\s(?<url>.*)\s(?<user.name>\w+|-)\s(?<proxyHierarchy>\w+)\/(?<destination.ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|-)\s(?<http.response.mime_type>.+)") |
parseTimestamp(field=@timestamp, format=unixtime) |

// LogScale PaSta fields
Vendor:="squid" | logtype:="squid-proxy-log" |
// ECS fields
ecs.version:="8.8.0" |
event.module:="squid-cache" |
event.kind:="event" | event.category:="web" | observer.type:="proxy" |
source.ip:=client.ip |

// If an https request is made, the squid logs don't contain the scheme of the url (https://), and parseurl requires that to correctly parse the url.
// To get around this issue, if url doesn't start with http*, the parser adds a fake scheme (temp://) to the url, parses the url, drops the temporary scheme field and blanks the value of url.scheme.
// if on the other hand the url does start with http*, then all the above shenanigans are not needed and the url is parsed normally.
// most of the fields created by parseurl() conform with ECS fields, except for url.host, which therefore gets renamed.
case {
    lower(url) | _lower!="http*" | temp:="temp://" | concat([temp,url], as=temp) | parseurl(temp, as=url) | drop([temp,_lower]) | url.scheme:="";
* | parseurl(url) } |
rename(url.host,as=url.domain) | url.original:=url |

// "source" defined as the device making the request, typically a host with a browser making a request to a web server via squid
// "destination" defined as the device receiving the request, typically a web server receiving a request via squid
// With https data, squid sets up a tunnel using "CONNECT" method. When method=CONNECT it is not possible to know what direction the data transfer is taking
// Other "methods" are logged, unsure whether to extract the data into destination/source bytes
case {
    regex("^(GET|HEAD)$", field=http.request.method) | destination.bytes:=responseSize | network.bytes:=responseSize;
    regex("^(PUT|POST)$", field=http.request.method) | source.bytes:=responseSize | network.bytes:=responseSize;
    regex("^CONNECT$", field=http.request.method) | network.bytes:=responseSize | network.direction:="unknown";
* } |

// logic for setting "event.type" values. There are other cacheResultCode reported by squid, but I'm unsure what values to set for these, so I'm not.
case {
    in(values=[TCP_DENIED]) | event.type:="denied";
    in(cacheResultCode, values=["TCP_TUNNEL*","TCP_MISS*","TCP_REFRESH*","TCP*HIT"]) | event.type:="allowed";
    in(cacheResultCode, values=["NONE*"]) | event.type:="error";
* }