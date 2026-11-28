#Vendor = corelight and #event.module = ndr
| #event.dataset = ndr.vpn
| in(field=observer.hostname, values=[?system_name])
| ?{additional_filter=*} and Vendor.vpn_type=?{vpn_type=*}
| network.protocol="spicy*"
| inference_filter := ?inference
| case {
    !text:contains(string=inference_filter, substring="*") |
    array:contains(array="Vendor.inferences[]", value=?inference);
    text:contains(string=inference_filter, substring="*") | *
}
| ipLocation(destination.ip, as=GeoIP)
| groupBy([source.ip, destination.ip, destination.port, GeoIP.country, network.protocol, network.transport], function=[sum("Vendor.resp_bytes", as=resp_bytes_sum), sum("Vendor.orig_bytes", as=orig_bytes_sum), count()], limit=max)
| total_bytes := orig_bytes_sum + resp_bytes_sum
| sort(total_bytes, limit=20)
| rename([[source.ip, "Source IP"], [destination.ip, "Destination IP"], [destination.port, "Destination Port"], [network.transport, Protocol], [GeoIP.country, "Destination Country"], [network.protocol, Service], [orig_bytes_sum, "Sum of Source Bytes"], [resp_bytes_sum, "Sum of Destination Bytes"], [total_bytes, Gigabytes], [_count, "Number of Connections"]])