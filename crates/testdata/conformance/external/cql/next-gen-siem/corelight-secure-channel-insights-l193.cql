#Vendor = corelight and #event.module = ndr
| in(field=#event.dataset, values= ["ndr.ssl", "ndr.ssl_red"])
| in(field=observer.hostname, values=[?sensor_name])
| is_dest_internal_ip:=if(cidr("destination.ip", subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]), then="true", else="false")
| is_dest_internal_ip = "true"
| array:reduceAll(array="Vendor.cert_chain_fps[]", function=[groupBy(fingerprint, function=tail(limit=max), limit=max)], var="fingerprint")
| join(query={
        #Vendor = corelight and #event.module = ndr
        | in(field=#event.dataset, values= ["ndr.x509", "ndr.x509_red"])
        | in(field=observer.hostname, values=[?sensor_name])
        | rename(field=Vendor.fingerprint, as="fingerprint")
        | ts_now := now()
        | parseTimestamp(field=Vendor.certificate.not_valid_after, as=ts_then)
        | time_diff := ts_then - ts_now
        | time_diff >0
        | formatDuration("time_diff",as=time_diff,from=ms)
        | regex(field=time_diff,regex="(?<days>\\d+)d")
        | days<30
        | days_to_expiry:= days
}, field=fingerprint, key=fingerprint, mode=inner,include=[Vendor.certificate.subject,Vendor.certificate.not_valid_after,days_to_expiry], limit=20000)
| groupBy([Vendor.certificate.subject,destination.ip],function=[collect([destination.port],separator=", "),collect([Vendor.certificate.not_valid_after],separator=", "),collect([days_to_expiry],separator=", ")], limit=max)
| default(value="N/A", field=["destination.ip", "destination.port", "Vendor.certificate.not_valid_after", "days_to_expiry"])
| default(value="No Results", field=[Vendor.certificate.subject])
| rename([[Vendor.certificate.subject,"Subject"],["destination.ip","Host"],["destination.port","Port"],[Vendor.certificate.not_valid_after,"Not Valid After"],["days_to_expiry","Days to Expire"]])