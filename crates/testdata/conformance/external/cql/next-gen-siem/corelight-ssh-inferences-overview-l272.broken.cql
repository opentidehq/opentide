#Vendor = corelight and #event.module = ndr
| in(field=#event.dataset, values=[ndr.ssh,ndr.ssh_red])
| in(field=observer.hostname, values=[?system_name])
| ?{additional_filter=*}
| inference_filter := ?{inferences=*}
| case {
    !text:contains(string=inference_filter, substring="*") |
    array:contains(array="Vendor.inferences[]", value=?{inferences=*});
    text:contains(string=inference_filter, substring="*") | *
}
| top([source.ip,Vendor.hassh,destination.ip,Vendor.hasshServer], limits=5)
| default(field=[source.ip,Vendor.hassh,destination.ip,Vendor.hasshServer],value="unknown")
| rename([[source.ip, "Source IP"],[Vendor.hassh, "HASSH Client"],[destination.ip,"Destination IP"],[Vendor.hasshServer,"HASSH Server"],[_count,"Count"]])