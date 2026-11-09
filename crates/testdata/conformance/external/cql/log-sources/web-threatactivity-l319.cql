#type=zscalernss-web
| user.email=~wildcard(?Username, ignoreCase=true)
| regex("^(?<Vendor.domain>.*?)(\/|$)", field=Vendor.eurl, strict=false)
| ioc:lookup(field=Vendor.domain, type=domain, confidenceThreshold=Unverified, strict=true)
| case {
    ioc[0].labels=Actor*
      | regex("^Actor\/(?<iocActor>\w+)\W+", field=ioc[0].labels, strict=false) ;
    * | iocActor:="None Listed" ;
  }
| replace(",", with="\n", field=ioc[0].labels, as="IOC.Details")
| rename(ioc[0].indicator, as="IOC.Domain")
| rename(ioc[0].malicious_confidence, as="IOC.Confidence")
| rename(iocActor, as="IOC.Actor")
| top([IOC.Actor, IOC.Domain], limit=20)
| sankey(source="IOC.Actor", target="IOC.Domain")