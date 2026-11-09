#repo=net-firewall #type=sonicwall

//IOC / Threat Actor / Times Series by Country
// a time series chart indicating IOC associated country

// IOC lookup on IP Addresses
| ioc:lookup([source.ip, destination.ip], type="ip_address", confidenceThreshold=?Confidence_Threshold, strict=true)
| split("ioc")

// Filter only IOCs associated with Threat Actors
| ioc.labels = /^Actor\/(?<iocActor>\w+)\W+/

// Parameter selections
| ioc.malicious_confidence = ?Malicious_Confidence
| iocActor = ?IOC_Actor

// IOC Geo lookups
| ipLocation(ioc.indicator)
| ioc.indicator.country = ?IOC_Country
| match(file="crowdstrike_fltr-firewall-adversaries_geo_mapping.csv", column=CountryCode, field=ioc.indicator.country, include=["Country"], ignoreCase=true, strict=false)

// Display the results
| timeChart(span=1d, function=count(), series=Country)