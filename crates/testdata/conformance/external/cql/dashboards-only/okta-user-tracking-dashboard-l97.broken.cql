#type=Okta-* |
Okta.actor.alternateId like ?{Username=*}
| parseJson(field=Okta.device.deviceIntegrator)
| Okta.eventType = "policy.evaluate_sign_on"
//| Okta.target[0].alternateId = "unknown"
| format("[Link](https://falcon.us-2.crowdstrike.com/search/host?term=_all:~'%s')", field=Okta.target[0].displayName, as="CRWD Search")  //<---Create Clickable Link to the Falcon UI
| rename(field="Okta.client.geographicalContext.city", as="City") | rename(field="Okta.client.geographicalContext.country", as="Country")
| rename(field="Okta.target[0].displayName", as="Object or Computer") | rename(field=Okta.target[1].alternateId, as="Application") | rename(field="CROWDSTRIKE.os", as="Asset ZTA")
| table([@timestamp,ActorUser,Okta.device.osVersion,ActorAddressIP,"Object or Computer",AuthenticationResult,"Asset ZTA",Application,City,Country,"CRWD Search"])
| "opentide"