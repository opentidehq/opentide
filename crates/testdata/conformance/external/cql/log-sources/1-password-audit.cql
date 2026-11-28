/************************************************************
****** Parse timestamp and log headers
****** Extract message field for parsing
****** Parse structured data
************************************************************/
| parseJson(prefix="Vendor.", excludeEmpty="true", handleNull="discard")
| parseTimestamp(field="Vendor.timestamp")
| parseJson(field="Vendor.aux_info", prefix="Vendor.aux_info.")


// #region METADATA
/************************************************************
****** Static Metadata Definitions
************************************************************/
| Parser_version := "0.1.0"
| Vendor := "1password"
| event.module := "audit-logs"
| ecs.version := "8.11.0"
| Cps.version := "1.0.0"
| event.dataset := "1password.audit"
| event.kind := "event"
| event.module := "1password"
| event.outcome := "success"
| observer.type := "IAM"

/************************************************************
****** Parse unstructured data (i.e. message field)
****** Normalize fields to data model
************************************************************/
| event.type := Vendor.object_type
| event.id := Vendor.uuid
| user.email := Vendor.actor_details.email
| user.full_name := Vendor.actor_details.name
| user.id := Vendor.actor_uuid
| host.id := Vendor.aux_info.deviceUuid
| client.geo.city_name := Vendor.location.city
| client.geo.country_name := Vendor.location.country
| client.geo.location := format("{ \"lon\": %s,\"lat\": %s }", field=[Vendor.location.longitude, Vendor.location.latitude])
| client.geo.region_name := Vendor.location.region

/************************************************************
****** Post Normalization
****** Custom parser logic needed after normalization
************************************************************/
| case{
    Vendor.action=*
    | event.action := format("%s-%s", field=[Vendor.action, Vendor.object_type])
    | match(file="Audit-events.csv", column="concat-action-type", field=event.action, include=["Event", "Description"], strict=false);*}