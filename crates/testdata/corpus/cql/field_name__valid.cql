# prod:field_name valid
@timestamp=* ioc[0].indicator.country=US my.Field..name=x 400 = statuscode
| user.email := lower(Vendor.properties.userPrincipalName)
