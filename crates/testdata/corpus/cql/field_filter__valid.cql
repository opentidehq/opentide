# prod:field_filter valid
url = *login* user != * name = "" "host-name"=* host[0]=* #repo=base_sensor
| class like "foo*bar" statuscode >= 400 Severity >= "80" LocalPort < ?maxPort
| method != /(PUT|POST)/ repo.name=docker/* foo=m/fisk/i
