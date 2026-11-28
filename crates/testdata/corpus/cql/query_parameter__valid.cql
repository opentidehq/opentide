# prod:query_parameter valid
host = ?host
| matchstring := ?"Matching String to Locate"
| groupBy(field=?{basefield="@host"})
| ComputerName=?{ComputerName=*}
