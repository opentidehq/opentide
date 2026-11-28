defineTable(
  query={
    createEvents([""])
    | ignoreUserNameList:="DWM-*|LOCAL SERVICE|UMFD-*|SYSTEM|ANONYMOUS LOGON|NT AUTHORITY\\SYSTEM|scheduled_tasks|*$"
    | splitString(field=ignoreUserNameList, by="\|", as=ignoreUserName)
    | split(ignoreUserName)
  },
  include=[ignoreUserName],
  name="ignore_username_table"
)

// Add a multipick array for value selection.
| in(field=#repo.cid, values=[?cid_input])

// Search for Windows RDP events.
| #event_simpleName=UserLogon
| #repo=base_sensor
| #type=falcon-raw-data
| event_platform="Win"
| LogonType=2 OR LogonType=10
| ComputerName=*
| UserName=*

// Ignore certain usernames.
| !match(file="ignore_username_table", field=UserName, column=ignoreUserName, mode=glob)
| UserName=/\w+/Fx

// Format the aid and ComputerName.
| format("%s -> %s", field=[aid, ComputerName], as=host.details)

// Put the username in lowercase.
| UserName:=lower(UserName)

// Group the results.
| groupBy(UserName, function=[count(aid, distinct=true, as=host.distinct.count), collect(host.details, limit=5)], limit=max)

// Filter minimum number of hosts.
| host.distinct.count>=?minDistinctHostsSuccess

// Sort the results
| sort(host.distinct.count, limit=1000)

// Format the URL.
| regex("^(?<UserName.stripped>[^@+]+)(?=\+|@|$)", field=UserName, strict=false, flags=F)
| UserName:=format("[%s](/search/user?term=_all:~'%s')", field=[UserName, UserName.stripped])
| drop([UserName.stripped])

// Rename for the widget.
| rename([[host.details, "Agent IDs [Sample of 5 Maximum]"], [host.distinct.count, "Unique Agent IDs"]])