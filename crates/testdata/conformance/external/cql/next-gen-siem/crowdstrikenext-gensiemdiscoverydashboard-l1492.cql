/*
This query looks for the following events from the Falcon
sensor over a 24 hour period:
    - UserLogon
    - NetworkConnectIP4
    - UserLogoff
You can try changing the sequence to "true" to see if the
events occurred in this exact order.
*/
correlate(
    user_logon: {
        #repo="base_sensor" #event_simpleName="UserLogon"
        | user.name <=> user_logoff.user.name
    },
    network_connection: {
        #repo="base_sensor" #event_simpleName="NetworkConnectIP4"
        | ComputerName <=> user_logon.ComputerName | ComputerName <=> user_logoff.ComputerName
    },
    user_logoff: {
        #repo="base_sensor" #event_simpleName="UserLogoff"
    },
    within = 24hr,
    sequence = false,
    includeMatchesOnceOnly=true
)