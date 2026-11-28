# prod:field_shorthand valid
ip_addr =~ cidr(subnet="127.0.0.1/24")
| loglevel =~ !in(values=["ERROR", "WARN"])
| aid =~ join({#event_simpleName=AgentOnline}, field=aid, include=[ComputerName])
