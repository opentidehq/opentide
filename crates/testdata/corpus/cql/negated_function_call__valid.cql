# prod:negated_function_call valid
!in(loglevel, values=["DEBUG", "INFO"])
| not test(cputime < 7500)
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "192.168.0.0/16"])
