# prod:link_constraint valid
correlate(Login: { #action="login" }, Purchase: { #action="purchase" | userId <=> Login.userId }, sequence=true, within=15m)
