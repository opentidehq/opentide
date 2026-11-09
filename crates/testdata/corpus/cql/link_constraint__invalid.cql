# prod:link_constraint invalid
correlate(Login: { #action="login" }, Purchase: { userId <=> })
