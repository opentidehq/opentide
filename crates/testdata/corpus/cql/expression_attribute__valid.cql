# prod:expression_attribute valid
correlate(Login: { #action="login" }, Purchase: { #action="purchase" | userId <=> Login.userId }, aggregation = [ pageViews: { #action="pageView" | userId <=> Login.userId | count() } after: "Login" before: "Purchase" ])
