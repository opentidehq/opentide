# prod:attributed_expression valid
correlate(LoginFail1 : { logon = FAILURE }, LoginSuccess : { logon = SUCCESS | user.email <=> LoginFail1.user.id } include: [user.email, platform], sequence=true, within=15m)
