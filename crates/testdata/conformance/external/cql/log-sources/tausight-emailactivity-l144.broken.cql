email
|$tausight/ephi-risk-posture:Tausight_EmailHasEphi()
|HostName=?HostName
|Sender=?Sender
|UserName=?UserName
|split(email.recipientDomains)

|case{regex(field=Sender, regex="^.+@(?<DomainFrom>.+)$")|*;*|DomainFrom:="Unknown"}
|DomainTo:=email.recipientDomains

|top([DomainFrom, DomainTo], field=[DomainFrom, DomainTo], limit=10, rest=others)
//|groupBy([DomainFrom, DomainTo])
//|sankey(source="DomainFrom", target=DomainTo)

