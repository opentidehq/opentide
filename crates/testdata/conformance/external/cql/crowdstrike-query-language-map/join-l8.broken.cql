#event_simpleName=ProcessRollup2
| ImageFileName=/(?<FilePath>(\/|\\).+(\/|\\))(?<FileName>.+$)/
| FileName=~wildcard(?FileName, ignoreCase=true)
| select([aid, ComputerName, UserSid, UserName, FilePath, FileName, CommandLine])
| join({#event_simpleName=/^(UserIdentity|UserLogon)$/ | UserName!=/(\$$|^DWM-|LOCAL\sSERVICE|^UMFD-|^$)/, field=UserSid, include=UserName, mode=left)
| UserName=~wildcard(?UserName, ignoreCase=true)