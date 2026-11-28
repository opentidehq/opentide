# prod:case_branch valid
case { HookId = "0" | HookId := "WH_JOURNALRECORD" ; !cidr(ip, subnet="10.0.0.0/8") | scope := "public" ; * }
