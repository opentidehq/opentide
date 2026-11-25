# prod:match_branch invalid
loglevel match { /.*ERROR.*/ => s := "High"; => s := "Medium" }
