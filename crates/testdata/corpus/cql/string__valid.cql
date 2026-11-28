# prod:string valid
"msg:\"welcome\" " | user= "Alan Turing" | regex("\x5c\x5c(?<file_name>[^\\]+)$", field=TargetFileName)
