# prod:not_filter valid
foo not statuscode=200
| NOT ParentBaseFileName=explorer.exe !UserName=/\$$/
