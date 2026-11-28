# prod:match_statement valid
logtype match {
  "accesslog" => time:=response_time ;
  /server_\d+/ => time:=server_time*1000 ;
  in(values=[5, 56, 567]) => kind := "listed";
  ** => * ;
}
