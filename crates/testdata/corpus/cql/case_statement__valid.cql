# prod:case_statement valid
| case {
    src="client-side" | type := "client";
    src="frontend-server" | ip != 192.168.1.1 | type := "frontend";
    // catch-all
    * | type := "server";
}
| case { event_platform=Lin | Status:="OK"; * ; }
