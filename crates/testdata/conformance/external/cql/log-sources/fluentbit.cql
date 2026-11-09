// Parse the basic object
parseJson() |
// Extract timestamp according to Fluent-Bit source (flb.source)
case {
    // parse using embedded timestamp
    flb.source="container" | parseTimestamp(field=time);
    flb.source="audit" | parseTimestamp(field=requestReceivedTimestamp);
    // systemd sources
    flb.source="systemd" | SYSLOG_IDENTIFIER match {
        // ("dockerd", "containerd") Timestamp (time) contained in MESSAGE KV
        in(values=["dockerd","containerd"]) => kvParse(field=MESSAGE) | parseTimestamp(field=time);
        // ("kubelet")  Timestamp (flb.time) added by fluent-bit
        in(values=["kubelet"]) => parseTimestamp(field=flb.time,format="seconds")
    };
    // parse using fluent-bit timestamp
    flb.source=* | parseTimestamp(field=flb.time,format="seconds")
}