; Tide YAML object highlighting. Injected KQL/SPL tokens are remapped onto
; the host document by opentide-highlight (not by this query).
; Generated key lists come from catalogs/tide/generated/fields.json
; (opentide 0.5.0). Runtime highlighting is path-aware and does not
; use this query. Capture names must stay a subset of HighlightSpec.

((block_mapping_pair
  key: (_) @tide.keyword)
 (#match? @tide.keyword "^(carbon_black_cloud|composition|configurations|criticality|crowdstrike|defender_for_endpoint|description|detection_model|file|harfanglab|metadata|name|objective|platforms|procedure|references|response|sentinel|sentinel_one|severity|splunk|status|techniques|threat)$"))

((block_mapping_pair
  key: (_) @tide.property)
 (#match? @tide.property "^(action|actions|actors|advanced|alert|alert_severity|allow_block|analysis|arch|att&ck|attack|author|availability|bcc|category|cc|chaining|classification|collect_investigation_package|column|comparator|composition|condition|confidence|containment|content_type|context|contributors|cool_off|correlation|correlation_search|create_incident|created|cron|cron_schedule|custom_condition|custom_details|custom_time|cve|data|description|details|detectors|device|device_groups|devices|disable_user|drilldown|duration|dynamic_properties|earliest|effort|email|enabled|end|entities|entity|event|examples|exclusions|expiration|expires|false_positives|field|fields|files|flags|force_password_reset|frequency|group_by_alert_details|group_by_custom_details|group_by_entities|group_name|grouping|grouping_lookback|groups|identifier|impact|impacted_entities|imports|include|initiate_investigation|inline_results|internal|investment|isolate_device|key|killchain|language|latest|let|leverage|link|logsource|logsources|lookback|mailbox|mappings|mark_as_compromised|match_in_order|matches_required|matching|maturity|message|meta|methodology|modified|modifiers|name|network_quarantine|notable|nrt|operator|organisation|organizations|os|outcome|parent|playbook|priority|product|property|public|purpose|quarantine_file|query|reason|recommendation|references|reopen_closed_incidents|report|reports|requirements|responders|response|restrict_app_execution|results_link|risk|risk_objects|rule_id|rule_id_bundle|run_antivirus_scan|schedule|scheduling|schema|scope|score|search|search_string|searches|security_domain|selection|selections|send_csv|send_pdf|severity|sighting|sigma|signals|single_event|start|status|strategy|strings|sub_queries|subject|suppression|surface|system|tactic|tactics|tags|technique|techniques|technology|template|tenant|tenants|terrain|threat_objects|threats|threshold|throttling|time_window|timerange|title|tlp|to|treat_as_threat|trigger|trigger_condition|trigger_time|type|user|users|uuid|value|version|viability|watchlist|yara)$"))

(comment) @comment
