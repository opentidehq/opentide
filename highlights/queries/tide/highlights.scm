; Tide YAML object highlighting. Injected KQL/SPL tokens are remapped onto
; the host document by opentide-highlight (not by this query).
; There is no Tide YAML tree-sitter grammar; runtime highlighting also paints
; values (tide.uuid, tide.schema, boolean, string, number, constant, comment,
; markdown.*) via highlight_tide. Capture names here must stay a subset of
; HighlightSpec. Keys listed here must match catalogs/tide/fields.toml.

((block_mapping_pair
  key: (_) @tide.keyword)
 (#match? @tide.keyword "^(name|metadata|description|status|severity|techniques|platforms|references|detection_model|response|configurations|file|composition|objective|threat|criticality|procedure|sentinel|defender_for_endpoint|splunk|crowdstrike|sentinel_one|harfanglab|carbon_black_cloud)$"))

((block_mapping_pair
  key: (_) @tide.property)
 (#match? @tide.property "^(uuid|schema|version|created|modified|tlp|author|contributors|organisation|public|internal|reports|alert_severity|analysis|searches|containment|purpose|system|query|search|enabled|scheduling|frequency|lookback|cron_schedule|alert|title|suppression|category|recommendation|grouping|event|impacted_entities|device|scope|selection|priority|type|strategy|threats|signals|methodology|entities|data|availability|requirements|impact|leverage|viability|terrain|surface|att&ck|actors|chaining|relation|vector)$"))

(comment) @comment
