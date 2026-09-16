; Tide YAML object highlighting. Injected KQL/SPL tokens are remapped onto
; the host document by opentide-highlight (not by this query).
; There is no Tide YAML tree-sitter grammar; runtime highlighting also paints
; values (tide.uuid, tide.schema, boolean, string, number, constant, comment)
; via highlight_tide. Capture names here must stay a subset of HighlightSpec.

((block_mapping_pair
  key: (_) @tide.keyword)
 (#match? @tide.keyword "^(name|metadata|description|status|severity|techniques|detection_model|response|configurations|objective|threat|composition|criticality)$"))

((block_mapping_pair
  key: (_) @tide.property)
 (#match? @tide.property "^(uuid|schema|version|created|modified|tlp|author|organisation|query|search|enabled)$"))

(comment) @comment
