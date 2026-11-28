# YARA fixtures of the opentide specifications

Copied unchanged from [opentidehq/specifications](https://github.com/opentidehq/specifications) at `a6378a8787a19a47ee05cc2eb3987c75961d6237`, licensed CC BY 4.0. Each file's header comment names the code it expects; `crates/opentide-tide/tests/yara.rs` asserts it.

| File | From | Expected |
|------|------|----------|
| `harfanglab-yara-signature.yaml` | `fixtures/platforms/` | no YARA finding |
| `harfanglab-yara.yaml` | `fixtures/platforms/` | no YARA finding (decomposed form) |
| `rule-bitdefender-yara-1.0.yaml` | `fixtures/valid/` | no YARA finding |
| `rule-yara-signature-alias.yaml` | `fixtures/invalid/` | `yara_signature_alias` |
| `rule-harfanglab-yara-include.yaml` | `fixtures/invalid/` | `yara_include` |
| `rule-harfanglab-yara-both-forms.yaml` | `fixtures/invalid/` | `harfanglab_yara_form` |
| `rule-harfanglab-sigma-and-yara.yaml` | `fixtures/invalid/` | `harfanglab_rule_kind` |
