# Google SecOps fixtures of the opentide specifications

Copied unchanged from [opentidehq/specifications](https://github.com/opentidehq/specifications) at `b81c8a02754ef8b855a26c8d7fe9f7e05c89d437`, licensed CC BY 4.0. Each invalid file's header comment names the code it expects; `crates/opentide-tide/tests/google_secops.rs` asserts it, and `crates/opentide-yaral/tests/codes.rs` parses the assembled rules.

| File | From | Expected |
|------|------|----------|
| `google-secops.yaml` | `fixtures/platforms/` | no error |
| `rule-google-secops-process-1.0.yaml` | `fixtures/valid/` | no error |
| `rule-google-secops-spray-1.0.yaml` | `fixtures/valid/` | no error (its hunt too) |
| `rule-google-secops-process-1.0.yaral` | `fixtures/platforms/google-secops/` | the rule deploy assembles; no error |
| `rule-google-secops-spray-1.0.yaral` | `fixtures/platforms/google-secops/` | the rule deploy assembles; no error |
| `rule-google-secops-section-header.yaml` | `fixtures/invalid/` | `yaral_section_header` |
| `rule-google-secops-condition-comment.yaml` | `fixtures/invalid/` | `yaral_section_empty` |
| `rule-google-secops-sliding-no-pivot.yaml` | `fixtures/invalid/` | `yaral_match_shape` |
| `rule-google-secops-missing-condition.yaml` | `fixtures/invalid/` | `yaral_section_missing` |
| `rule-google-secops-hourly.yaml` | `fixtures/invalid/` | `google_secops_run_frequency`, `google_secops_schedule` |
| `rule-google-secops-meta-reserved.yaml` | `fixtures/invalid/` | `google_secops_meta_key` |
