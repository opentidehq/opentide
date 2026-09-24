---
name: add-language
description: Add a query language to the OpenTide language server. Use when implementing S1QL, Lucene, Sigma, YARA, or any new engine crate. CrowdStrike stays unsupported.
---

# Add a language

Read `docs/LANGUAGE-HARNESS.md` and follow every step. Authoring guidance for detections lives in the `opentidehq/skills` repository (`kusto-query-language`, `splunk-spl-processing`, and the platform skills). Those skills are not an engine.

A language is done when:

- `LanguageId` parses its name
- the grammar coverage gate names its productions
- catalogs load once per process
- highlight generation checks its query file
- `testdata/conformance/external/<id>/` contains real public rules and the same rules with one injected fault
- unsupported platforms still produce no fake validation
