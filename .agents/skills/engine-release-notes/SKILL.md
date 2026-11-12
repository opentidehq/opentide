---
name: release-notes
description: Write and review the language server's release notes in CHANGELOG.md, the GitHub Release body and opentide.org/releases/language-server - the headline, Upgrade and Breaking, the Keep a Changelog categories in a fixed order, and entries with a bold lead that name the protocol methods, settings, codes and API items integrators use. Use when a change needs a changelog entry, when preparing a release's notes, or when reviewing either.
license: EUPL-1.2
metadata:
  author: opentidehq
---

# Release notes: the language server

How to write what integrators read about a release. The release procedure itself (version bump,
crates.io, the opentide pin) is `skills/release/SKILL.md`.

## Where they are read

- `CHANGELOG.md` is the only source. Its version section is the GitHub Release body
  (`scripts/release.py notes X.Y.Z`, run by `release.yml`), and
  [opentide.org/releases/language-server](https://opentide.org/releases/language-server/) renders
  it, synced from `main` every hour.
- opentide's own changelog cites the release when it repins the engine (`skills/release`, step 4),
  so the headline is what opentide's users read about it too.

## When they are written

- Each pull request with a user-visible change adds its entries under `## [Unreleased]`, in the
  right part.
- The release pull request renames the section `## [X.Y.Z] - YYYY-MM-DD`, keeps an empty
  `## [Unreleased]` above it, and writes the headline (`skills/release`, step 1).
- One line per list item and per paragraph, no hard wraps; nested items are indented two spaces.

## Write it like an announcement

Release notes tell people what shipped. Write them the way you would tell a colleague, not the
way the code is built.

- **Lead with the news.** "Graylog support." comes first. How it works comes after, if at all.
- **Short sentences, one idea each.** If a sentence needs a colon and three commas, split it.
- **Plain words.** "Deploy rules to Graylog", not "Graylog event definitions deploy from a
  `configurations.graylog` block".
- **Name what people see and type**: commands, flags, settings, views, error messages. Leave out
  how the code does it.
- **Read it aloud.** If you run out of breath or have to re-read it, rewrite it.

## The headline

The first paragraph of every version is its headline (the summary).
[opentide.org/releases](https://opentide.org/releases/) shows it large under the version number,
and for most readers it is the only thing they read.

- **One or two short sentences, at most 25 words.**
- **Start with the biggest change, in a few words**: "Graylog support." "`pip install opentide`
  works again." "First release."
- **A second sentence only for the second-biggest change.** The lists below carry the rest.
- **Leave out** upgrade steps, issue links, the versions of other products, which tools run a
  check, supported version ranges beyond the headline one, and "minor", "patch" or "pre-release"
  (the page shows those).

| Instead of | Write |
|------------|-------|
| Graylog event definitions deploy from a `configurations.graylog` block on Graylog 6.3 to 7.2, checked by `validate`, the editor and `opentide tui`. Generated documentation is redesigned, with kill-chain maps and ATT&CK coverage. The engine is language-server 0.14.0. | Graylog support: deploy rules to Graylog 6.3–7.2 as event definitions. Generated documentation is redesigned, with kill-chain maps and ATT&CK coverage. |
| YARA is a language: `.yar` files and the YARA in HarfangLab and Bitdefender rules are checked as libyara 4.5 compiles them, with YARA-X differences flagged, and Bitdefender GravityZone rules are checked against GravityZone's criteria. | YARA support: `.yar` files and the YARA in HarfangLab and Bitdefender rules are checked as you type. |
| `npx @opentide/explorer serve` works: 0.5.0 shipped two commands, so npx could not tell which to run and stopped with "could not determine executable to run". | Fixes `npx @opentide/explorer serve`, which failed with "could not determine executable to run". |

## The parts of a version

Every version has the same parts, in this order, in all four products. Leave out an empty part.
Never add one.

| Part | What goes in it |
|------|-----------------|
| Headline | The first paragraph: what the release is, in at most 25 words |
| **Upgrade** | The steps to take after installing, in order. Only when there is something to do |
| **Breaking** | What stops working the way it did, and what replaces it |
| **Added** | Something people can do that they could not before |
| **Changed** | Existing behaviour that is different, but not broken. Includes a bundled or pinned version people see |
| **Deprecated** | Still works, will be removed. Say what to use instead |
| **Removed** | Gone, and nobody relied on it. If someone could have, it is **Breaking** |
| **Fixed** | Something that did not work as documented, and now does |
| **Security** | A vulnerability fixed, with its advisory id, and whether to upgrade promptly |

**Added** through **Security** are the six types of
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/). **Upgrade** and **Breaking** are
ours, and come first because an upgrading reader needs them first.

[opentide.org/releases](https://opentide.org/releases/) recognises exactly these names: the
Upgrade steps become a numbered panel and each category gets an icon and a count. Any other
heading (Install, Tests, Notes, Highlights, Migration) shows as plain text after the categories.
That is a review finding.

Each change goes in one part. A breaking change is under **Breaking** only, and the step that
deals with it is under **Upgrade**.

## Upgrade

- Numbered steps, in the order to take them. One action per step, starting with a verb, with the
  exact command in backticks.
- A step for some users only starts with who: "If you use Splunk, …".
- Add the reason in a few words when it is not obvious: "Run `opentide setup ci github --yes`, so
  the live query job checks the same variables."
- Nothing to do? Leave the part out. Do not write "Nothing to do".

## Breaking

A change is breaking when something that worked stops working the way it did:

- a command, flag, setting, key, protocol method or API is removed or renamed;
- output, a field or an exit code that scripts read changes;
- validation rejects a file that used to pass;
- a default changes what a run does.

Each entry says what replaces the old behaviour, and **Upgrade** has the step. Before 1.0 a minor
version may break things. A patch breaks only to correct a defect the previous release shipped,
and its headline says so.

## Entries

Each entry is one change, as one list item:

```markdown
- **Graylog queries are checked.** Rule queries, hunts and `opentide-lsp analyze --platform graylog` get Lucene checks tuned for Graylog ([#242](https://github.com/opentidehq/language-server/pull/242)).
```

- **Bold lead first**: the change in at most 10 words, as a user would say it. Readers scan the
  leads. The lead is a complete phrase ("`deploy --uuid` selects the rules to deploy"), not the
  start of a sentence the rest finishes ("**Progress events** with …").
- **Then one or two short sentences**: what it does for the reader, any limit, what to do. About 40
  words in all.
- **Specifics in a nested list** when there are more than two (codes, keys, flags, API items): one
  level, a few words each, about six at most.
- **Link the issue or pull request** at the end of the sentence it belongs to. Another
  repository's: `[opentidehq/opentide#745](https://github.com/opentidehq/opentide/pull/745)`.
  Another product's version, by its release:
  `[language-server 0.10.0](https://github.com/opentidehq/language-server/releases/tag/v0.10.0)`.
- **Present tense, the thing that changed as the subject**: "`lint` checks files that start with a
  byte-order mark", not "We made lint check …". Skip filler like "now", "new" and "finally".
- **What, not how.** Functions, refactors, tests and CI belong in the pull request. If the detail
  does not fit in 40 words, it belongs in the documentation: link to it.
- **A fix names the symptom people search for**: "`deploy` no longer fails with `b'HEAD'` in a
  repository with no commits".
- **Leave out what users never see**: tests, CI, refactors, internal renames, dependency bumps with
  no visible effect, contributor docs. A release with nothing users see has no notes, and is
  usually not a release.

## Groups

A category with more than about eight entries may be split into groups users recognise
("Problems", "Graph and search"), one `####` heading each. Never nest deeper, and never group a
short category.

## Before and after

| Before | After |
|--------|-------|
| **Graylog queries are checked in a Graylog dialect of Lucene.** `configurations.graylog.query`, hunts with `system: graylog` and `opentide-lsp analyze --platform graylog` get Elastic's Lucene checks without the ECS and Kibana KQL advice, plus graylog-1.1's seven codes. | **Graylog queries are checked.** Rule queries, hunts and `opentide-lsp analyze --platform graylog` get Lucene checks tuned for Graylog, plus seven Graylog codes. |
| The ES\|QL TextMate grammar's scope is `source.opentide.esql`, as `docs/EDITORS.md` promised, not `source.esql`, the scope of Elastic's ES\|QL extension (#195). An editor that loaded both grammars kept only one. … | **Breaking**: "**The ES\|QL grammar's scope is `source.opentide.esql`.** It was `source.esql`, which clashed with Elastic's extension (#195)." **Upgrade**: "If your editor includes the ES\|QL grammar by scope, use `source.opentide.esql`." |
| **Fixes.** `deploy` and `--changed` in a repository with no commit yet; a duplicate UUID counted as a load error by `info`; an interrupted `generate` no longer leaves an empty schema. | Three entries under **Fixed**, each with its own lead: "**`deploy` works in a repository with no commits.** …" |
| React component tests in happy-dom, beside a faster unit run (#78). | Nothing: tests are not a change users see. |

## In this repository

Editor and tool integrators wiring `opentide-lsp`, the WASM build or the TypeScript packages into
an editor; opentide's maintainers, who compile the crates into opentide; and users of the crates on
crates.io and the packages on npm. So:

- Name the protocol methods, notifications, capabilities, settings, diagnostic codes, file globs
  and package exports a change touches; when there are several, in a nested list.
- Name public API items of the published crates and packages in a nested list ("API:
  `opentide_tide::object_refs`"). Internal types and functions stay out.
- Message shapes belong in `docs/EDITORS.md`: the entry says what changed and links there.
- Breaking here includes a renamed grammar scope, a diagnostic code or default severity that
  changes, a removed setting or RPC, and a changed public API. A renamed HighlightSpec capture is
  never allowed (AGENTS.md, hard rules).

## One standard, four products

opentide, language-server, vscode-extension and explorer share this standard, and
[opentide.org/releases](https://opentide.org/releases/) renders all four the same way (the
website's `lib/releases.ts` parses them). A change to the standard goes to all four
`release-notes` skills together, and to the website's parser when it adds or renames a part.

## Review checklist

- [ ] The headline is at most 25 words, leads with the biggest change, and reads cleanly aloud.
- [ ] Every action a user must take is an **Upgrade** step, with its command.
- [ ] Everything that stops working as it did is under **Breaking**, with its replacement and an
      **Upgrade** step.
- [ ] Every entry is in the right part, and in one part only.
- [ ] Every entry starts with a bold lead and is about 40 words at most.
- [ ] Sentences are short and plain: no stacked clauses, no internal names.
- [ ] No entry is about tests, CI, refactors or contributor docs.
- [ ] The parts are in the order above, under no other names.
- [ ] Links point at the issue or pull request, and at other products' releases.
