# Skills

Agent procedures for working in this repository. [`AGENTS.md`](../../AGENTS.md) at the root is the index of all of them. Detection-engineering skills are not here; they live in [opentidehq/skills](https://github.com/opentidehq/skills).

The engine's skills came from opentidehq/language-server with its history (#800). Their index is [`crates/AGENTS.md`](../../crates/AGENTS.md), and `scripts/engine/validate-skills.sh` checks them against the [Agent Skills specification](https://agentskills.io/specification):

| Skill | Use when |
| --- | --- |
| `rust-engine` | Editing the Rust workspace, edition 2024 code, or `Cargo.lock` |
| `parser` | The query parsers: lexers, grammars on `opentide-parse`, `.ungram`, keyword tables |
| `lsp-host` | The stdio server, editor samples, or protocol tests |
| `wasm-hosts` | `wasm-bindgen`, WASI, the TypeScript client, or packaging |
| `catalogs` | Compiled catalogs, HighlightSpec, or conformance corpora |
| `add-language` | Adding S1QL, Lucene, Sigma, or YARA |
| `engine-release-notes` | Writing a `crates/CHANGELOG.md` entry or an engine release's notes |

`engine-release-notes` was language-server's `release-notes`: opentide's own `release-notes` keeps that name. Its `release` skill, imported as `engine-release`, was retired with the engine's own `engine-v*` releases: every release, the engine crates' included, is the release train's ([`release-management`](release-management/SKILL.md)).
