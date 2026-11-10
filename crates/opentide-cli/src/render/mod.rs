//! The renderers every command's result goes through (UC-3.4, #826): code
//! frames, outcome lines, report files, CI sinks and progress.
//!
//! Each builds text (or a JSON document) from data; the command writes it to
//! its stream. Their output is the CLI's contract (plan §3 invariant 1,
//! `docs/internal/cli-experience.md`, `docs/cli/diagnostics.md`), proven byte
//! for byte against the oracle by `tests/render.rs`.
//!
//! | Module | What |
//! |--------|------|
//! | [`text`] | Styled text, written as SGR runs and OSC 8 links; terminal cells |
//! | [`glyphs`] | `✓ ✗ ! ○ → ·` and the frame characters |
//! | [`diagnostic`] | The finding every renderer reads, and its source lines |
//! | [`codeframe`] | `error[code]: …` frames; `validate --fix`'s diff and `fixed:` lines |
//! | [`outcome`] | Outcome, warning, error and next-step lines; a result's text |
//! | [`report`] | SARIF 2.1.0 and GitLab Code Quality, `--format` and `--output` |
//! | [`ci`] | GitHub, GitLab and Azure annotations and job summaries |
//! | [`summary`] | The summaries' Markdown, cut at 256 KiB |
//! | [`progress`] | The step lines and checklist; `OPENTIDE_PROGRESS=json` events |
//! | [`table`] | `info`'s tables and aligned columns |

pub mod ci;
pub mod codeframe;
pub mod diagnostic;
pub mod glyphs;
pub mod outcome;
pub mod progress;
pub mod report;
pub mod summary;
pub mod table;
pub mod text;
