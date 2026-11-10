//! The status glyphs and frame characters (`docs/internal/cli-experience.md`, "Human output grammar").
//!
//! Looked up by name, so a renderer never hard-codes a character. The Rust
//! CLI writes UTF-8 on every stream (the Windows console through its wide
//! API), so there is no ASCII fallback as the oracle had for a cp1252 pipe.

/// `✓`: an outcome or step that succeeded.
pub const OK: &str = "✓";
/// `✗`: one that failed.
pub const FAILED: &str = "✗";
/// `!`: one that passed with issues.
pub const WARNING: &str = "!";
/// `○`: one that was skipped.
pub const SKIP: &str = "○";
/// `-`: a step left out (a plan's `disable`).
pub const DISABLE: &str = "-";
/// `→`: a next step.
pub const NEXT: &str = "→";
/// `·`: between the facts of a line.
pub const SEPARATOR: &str = "·";
/// `╭─▶`: a frame's location, with lines under it.
pub const FRAME_OPEN: &str = "╭─▶";
/// `╰─▶`: a frame's location, alone.
pub const FRAME_ONLY: &str = "╰─▶";
/// `│`: a frame's bar.
pub const FRAME_BAR: &str = "│";
/// `├─`: a frame's note, more to come.
pub const FRAME_NOTE: &str = "├─";
/// `╰─`: a frame's last note.
pub const FRAME_CLOSE: &str = "╰─";
/// `━`: a frame's underline.
pub const UNDERLINE: &str = "━";
