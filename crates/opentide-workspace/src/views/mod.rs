//! What `opentide tui` shows beside the catalogue (UC-3.6d, #951): threat
//! chaining as attack flow ([`chains`]) and an object read as a page under
//! its schema's fields ([`object`]). No terminal here: the command line draws
//! them.

pub mod chains;
pub mod object;
