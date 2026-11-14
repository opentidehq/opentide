//! `cargo xtask corpus`: the heavy workspace generator, the fault catalogue
//! and the coverage report (UC-0.6, plan §5.3; `tests/corpora/README.md`).
//!
//! [`generate`], [`yaml`], [`rng`], [`workspace`], [`faults`] and
//! [`configuration`] (the configuration fault kinds) compute and never touch
//! the file system; [`cli`] writes workspaces and prints.

pub mod cli;
pub mod configuration;
pub mod coverage;
pub mod faults;
pub mod generate;
pub mod rng;
pub mod vocab;
pub mod workspace;
pub mod yaml;
