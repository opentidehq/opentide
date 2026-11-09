//! `cargo xtask corpus`: the heavy workspace generator, the fault catalogue
//! and its runner, and the coverage report (UC-0.6, plan §5.3;
//! `tests/corpora/README.md`).
//!
//! [`generate`], [`yaml`], [`rng`], [`workspace`], [`faults`] and
//! [`structural`] (the Rust engine's structural check, UC-1.2) compute and
//! never touch the file system; [`cli`] writes workspaces, runs the oracle
//! and prints.

pub mod cli;
pub mod coverage;
pub mod faults;
pub mod generate;
pub mod rng;
pub mod structural;
pub mod vocab;
pub mod workspace;
pub mod yaml;
