#![no_main]
//! The semantic layer (#1946): a rule file from arbitrary YAML in a template
//! workspace with every built-in platform enabled, through `validate` (with
//! the compile check) and `deploy --dry-run`'s compile of every block.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    opentide_fuzz::semantic(data);
});
