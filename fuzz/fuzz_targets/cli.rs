#![no_main]
//! The `opentide` command line: `\0`-separated arguments through the clap
//! tree, hoisting, the output modes and the usage errors (UC-3.3, #825).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    opentide_fuzz::cli(data);
});
