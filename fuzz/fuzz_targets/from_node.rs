#![no_main]
//! A Tide object built from arbitrary YAML (UC-1.2, #808; UC-X.1, #843): the
//! YAML 1.2 loader, the structural conversion of every model, the CLI's
//! positions for every error, and the round trip of whatever converts.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    opentide_fuzz::from_node(data);
});
