#![no_main]
//! The LSP host on arbitrary message bodies (#182, #185 P2.8).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    opentide_fuzz::session(data);
});
