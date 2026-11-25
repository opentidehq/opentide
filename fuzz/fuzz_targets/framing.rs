#![no_main]
//! The LSP host's message reader on raw bytes: headers, lengths and bodies
//! as a client could send them (#843).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    opentide_fuzz::framing(data);
});
