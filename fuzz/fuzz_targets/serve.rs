#![no_main]
//! `opentide serve`'s message reader: arbitrary bytes as a client's stdin,
//! one JSON-RPC message a line, served to the end of the session (UC-3.8, #830).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    opentide_fuzz::serve(data);
});
