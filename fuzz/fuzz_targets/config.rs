#![no_main]
//! Configuration TOML: the host checker's findings placed in the buffer,
//! hover and completion from the host's schemas (#843).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    opentide_fuzz::configuration(data);
});
