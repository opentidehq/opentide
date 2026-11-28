#![no_main]
//! `analyze()` and the editor requests on Datadog log search queries (Datadog Cloud SIEM).

use libfuzzer_sys::fuzz_target;
use opentide_analysis::LanguageId;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        opentide_fuzz::exercise(LanguageId::Datadog, text);
    }
});
