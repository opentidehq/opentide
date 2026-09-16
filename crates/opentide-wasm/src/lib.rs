//! wasm32-unknown-unknown highlight() — do not mix WASI in this artifact.

use opentide_core::LanguageId;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn legend() -> js_sys::Array {
    let spec = opentide_highlight::HighlightSpec::load().expect("spec");
    let arr = js_sys::Array::new();
    for name in spec.legend {
        arr.push(&JsValue::from_str(&name));
    }
    arr
}

/// Highlight `language_id` source bytes. Usable without a full language client.
#[wasm_bindgen]
pub fn highlight(language_id: &str, bytes: &[u8]) -> Result<JsValue, JsValue> {
    let language = LanguageId::parse(language_id)
        .ok_or_else(|| JsValue::from_str(&format!("unknown language {language_id}")))?;
    let text = std::str::from_utf8(bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let result = opentide_analysis::highlight(language, text);
    serde_wasm_bindgen_compat(&result).map_err(|e| JsValue::from_str(&e))
}

fn serde_wasm_bindgen_compat<T: serde::Serialize>(value: &T) -> Result<JsValue, String> {
    let json = serde_json::to_string(value).map_err(|e| e.to_string())?;
    js_sys::JSON::parse(&json).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests {
    use opentide_analysis::highlight;
    use opentide_core::LanguageId;

    #[test]
    fn highlight_kql_and_spl() {
        let k = highlight(LanguageId::Kql, "SecurityEvent | take 1");
        assert!(k.tokens.iter().any(|t| t.capture == "keyword"));
        let s = highlight(LanguageId::Spl, "index=main | head 1");
        assert!(s.tokens.iter().any(|t| t.capture == "operator.pipe"));
    }
}
