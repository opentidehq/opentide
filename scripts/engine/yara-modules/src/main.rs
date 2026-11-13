//! Print every YARA-X module's fields and functions as JSON.
//!
//! `cargo run --release --manifest-path scripts/yara-modules/Cargo.toml > yara-x-modules.json`

use serde_json::{Value, json};
use yara_x::mods::reflect::{Struct, Type};

fn ty(t: &Type, depth: usize) -> Value {
    match t {
        Type::Integer => json!("integer"),
        Type::Float => json!("float"),
        Type::Bool => json!("boolean"),
        Type::String => json!("string"),
        Type::Regexp => json!("regexp"),
        Type::Struct(s) if depth < 12 => json!({ "struct": fields(s, depth + 1) }),
        Type::Struct(_) => json!({ "struct": [] }),
        Type::Array(inner) => json!({ "array": ty(inner, depth) }),
        Type::Map(key, value) => json!({ "map": [ty(key, depth), ty(value, depth)] }),
        Type::Func(f) => json!({
            "function": f.signatures.iter().map(|s| json!({
                "args": s.args().map(|(n, t)| json!([n, ty(t, depth)])).collect::<Vec<_>>(),
                "ret": ty(s.ret_type(), depth),
                "doc": s.doc(),
            })).collect::<Vec<_>>()
        }),
    }
}

fn fields(s: &Struct, depth: usize) -> Vec<Value> {
    s.fields()
        .map(|f| {
            json!({
                "name": f.name(),
                "type": ty(&f.ty(), depth),
                "const": f.is_const(),
                "doc": f.doc(),
                "enum": matches!(f.ty(), Type::Struct(ref s) if s.is_enum()),
            })
        })
        .collect()
}

fn main() {
    let modules: serde_json::Map<String, Value> = yara_x::mods::module_names()
        .filter_map(|name| {
            let def = yara_x::mods::module_definition(name)?;
            Some((name.to_string(), json!(fields(&def, 0))))
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&modules).unwrap());
}
