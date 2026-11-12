//! A tool's arguments, read as the Python server's argument model reads them
//! (MCPServer builds it from the tool's signature, in Pydantic's lax mode):
//! a string is only a string; a boolean is `true`/`false`, `0`/`1` or one of
//! the words Pydantic reads as one; an integer is a whole number, written as
//! a number or as text. Unknown arguments are ignored. A missing required
//! argument or a value of the wrong type refuses the call, worded by opentide
//! rather than as Pydantic's validation error (`tests/golden/APPROVED_DIFFS.toml`).

use serde_json::{Map, Value};

/// The arguments of one call.
pub struct Args<'a> {
    map: &'a Map<String, Value>,
}

impl<'a> Args<'a> {
    /// The call's `arguments`.
    pub fn new(map: &'a Map<String, Value>) -> Args<'a> {
        Args { map }
    }

    /// The required string `name`.
    pub fn required(&self, name: &str) -> Result<String, String> {
        match self.map.get(name) {
            None => Err(missing(name)),
            Some(value) => string(name, value),
        }
    }

    /// The string `name`, `default` when absent.
    pub fn string(&self, name: &str, default: &str) -> Result<String, String> {
        self.map
            .get(name)
            .map_or_else(|| Ok(default.to_owned()), |value| string(name, value))
    }

    /// The boolean `name`, `default` when absent.
    pub fn boolean(&self, name: &str, default: bool) -> Result<bool, String> {
        let Some(value) = self.map.get(name) else {
            return Ok(default);
        };
        let parsed = match value {
            Value::Bool(flag) => Some(*flag),
            Value::Number(number) => {
                let n = number.as_f64().unwrap_or(f64::NAN);
                if n.abs() < f64::EPSILON {
                    Some(false)
                } else if (n - 1.0).abs() < f64::EPSILON {
                    Some(true)
                } else {
                    None
                }
            }
            Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
                "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
                "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
                _ => None,
            },
            _ => None,
        };
        parsed.ok_or_else(|| {
            format!(
                "argument {name} must be a boolean (true or false), not {}",
                shown(value)
            )
        })
    }

    /// The integer `name`, `default` when absent.
    pub fn integer(&self, name: &str, default: i64) -> Result<i64, String> {
        let Some(value) = self.map.get(name) else {
            return Ok(default);
        };
        let parsed = match value {
            Value::Number(number) => number.as_i64().or_else(|| {
                number
                    .as_f64()
                    .filter(|n| n.fract() == 0.0 && n.abs() < 9.0e15)
                    .map(|n| {
                        #[expect(
                            clippy::cast_possible_truncation,
                            reason = "a whole number below 2^53, checked above"
                        )]
                        let whole = n as i64;
                        whole
                    })
            }),
            Value::String(text) => text.trim().replace('_', "").parse::<i64>().ok(),
            _ => None,
        };
        parsed.ok_or_else(|| format!("argument {name} must be an integer, not {}", shown(value)))
    }
}

fn missing(name: &str) -> String {
    format!("argument {name} is required")
}

fn string(name: &str, value: &Value) -> Result<String, String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        other => Err(format!(
            "argument {name} must be a string, not {}",
            kind(other)
        )),
    }
}

/// What a value is, in words.
pub fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// A refused value as the refusal shows it: a string quoted, else its kind.
fn shown(value: &Value) -> String {
    match value {
        Value::String(text) => crate::render::codeframe::quoted(text),
        other => kind(other).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => Map::new(),
        }
    }

    #[test]
    fn strings_are_only_strings() {
        let arguments = map(json!({"a": "x", "b": 7, "c": null}));
        let args = Args::new(&arguments);
        assert_eq!(args.required("a").unwrap(), "x");
        assert_eq!(
            args.required("b").unwrap_err(),
            "argument b must be a string, not a number"
        );
        assert_eq!(
            args.string("c", "").unwrap_err(),
            "argument c must be a string, not null"
        );
        assert_eq!(args.required("d").unwrap_err(), "argument d is required");
        assert_eq!(args.string("d", "dflt").unwrap(), "dflt");
    }

    #[test]
    fn booleans_read_as_pydantic_reads_them() {
        let arguments = map(json!({
            "a": true, "b": "Yes", "c": 0, "d": "sometimes", "e": 2, "f": [true]
        }));
        let args = Args::new(&arguments);
        assert!(args.boolean("a", false).unwrap());
        assert!(args.boolean("b", false).unwrap());
        assert!(!args.boolean("c", true).unwrap());
        assert_eq!(
            args.boolean("d", false).unwrap_err(),
            "argument d must be a boolean (true or false), not 'sometimes'"
        );
        assert!(args.boolean("e", false).is_err());
        assert!(args.boolean("f", false).is_err());
        assert!(args.boolean("g", true).unwrap());
    }

    #[test]
    fn integers_read_as_pydantic_reads_them() {
        let arguments =
            map(json!({"a": 5, "b": " 12 ", "c": 3.0, "d": 3.5, "e": "many", "f": true}));
        let args = Args::new(&arguments);
        assert_eq!(args.integer("a", 0).unwrap(), 5);
        assert_eq!(args.integer("b", 0).unwrap(), 12);
        assert_eq!(args.integer("c", 0).unwrap(), 3);
        assert!(args.integer("d", 0).is_err());
        assert_eq!(
            args.integer("e", 0).unwrap_err(),
            "argument e must be an integer, not 'many'"
        );
        assert!(args.integer("f", 0).is_err());
        assert_eq!(args.integer("g", 100).unwrap(), 100);
    }
}
