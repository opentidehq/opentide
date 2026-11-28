//! `{name}` placeholders filled in, for the templates `generate extract` and
//! `setup skills` write.

/// `template` with each `{name}` placeholder that `values` names replaced by
/// its value, in one pass: a value is never read as a placeholder, and a
/// placeholder `values` does not name is kept as it is.
pub(crate) fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some((head, after)) = rest.split_once('{') {
        out.push_str(head);
        let Some((name, tail)) = after.split_once('}') else {
            out.push('{');
            out.push_str(after);
            rest = "";
            break;
        };
        match values.iter().find(|(key, _)| *key == name) {
            Some((_, value)) => out.push_str(value),
            None => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_fill_in_one_pass() {
        assert_eq!(
            fill("a {x} {y} {z}", &[("x", "{y}"), ("y", "2")]),
            "a {y} 2 {z}"
        );
        assert_eq!(fill("a {", &[]), "a {");
        assert_eq!(fill("{a}{b}", &[("b", "B")]), "{a}B");
        // #1946: placeholders among multi-byte text.
        assert_eq!(
            fill("é{😀}é {nom} 😀{", &[("😀", "é"), ("x", "y")]),
            "ééé {nom} 😀{"
        );
        assert_eq!(fill("{é}😀}", &[("é", "{😀}")]), "{😀}😀}");
    }
}
