//! Eval and where expressions, and `where` and `eval` themselves.
//!
//! The precedence of `grammar.js`, loosest first: `or` < `and` < comparison
//! (`= == != < > <= >= LIKE IN`, not chained) < additive (`+ - .`) <
//! multiplicative (`* / %`) < unary (`NOT not ! - +`, over one primary) <
//! primary. A run of one level is one flat n-ary node (`a or b or c` is one
//! `BIN_EXPR` with five children), so a 20,000-term chain is not 20,000
//! levels deep; parentheses, calls and subsearches nest, and so does an
//! operator's operand that has operators of its own (see [`bin`]).

use super::kind::SyntaxKind as K;
use super::parser::{at, leaf};
use super::search;
use opentide_parse::{CompletedMarker, Parser};

/// The binding power of the current token as an infix operator, and the kind
/// it takes in the tree.
fn infix(p: &Parser<'_>) -> Option<(u8, K)> {
    let kind = p.current();
    if kind == K::IDENT.raw() {
        return match p.current_text() {
            "OR" => Some((1, K::OR_KW)),
            "or" => Some((1, K::OR_LOWER_KW)),
            "AND" => Some((2, K::AND_KW)),
            "and" => Some((2, K::AND_LOWER_KW)),
            "IN" => Some((3, K::IN_KW)),
            "LIKE" => Some((3, K::LIKE_KW)),
            "like" => Some((3, K::LIKE_LOWER_KW)),
            _ => None,
        };
    }
    [
        (K::EQ, 3),
        (K::EQ2, 3),
        (K::NE, 3),
        (K::LT, 3),
        (K::GT, 3),
        (K::LE, 3),
        (K::GE, 3),
        (K::PLUS, 4),
        (K::MINUS, 4),
        (K::DOT, 4),
        (K::STAR, 5),
        (K::SLASH, 5),
        (K::PERCENT, 5),
    ]
    .into_iter()
    .find(|(k, _)| k.raw() == kind)
    .map(|(k, power)| (power, k))
}

/// Whether the current token can start an expression.
pub(super) fn starts_expr(p: &Parser<'_>) -> bool {
    let kind = p.current();
    [
        K::IDENT,
        K::NUMBER_TOKEN,
        K::STRING_TOKEN,
        K::MACRO_TOKEN,
        K::DYNAMIC_NAME,
        K::TOKEN_NAME,
        K::TEMPLATE_NAME,
        K::L_PAREN,
        K::L_BRACKET,
        K::BANG,
        K::MINUS,
        K::PLUS,
    ]
    .iter()
    .any(|k| k.raw() == kind)
}

/// An expression; `None` (and nothing consumed) when none starts here.
pub(super) fn expression(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    bin(p, 1)
}

/// Operators of binding power at least `min`.
///
/// An operator's operand (`min` above 1) that has operators of its own is a
/// level of `max_depth`: it recurses into the tighter levels, and a chain
/// through every precedence inside each call (`f(a OR b AND NOT c == d + e *
/// -(`) recursed several frames a level unchecked and overflowed a 1 MB stack
/// (#1473). A plain operand (`x=[ subsearch ]`) costs nothing more.
fn bin(p: &mut Parser<'_>, min: u8) -> Option<CompletedMarker> {
    let mut lhs = operand(p)?;
    let mut entered = false;
    // The power of the last run: an operator that binds tighter than it is
    // one the run's operand refused (a second comparison, `a and b = c = d`),
    // which no level of the grammar takes either.
    let mut last: Option<u8> = None;
    while let Some((power, _)) = infix(p) {
        if power < min || last.is_some_and(|last| power > last || (power == 3 && last == 3)) {
            break;
        }
        last = Some(power);
        if min > 1 && !entered {
            if !p.enter() {
                return Some(lhs);
            }
            entered = true;
        }
        let m = lhs.precede(p);
        // One flat node per level and run: `a + b - c` is one node.
        while let Some((next, kind)) = infix(p) {
            if next != power {
                break;
            }
            p.bump_as(kind.raw());
            if kind == K::IN_KW {
                if at(p, K::L_PAREN) {
                    search::value_list(p);
                } else {
                    p.error("expected a list of values after `IN`");
                }
            } else if bin(p, power + 1).is_none() {
                p.error("expected an expression after the operator");
                break;
            }
            if power == 3 {
                // Comparisons do not chain.
                break;
            }
        }
        lhs = m.complete(p, K::BIN_EXPR.raw());
    }
    if entered {
        p.exit();
    }
    Some(lhs)
}

/// A unary operator over one primary, or a primary.
fn operand(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let kind = p.current();
    let sign = [K::BANG, K::MINUS, K::PLUS].iter().any(|k| k.raw() == kind);
    let not = kind == K::IDENT.raw() && matches!(p.current_text(), "NOT" | "not");
    // `NOT` is reserved: always negation. `not(x)` is a call.
    let not = not && (p.current_text() == "NOT" || p.nth(1) != K::L_PAREN.raw());
    if sign || not {
        let m = p.start();
        let kind = match p.current_text() {
            "NOT" => K::NOT_KW,
            "not" => K::NOT_LOWER_KW,
            "!" => K::BANG,
            "-" => K::MINUS,
            _ => K::PLUS,
        };
        p.bump_as(kind.raw());
        if primary(p).is_none() {
            p.error("expected an expression after the operator");
        }
        return Some(m.complete(p, K::UNARY_EXPR.raw()));
    }
    primary(p)
}

fn primary(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let kind = p.current();
    let is = |k: K| k.raw() == kind;
    if is(K::L_PAREN) {
        if !p.enter() {
            return None;
        }
        let m = p.start();
        p.bump();
        if bin(p, 1).is_none() {
            p.error("expected an expression");
        }
        if !p.eat(K::R_PAREN.raw()) {
            p.error("missing `)`");
        }
        let done = m.complete(p, K::PAREN_EXPR.raw());
        p.exit();
        Some(done)
    } else if is(K::L_BRACKET) {
        search::subsearch(p)
    } else if is(K::MACRO_TOKEN) {
        Some(leaf_marker(p, K::MACRO_CALL, K::MACRO_TOKEN))
    } else if is(K::NUMBER_TOKEN) {
        Some(leaf_marker(p, K::NUMBER, K::NUMBER_TOKEN))
    } else if is(K::STRING_TOKEN) {
        Some(leaf_marker(p, K::STR, K::STRING_TOKEN))
    } else if is(K::TOKEN_NAME) || is(K::TEMPLATE_NAME) {
        Some(leaf_marker(p, K::IDENTIFIER, kind_of(p)))
    } else if is(K::IDENT) && !matches!(p.current_text(), "AND" | "OR" | "NOT") {
        name_or_call(p)
    } else {
        None
    }
}

fn kind_of(p: &Parser<'_>) -> K {
    let kind = p.current();
    [K::DYNAMIC_NAME, K::TOKEN_NAME, K::TEMPLATE_NAME]
        .into_iter()
        .find(|k| k.raw() == kind)
        .unwrap_or(K::IDENT)
}

fn leaf_marker(p: &mut Parser<'_>, node: K, token: K) -> CompletedMarker {
    let m = p.start();
    p.bump_as(token.raw());
    m.complete(p, node.raw())
}

/// A name, a boolean, or a call (`f(`, `true()`).
pub(super) fn name_or_call(p: &mut Parser<'_>) -> Option<CompletedMarker> {
    let boolean = matches!(p.current_text(), "true" | "false" | "TRUE" | "FALSE");
    let call = p.nth(1) == K::L_PAREN.raw();
    let name_node = if boolean && !call {
        K::BOOLEAN
    } else {
        K::IDENTIFIER
    };
    let token = if boolean { K::BOOL_KW } else { K::IDENT };
    let name = leaf_marker(p, name_node, token);
    if !call {
        return Some(name);
    }
    if !p.enter() {
        return Some(name);
    }
    let m = name.precede(p);
    p.bump();
    if !at(p, K::R_PAREN) {
        loop {
            if expression(p).is_none() {
                p.error("expected an argument");
                break;
            }
            if !p.eat(K::COMMA.raw()) {
                break;
            }
        }
    }
    if !p.eat(K::R_PAREN.raw()) {
        p.error("missing `)`");
    }
    let done = m.complete(p, K::FUNCTION_CALL.raw());
    p.exit();
    Some(done)
}

/// `where [expression]`: no predicate keeps every row.
pub(super) fn where_command(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::WHERE_KW.raw());
    if starts_expr(p) {
        expression(p);
    }
    m.complete(p, K::WHERE_COMMAND.raw());
}

/// `eval name=expr, ...`.
pub(super) fn eval_command(p: &mut Parser<'_>) {
    let m = p.start();
    p.bump_as(K::EVAL_KW.raw());
    loop {
        assignment(p);
        if !p.eat(K::COMMA.raw()) {
            break;
        }
    }
    m.complete(p, K::EVAL_COMMAND.raw());
}

fn assignment(p: &mut Parser<'_>) {
    let m = p.start();
    let kind = p.current();
    let named = [K::IDENT, K::DYNAMIC_NAME, K::TEMPLATE_NAME, K::STRING_TOKEN]
        .iter()
        .any(|k| k.raw() == kind);
    if named {
        if kind == K::STRING_TOKEN.raw() {
            leaf(p, K::STR, K::STRING_TOKEN);
        } else {
            leaf(p, K::IDENTIFIER, kind_of(p));
        }
    } else {
        p.error("expected a field name");
        m.complete(p, K::ASSIGNMENT.raw());
        return;
    }
    if p.eat(K::EQ.raw()) {
        if expression(p).is_none() {
            p.error("expected an expression");
        }
    } else {
        p.error("expected `=`");
    }
    m.complete(p, K::ASSIGNMENT.raw());
}

#[cfg(test)]
mod tests {
    use super::super::parser::tests::render;

    #[test]
    fn precedence_and_flat_chains() {
        let out = render("| where a or b or c and d");
        assert!(out.ends_with("--\n"), "{out}");
        // `a or b or (c and d)`: the outer or is one node with five children.
        assert_eq!(out.matches("BIN_EXPR@").count(), 2, "{out}");
        let out = render("| eval x=a+b*c-d");
        assert!(out.ends_with("--\n"), "{out}");
        assert_eq!(out.matches("BIN_EXPR@").count(), 2, "{out}");
    }

    #[test]
    fn comparisons_do_not_chain_and_in_takes_a_list() {
        assert!(render("| where a<b").ends_with("--\n"));
        assert!(render("| where a<b<c").contains("unexpected token"));
        // A comparison after an `and` or `or` run does not chain either:
        // tree-sitter's comparison operands are additive expressions.
        for chained in [
            "| where a and b = c = d",
            "| where a or b < c > d",
            "| where a<b and c<d<e",
            "| eval x=a and b == c != d",
            "| where (a and b = c = d)",
        ] {
            assert!(!render(chained).ends_with("--\n"), "{chained}");
        }
        for valid in [
            "| where a<b and c<d",
            "| where a + b = c and d",
            "| where a * b = c or d = e",
            "| where a = b and c or d",
        ] {
            assert!(render(valid).ends_with("--\n"), "{valid}");
        }
        let out = render(r#"| where x IN ("a", b) and not y"#);
        assert!(out.contains("VALUE_LIST") && out.ends_with("--\n"), "{out}");
    }

    #[test]
    fn calls_booleans_and_templates() {
        let out = render("| eval a=if(x>1, true, false()), {f}=1, `m`");
        assert_eq!(out.matches("FUNCTION_CALL@").count(), 2, "{out}");
        assert_eq!(out.matches("BOOLEAN@").count(), 1, "{out}");
    }

    #[test]
    fn a_long_chain_stays_flat() {
        let source = format!("| where {}a", "a or ".repeat(30_000));
        let out = super::super::parse(&source);
        assert!(out.1.errors.is_empty(), "{:?}", out.1.errors.first());
    }
}
