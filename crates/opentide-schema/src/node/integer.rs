//! Python's `int`: YAML 1.1 integers have no bound (`0xFFFFFFFFFFFFFFFFFFFF`
//! is an integer to PyYAML), so the tree keeps the exact value, not an `i64`.

use std::cmp::Ordering;
use std::fmt;

/// Base of one limb: nine decimal digits.
const LIMB: u64 = 1_000_000_000;

/// An integer of any size, as Python's `int` holds it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Integer {
    negative: bool,
    /// Base-10⁹ limbs, least significant first, without trailing zero limbs;
    /// empty for zero.
    limbs: Vec<u32>,
}

impl Integer {
    /// Zero.
    pub const fn zero() -> Self {
        Self {
            negative: false,
            limbs: Vec::new(),
        }
    }

    /// The integer `value`.
    pub fn from_i64(value: i64) -> Self {
        let mut magnitude = value.unsigned_abs();
        let mut limbs = Vec::new();
        while magnitude > 0 {
            limbs.push(limb(magnitude % LIMB));
            magnitude /= LIMB;
        }
        Self {
            negative: value < 0,
            limbs,
        }
    }

    /// Whether the value is 0.
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    /// Whether the value is below 0.
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// The value as an `i64`, if it fits.
    pub fn to_i64(&self) -> Option<i64> {
        let mut magnitude: u128 = 0;
        for &limb in self.limbs.iter().rev() {
            magnitude = magnitude.checked_mul(u128::from(LIMB))? + u128::from(limb);
            if magnitude > u128::from(u64::MAX) {
                return None;
            }
        }
        if self.negative {
            let min = u128::from(i64::MIN.unsigned_abs());
            match magnitude.cmp(&min) {
                Ordering::Greater => None,
                Ordering::Equal => Some(i64::MIN),
                Ordering::Less => i64::try_from(magnitude).ok().map(|m| -m),
            }
        } else {
            i64::try_from(magnitude).ok()
        }
    }

    /// The value as Python's `float(int)` gives it: the nearest `f64`, or
    /// `None` where Python raises `OverflowError`.
    pub fn to_f64(&self) -> Option<f64> {
        let value: f64 = self.to_string().parse().ok()?;
        value.is_finite().then_some(value)
    }

    /// Parses `digits` in `radix` (2 to 16), as Python's `int(digits, radix)`
    /// does after PyYAML removed every `_`: surrounding whitespace, one sign,
    /// then at least one digit. `None` where Python raises `ValueError`.
    pub fn parse_python(text: &str, radix: u32) -> Option<Self> {
        let text = text.trim_matches(is_python_space);
        let (negative, digits) = match text.as_bytes().first() {
            Some(b'-') => (true, &text[1..]),
            Some(b'+') => (false, &text[1..]),
            _ => (false, text),
        };
        if digits.is_empty() {
            return None;
        }
        let mut value = Self::zero();
        for character in digits.chars() {
            let digit = character.to_digit(radix)?;
            value.mul_add(radix, digit);
        }
        value.negative = negative && !value.is_zero();
        Some(value)
    }

    /// `self * factor + addend` on the magnitude.
    fn mul_add(&mut self, factor: u32, addend: u32) {
        let mut carry = u64::from(addend);
        for limb_value in &mut self.limbs {
            let product = u64::from(*limb_value) * u64::from(factor) + carry;
            *limb_value = limb(product % LIMB);
            carry = product / LIMB;
        }
        while carry > 0 {
            self.limbs.push(limb(carry % LIMB));
            carry /= LIMB;
        }
    }

    /// The sum of the magnitudes, with `self`'s sign (both are non-negative
    /// where it is used: sexagesimal parts).
    pub(crate) fn add_magnitude(&mut self, other: &Self) {
        let mut carry = 0u64;
        let length = self.limbs.len().max(other.limbs.len());
        self.limbs.resize(length, 0);
        for (index, limb_value) in self.limbs.iter_mut().enumerate() {
            let sum = u64::from(*limb_value)
                + u64::from(other.limbs.get(index).copied().unwrap_or(0))
                + carry;
            *limb_value = limb(sum % LIMB);
            carry = sum / LIMB;
        }
        if carry > 0 {
            self.limbs.push(limb(carry));
        }
    }

    /// The magnitude times `factor`.
    pub(crate) fn times(&self, factor: u32) -> Self {
        let mut product = self.clone();
        product.mul_add(factor, 0);
        product.trim();
        product
    }

    /// The value negated.
    pub(crate) fn negated(mut self) -> Self {
        self.negative = !self.negative && !self.is_zero();
        self
    }

    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
        if self.limbs.is_empty() {
            self.negative = false;
        }
    }
}

/// Python's `str.strip()` whitespace that `int()` and `float()` ignore.
pub(crate) fn is_python_space(character: char) -> bool {
    character.is_whitespace()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "every caller passes a value reduced modulo 10^9, below u32::MAX"
)]
fn limb(value: u64) -> u32 {
    value as u32
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some((most, rest)) = self.limbs.split_last() else {
            return f.write_str("0");
        };
        if self.negative {
            f.write_str("-")?;
        }
        write!(f, "{most}")?;
        for limb_value in rest.iter().rev() {
            write!(f, "{limb_value:09}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Integer;

    #[test]
    fn parses_and_prints_any_size() {
        let big = Integer::parse_python("FFFFFFFFFFFFFFFFFFFF", 16).unwrap();
        assert_eq!(big.to_string(), "1208925819614629174706175");
        assert_eq!(big.to_i64(), None);
        assert_eq!(Integer::parse_python("-0", 10).unwrap().to_string(), "0");
        assert_eq!(Integer::parse_python(" +17 ", 8).unwrap().to_string(), "15");
        assert_eq!(Integer::parse_python("", 2), None);
        assert_eq!(Integer::parse_python("12", 2), None);
        assert_eq!(Integer::parse_python("-", 10), None);
    }

    #[test]
    fn i64_bounds() {
        for value in [0, 1, -1, i64::MAX, i64::MIN, 1_000_000_000, -999_999_999] {
            let integer = Integer::from_i64(value);
            assert_eq!(integer.to_string(), value.to_string());
            assert_eq!(integer.to_i64(), Some(value));
            assert_eq!(
                Integer::parse_python(&value.to_string(), 10).unwrap(),
                integer
            );
        }
        let above = Integer::parse_python("9223372036854775808", 10).unwrap();
        assert_eq!(above.to_i64(), None);
        let below = Integer::parse_python("-9223372036854775809", 10).unwrap();
        assert_eq!(below.to_i64(), None);
    }

    #[test]
    fn arithmetic() {
        let mut total = Integer::from_i64(30);
        total.add_magnitude(&Integer::from_i64(20).times(60));
        total.add_magnitude(&Integer::from_i64(190).times(3600));
        assert_eq!(total.to_string(), "685230");
        assert_eq!(total.clone().negated().to_string(), "-685230");
        assert_eq!(Integer::zero().negated().to_string(), "0");
        assert_eq!(Integer::from_i64(3).to_f64(), Some(3.0));
    }
}
