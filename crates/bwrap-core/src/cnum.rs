//! One C `strtoul`/`strtol`-style numeric prefix scanner, shared by every
//! command-line number parser.
//!
//! bwrap reads numbers with glibc's `strtol`/`strtoul`/`strtoull`. Each call
//! site needs the same scan — skip whitespace, take an optional sign, read the
//! digit run for a base, saturate on overflow — but a *different post-check*:
//! the `long`→`int` narrowing of `--uid`/fd arguments, the `<= 07777` clamp of
//! `--perms`, the full-consumption + non-zero guard of `--size`, or libcap's
//! "ignore the trailing junk" for a numeric `--cap-add`. Writing the scan once
//! means a correction to glibc-quirk handling reaches all of them; the callers
//! keep their own post-checks, which deliberately differ.

/// C `isspace`: space, tab, newline, vertical tab, form feed, carriage return.
/// Rust's `is_ascii_whitespace` omits vertical tab (`\x0b`), so we match C here.
#[must_use]
pub fn is_c_whitespace(c: u8) -> bool {
    matches!(c, b' ' | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d)
}

/// The outcome of a [`c_strtou64`] scan.
///
/// glibc parses a number as an unsigned magnitude and then applies the sign —
/// `strtoul` negates by wrapping, `strtol` range-checks against
/// `LONG_MIN`/`LONG_MAX` — so this reports the magnitude and the sign
/// separately and lets the caller finish the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CNum {
    /// A leading `-` was present. glibc applies the sign *after* reading the
    /// digits, so the caller combines this with [`val`](Self::val).
    pub neg: bool,
    /// The parsed magnitude, saturated at `u64::MAX` on overflow (glibc's
    /// `ERANGE` → `ULONG_MAX`).
    pub val: u64,
    /// The digit run overflowed `u64` (glibc would set `errno == ERANGE`).
    pub overflow: bool,
    /// Byte offset of glibc's `endptr`: one past the last consumed digit.
    pub end: usize,
    /// How many value digits were consumed. `0` means no number was present
    /// (glibc would leave `endptr == nptr`).
    pub digits: usize,
}

/// Scan the leading number of `s` the way glibc's `strtoul`/`strtol` do.
///
/// Skips leading C whitespace and an optional `+`/`-`, then reads the longest
/// run of digits valid for `radix`. `radix == 0` auto-detects as C does: a
/// `0x`/`0X` prefix *followed by a hex digit* → base 16, an otherwise-leading
/// `0` → base 8, else base 10 (a lone `"0x"` is thus the value `0` with `x`
/// left as trailing junk, exactly as glibc backs up its `endptr`). The
/// magnitude saturates at `u64::MAX` on overflow.
///
/// The caller decides what to do with the sign, the overflow flag and any bytes
/// past [`CNum::end`]: require full consumption, clamp a range, or ignore the
/// trailing junk.
#[must_use]
pub fn c_strtou64(s: &str, radix: u32) -> CNum {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && is_c_whitespace(b[i]) {
        i += 1;
    }
    let neg = match b.get(i) {
        Some(b'+') => {
            i += 1;
            false
        }
        Some(b'-') => {
            i += 1;
            true
        }
        _ => false,
    };
    // Resolve the base. For `radix == 0`, auto-detect like C and consume a
    // `0x`/`0X` prefix only when a hex digit actually follows it.
    let radix = if radix == 0 {
        if b.get(i) == Some(&b'0') {
            match (b.get(i + 1), b.get(i + 2)) {
                (Some(b'x' | b'X'), Some(c)) if c.is_ascii_hexdigit() => {
                    i += 2;
                    16
                }
                _ => 8, // a leading `0` is octal; a lone `0` is octal zero
            }
        } else {
            10
        }
    } else {
        radix
    };
    let start = i;
    let mut val: u64 = 0;
    let mut overflow = false;
    while let Some(d) = b.get(i).and_then(|&c| (c as char).to_digit(radix)) {
        match val
            .checked_mul(u64::from(radix))
            .and_then(|v| v.checked_add(u64::from(d)))
        {
            Some(v) => val = v,
            None => {
                overflow = true;
                val = u64::MAX;
            }
        }
        i += 1;
    }
    CNum {
        neg,
        val,
        overflow,
        end: i,
        digits: i - start,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_whitespace_includes_vertical_tab() {
        for c in [b' ', b'\t', b'\n', 0x0b, 0x0c, b'\r'] {
            assert!(is_c_whitespace(c));
        }
        assert!(!is_c_whitespace(b'x'));
        assert!(!is_c_whitespace(0));
    }

    #[test]
    fn base10_skips_whitespace_and_sign() {
        let c = c_strtou64(" \t\x0b-42", 10);
        assert!(c.neg);
        assert_eq!(c.val, 42);
        assert!(!c.overflow);
        assert_eq!(c.digits, 2);
        assert_eq!(c.end, " \t\x0b-42".len());
    }

    #[test]
    fn no_digits_is_reported() {
        let c = c_strtou64("  +", 10);
        assert_eq!(c.digits, 0);
        assert_eq!(c.val, 0);
    }

    #[test]
    fn overflow_saturates_and_consumes_all_digits() {
        let c = c_strtou64("99999999999999999999999999", 10);
        assert!(c.overflow);
        assert_eq!(c.val, u64::MAX);
        assert_eq!(c.end, "99999999999999999999999999".len());
    }

    #[test]
    fn u64_max_is_not_overflow() {
        let c = c_strtou64("18446744073709551615", 10);
        assert!(!c.overflow);
        assert_eq!(c.val, u64::MAX);
    }

    #[test]
    fn base0_autodetects_like_c() {
        assert_eq!(c_strtou64("0x10000", 0).val, 0x10000);
        assert_eq!(c_strtou64("010", 0).val, 0o10);
        assert_eq!(c_strtou64("10", 0).val, 10);
        // A lone "0x" is the value 0 with "x" trailing (endptr backs up).
        let c = c_strtou64("0x", 0);
        assert_eq!(c.val, 0);
        assert_eq!(c.end, 1);
        assert_eq!(c.digits, 1);
        // "0x" is a hex prefix ONLY when a hex digit follows. "0xZ" is therefore
        // octal zero with "xZ" trailing (endptr at the 'x'), exactly as C's
        // strtoul(…, 0) does — the hex prefix is not consumed. Guards the
        // `is_ascii_hexdigit()` check in the base-0 autodetect.
        let c = c_strtou64("0xZ", 0);
        assert_eq!(c.val, 0);
        assert_eq!(c.end, 1);
        assert_eq!(c.digits, 1);
    }

    #[test]
    fn trailing_junk_stops_the_scan() {
        let c = c_strtou64("5x", 10);
        assert_eq!(c.val, 5);
        assert_eq!(c.end, 1);
        assert_eq!(c.digits, 1);
    }

    #[test]
    fn octal_stops_at_non_octal_digit() {
        // "08" in base 8: the "0" is the value, "8" is trailing.
        let c = c_strtou64("08", 8);
        assert_eq!(c.val, 0);
        assert_eq!(c.end, 1);
    }
}
