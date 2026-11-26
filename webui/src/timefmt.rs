//! Calendar arithmetic and UTC formatting, without a time zone database.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            eprintln!("the system clock is before 1970: {e}");
            0
        }
    }
}

/// `2026-01-31T09:05:00Z`
pub fn iso(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `2026-01-31 09:05 UTC`, for people.
pub fn display(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

/// Year, month, day, hour, minute and second, in UTC.
pub fn parts(secs: u64) -> (i64, i64, i64, u64, u64, u64) {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// True for a real calendar date written `YYYY-MM-DD`.
pub fn valid_date(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    if !digits(0..4) || !digits(5..7) || !digits(8..10) {
        return false;
    }
    let num = |r: std::ops::Range<usize>| b[r].iter().fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0'));
    let (y, m, d) = (num(0..4), num(5..7), num(8..10));
    if !(1..=12).contains(&m) || d < 1 {
        return false;
    }
    civil_from_days(days_from_civil(y, m, d)) == (y, m, d)
}

/// Days since the epoch of a date known to be valid.
pub fn days_of(text: &str) -> i64 {
    let num = |s: &str| s.bytes().fold(0i64, |acc, d| acc * 10 + i64::from(d.wrapping_sub(b'0')));
    days_from_civil(num(&text[0..4]), num(&text[5..7]), num(&text[8..10]))
}

/// Seconds since 1970 of an RFC 3339 time such as
/// `2026-11-26T01:00:00.123456+01:00`, offset applied; None for anything else.
pub fn parse_rfc3339(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.len() < 20 || b[10] != b'T' || b[13] != b':' || b[16] != b':' || !valid_date(&text[0..10]) {
        return None;
    }
    let (h, mi, s) = (number(&b[11..13])?, number(&b[14..16])?, number(&b[17..19])?);
    if h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut rest = &b[19..];
    if let Some((b'.', frac)) = rest.split_first() {
        let n = frac.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        rest = &frac[n..];
    }
    let offset = match rest {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let off = number(&[*h1, *h2])? * 3600 + number(&[*m1, *m2])? * 60;
            if *sign == b'+' { off } else { -off }
        }
        _ => return None,
    };
    let secs = days_of(&text[0..10]) * 86_400 + h * 3600 + mi * 60 + s - offset;
    if secs < 0 { None } else { Some(secs.unsigned_abs()) }
}

/// The value of ASCII digits; None when any byte is not one.
fn number(digits: &[u8]) -> Option<i64> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(digits.iter().fold(0, |acc, d| acc * 10 + i64::from(d - b'0')))
}

// Howard Hinnant's algorithms, valid for every date in the proleptic
// Gregorian calendar.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_validates() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1_801_353_600), "2027-01-31T00:00:00Z");
        assert!(valid_date("2027-01-31"));
        assert!(valid_date("2028-02-29"));
        assert!(!valid_date("2027-02-29"));
        assert!(!valid_date("2027-13-01"));
        assert!(!valid_date("2027-1-01"));
        assert_eq!(days_of("1970-01-02"), 1);
        assert_eq!(days_of("2027-01-31"), 20_849);
    }
}
