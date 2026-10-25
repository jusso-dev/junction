//! UTC timestamps without a calendar dependency.
//!
//! Stored timestamps use one fixed-width RFC 3339 form, `YYYY-MM-DDTHH:MM:SS.mmmZ`,
//! so lexicographic order in SQLite equals chronological order.
use anyhow::{Result, bail};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(pub i64);

impl Instant {
    pub fn now() -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Self(millis)
    }
    pub fn plus(self, duration: Duration) -> Self {
        Self(self.0.saturating_add(duration.as_millis() as i64))
    }
    pub fn minus(self, duration: Duration) -> Self {
        Self(self.0.saturating_sub(duration.as_millis() as i64))
    }
    pub fn since(self, earlier: Instant) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0).max(0) as u64)
    }
    /// `YYYY-MM-DDTHH:MM:SS.mmmZ`
    pub fn to_rfc3339(self) -> String {
        let (date, ms) = (self.0.div_euclid(86_400_000), self.0.rem_euclid(86_400_000));
        let (y, m, d) = civil_from_days(date);
        let secs = ms / 1000;
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
            secs / 3600,
            (secs / 60) % 60,
            secs % 60,
            ms % 1000
        )
    }
    /// Second precision without fraction, as the Management Activity API expects:
    /// `YYYY-MM-DDTHH:MM:SS`.
    pub fn to_api_seconds(self) -> String {
        self.to_rfc3339()[..19].to_owned()
    }
    /// Accepts the forms Microsoft APIs emit: optional fraction (any length),
    /// optional `Z` or `+00:00`. Non-UTC offsets are converted.
    pub fn parse(value: &str) -> Result<Self> {
        // Fixed byte offsets below are only safe on ASCII; audit content is untrusted.
        if !value.is_ascii() {
            bail!("invalid timestamp");
        }
        let b = value.as_bytes();
        if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b' ') {
            bail!("invalid timestamp");
        }
        if b[13] != b':' || b[16] != b':' {
            bail!("invalid timestamp");
        }
        let num = |range: std::ops::Range<usize>| -> Result<i64> {
            let s = &value[range];
            if !s.bytes().all(|c| c.is_ascii_digit()) {
                bail!("invalid timestamp");
            }
            Ok(s.parse()?)
        };
        let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
        if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
            bail!("invalid timestamp");
        }
        let mut rest = &value[19..];
        let mut millis = 0i64;
        if let Some(fraction) = rest.strip_prefix('.') {
            let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                bail!("invalid timestamp");
            }
            let padded = format!("{:0<3}", &fraction[..digits.min(3)]);
            millis = padded.parse()?;
            rest = &fraction[digits..];
        }
        let offset_minutes = match rest {
            "" | "Z" | "z" => 0,
            _ if rest.len() == 6 && matches!(&rest[..1], "+" | "-") && &rest[3..4] == ":" => {
                let hours: i64 = rest[1..3].parse()?;
                let minutes: i64 = rest[4..6].parse()?;
                let total = hours * 60 + minutes;
                if &rest[..1] == "+" { total } else { -total }
            }
            _ => bail!("invalid timestamp"),
        };
        let days = days_from_civil(y, mo, d);
        let seconds = days * 86_400 + h * 3600 + mi * 60 + s.min(59) - offset_minutes * 60;
        Ok(Self(seconds * 1000 + millis))
    }
}

// Howard Hinnant's civil calendar algorithms (public domain).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trips_and_accepts_microsoft_forms() {
        let t = Instant::parse("2026-10-25T01:02:03.456Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-10-25T01:02:03.456Z");
        assert_eq!(t.to_api_seconds(), "2026-10-25T01:02:03");
        assert_eq!(Instant::parse("2026-10-25T01:02:03").unwrap().0, t.0 - 456);
        assert_eq!(Instant::parse("2026-10-25T01:02:03.4567891Z").unwrap(), t);
        assert_eq!(
            Instant::parse("2026-10-25T12:02:03.456+11:00").unwrap(),
            t,
            "AEDT offsets convert to UTC"
        );
        assert_eq!(Instant(0).to_rfc3339(), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            Instant::parse("2024-02-29T23:59:59Z").unwrap().to_rfc3339(),
            "2024-02-29T23:59:59.000Z"
        );
        for bad in [
            "2026-10-25T01:02:0\u{e9}Z",
            "2026-10-25T01:02:03.\u{e9}Z",
            "\u{e9}026-10-25T01:02:03Z",
            "",
            "2026-13-01T00:00:00Z",
            "2026-10-25",
            "2026-10-25T01:02:03.Z",
            "2026-10-25T01:02:03 junk",
            "2026-1a-25T01:02:03Z",
        ] {
            assert!(Instant::parse(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn ordering_matches_string_ordering() {
        let a = Instant::parse("2026-01-09T23:00:00Z").unwrap();
        let b = Instant::parse("2026-01-10T01:00:00Z").unwrap();
        assert!(a < b && a.to_rfc3339() < b.to_rfc3339());
        assert_eq!(b.since(a), Duration::from_secs(7200));
        assert_eq!(a.since(b), Duration::ZERO);
    }
}
