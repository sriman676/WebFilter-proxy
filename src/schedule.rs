//! Time windows for category rules (A-27): `"Mon-Fri 09:00-17:00"`, `"Sat,Sun 00:00-24:00"`,
//! overnight `"Fri 22:00-02:00"` (continues into the next day). Evaluated in a fixed UTC offset.
#![forbid(unsafe_code)]

use time::{OffsetDateTime, UtcOffset, Weekday};

const DAYS: [(&str, Weekday); 7] = [
    ("mon", Weekday::Monday),
    ("tue", Weekday::Tuesday),
    ("wed", Weekday::Wednesday),
    ("thu", Weekday::Thursday),
    ("fri", Weekday::Friday),
    ("sat", Weekday::Saturday),
    ("sun", Weekday::Sunday),
];

/// One window: the set of start days and a minute range (end may be <= start: overnight).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Window {
    days: [bool; 7], // indexed by Weekday::number_days_from_monday
    start: u16,      // minutes since midnight
    end: u16,        // 1..=1440
}

/// A set of windows; empty = always active.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schedule {
    windows: Vec<Window>,
    offset: Option<UtcOffset>,
}

fn day_index(name: &str) -> Result<usize, String> {
    let lower = name.trim().to_ascii_lowercase();
    DAYS.iter()
        .position(|(n, _)| *n == lower)
        .ok_or_else(|| format!("unknown day {name:?} (use Mon..Sun)"))
}

fn parse_days(spec: &str) -> Result<[bool; 7], String> {
    let mut days = [false; 7];
    for part in spec.split(',') {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let (a, b) = (day_index(a)?, day_index(b)?);
        let mut d = a;
        loop {
            if let Some(slot) = days.get_mut(d) {
                *slot = true;
            }
            if d == b {
                break;
            }
            d = (d + 1) % 7; // ranges may wrap (Fri-Mon)
        }
    }
    Ok(days)
}

fn parse_time(s: &str) -> Result<u16, String> {
    let bad = || format!("invalid time {s:?} (use HH:MM, 00:00..24:00)");
    let (h, m) = s.split_once(':').ok_or_else(bad)?;
    if h.len() != 2 || m.len() != 2 {
        return Err(bad());
    }
    let (h, m): (u16, u16) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    let minutes = h * 60 + m;
    if m > 59 || minutes > 1440 { Err(bad()) } else { Ok(minutes) }
}

/// Parse a `+HH:MM` / `-HH:MM` offset (e.g. `"+05:30"`).
pub fn parse_offset(s: &str) -> Result<UtcOffset, String> {
    let bad = || format!("invalid UTC offset {s:?} (use +HH:MM or -HH:MM)");
    let (sign, rest) = match s.as_bytes().first() {
        Some(b'+') => (1i8, s.get(1..).unwrap_or("")),
        Some(b'-') => (-1i8, s.get(1..).unwrap_or("")),
        _ => return Err(bad()),
    };
    let minutes = parse_time(rest).map_err(|_| bad())?;
    let (h, m) = (
        i8::try_from(minutes / 60).map_err(|_| bad())?,
        i8::try_from(minutes % 60).map_err(|_| bad())?,
    );
    UtcOffset::from_hms(sign * h, sign * m, 0).map_err(|_| bad())
}

impl Schedule {
    /// Parse windows such as `["Mon-Fri 09:00-17:00", "Sat 10:00-12:00"]` in `offset`.
    pub fn parse(specs: &[String], offset: UtcOffset) -> Result<Self, String> {
        let windows = specs
            .iter()
            .map(|spec| {
                let (days, times) = spec.trim().split_once(' ').ok_or_else(|| {
                    format!("invalid window {spec:?} (use \"Mon-Fri 09:00-17:00\")")
                })?;
                let (start, end) = times
                    .trim()
                    .split_once('-')
                    .ok_or_else(|| format!("invalid window {spec:?}"))?;
                let (start, end) = (parse_time(start)?, parse_time(end)?);
                if start == end || start == 1440 {
                    return Err(format!("empty window {spec:?}"));
                }
                Ok(Window { days: parse_days(days)?, start, end })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { windows, offset: Some(offset) })
    }

    /// Whether the schedule is active at `now` (always, when there are no windows).
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        if self.windows.is_empty() {
            return true;
        }
        let local = now.to_offset(self.offset.unwrap_or(UtcOffset::UTC));
        let today = usize::from(local.weekday().number_days_from_monday());
        let yesterday = (today + 6) % 7;
        let minute = u16::from(local.hour()) * 60 + u16::from(local.minute());
        let day = |w: &Window, d: usize| w.days.get(d).copied().unwrap_or(false);
        self.windows.iter().any(|w| {
            if w.start < w.end {
                day(w, today) && (w.start..w.end).contains(&minute)
            } else {
                (day(w, today) && minute >= w.start) || (day(w, yesterday) && minute < w.end) // overnight
            }
        })
    }
}
