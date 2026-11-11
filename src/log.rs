//! Minimal leveled logger: every line is `<local timestamp> <LEVEL> <message>`.
//! ERROR goes to stderr, everything else to stdout.

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

static MIN_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub fn set_level(level: Level) {
    MIN_LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn enabled(level: Level) -> bool {
    level as u8 >= MIN_LEVEL.load(Ordering::Relaxed)
}

/// `<timestamp> <LEVEL> ` prefix, also usable for prompts without a newline.
pub fn prefix(level: Level) -> String {
    format!("{} {:<5} ", timestamp(), level.label())
}

pub fn write(level: Level, args: fmt::Arguments<'_>) {
    if !enabled(level) {
        return;
    }
    let prefix = prefix(level);
    let message = args.to_string();
    let mut text = String::new();
    // Prefix every line so multi-line messages stay greppable.
    for line in message.split('\n') {
        text.push_str(&prefix);
        text.push_str(line);
        text.push('\n');
    }
    // Write each message in one call so parallel workers do not interleave.
    let _ = if level == Level::Error {
        io::stderr().lock().write_all(text.as_bytes())
    } else {
        io::stdout().lock().write_all(text.as_bytes())
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Debug, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Info, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Warn, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Error, format_args!($($arg)*)) };
}

/// Local time as `YYYY-MM-DDTHH:MM:SS.mmm+HH:MM`.
pub fn timestamp() -> String {
    format_time(SystemTime::now())
}

/// Format `time` like [`timestamp`].
pub fn format_time(time: SystemTime) -> String {
    let now = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let (local, offset) = local_time(now.as_secs());
    let sign = if offset < 0 { '-' } else { '+' };
    let offset = offset.unsigned_abs();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}{sign}{:02}:{:02}",
        local.year,
        local.month,
        local.day,
        local.hour,
        local.minute,
        local.second,
        now.subsec_millis(),
        offset / 3600,
        offset % 3600 / 60,
    )
}

/// Calendar date and time of day.
struct LocalTime {
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
}

/// `seconds` since the Unix epoch in the local time zone, and that zone's
/// offset from UTC in seconds. Falls back to UTC.
#[cfg(unix)]
fn local_time(seconds: u64) -> (LocalTime, i64) {
    use std::sync::Once;
    static TZSET: Once = Once::new();
    unsafe extern "C" {
        fn tzset();
    }
    // SAFETY: tzset only initialises libc's timezone state; Once prevents
    // concurrent calls from this crate.
    TZSET.call_once(|| unsafe { tzset() });
    // libc deprecates time_t on musl over its width on 32-bit targets only.
    #[allow(deprecated)]
    let seconds = seconds as libc::time_t;
    // SAFETY: tm is plain old data; localtime_r writes only into it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // tm_gmtoff is a C long, which is only 32 bits wide on some targets.
    #[allow(clippy::useless_conversion)]
    let offset = if unsafe { libc::localtime_r(&seconds, &mut tm) }.is_null() {
        // SAFETY: as above.
        unsafe { libc::gmtime_r(&seconds, &mut tm) };
        0
    } else {
        tm.tm_gmtoff.into()
    };
    let local = LocalTime {
        year: tm.tm_year + 1900,
        month: tm.tm_mon + 1,
        day: tm.tm_mday,
        hour: tm.tm_hour,
        minute: tm.tm_min,
        second: tm.tm_sec,
    };
    (local, offset)
}

#[cfg(windows)]
fn local_time(seconds: u64) -> (LocalTime, i64) {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{
        FileTimeToSystemTime, SystemTimeToFileTime, SystemTimeToTzSpecificLocalTime,
    };
    // A FILETIME counts 100 ns intervals since 1601-01-01 UTC.
    const TICKS_PER_SECOND: u64 = 10_000_000;
    const FROM_1601_TO_1970: u64 = 11_644_473_600;
    let ticks = (seconds + FROM_1601_TO_1970) * TICKS_PER_SECOND;
    let utc_ticks = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    let mut local_ticks = FILETIME::default();
    // SAFETY: every pointer refers to a live local of the expected type; a
    // null time zone selects the one currently in effect.
    let converted = unsafe {
        FileTimeToSystemTime(&utc_ticks, &mut utc) != 0
            && SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) != 0
            && SystemTimeToFileTime(&local, &mut local_ticks) != 0
    };
    let (time, offset) = if converted {
        let local_ticks =
            (u64::from(local_ticks.dwHighDateTime) << 32) | u64::from(local_ticks.dwLowDateTime);
        // Both are whole seconds, so this is exact.
        let offset = (local_ticks as i64 - ticks as i64) / TICKS_PER_SECOND as i64;
        (local, offset)
    } else {
        (utc, 0)
    };
    let local = LocalTime {
        year: time.wYear.into(),
        month: time.wMonth.into(),
        day: time.wDay.into(),
        hour: time.wHour.into(),
        minute: time.wMinute.into(),
        second: time.wSecond.into(),
    };
    (local, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_has_iso_shape() {
        let ts = timestamp();
        assert_eq!(ts.len(), "2026-11-10T14:03:22.123+09:00".len(), "{ts}");
        assert_eq!(&ts[10..11], "T");
        assert!(matches!(&ts[23..24], "+" | "-"), "{ts}");
    }

    #[test]
    fn formats_the_epoch_with_its_local_offset() {
        let text = format_time(UNIX_EPOCH);
        assert_eq!(text.len(), "1970-01-01T00:00:00.000+00:00".len(), "{text}");
        // Whatever the local zone, the epoch falls on Dec 31 1969 or Jan 1 1970.
        assert!(
            text.starts_with("1970-01-01T") || text.starts_with("1969-12-31T"),
            "{text}"
        );
        assert!(text.contains(".000"), "{text}");
    }

    #[test]
    fn levels_are_ordered() {
        assert!(Level::Debug < Level::Info && Level::Warn < Level::Error);
    }
}
