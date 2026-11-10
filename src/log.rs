//! Minimal leveled logger: every line is `<local timestamp> <LEVEL> <message>`.
//! ERROR goes to stderr, everything else to stdout.

use std::fmt;
use std::io::{self, Write};
use std::sync::Once;
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
    static TZSET: Once = Once::new();
    unsafe extern "C" {
        fn tzset();
    }
    // SAFETY: tzset only initialises libc's timezone state; Once prevents
    // concurrent calls from this crate.
    TZSET.call_once(|| unsafe { tzset() });
    let now = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = now.as_secs() as libc::time_t;
    // SAFETY: tm is plain old data; localtime_r writes only into it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let (tm, offset) = if unsafe { libc::localtime_r(&seconds, &mut tm) }.is_null() {
        // SAFETY: as above.
        unsafe { libc::gmtime_r(&seconds, &mut tm) };
        (tm, 0)
    } else {
        let offset = tm.tm_gmtoff;
        (tm, offset)
    };
    let sign = if offset < 0 { '-' } else { '+' };
    let offset = offset.unsigned_abs();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}{sign}{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        now.subsec_millis(),
        offset / 3600,
        offset % 3600 / 60,
    )
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
    fn levels_are_ordered() {
        assert!(Level::Debug < Level::Info && Level::Warn < Level::Error);
    }
}
