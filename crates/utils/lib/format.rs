//! Small display formatters shared across the workspace.
//!
//! Lives in `microsandbox-utils` so the CLI (`crates/cli`), the metrics
//! collector (`crates/metrics-collector`), and anything else that needs
//! human-readable byte counts or durations can use a single
//! implementation. Output style is fixed (binary units for bytes,
//! `<mins>m<secs>s` for durations) so output across surfaces stays
//! consistent.

use std::time::Duration;

/// Format a byte count with binary units (`B`, `KiB`, `MiB`, `GiB`,
/// `TiB`). Values below `1 KiB` are rendered as the exact byte count;
/// everything larger uses one decimal.
///
/// ```
/// use microsandbox_utils::format::format_bytes;
/// assert_eq!(format_bytes(0), "0 B");
/// assert_eq!(format_bytes(1023), "1023 B");
/// assert_eq!(format_bytes(1024), "1.0 KiB");
/// assert_eq!(format_bytes(14_628_864), "14.0 MiB");
/// ```
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Format a duration for display. Sub-minute values are rendered as
/// `<seconds.1>s`; longer ones as `<mins>m<remaining-secs>s`.
///
/// ```
/// use std::time::Duration;
/// use microsandbox_utils::format::format_duration;
/// assert_eq!(format_duration(Duration::from_secs_f64(12.3)), "12.3s");
/// assert_eq!(format_duration(Duration::from_secs(125)), "2m5s");
/// ```
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        let mins = secs as u64 / 60;
        let remaining = secs as u64 % 60;
        format!("{mins}m{remaining}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_renders_each_unit_boundary() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 1024), "1.0 TiB");
    }

    #[test]
    fn bytes_uses_one_decimal_above_one_kib() {
        assert_eq!(format_bytes(14 * 1024 * 1024), "14.0 MiB");
        assert_eq!(format_bytes(14_628_864), "14.0 MiB");
    }

    #[test]
    fn duration_under_minute_uses_seconds() {
        assert_eq!(format_duration(Duration::from_secs_f64(0.0)), "0.0s");
        assert_eq!(format_duration(Duration::from_secs_f64(59.9)), "59.9s");
    }

    #[test]
    fn duration_over_minute_uses_mins_secs() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1m0s");
        assert_eq!(format_duration(Duration::from_secs(125)), "2m5s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "61m1s");
    }
}
