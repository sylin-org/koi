//! Pure version arithmetic, shared by `build.rs` (via `#[path]`) and this
//! crate's tests. No I/O: the build script supplies git facts and the clock.

/// The release core of a Cargo version: `1.0.0-dev.0` and `1.0.0+meta` both
/// become `1.0.0`. The pre-release names the process, not the product.
pub fn core_version(cargo_version: &str) -> &str {
    cargo_version
        .split(['-', '+'])
        .next()
        .unwrap_or(cargo_version)
}

/// `MAJOR.MINOR.PATCH.N`, where `N` counts the commits in the build's history.
pub fn product_version(core: &str, commits: u64) -> String {
    format!("{core}.{commits}")
}

/// Windows VERSIONINFO packs four 16-bit numbers into a u64. Parts beyond
/// 65535 are clamped; missing parts are zero.
pub fn pack_windows_version(version: &str) -> u64 {
    let mut parts = version
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0).min(0xFFFF));
    let mut packed = 0u64;
    for _ in 0..4 {
        packed = (packed << 16) | parts.next().unwrap_or(0);
    }
    packed
}

/// Seconds since the Unix epoch as RFC 3339 UTC, without a date library.
/// Days to civil date: Howard Hinnant's algorithm.
pub fn utc_rfc3339(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_process_never_reaches_the_version() {
        assert_eq!(core_version("1.0.0-dev.0"), "1.0.0");
        assert_eq!(core_version("1.2.3+build.5"), "1.2.3");
        assert_eq!(core_version("1.0.0-rc.2"), "1.0.0");
        assert_eq!(core_version("1.0.0"), "1.0.0");
        assert_eq!(product_version("1.0.0", 2147), "1.0.0.2147");
    }

    #[test]
    fn windows_versions_pack_four_parts() {
        assert_eq!(pack_windows_version("1.0.0.2147"), 0x0001_0000_0000_0863);
        assert_eq!(pack_windows_version("1.2.3"), 0x0001_0002_0003_0000);
        assert_eq!(pack_windows_version("1.0.0.70000"), 0x0001_0000_0000_FFFF);
    }

    #[test]
    fn epoch_seconds_format_as_utc() {
        assert_eq!(utc_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
    }
}
