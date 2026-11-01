//! Shared time formatting helpers.

use std::time::SystemTime;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// RFC 3339 UTC string for `time`, or empty on failure.
pub fn rfc3339(time: SystemTime) -> String {
    OffsetDateTime::from(time)
        .format(&Rfc3339)
        .unwrap_or_default()
}
