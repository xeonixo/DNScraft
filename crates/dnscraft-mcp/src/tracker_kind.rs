//! Map tracker-database categories to tracking / functional / unclear.
//!
//! Mirrors `web/src/lib/querylog/view.ts` `trackerKind` so MCP and the UI
//! agree on whether a domain is primarily ads/tracking.

/// Whether a tracker category is about tracking, making a page work, or unclear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerKind {
    /// Advertising, analytics, telemetry, social tracking.
    Tracking,
    /// CDN, hosting, essential, consent, media players, etc.
    Functional,
    /// Unknown or uncategorised.
    Unclear,
}

impl TrackerKind {
    /// Stable wire label for tool output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tracking => "tracking",
            Self::Functional => "functional",
            Self::Unclear => "unclear",
        }
    }
}

const TRACKING: &[&str] = &[
    "advertising",
    "pornvertising",
    "site_analytics",
    "mobile_analytics",
    "telemetry",
    "social_media",
];

const FUNCTIONAL: &[&str] = &[
    "essential",
    "cdn",
    "hosting",
    "audio_video_player",
    "comments",
    "consent",
    "email",
    "extensions",
];

/// Classify a tracker-database category id.
pub fn tracker_kind(category: &str) -> TrackerKind {
    if TRACKING.contains(&category) {
        TrackerKind::Tracking
    } else if FUNCTIONAL.contains(&category) {
        TrackerKind::Functional
    } else {
        TrackerKind::Unclear
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_tracking_from_functional() {
        assert_eq!(tracker_kind("advertising"), TrackerKind::Tracking);
        assert_eq!(tracker_kind("site_analytics"), TrackerKind::Tracking);
        assert_eq!(tracker_kind("cdn"), TrackerKind::Functional);
        assert_eq!(tracker_kind("hosting"), TrackerKind::Functional);
        assert_eq!(tracker_kind("misc"), TrackerKind::Unclear);
        assert_eq!(tracker_kind("brand_new"), TrackerKind::Unclear);
    }
}
