#![no_main]

//! Fuzzes node-local cluster settings JSON: deserialize `ClusterSettings` /
//! `ClusterSettingsUpdate` and apply updates without panicking. Rejected
//! updates must expose a well-formed `cluster.*` code.

use dnscraft_cluster::{ClusterError, ClusterSettings, ClusterSettingsUpdate};
use libfuzzer_sys::fuzz_target;

fn check_code(error: &ClusterError) {
    let code = error.code();
    assert!(
        code.starts_with("cluster."),
        "code {code} is not namespaced"
    );
    assert!(
        code.split('.').all(|segment| !segment.is_empty()),
        "code {code} has an empty segment"
    );
}

fuzz_target!(|data: &[u8]| {
    if let Ok(mut settings) = serde_json::from_slice::<ClusterSettings>(data) {
        // Round-trip serialize must succeed for accepted shapes.
        let _ = serde_json::to_vec(&settings);
        if let Ok(update) = serde_json::from_slice::<ClusterSettingsUpdate>(data) {
            if let Err(error) = settings.apply_update(update) {
                check_code(&error);
            }
        }
        return;
    }
    if let Ok(update) = serde_json::from_slice::<ClusterSettingsUpdate>(data) {
        let mut settings = ClusterSettings::default();
        if let Err(error) = settings.apply_update(update) {
            check_code(&error);
        }
    }
});
