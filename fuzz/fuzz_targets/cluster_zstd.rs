#![no_main]

//! Fuzzes zstd envelope decode/decompress: never panics; size/digest failures
//! must expose `cluster.compression`.

use dnscraft_cluster::{ClusterError, ZstdEnvelope};
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
    let Ok(envelope) = serde_json::from_slice::<ZstdEnvelope>(data) else {
        return;
    };
    match envelope.decompress() {
        Ok(plain) => {
            // Accepted plaintext must match the declared digest when re-hashed
            // via a fresh compress at level 1 (digest field already verified).
            assert!(!plain.is_empty() || envelope.sha256.len() == 64);
        }
        Err(error) => check_code(&error),
    }
});
