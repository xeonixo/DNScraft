//! Write-only UniFi API keys in SQLite kv (`unifi.api_key.{profile_id}`).

use crate::error::ControlApiError;
use crate::kv_secret;
use crate::storage::Db;

/// Kv key for one UniFi profile's API key.
pub(crate) fn api_key_kv(profile_id: &str) -> String {
    format!("unifi.api_key.{profile_id}")
}

fn empty_err() -> ControlApiError {
    ControlApiError::Module {
        code: "clients.config.invalid",
        params: Some(serde_json::json!({
            "reason": "api_key must not be empty; use null to clear"
        })),
    }
}

/// Whether a non-empty API key is stored for `profile_id`.
pub(crate) async fn has_api_key(db: &Db, profile_id: &str) -> Result<bool, ControlApiError> {
    kv_secret::has(db, &api_key_kv(profile_id)).await
}

/// Stores or clears the API key for `profile_id`.
///
/// `None` clears the key; `Some("")` is rejected.
pub(crate) async fn set_api_key(
    db: &Db,
    profile_id: &str,
    api_key: Option<&str>,
) -> Result<(), ControlApiError> {
    kv_secret::set(db, &api_key_kv(profile_id), api_key, empty_err()).await
}

/// Loads the stored API key, if any (cluster `SecretPush` and the clients applier).
pub async fn get_api_key(db: &Db, profile_id: &str) -> Result<Option<String>, ControlApiError> {
    kv_secret::get(db, &api_key_kv(profile_id)).await
}
