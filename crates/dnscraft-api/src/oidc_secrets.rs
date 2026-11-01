//! Write-only OIDC client secret in SQLite kv (`auth.oidc.client_secret`).
//!
//! The secret never appears in the versioned config snapshot or in GET responses.

use crate::error::ControlApiError;
use crate::kv_secret;
use crate::storage::Db;

const KV_KEY: &str = "auth.oidc.client_secret";

fn empty_err() -> ControlApiError {
    ControlApiError::Module {
        code: "control_api.auth.oidc",
        params: Some(serde_json::json!({
            "reason": "client_secret must not be empty; use null to clear"
        })),
    }
}

/// Whether a non-empty OIDC client secret is stored in kv.
pub(crate) async fn has_client_secret(db: &Db) -> Result<bool, ControlApiError> {
    kv_secret::has(db, KV_KEY).await
}

/// Stores or clears the OIDC client secret.
///
/// `None` clears; `Some("")` is rejected.
pub(crate) async fn set_client_secret(
    db: &Db,
    secret: Option<&str>,
) -> Result<(), ControlApiError> {
    kv_secret::set(db, KV_KEY, secret, empty_err()).await
}

/// Loads the stored secret, if any (runtime apply / restart).
pub(crate) async fn get_client_secret(db: &Db) -> Result<Option<String>, ControlApiError> {
    kv_secret::get(db, KV_KEY).await
}
