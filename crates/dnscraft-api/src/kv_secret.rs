//! Shared write-only SQLite kv secret helpers.

use crate::error::ControlApiError;
use crate::storage::Db;

/// Whether a non-empty value is stored under `key`.
pub(crate) async fn has(db: &Db, key: &str) -> Result<bool, ControlApiError> {
    Ok(db.kv_get(key).await?.is_some_and(|v| !v.is_empty()))
}

/// Loads a non-empty value under `key`, if any.
pub(crate) async fn get(db: &Db, key: &str) -> Result<Option<String>, ControlApiError> {
    Ok(db.kv_get(key).await?.filter(|v| !v.is_empty()))
}

/// Stores or clears a secret. `None` clears; `Some("")` is rejected with `empty`.
pub(crate) async fn set(
    db: &Db,
    key: &str,
    value: Option<&str>,
    empty: ControlApiError,
) -> Result<(), ControlApiError> {
    match value {
        None => db.kv_delete(key).await,
        Some("") => Err(empty),
        Some(v) => db.kv_set(key, v).await,
    }
}
