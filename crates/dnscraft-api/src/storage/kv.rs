//! Key-value store (`kv` table) over the shared connection.

use rusqlite::{Connection, OptionalExtension, params};

use super::{Db, db_err};
use crate::error::ControlApiError;

/// Looks up the value for `key`, or `None` when the key is absent.
pub(crate) fn kv_get(conn: &Connection, key: &str) -> Result<Option<String>, ControlApiError> {
    conn.prepare_cached("SELECT value FROM kv WHERE key = ?1")
        .map_err(db_err)?
        .query_row(params![key], |row| row.get(0))
        .optional()
        .map_err(db_err)
}

/// Inserts or replaces the value for `key`.
pub(crate) fn kv_set(conn: &Connection, key: &str, value: &str) -> Result<(), ControlApiError> {
    conn.prepare_cached(
        "INSERT INTO kv (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .map_err(db_err)?
    .execute(params![key, value])
    .map_err(db_err)?;
    Ok(())
}

/// Removes `key`, if present.
fn kv_delete(conn: &Connection, key: &str) -> Result<(), ControlApiError> {
    conn.prepare_cached("DELETE FROM kv WHERE key = ?1")
        .map_err(db_err)?
        .execute(params![key])
        .map_err(db_err)?;
    Ok(())
}

impl Db {
    /// Reads a key from the `kv` table.
    pub async fn kv_get(&self, key: &str) -> Result<Option<String>, ControlApiError> {
        let key = key.to_owned();
        self.with_read_conn(move |conn| kv_get(conn, &key)).await
    }

    /// Writes (or replaces) a key in the `kv` table.
    pub async fn kv_set(&self, key: &str, value: &str) -> Result<(), ControlApiError> {
        let key = key.to_owned();
        let value = value.to_owned();
        self.with_conn(move |conn| kv_set(conn, &key, &value)).await
    }

    /// Deletes a key from the `kv` table.
    pub async fn kv_delete(&self, key: &str) -> Result<(), ControlApiError> {
        let key = key.to_owned();
        self.with_conn(move |conn| kv_delete(conn, &key)).await
    }
}
