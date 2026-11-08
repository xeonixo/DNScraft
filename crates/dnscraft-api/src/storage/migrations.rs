//! SQLite schema migrations (idempotent, versioned via `PRAGMA user_version`).

use rusqlite::Connection;

use super::db_err;
use crate::error::ControlApiError;

/// Ordered migrations; index `i` is schema version `i + 1`.
pub(crate) const MIGRATIONS: &[&str] = &[
    // v1: core schema + reserved tables (refined in later tasks).
    "CREATE TABLE IF NOT EXISTS kv (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS config_versions (
        version    INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot   TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        time           INTEGER NOT NULL,
        node_id        TEXT NOT NULL,
        actor_id       TEXT NOT NULL,
        actor_type     TEXT NOT NULL,
        action         TEXT NOT NULL,
        object_type    TEXT NOT NULL,
        object_id      TEXT NOT NULL,
        config_version INTEGER,
        before_digest  TEXT,
        after_digest   TEXT,
        before         TEXT,
        after          TEXT,
        result         TEXT NOT NULL,
        error_code     TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id_hash     TEXT PRIMARY KEY,
        actor_id    TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        last_active INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tokens (
        id_hash    TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        scope      TEXT NOT NULL,
        actor_id   TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS query_log (
        id         TEXT PRIMARY KEY,
        time       INTEGER NOT NULL,
        node_id    TEXT NOT NULL,
        source_ip  TEXT NOT NULL,
        query_name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS stats_hourly (
        hour          INTEGER NOT NULL,
        profile_id    TEXT NOT NULL,
        protocol      TEXT NOT NULL,
        answer_source TEXT NOT NULL,
        query_count   INTEGER NOT NULL,
        PRIMARY KEY (hour, profile_id, protocol, answer_source)
    );
    CREATE TABLE IF NOT EXISTS stats_daily (
        day           INTEGER NOT NULL,
        profile_id    TEXT NOT NULL,
        protocol      TEXT NOT NULL,
        answer_source TEXT NOT NULL,
        query_count   INTEGER NOT NULL,
        PRIMARY KEY (day, profile_id, protocol, answer_source)
    );",
    // v2: audit log is append-only — UPDATE/DELETE are rejected at the SQL
    // layer so no code path (including retention, which needs its own explicit
    // migration) can silently mutate recorded history.
    "CREATE TRIGGER audit_log_no_update
        BEFORE UPDATE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only');
    END;
    CREATE TRIGGER audit_log_no_delete
        BEFORE DELETE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only');
    END;",
    // v3: cookie sessions carry a viewer/admin role (A6).
    "ALTER TABLE sessions ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer';",
    // v4: local break-glass accounts (Argon2id PHC hashes) and per-account
    // lockout state (A8). No plaintext password is ever stored.
    "CREATE TABLE IF NOT EXISTS local_accounts (
        username        TEXT PRIMARY KEY,
        password_hash   TEXT NOT NULL,
        role            TEXT NOT NULL,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        window_started  INTEGER,
        locked_until    INTEGER
    );",
    // v5: query-log consumer columns (A12). `time` is unix microseconds for
    // sub-second ordering; the denormalised columns back filtering/ordering,
    // while `record` holds the full JSON record (including the policy decision
    // record for "why blocked?"). Old rows keep safe defaults.
    "ALTER TABLE query_log ADD COLUMN listener_id TEXT NOT NULL DEFAULT '';
    ALTER TABLE query_log ADD COLUMN protocol TEXT NOT NULL DEFAULT '';
    ALTER TABLE query_log ADD COLUMN source_ip_truncated INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE query_log ADD COLUMN client_id TEXT;
    ALTER TABLE query_log ADD COLUMN client_name TEXT;
    ALTER TABLE query_log ADD COLUMN query_type TEXT NOT NULL DEFAULT '';
    ALTER TABLE query_log ADD COLUMN query_class TEXT NOT NULL DEFAULT '';
    ALTER TABLE query_log ADD COLUMN view_id TEXT NOT NULL DEFAULT '';
    ALTER TABLE query_log ADD COLUMN profile_id TEXT NOT NULL DEFAULT '';
    ALTER TABLE query_log ADD COLUMN status TEXT NOT NULL DEFAULT '';
    ALTER TABLE query_log ADD COLUMN answer_source TEXT NOT NULL DEFAULT '';
    ALTER TABLE query_log ADD COLUMN rcode TEXT NOT NULL DEFAULT '';
    ALTER TABLE query_log ADD COLUMN record TEXT NOT NULL DEFAULT '{}';
    CREATE INDEX IF NOT EXISTS query_log_time_idx ON query_log(time);
    CREATE INDEX IF NOT EXISTS query_log_client_idx ON query_log(client_id);
    CREATE INDEX IF NOT EXISTS query_log_status_idx ON query_log(status);",
    // v6: cluster log/stat aggregation (CL4/CL5). `seq` is the per-node
    // outbox position allocated in the insert transaction; the unique index
    // enforces the spec's `(node_id, seq)` dedupe key. Rollups gain the
    // `node_id` dimension, which rebuilds both tables because SQLite cannot
    // alter a primary key; existing rows are attributed to the empty node id.
    "ALTER TABLE query_log ADD COLUMN seq INTEGER;
    CREATE UNIQUE INDEX IF NOT EXISTS query_log_node_seq_idx ON query_log(node_id, seq);
    CREATE TABLE stats_hourly_v6 (
        hour          INTEGER NOT NULL,
        node_id       TEXT NOT NULL,
        profile_id    TEXT NOT NULL,
        protocol      TEXT NOT NULL,
        answer_source TEXT NOT NULL,
        query_count   INTEGER NOT NULL,
        PRIMARY KEY (hour, node_id, profile_id, protocol, answer_source)
    );
    INSERT INTO stats_hourly_v6 (hour, node_id, profile_id, protocol, answer_source, query_count)
        SELECT hour, '', profile_id, protocol, answer_source, query_count FROM stats_hourly;
    DROP TABLE stats_hourly;
    ALTER TABLE stats_hourly_v6 RENAME TO stats_hourly;
    CREATE TABLE stats_daily_v6 (
        day           INTEGER NOT NULL,
        node_id       TEXT NOT NULL,
        profile_id    TEXT NOT NULL,
        protocol      TEXT NOT NULL,
        answer_source TEXT NOT NULL,
        query_count   INTEGER NOT NULL,
        PRIMARY KEY (day, node_id, profile_id, protocol, answer_source)
    );
    INSERT INTO stats_daily_v6 (day, node_id, profile_id, protocol, answer_source, query_count)
        SELECT day, '', profile_id, protocol, answer_source, query_count FROM stats_daily;
    DROP TABLE stats_daily;
    ALTER TABLE stats_daily_v6 RENAME TO stats_daily;",
    // v7: cookie sessions record the auth epoch they were created under, so a
    // bumped epoch (global sign-out, revocation) invalidates existing sessions
    // during validation. Existing rows default to epoch 0.
    "ALTER TABLE sessions ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;",
    // v8: query-log dedupe is per node, not global. The original table used a
    // global `id` PRIMARY KEY, which made a record id collide across nodes and
    // silently drop one node's row; rebuild with `(node_id, id)` as the key and
    // expose the documented `(node_id, id)` dedupe index. Existing indexes are
    // recreated because rebuilding the table drops them.
    "CREATE TABLE query_log_v8 (
        id         TEXT NOT NULL,
        time       INTEGER NOT NULL,
        node_id    TEXT NOT NULL,
        source_ip  TEXT NOT NULL,
        query_name TEXT NOT NULL,
        listener_id TEXT NOT NULL DEFAULT '',
        protocol TEXT NOT NULL DEFAULT '',
        source_ip_truncated INTEGER NOT NULL DEFAULT 0,
        client_id TEXT,
        client_name TEXT,
        query_type TEXT NOT NULL DEFAULT '',
        query_class TEXT NOT NULL DEFAULT '',
        view_id TEXT NOT NULL DEFAULT '',
        profile_id TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        answer_source TEXT NOT NULL DEFAULT '',
        rcode TEXT NOT NULL DEFAULT '',
        record TEXT NOT NULL DEFAULT '{}',
        seq INTEGER,
        PRIMARY KEY (node_id, id)
    );
    INSERT INTO query_log_v8 (
        id, time, node_id, source_ip, query_name, listener_id, protocol,
        source_ip_truncated, client_id, client_name, query_type, query_class,
        view_id, profile_id, status, answer_source, rcode, record, seq
    )
        SELECT
            id, time, node_id, source_ip, query_name, listener_id, protocol,
            source_ip_truncated, client_id, client_name, query_type, query_class,
            view_id, profile_id, status, answer_source, rcode, record, seq
        FROM query_log;
    DROP TABLE query_log;
    ALTER TABLE query_log_v8 RENAME TO query_log;
    CREATE INDEX IF NOT EXISTS query_log_time_idx ON query_log(time);
    CREATE INDEX IF NOT EXISTS query_log_client_idx ON query_log(client_id);
    CREATE INDEX IF NOT EXISTS query_log_status_idx ON query_log(status);
    CREATE UNIQUE INDEX IF NOT EXISTS query_log_node_seq_idx ON query_log(node_id, seq);
    CREATE UNIQUE INDEX IF NOT EXISTS query_log_node_id_idx ON query_log(node_id, id);",
    // v9: session list metadata (WX8): a truncated IP and a parsed browser label.
    // The raw user agent is never stored.
    "ALTER TABLE sessions ADD COLUMN ip TEXT;
     ALTER TABLE sessions ADD COLUMN client_label TEXT;",
    // v10: stable device key per query-log row (the directory client id). Old
    // rows keep NULL and fall back to client id / name / address when grouped.
    "ALTER TABLE query_log ADD COLUMN device_id TEXT;
     CREATE INDEX IF NOT EXISTS query_log_device_idx ON query_log(device_id);",
    // v11: compact on-disk query-log encoding.
    // - Closed enums (status/protocol/answer_source) and DNS type/class/rcode
    //   become INTEGER columns (legacy TEXT cells still readable via affinity).
    // - `cached` flags resolve-from-cache hits without keeping `steps` on every row.
    // - `query_log_detail` holds steps/selection/timings for block/error rows only.
    // Existing `record` JSON is left as-is; new writes store a slim blob and the
    // reader hydrates wire fields from columns (+ detail on demand).
    "CREATE TABLE query_log_v11 (
        id         TEXT NOT NULL,
        time       INTEGER NOT NULL,
        node_id    TEXT NOT NULL,
        source_ip  TEXT NOT NULL,
        query_name TEXT NOT NULL,
        listener_id TEXT NOT NULL DEFAULT '',
        protocol INTEGER NOT NULL DEFAULT 0,
        source_ip_truncated INTEGER NOT NULL DEFAULT 0,
        client_id TEXT,
        client_name TEXT,
        query_type INTEGER NOT NULL DEFAULT 0,
        query_class INTEGER NOT NULL DEFAULT 1,
        view_id TEXT NOT NULL DEFAULT '',
        profile_id TEXT NOT NULL DEFAULT '',
        status INTEGER NOT NULL DEFAULT 0,
        answer_source INTEGER NOT NULL DEFAULT 0,
        rcode INTEGER NOT NULL DEFAULT 0,
        record TEXT NOT NULL DEFAULT '{}',
        seq INTEGER,
        device_id TEXT,
        cached INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (node_id, id)
    );
    INSERT INTO query_log_v11 (
        id, time, node_id, source_ip, query_name, listener_id, protocol,
        source_ip_truncated, client_id, client_name, query_type, query_class,
        view_id, profile_id, status, answer_source, rcode, record, seq,
        device_id, cached
    )
    SELECT
        id, time, node_id, source_ip, query_name, listener_id,
        CASE protocol
            WHEN 'udp53' THEN 1 WHEN 'tcp53' THEN 2 WHEN 'dot' THEN 3
            WHEN 'doh' THEN 4 WHEN 'doq' THEN 5
            ELSE COALESCE(protocol, 0)
        END,
        source_ip_truncated, client_id, client_name,
        CASE query_type
            WHEN 'A' THEN 1 WHEN 'NS' THEN 2 WHEN 'CNAME' THEN 5 WHEN 'SOA' THEN 6
            WHEN 'PTR' THEN 12 WHEN 'MX' THEN 15 WHEN 'TXT' THEN 16 WHEN 'AAAA' THEN 28
            WHEN 'SRV' THEN 33 WHEN 'DNAME' THEN 39 WHEN 'OPT' THEN 41 WHEN 'DS' THEN 43
            WHEN 'RRSIG' THEN 46 WHEN 'NSEC' THEN 47 WHEN 'DNSKEY' THEN 48
            WHEN 'NSEC3' THEN 50 WHEN 'NSEC3PARAM' THEN 51 WHEN 'SVCB' THEN 64
            WHEN 'HTTPS' THEN 65 WHEN 'ANY' THEN 255 WHEN 'CAA' THEN 257
            ELSE COALESCE(query_type, 0)
        END,
        CASE query_class
            WHEN 'IN' THEN 1 WHEN 'CH' THEN 3 WHEN 'NONE' THEN 254 WHEN 'ANY' THEN 255
            ELSE COALESCE(query_class, 1)
        END,
        view_id, profile_id,
        CASE status
            WHEN 'allowed' THEN 1 WHEN 'blocked' THEN 2 WHEN 'servfail' THEN 3
            WHEN 'dnssec_bogus' THEN 4
            ELSE COALESCE(status, 0)
        END,
        CASE answer_source
            WHEN 'resolver' THEN 1 WHEN 'synth_any' THEN 2 WHEN 'resolve_error' THEN 3
            WHEN 'local_view' THEN 4 WHEN 'local_client' THEN 5 WHEN 'bypass' THEN 6
            WHEN 'filter_block' THEN 7 WHEN 'listener_ddr' THEN 8
            ELSE COALESCE(answer_source, 0)
        END,
        CASE rcode
            WHEN 'NOERROR' THEN 0 WHEN 'FORMERR' THEN 1 WHEN 'SERVFAIL' THEN 2
            WHEN 'NXDOMAIN' THEN 3 WHEN 'NOTIMP' THEN 4 WHEN 'REFUSED' THEN 5
            WHEN 'YXDOMAIN' THEN 6 WHEN 'YXRRSET' THEN 7 WHEN 'NXRRSET' THEN 8
            WHEN 'NOTAUTH' THEN 9 WHEN 'NOTZONE' THEN 10
            ELSE COALESCE(rcode, 0)
        END,
        record, seq, device_id, 0
    FROM query_log;
    DROP TABLE query_log;
    ALTER TABLE query_log_v11 RENAME TO query_log;
    CREATE INDEX IF NOT EXISTS query_log_time_idx ON query_log(time);
    CREATE INDEX IF NOT EXISTS query_log_client_idx ON query_log(client_id);
    CREATE INDEX IF NOT EXISTS query_log_status_idx ON query_log(status);
    CREATE UNIQUE INDEX IF NOT EXISTS query_log_node_seq_idx ON query_log(node_id, seq);
    CREATE UNIQUE INDEX IF NOT EXISTS query_log_node_id_idx ON query_log(node_id, id);
    CREATE INDEX IF NOT EXISTS query_log_device_idx ON query_log(device_id);
    CREATE TABLE IF NOT EXISTS query_log_detail (
        node_id TEXT NOT NULL,
        id      TEXT NOT NULL,
        detail  TEXT NOT NULL,
        PRIMARY KEY (node_id, id)
    );",
    // v12: v11 made the primary key (node_id, id), so lookups by `id` alone
    // (live-stream hydration, record detail) lost their index and scanned the table.
    "CREATE INDEX IF NOT EXISTS query_log_id_idx ON query_log(id);",
    // v13: move the bulky `record` JSON out of the hot `query_log` table into
    // `query_log_record`, so scans over query_name/time/status touch narrow pages.
    // The table is rebuilt (not DROP COLUMN) so its pages end up compact.
    // Perf: rows are copied in rowid order and the (node_id, id) uniqueness is
    // enforced by the unique index built afterwards (sorted build). A PRIMARY KEY
    // on random UUIDs filled in insertion order thrashes the page cache for hours.
    // NOT INDEXED + the `|| ''` sort keys force a sequential table scan and an
    // external sort: walking an index in key order does one random read per row,
    // which is hours on a rotating disk (a 1.5M-row table on a 5400 rpm HDD).
    "CREATE TABLE query_log_record (
        node_id TEXT NOT NULL,
        id      TEXT NOT NULL,
        record  TEXT NOT NULL,
        PRIMARY KEY (node_id, id)
    ) WITHOUT ROWID;
    INSERT INTO query_log_record (node_id, id, record)
        SELECT node_id, id, record FROM query_log NOT INDEXED WHERE record <> '{}'
        ORDER BY node_id || '', id || '';
    CREATE TABLE query_log_v13 (
        id         TEXT NOT NULL,
        time       INTEGER NOT NULL,
        node_id    TEXT NOT NULL,
        source_ip  TEXT NOT NULL,
        query_name TEXT NOT NULL,
        listener_id TEXT NOT NULL DEFAULT '',
        protocol INTEGER NOT NULL DEFAULT 0,
        source_ip_truncated INTEGER NOT NULL DEFAULT 0,
        client_id TEXT,
        client_name TEXT,
        query_type INTEGER NOT NULL DEFAULT 0,
        query_class INTEGER NOT NULL DEFAULT 1,
        view_id TEXT NOT NULL DEFAULT '',
        profile_id TEXT NOT NULL DEFAULT '',
        status INTEGER NOT NULL DEFAULT 0,
        answer_source INTEGER NOT NULL DEFAULT 0,
        rcode INTEGER NOT NULL DEFAULT 0,
        seq INTEGER,
        device_id TEXT,
        cached INTEGER NOT NULL DEFAULT 0
    );
    INSERT INTO query_log_v13 (
        id, time, node_id, source_ip, query_name, listener_id, protocol,
        source_ip_truncated, client_id, client_name, query_type, query_class,
        view_id, profile_id, status, answer_source, rcode, seq, device_id, cached
    )
    SELECT
        id, time, node_id, source_ip, query_name, listener_id, protocol,
        source_ip_truncated, client_id, client_name, query_type, query_class,
        view_id, profile_id, status, answer_source, rcode, seq, device_id, cached
    FROM query_log NOT INDEXED;
    DROP TABLE query_log;
    ALTER TABLE query_log_v13 RENAME TO query_log;
    CREATE INDEX query_log_time_idx ON query_log(time);
    CREATE INDEX query_log_client_idx ON query_log(client_id);
    CREATE INDEX query_log_status_idx ON query_log(status);
    CREATE UNIQUE INDEX query_log_node_seq_idx ON query_log(node_id, seq);
    CREATE UNIQUE INDEX query_log_node_id_idx ON query_log(node_id, id);
    CREATE INDEX query_log_device_idx ON query_log(device_id);
    CREATE INDEX query_log_id_idx ON query_log(id);",
];

/// Applies every migration newer than the recorded version, then records it.
pub(crate) fn migrate(conn: &mut Connection) -> Result<(), ControlApiError> {
    // Large rebuilds (v13) are page-cache bound; the default 2 MB cache makes them crawl.
    conn.pragma_update(None, "cache_size", -262_144).map_err(db_err)?;
    let result = migrate_inner(conn);
    // Restore the default so steady-state memory use is unchanged.
    let _ = conn.pragma_update(None, "cache_size", -2_000);
    result
}

fn migrate_inner(conn: &mut Connection) -> Result<(), ControlApiError> {
    let tx = conn.transaction().map_err(db_err)?;
    let current: i64 = tx
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_err)?;
    for (index, sql) in MIGRATIONS.iter().enumerate() {
        let target = (index + 1) as i64;
        if current < target {
            tx.execute_batch(sql).map_err(db_err)?;
            tx.pragma_update(None, "user_version", target)
                .map_err(db_err)?;
        }
    }
    tx.commit().map_err(db_err)?;
    Ok(())
}

/// Reads the current `PRAGMA user_version`.
pub(crate) fn schema_version(conn: &Connection) -> Result<i64, ControlApiError> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_err)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn device_id_migration_adds_column_and_index() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 13);

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(query_log)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(columns.iter().any(|name| name == "device_id"));
        assert!(columns.iter().any(|name| name == "cached"));

        let index: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND name = 'query_log_device_idx'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index, 1);

        let detail: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'query_log_detail'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(detail, 1);
    }

    #[test]
    fn audit_log_rejects_update_and_delete_after_v2() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 13);

        conn.execute(
            "INSERT INTO audit_log (
                time, node_id, actor_id, actor_type, action, object_type, object_id, result
             ) VALUES (1, 'n', 'a', 'user', 'config.write', 'config', 'cfg', 'ok')",
            [],
        )
        .unwrap();

        // Append-only: UPDATE and DELETE are rejected by the v2 triggers.
        assert!(
            conn.execute("UPDATE audit_log SET action = 'x' WHERE id = 1", [])
                .is_err()
        );
        assert!(
            conn.execute("DELETE FROM audit_log WHERE id = 1", [])
                .is_err()
        );

        // INSERT and SELECT still work; the single row is intact.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
