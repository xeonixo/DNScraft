//! On-disk layout for SQLite files under `data_dir`.
//!
//! Databases live in `data_dir/db/` so operators can bind-mount or symlink that
//! subdirectory onto another volume without moving TLS material, filter bodies,
//! or backups. A one-shot startup migrate moves legacy root-level `*.db` files
//! (plus SQLite sidecars) into the new location.

use std::io;
use std::path::{Path, PathBuf};

/// Subdirectory of `data_dir` that holds SQLite databases.
pub const DB_SUBDIR: &str = "db";

/// Primary control-api database (config, audit, query log, rollups, auth).
pub const CONFIG_DB_FILE: &str = "dnscraft.db";

/// Cluster registry / offline-write / relay-cache database.
pub const CLUSTER_DB_FILE: &str = "cluster.db";

/// `data_dir/db`.
pub fn database_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(DB_SUBDIR)
}

/// `data_dir/db/dnscraft.db`.
pub fn config_db_path(data_dir: &Path) -> PathBuf {
    database_dir(data_dir).join(CONFIG_DB_FILE)
}

/// `data_dir/db/cluster.db`.
pub fn cluster_db_path(data_dir: &Path) -> PathBuf {
    database_dir(data_dir).join(CLUSTER_DB_FILE)
}

/// Ensures `data_dir/db` exists and migrates legacy root-level SQLite files.
///
/// Safe to call on every boot: no-ops when the destination already exists or
/// there is nothing to move. Cross-device destinations (bind-mounted `db/`)
/// fall back to copy + remove when `rename` returns [`io::ErrorKind::CrossesDevices`].
pub fn ensure_database_layout(data_dir: &Path) -> io::Result<()> {
    let dest_dir = database_dir(data_dir);
    std::fs::create_dir_all(&dest_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest_dir, std::fs::Permissions::from_mode(0o700));
    }
    for name in [CONFIG_DB_FILE, CLUSTER_DB_FILE] {
        migrate_sqlite_file(&data_dir.join(name), &dest_dir.join(name))?;
    }
    Ok(())
}

fn migrate_sqlite_file(src_base: &Path, dest_base: &Path) -> io::Result<()> {
    if dest_base.exists() || !src_base.exists() {
        return Ok(());
    }
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let from = sidecar(src_base, suffix);
        if !from.exists() {
            continue;
        }
        let to = sidecar(dest_base, suffix);
        move_file(&from, &to)?;
    }
    Ok(())
}

fn sidecar(base: &Path, suffix: &str) -> PathBuf {
    if suffix.is_empty() {
        return base.to_path_buf();
    }
    let mut path = base.as_os_str().to_owned();
    path.push(suffix);
    PathBuf::from(path)
}

fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
            std::fs::copy(from, to)?;
            std::fs::remove_file(from)?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn migrate_moves_main_and_sidecars() {
        let root = std::env::temp_dir().join(format!(
            "dnscraft-db-layout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("dnscraft.db"), b"main").unwrap();
        std::fs::write(root.join("dnscraft.db-wal"), b"wal").unwrap();
        std::fs::write(root.join("cluster.db"), b"cluster").unwrap();

        ensure_database_layout(&root).unwrap();

        assert!(!root.join("dnscraft.db").exists());
        assert!(!root.join("dnscraft.db-wal").exists());
        assert!(!root.join("cluster.db").exists());
        assert_eq!(
            std::fs::read(root.join("db/dnscraft.db")).unwrap(),
            b"main"
        );
        assert_eq!(
            std::fs::read(root.join("db/dnscraft.db-wal")).unwrap(),
            b"wal"
        );
        assert_eq!(
            std::fs::read(root.join("db/cluster.db")).unwrap(),
            b"cluster"
        );

        // Second boot is a no-op even if a stray root file appears later.
        std::fs::write(root.join("dnscraft.db"), b"stale").unwrap();
        ensure_database_layout(&root).unwrap();
        assert_eq!(
            std::fs::read(root.join("db/dnscraft.db")).unwrap(),
            b"main"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
