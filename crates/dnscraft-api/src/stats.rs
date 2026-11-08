//! Statistics rollups, dashboard aggregations and query-log export (A13).
//!
//! ## Rollups
//!
//! [`QueryLog::run_rollup`] folds the raw query log into the `stats_hourly`
//! and `stats_daily` tables (one row per bucket, profile, protocol and answer
//! origin) and prunes rollups older than [`ROLLUP_RETENTION_DAYS`]. It is an
//! explicit, idempotent pass driven by the injected clock, so callers (the
//! binary's scheduler, or a `ManualClock` test) decide when it runs. Raw rows
//! stay the source for ad-hoc filtering (retention default 30 days); rollups
//! keep dashboard counters for up to a year.
//!
//! ## Endpoint aggregations
//!
//! [`QueryLog::stats_overview`] prefers `stats_hourly` for completed hours and
//! only scans the raw log for the still-open hour (plus a full raw fallback
//! before the first rollup pass). Top-domain / top-client endpoints still read
//! the raw log inside the requested window. Cardinality is capped per the
//! spec: [`TOP_CLIENTS_MAX`] and [`TOP_DOMAINS_MAX`].
//!
//! ## Export
//!
//! [`export_body`] streams the stored records for one [`QueryLogFilter`] page
//! by page, so a large export never sits in memory as a whole. NDJSON is the
//! primary format (one stored record per line); CSV is a convenience projection
//! of the documented record schema.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::Body;
use hyper::body::{Body as HttpBody, Bytes, Frame};
use rusqlite::params;
use serde::Serialize;
use serde_json::Value as Json;
use tokio::sync::mpsc;

use crate::query_log_codec::{
    StatusCode, rcode_to_str, read_answer_source, read_protocol, read_rcode, read_status,
};

use crate::error::ControlApiError;
use crate::query_log::{QueryLog, QueryLogFilter};
use crate::storage::{Db, db_err};

/// Maximum `top_clients` entries returned per window.
pub const TOP_CLIENTS_MAX: u32 = 1000;
/// Maximum `top_domains` entries returned per window.
pub const TOP_DOMAINS_MAX: u32 = 10_000;
/// Rollup retention in days (the spec's 365-day dashboard window).
pub const ROLLUP_RETENTION_DAYS: i64 = 365;
/// Raw-log days each rollup pass recomputes; covers rows a node delivers late after being offline.
const ROLLUP_RECOMPUTE_DAYS: i64 = 3;

const MICROS_PER_HOUR: i64 = 3_600_000_000;
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;
/// Rules listed in the overview's `filter_hits.top_rules`.
const OVERVIEW_TOP_RULES: i64 = 10;
const DEFAULT_WINDOW_HOURS: i64 = 24;
const EXPORT_PAGE_ROWS: u32 = 512;
const EXPORT_CHANNEL_DEPTH: usize = 16;

/// CSV columns exported for the documented query-log record schema.
const CSV_COLUMNS: &[&str] = &[
    "id",
    "time",
    "node_id",
    "listener_id",
    "protocol",
    "source_ip",
    "source_ip_truncated",
    "client_id",
    "client_name",
    "query_name",
    "query_type",
    "query_class",
    "view_id",
    "profile_id",
    "answer_source",
    "dnssec",
    "rcode",
    "answer_size",
];

/// Which rollup table to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollupWindow {
    /// Hourly rollups (`stats_hourly`).
    Hourly,
    /// Daily rollups (`stats_daily`).
    Daily,
}

impl RollupWindow {
    /// Returns `(table, bucket expression)` for this window.
    fn sql(self) -> (&'static str, &'static str) {
        match self {
            Self::Hourly => ("stats_hourly", "hour"),
            Self::Daily => ("stats_daily", "day"),
        }
    }
}

/// One stored rollup row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RollupRow {
    /// Unix hour for [`RollupWindow::Hourly`], unix day for [`RollupWindow::Daily`].
    pub bucket: i64,
    /// Originating node id (`""` for rows written before the dimension existed).
    pub node_id: String,
    /// Policy profile id.
    pub profile_id: String,
    /// Transport (`udp53`, `tcp53`, `dot`, `doh`, `doq`).
    pub protocol: String,
    /// Decision answer origin (`resolver`, `filter_block`, …).
    pub answer_source: String,
    /// Queries counted in this bucket.
    pub query_count: i64,
}

/// One blocking rule and how often it fired in the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleHits {
    /// Rule text as written in its list or custom set.
    pub rule: String,
    /// Queries blocked by the rule.
    pub hits: i64,
}

/// Nearest-rank response-time percentiles, in milliseconds.
#[derive(Clone, Debug, Serialize)]
pub struct ResponseTimeMs {
    /// 50th percentile.
    pub p50: f64,
    /// 95th percentile.
    pub p95: f64,
}

/// Filter hits (blocked queries) broken down by source for one window.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FilterHits {
    /// Queries that hit any filter rule.
    pub total: i64,
    /// Hits by filter list id (custom, service and MCP rules have no list).
    pub by_list: BTreeMap<String, i64>,
    /// Hits by rule provenance (`list`, `custom`, `service`, …).
    pub by_reason: BTreeMap<String, i64>,
    /// Most-hit rules, at most [`OVERVIEW_TOP_RULES`].
    pub top_rules: Vec<RuleHits>,
}

/// Aggregated dashboard statistics for one window.
///
/// `source` is `raw` when the response was built entirely from the query log
/// (open-hour windows, or before rollups are seeded) and `rollup` when
/// completed hours came from `stats_hourly` / `stats_daily`. Rollups keep only
/// protocol, profile, answer origin and node, so in `rollup` mode `by_view`,
/// `by_rcode` and `dnssec` are empty, `active_clients`, `filter_hits` and
/// `response_time_ms` are `null`, and `blocked` counts the `filter_block`
/// answer origin.
#[derive(Clone, Debug, Serialize)]
pub struct StatsOverview {
    /// `raw` or `rollup`: which storage answered the request.
    pub source: &'static str,
    /// Window start (RFC 3339).
    pub from: String,
    /// Window end (RFC 3339).
    pub to: String,
    /// Total queries in the window.
    pub total: i64,
    /// Queries with outcome `allowed`.
    pub allowed: i64,
    /// Queries with outcome `blocked`.
    pub blocked: i64,
    /// `allowed / total` (`0.0` for an empty window).
    pub allowed_ratio: f64,
    /// Distinct attributed clients in the window (`null` in rollup mode).
    pub active_clients: Option<i64>,
    /// Events dropped by the query-log sink since process start (node-local).
    pub query_log_dropped: u64,
    /// Live-stream events skipped by lagging subscribers since process start.
    pub query_log_stream_dropped: u64,
    /// Filter-hit breakdown (`null` in rollup mode).
    pub filter_hits: Option<FilterHits>,
    /// Response-time percentiles (`null` in rollup mode).
    pub response_time_ms: Option<ResponseTimeMs>,
    /// Query counts by transport.
    pub by_protocol: BTreeMap<String, i64>,
    /// Query counts by policy view.
    pub by_view: BTreeMap<String, i64>,
    /// Query counts by policy profile.
    pub by_profile: BTreeMap<String, i64>,
    /// Query counts by decision answer origin.
    pub by_answer_source: BTreeMap<String, i64>,
    /// Query counts by response code.
    pub by_rcode: BTreeMap<String, i64>,
    /// Query counts by DNSSEC outcome (`secure`, `insecure`, `bogus`, …).
    pub dnssec: BTreeMap<String, i64>,
}

/// One `top_clients` entry.
#[derive(Clone, Debug, Serialize)]
pub struct TopClient {
    /// Client id from the query log (`DoH`/`DoT` id or directory id).
    pub client_id: String,
    /// Client display name, or an empty string when the directory had none.
    pub client_name: String,
    /// Queries attributed to the client.
    pub queries: i64,
    /// Queries of those that were blocked.
    pub blocked: i64,
}

/// `top_clients` rows plus the resolved window.
#[derive(Clone, Debug, Serialize)]
pub struct TopClients {
    /// Window start (RFC 3339).
    pub from: String,
    /// Window end (RFC 3339).
    pub to: String,
    /// Up to [`TOP_CLIENTS_MAX`] clients.
    pub clients: Vec<TopClient>,
}

/// One `top_domains` entry.
#[derive(Clone, Debug, Serialize)]
pub struct TopDomain {
    /// Normalized owner name (lowercase, no trailing dot).
    pub domain: String,
    /// Queries for the name.
    pub queries: i64,
    /// Queries for the name that were blocked.
    pub blocked: i64,
}

/// `top_domains` rows plus the resolved window.
#[derive(Clone, Debug, Serialize)]
pub struct TopDomains {
    /// Window start (RFC 3339).
    pub from: String,
    /// Window end (RFC 3339).
    pub to: String,
    /// Up to [`TOP_DOMAINS_MAX`] domains.
    pub domains: Vec<TopDomain>,
}

/// Cache hit statistics for one window.
#[derive(Clone, Debug, Serialize)]
pub struct CacheStats {
    /// Window start (RFC 3339).
    pub from: String,
    /// Window end (RFC 3339).
    pub to: String,
    /// Resolved queries answered from cache.
    pub hits: i64,
    /// Resolved queries not answered from cache (recursion or stale).
    pub misses: i64,
    /// `hits / (hits + misses)` (`0.0` when nothing resolved).
    pub hit_ratio: f64,
}

/// One bucket of [`TimeSeries`].
#[derive(Clone, Debug, Serialize)]
pub struct TimeSeriesBucket {
    /// Start of the bucket (RFC 3339).
    pub bucket_start: String,
    /// Queries in the bucket.
    pub total: i64,
    /// Queries of those that were blocked.
    pub blocked: i64,
}

/// Query counts over time for one window.
#[derive(Clone, Debug, Serialize)]
pub struct TimeSeries {
    /// Window start (RFC 3339).
    pub from: String,
    /// Window end (RFC 3339).
    pub to: String,
    /// `hour` or `day`.
    pub bucket: String,
    /// Non-empty buckets in the window, oldest first.
    pub buckets: Vec<TimeSeriesBucket>,
}

/// How to order `top_clients`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TopBy {
    /// Most queries first (default).
    #[default]
    Queries,
    /// Most blocked queries first.
    Blocked,
}

impl TopBy {
    /// The wire name (`queries` | `blocked`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queries => "queries",
            Self::Blocked => "blocked",
        }
    }
}

/// Export wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExportFormat {
    /// Streaming NDJSON (one stored record per line).
    Ndjson,
    /// Streaming CSV projection of the documented record schema.
    Csv,
}

impl ExportFormat {
    /// Response content type.
    pub(crate) fn content_type(self) -> &'static str {
        match self {
            Self::Ndjson => "application/x-ndjson",
            Self::Csv => "text/csv; charset=utf-8",
        }
    }

    /// Download file name.
    pub(crate) fn file_name(self) -> &'static str {
        match self {
            Self::Ndjson => "query-log.ndjson",
            Self::Csv => "query-log.csv",
        }
    }
}

impl QueryLog {
    /// Folds the raw query log into the hourly and daily rollup tables and
    /// prunes rollups older than [`ROLLUP_RETENTION_DAYS`].
    ///
    /// Idempotent: counts are the maximum of the stored and recomputed value,
    /// so running the pass again never double-counts. Callers trigger it on a
    /// schedule; tests drive it after inserting fixed-time events.
    ///
    /// Only the last [`ROLLUP_RECOMPUTE_DAYS`] are re-read (everything on the
    /// first pass, while the rollups are empty): the pass holds the single
    /// writer connection, and a full-table scan would stall config saves and
    /// log ingestion for as long as it runs.
    pub async fn run_rollup(&self) -> Result<(), ControlApiError> {
        let now = self.db().now_unix();
        let cutoff_seconds = now.saturating_sub(ROLLUP_RETENTION_DAYS * SECONDS_PER_DAY);
        let hour_cutoff = cutoff_seconds.div_euclid(SECONDS_PER_HOUR);
        let day_cutoff = cutoff_seconds.div_euclid(SECONDS_PER_DAY);
        let recent_us = now
            .saturating_sub(ROLLUP_RECOMPUTE_DAYS * SECONDS_PER_DAY)
            .saturating_mul(1_000_000);
        // The scans run on a reader (seconds on a large log); only the small
        // aggregate is written, so the writer is held for milliseconds.
        type Bucket = (i64, String, String, String, String, i64);
        let (hourly, daily) = self
            .db()
            .with_read_conn(move |conn| {
                let seeded: bool = conn
                    .query_row("SELECT EXISTS(SELECT 1 FROM stats_daily)", [], |row| {
                        row.get(0)
                    })
                    .map_err(db_err)?;
                let since_us = if seeded { recent_us } else { 0 };
                let scan = |divisor: i64| -> Result<Vec<Bucket>, ControlApiError> {
                    // Rollup tables keep string labels so older buckets stay comparable.
                    let mut stmt = conn
                        .prepare(
                            "SELECT time / ?2, node_id, profile_id,
                                    CASE protocol
                                        WHEN 1 THEN 'udp53' WHEN 2 THEN 'tcp53' WHEN 3 THEN 'dot'
                                        WHEN 4 THEN 'doh' WHEN 5 THEN 'doq'
                                        ELSE CAST(protocol AS TEXT)
                                    END,
                                    CASE answer_source
                                        WHEN 1 THEN 'resolver' WHEN 2 THEN 'synth_any'
                                        WHEN 3 THEN 'resolve_error' WHEN 4 THEN 'local_view'
                                        WHEN 5 THEN 'local_client' WHEN 6 THEN 'bypass'
                                        WHEN 7 THEN 'filter_block' WHEN 8 THEN 'listener_ddr'
                                        ELSE CAST(answer_source AS TEXT)
                                    END,
                                    COUNT(*)
                             FROM query_log
                             WHERE time >= ?1
                             GROUP BY 1, 2, 3, 4, 5",
                        )
                        .map_err(db_err)?;
                    let rows = stmt
                        .query_map(params![since_us, divisor], |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                                row.get(5)?,
                            ))
                        })
                        .map_err(db_err)?;
                    rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
                };
                Ok((scan(MICROS_PER_HOUR)?, scan(MICROS_PER_HOUR * 24)?))
            })
            .await?;
        self.db()
            .with_conn(move |conn| {
                let tx = conn.transaction().map_err(db_err)?;
                for (table, bucket, rows) in [
                    ("stats_hourly", "hour", &hourly),
                    ("stats_daily", "day", &daily),
                ] {
                    let mut stmt = tx
                        .prepare(&format!(
                            "INSERT INTO {table} (
                                 {bucket}, node_id, profile_id, protocol, answer_source,
                                 query_count
                             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                             ON CONFLICT({bucket}, node_id, profile_id, protocol, answer_source)
                             DO UPDATE SET query_count = MAX(query_count, excluded.query_count)"
                        ))
                        .map_err(db_err)?;
                    for (b, node, profile, protocol, source, count) in rows {
                        stmt.execute(params![b, node, profile, protocol, source, count])
                            .map_err(db_err)?;
                    }
                }
                tx.execute(
                    "DELETE FROM stats_hourly WHERE hour < ?1",
                    params![hour_cutoff],
                )
                .map_err(db_err)?;
                tx.execute(
                    "DELETE FROM stats_daily WHERE day < ?1",
                    params![day_cutoff],
                )
                .map_err(db_err)?;
                tx.commit().map_err(db_err)?;
                Ok(())
            })
            .await
    }

    /// Returns every stored rollup row for `window`, ordered by bucket.
    pub async fn rollup_rows(
        &self,
        window: RollupWindow,
    ) -> Result<Vec<RollupRow>, ControlApiError> {
        let (table, bucket) = window.sql();
        // `table`/`bucket` are fixed constants, never user input.
        let sql = format!(
            "SELECT {bucket}, node_id, profile_id, protocol, answer_source, query_count
             FROM {table} ORDER BY {bucket}, node_id, profile_id, protocol, answer_source"
        );
        self.db()
            .with_read_conn(move |conn| {
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(RollupRow {
                            bucket: row.get(0)?,
                            node_id: row.get(1)?,
                            profile_id: row.get(2)?,
                            protocol: row.get(3)?,
                            answer_source: row.get(4)?,
                            query_count: row.get(5)?,
                        })
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
    }

    /// Aggregated dashboard counters for `[from_us, to_us]`, optionally
    /// restricted to one `node_id`.
    ///
    /// Absent bounds default to the last 24 hours, measured on the injected
    /// clock. `from > to` is `control_api.query_log.invalid`. Prefer
    /// `stats_hourly` for completed hours and only scan the raw log for the
    /// open hour; see [`StatsOverview`].
    pub async fn stats_overview(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
    ) -> Result<StatsOverview, ControlApiError> {
        self.stats_overview_scoped(
            from_us,
            to_us,
            StatsScope {
                node_id,
                profile_id: None,
            },
        )
        .await
    }

    /// [`Self::stats_overview`] restricted by a [`StatsScope`] (GM6 profile filter).
    pub async fn stats_overview_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
    ) -> Result<StatsOverview, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let scope = Scope::from(scope);
        let dropped = self.sink_dropped();
        let stream_dropped = self.stream_dropped();
        if let Some(overview) =
            overview_hourly_with_tail(db, from, to, scope.clone(), dropped, stream_dropped).await?
        {
            return Ok(overview);
        }
        let retention_secs =
            i64::from(self.config().retention_days).saturating_mul(SECONDS_PER_DAY);
        let raw_horizon = db
            .now_unix()
            .saturating_sub(retention_secs)
            .saturating_mul(1_000_000);
        if from < raw_horizon {
            let rolled =
                rollup_overview(db, from, to, scope.clone(), dropped, stream_dropped).await?;
            // Cheap existence check: never show less than the raw rows that
            // still exist in the window when rollups lag or are empty.
            let raw_total = raw_row_count(db, from, to, &scope).await?;
            if raw_total <= rolled.total {
                return Ok(rolled);
            }
        }
        overview_from_raw(db, from, to, &scope, dropped, stream_dropped).await
    }

    /// Top clients by query or blocked count for `[from_us, to_us]`.
    ///
    /// `limit` is clamped to `1..=TOP_CLIENTS_MAX`. A device is its client id, else its directory
    /// name, else its source address.
    pub async fn top_clients(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
        limit: u32,
        by: TopBy,
    ) -> Result<TopClients, ControlApiError> {
        let scope = StatsScope {
            node_id,
            profile_id: None,
        };
        self.top_clients_scoped(from_us, to_us, scope, limit, by)
            .await
    }

    /// [`Self::top_clients`] restricted by a [`StatsScope`].
    pub async fn top_clients_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
        limit: u32,
        by: TopBy,
    ) -> Result<TopClients, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let scope = Scope::from(scope);
        let limit = i64::from(limit.clamp(1, TOP_CLIENTS_MAX));
        let order = match by {
            TopBy::Queries => "queries DESC, cid ASC",
            TopBy::Blocked => "blocked DESC, queries DESC, cid ASC",
        };
        let clients = db
            .with_read_conn(move |conn| {
                let sql = format!(
                    // A device is its directory client id, else its client id, else its directory
                    // name, else its source address (LAN clients carry no client id). `cid` is the
                    // id, or the address when the row has neither id nor name.
                    "SELECT COALESCE(device_id, client_id, CASE WHEN client_name IS NULL THEN source_ip ELSE '' END) AS cid,
                            COALESCE(MAX(client_name), ''),
                            COUNT(*) AS queries,
                            COALESCE(SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END), 0)
                                AS blocked
                     FROM query_log
                     WHERE time >= ?1 AND time <= ?2
                       AND (?4 IS NULL OR node_id = ?4)
                       AND (?5 IS NULL OR profile_id = ?5)
                     GROUP BY COALESCE(device_id, client_id, client_name, source_ip)
                     ORDER BY {order}
                     LIMIT ?3"
                );
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map(
                        params![from, to, limit, scope.node_id, scope.profile_id],
                        |row| {
                            Ok(TopClient {
                                client_id: row.get(0)?,
                                client_name: row.get(1)?,
                                queries: row.get(2)?,
                                blocked: row.get(3)?,
                            })
                        },
                    )
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await?;
        Ok(TopClients {
            from: format_micros(from),
            to: format_micros(to),
            clients,
        })
    }

    /// Top domains by query count for `[from_us, to_us]`.
    ///
    /// `limit` is clamped to `1..=TOP_DOMAINS_MAX`.
    pub async fn top_domains(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
        limit: u32,
    ) -> Result<TopDomains, ControlApiError> {
        let scope = StatsScope {
            node_id,
            profile_id: None,
        };
        self.top_domains_scoped(from_us, to_us, scope, limit).await
    }

    /// [`Self::top_domains`] restricted by a [`StatsScope`].
    pub async fn top_domains_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
        limit: u32,
    ) -> Result<TopDomains, ControlApiError> {
        self.ranked_domains(from_us, to_us, scope, limit, "queries DESC, query_name ASC")
            .await
    }

    /// Top domains by blocked count for `[from_us, to_us]`.
    ///
    /// `limit` is clamped to `1..=TOP_DOMAINS_MAX`.
    pub async fn top_blocked_domains(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
        limit: u32,
    ) -> Result<TopDomains, ControlApiError> {
        let scope = StatsScope {
            node_id,
            profile_id: None,
        };
        self.top_blocked_domains_scoped(from_us, to_us, scope, limit)
            .await
    }

    /// [`Self::top_blocked_domains`] restricted by a [`StatsScope`].
    pub async fn top_blocked_domains_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
        limit: u32,
    ) -> Result<TopDomains, ControlApiError> {
        self.ranked_domains(
            from_us,
            to_us,
            scope,
            limit,
            "blocked DESC, queries DESC, query_name ASC",
        )
        .await
    }

    /// Shared body of the two domain rankings; `order` is a fixed constant.
    async fn ranked_domains(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
        limit: u32,
        order: &'static str,
    ) -> Result<TopDomains, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let scope = Scope::from(scope);
        let limit = i64::from(limit.clamp(1, TOP_DOMAINS_MAX));
        let domains = db
            .with_read_conn(move |conn| {
                // `order` is always one of the constants passed above.
                let sql = format!(
                    "SELECT query_name,
                            COUNT(*) AS queries,
                            COALESCE(SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END), 0)
                                AS blocked
                     FROM query_log
                     WHERE time >= ?1 AND time <= ?2
                       AND (?4 IS NULL OR node_id = ?4)
                       AND (?5 IS NULL OR profile_id = ?5)
                     GROUP BY query_name
                     ORDER BY {order}
                     LIMIT ?3"
                );
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map(
                        params![from, to, limit, scope.node_id, scope.profile_id],
                        |row| {
                            Ok(TopDomain {
                                domain: row.get(0)?,
                                queries: row.get(1)?,
                                blocked: row.get(2)?,
                            })
                        },
                    )
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await?;
        Ok(TopDomains {
            from: format_micros(from),
            to: format_micros(to),
            domains,
        })
    }

    /// Cache hit statistics for `[from_us, to_us]`.
    ///
    /// Uses the denormalised `cached` column (set when a resolve step came from
    /// cache). Hits are `cached = 1`; misses are allowed rows that did not hit
    /// cache — the same population the old `steps`-scan counted.
    pub async fn cache_stats(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        node_id: Option<&str>,
    ) -> Result<CacheStats, ControlApiError> {
        let scope = StatsScope {
            node_id,
            profile_id: None,
        };
        self.cache_stats_scoped(from_us, to_us, scope).await
    }

    /// [`Self::cache_stats`] restricted by a [`StatsScope`].
    pub async fn cache_stats_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
    ) -> Result<CacheStats, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let scope = Scope::from(scope);
        let (hits, misses) = db
            .with_read_conn(move |conn| {
                conn.query_row(
                    "SELECT
                         COALESCE(SUM(CASE WHEN cached = 1 THEN 1 ELSE 0 END), 0),
                         COALESCE(SUM(CASE WHEN cached = 0 AND status = 1
                                           THEN 1 ELSE 0 END), 0)
                     FROM query_log
                     WHERE time >= ?1 AND time <= ?2
                       AND (?3 IS NULL OR node_id = ?3)
                       AND (?4 IS NULL OR profile_id = ?4)",
                    params![from, to, scope.node_id, scope.profile_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(db_err)
            })
            .await?;
        Ok(CacheStats {
            from: format_micros(from),
            to: format_micros(to),
            hits,
            misses,
            hit_ratio: ratio(hits, hits.saturating_add(misses)),
        })
    }

    /// Query counts grouped by hour or day over the raw log for `[from_us, to_us]`.
    ///
    /// `bucket` is `hour` or `day`; any other value is read as `hour` (the HTTP
    /// route rejects those before calling this).
    pub async fn timeseries_scoped(
        &self,
        from_us: Option<i64>,
        to_us: Option<i64>,
        scope: StatsScope<'_>,
        bucket: &str,
    ) -> Result<TimeSeries, ControlApiError> {
        let db = self.db();
        let (from, to) = resolve_window(db, from_us, to_us)?;
        let scope = Scope::from(scope);
        let (label, width) = if bucket == "day" {
            ("day", MICROS_PER_DAY)
        } else {
            ("hour", MICROS_PER_HOUR)
        };
        let buckets = db
            .with_read_conn(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT (time / ?5) * ?5,
                                COUNT(*),
                                COALESCE(SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END), 0)
                         FROM query_log
                         WHERE time >= ?1 AND time <= ?2
                           AND (?3 IS NULL OR node_id = ?3)
                           AND (?4 IS NULL OR profile_id = ?4)
                         GROUP BY time / ?5
                         ORDER BY 1",
                    )
                    .map_err(db_err)?;
                let rows = stmt
                    .query_map(
                        params![from, to, scope.node_id, scope.profile_id, width],
                        |row| {
                            Ok(TimeSeriesBucket {
                                bucket_start: format_micros(row.get(0)?),
                                total: row.get(1)?,
                                blocked: row.get(2)?,
                            })
                        },
                    )
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await?;
        Ok(TimeSeries {
            from: format_micros(from),
            to: format_micros(to),
            bucket: label.to_owned(),
            buckets,
        })
    }
}

/// Optional node and profile filters shared by the dashboard aggregations
/// (GM6 adds the profile dimension; `None` means "all").
#[derive(Clone, Copy, Debug, Default)]
pub struct StatsScope<'a> {
    /// Exact `node_id` filter.
    pub node_id: Option<&'a str>,
    /// Exact policy profile filter.
    pub profile_id: Option<&'a str>,
}

/// Owned form of [`StatsScope`] for moving into `with_conn` closures.
#[derive(Clone, Debug, Default)]
struct Scope {
    node_id: Option<String>,
    profile_id: Option<String>,
}

impl From<StatsScope<'_>> for Scope {
    fn from(scope: StatsScope<'_>) -> Self {
        Self {
            node_id: scope.node_id.map(str::to_owned),
            profile_id: scope.profile_id.map(str::to_owned),
        }
    }
}

/// Resolves `from`/`to` defaults (last 24 hours) on the injected clock.
fn resolve_window(
    db: &Db,
    from_us: Option<i64>,
    to_us: Option<i64>,
) -> Result<(i64, i64), ControlApiError> {
    let now_us = db.now_unix().saturating_mul(1_000_000);
    let to = to_us.unwrap_or(now_us);
    let from = from_us.unwrap_or_else(|| to.saturating_sub(DEFAULT_WINDOW_HOURS * MICROS_PER_HOUR));
    if from > to {
        // Keep the A12 code: stats windows are query-log filters.
        return Err(ControlApiError::QueryLogInvalid {
            reason: "`from` must not be after `to`".to_owned(),
        });
    }
    Ok((from, to))
}

/// Filter-hit breakdown over the raw log for `[from, to]`.
async fn filter_hits(
    db: &Db,
    from: i64,
    to: i64,
    scope: &Scope,
    by_list: BTreeMap<String, i64>,
    by_reason: BTreeMap<String, i64>,
) -> Result<FilterHits, ControlApiError> {
    let scope = scope.clone();
    let top_rules = db
        .with_read_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT json_extract(r.record, '$.filter.rule_text') AS rule, COUNT(*) AS hits
                     FROM query_log
                     LEFT JOIN query_log_record r
                       ON r.node_id = query_log.node_id AND r.id = query_log.id
                     WHERE time >= ?1 AND time <= ?2
                       AND json_extract(r.record, '$.filter.rule_text') IS NOT NULL
                       AND (?3 IS NULL OR query_log.node_id = ?3)
                       AND (?4 IS NULL OR profile_id = ?4)
                     GROUP BY rule
                     ORDER BY hits DESC, rule ASC
                     LIMIT ?5",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(
                    params![
                        from,
                        to,
                        scope.node_id,
                        scope.profile_id,
                        OVERVIEW_TOP_RULES
                    ],
                    |row| {
                        Ok(RuleHits {
                            rule: row.get(0)?,
                            hits: row.get(1)?,
                        })
                    },
                )
                .map_err(db_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
        })
        .await?;
    let total = by_reason.values().sum();
    Ok(FilterHits {
        total,
        by_list,
        by_reason,
        top_rules,
    })
}

/// Raw-window counts for the overview, gathered in one pass over the log.
///
/// Rows are wide (the `record` JSON), so every separate `GROUP BY` re-reads the whole window; one
/// grouped scan answers all breakdowns. `json_extract` takes several paths at once so the JSON is
/// parsed once per row.
#[derive(Default)]
struct RawCounts {
    total: i64,
    allowed: i64,
    blocked: i64,
    by_protocol: BTreeMap<String, i64>,
    by_view: BTreeMap<String, i64>,
    by_profile: BTreeMap<String, i64>,
    by_answer_source: BTreeMap<String, i64>,
    by_rcode: BTreeMap<String, i64>,
    dnssec: BTreeMap<String, i64>,
    /// Filter hits by list id (unfiltered rows excluded).
    by_list: BTreeMap<String, i64>,
    /// Filter hits by rule provenance (unfiltered rows excluded).
    by_reason: BTreeMap<String, i64>,
}

async fn raw_counts(
    db: &Db,
    from: i64,
    to: i64,
    scope: &Scope,
) -> Result<RawCounts, ControlApiError> {
    let scope = scope.clone();
    db.with_read_conn(move |conn| {
        let mut stmt = conn
            .prepare(
                "SELECT protocol, view_id, profile_id, answer_source, rcode, status,
                        json_extract(r.record, '$.dnssec', '$.filter.list_id', '$.filter.reason'),
                        COUNT(*)
                 FROM query_log
                 LEFT JOIN query_log_record r
                   ON r.node_id = query_log.node_id AND r.id = query_log.id
                 WHERE time >= ?1 AND time <= ?2
                   AND (?3 IS NULL OR query_log.node_id = ?3)
                   AND (?4 IS NULL OR profile_id = ?4)
                 GROUP BY 1, 2, 3, 4, 5, 6, 7",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![from, to, scope.node_id, scope.profile_id], |row| {
                Ok((
                    read_protocol(row.get_ref(0)?),
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    read_answer_source(row.get_ref(3)?),
                    read_rcode(row.get_ref(4)?),
                    read_status(row.get_ref(5)?),
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .map_err(db_err)?;
        let mut out = RawCounts {
            total: 0,
            allowed: 0,
            blocked: 0,
            by_protocol: BTreeMap::new(),
            by_view: BTreeMap::new(),
            by_profile: BTreeMap::new(),
            by_answer_source: BTreeMap::new(),
            by_rcode: BTreeMap::new(),
            dnssec: BTreeMap::new(),
            by_list: BTreeMap::new(),
            by_reason: BTreeMap::new(),
        };
        for row in rows {
            let (protocol, view, profile, answer_source, rcode, status, json, count) =
                row.map_err(db_err)?;
            out.total += count;
            match status {
                StatusCode::Allowed => out.allowed += count,
                StatusCode::Blocked => out.blocked += count,
                _ => {}
            }
            // `[dnssec, filter.list_id, filter.reason]`, each `null` when absent.
            let paths: Vec<Json> = json
                .as_deref()
                .and_then(|text| serde_json::from_str(text).ok())
                .unwrap_or_default();
            let text_at = |index: usize| {
                paths
                    .get(index)
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            *out.by_protocol
                .entry(protocol.as_str().to_owned())
                .or_default() += count;
            *out.by_view.entry(view).or_default() += count;
            *out.by_profile.entry(profile).or_default() += count;
            *out.by_answer_source
                .entry(answer_source.as_str().to_owned())
                .or_default() += count;
            *out.by_rcode.entry(rcode_to_str(rcode)).or_default() += count;
            *out.dnssec.entry(text_at(0)).or_default() += count;
            for (map, key) in [
                (&mut out.by_list, text_at(1)),
                (&mut out.by_reason, text_at(2)),
            ] {
                if !key.is_empty() {
                    *map.entry(key).or_default() += count;
                }
            }
        }
        Ok(out)
    })
    .await
}

/// Full raw overview (filter hits, active clients, every breakdown).
async fn overview_from_raw(
    db: &Db,
    from: i64,
    to: i64,
    scope: &Scope,
    dropped: u64,
    stream_dropped: u64,
) -> Result<StatsOverview, ControlApiError> {
    let counts = raw_counts(db, from, to, scope).await?;
    let RawCounts {
        total,
        allowed,
        blocked,
        by_protocol,
        by_view,
        by_profile,
        by_answer_source,
        by_rcode,
        dnssec,
        by_list,
        by_reason,
    } = counts;
    let active_clients = active_client_count(db, from, to, scope).await?;
    let hits = filter_hits(db, from, to, scope, by_list, by_reason).await?;
    let response_time_ms = response_time_ms(db, from, to, scope).await?;
    Ok(StatsOverview {
        source: "raw",
        from: format_micros(from),
        to: format_micros(to),
        total,
        allowed,
        blocked,
        allowed_ratio: ratio(allowed, total),
        active_clients: Some(active_clients),
        query_log_dropped: dropped,
        query_log_stream_dropped: stream_dropped,
        filter_hits: Some(hits),
        response_time_ms: Some(response_time_ms),
        by_protocol,
        by_view,
        by_profile,
        by_answer_source,
        by_rcode,
        dnssec,
    })
}

/// Fast overview: closed hours from `stats_hourly`, open hour from raw.
///
/// Returns `None` when hourly rollups are not seeded yet so the caller can
/// fall back to daily rollups or a full raw scan.
async fn overview_hourly_with_tail(
    db: &Db,
    from: i64,
    to: i64,
    scope: Scope,
    dropped: u64,
    stream_dropped: u64,
) -> Result<Option<StatsOverview>, ControlApiError> {
    let seeded: bool = db
        .with_read_conn(|conn| {
            conn.query_row("SELECT EXISTS(SELECT 1 FROM stats_hourly)", [], |row| {
                row.get(0)
            })
            .map_err(db_err)
        })
        .await?;
    if !seeded {
        return Ok(None);
    }

    let from_hour = from.div_euclid(MICROS_PER_HOUR);
    let open_hour = to.div_euclid(MICROS_PER_HOUR);
    let closed = if from_hour < open_hour {
        hourly_rollup_parts(db, from_hour, open_hour - 1, &scope).await?
    } else {
        HourlyParts::default()
    };

    let tail_from = (open_hour.saturating_mul(MICROS_PER_HOUR)).max(from);
    let whole_window_is_open_hour = from_hour == open_hour;
    let (tail, active_clients, hits, response_time_ms, source) = if tail_from <= to {
        let counts = raw_counts(db, tail_from, to, &scope).await?;
        if whole_window_is_open_hour {
            let clients = active_client_count(db, from, to, &scope).await?;
            let hits = filter_hits(
                db,
                from,
                to,
                &scope,
                counts.by_list.clone(),
                counts.by_reason.clone(),
            )
            .await?;
            let latency = response_time_ms(db, from, to, &scope).await?;
            (counts, Some(clients), Some(hits), Some(latency), "raw")
        } else {
            (counts, None, None, None, "rollup")
        }
    } else {
        (RawCounts::default(), None, None, None, "rollup")
    };

    let total = closed.total + tail.total;
    let blocked = closed.blocked + tail.blocked;
    // Closed hours only know `filter_block`; the open-hour tail uses status.
    let allowed = closed.total.saturating_sub(closed.blocked) + tail.allowed;
    // Rollup responses omit dimensions the hourly table does not store, even
    // when the open-hour tail could fill them — keeps `source` semantics stable.
    let (by_view, by_rcode, dnssec) = if source == "raw" {
        (tail.by_view, tail.by_rcode, tail.dnssec)
    } else {
        (BTreeMap::new(), BTreeMap::new(), BTreeMap::new())
    };
    Ok(Some(StatsOverview {
        source,
        from: format_micros(from),
        to: format_micros(to),
        total,
        allowed,
        blocked,
        allowed_ratio: ratio(allowed, total),
        active_clients,
        query_log_dropped: dropped,
        query_log_stream_dropped: stream_dropped,
        filter_hits: hits,
        response_time_ms,
        by_protocol: merge_counts(closed.by_protocol, tail.by_protocol),
        by_view,
        by_profile: merge_counts(closed.by_profile, tail.by_profile),
        by_answer_source: merge_counts(closed.by_answer_source, tail.by_answer_source),
        by_rcode,
        dnssec,
    }))
}

#[derive(Default)]
struct HourlyParts {
    total: i64,
    blocked: i64,
    by_protocol: BTreeMap<String, i64>,
    by_profile: BTreeMap<String, i64>,
    by_answer_source: BTreeMap<String, i64>,
}

async fn hourly_rollup_parts(
    db: &Db,
    from_hour: i64,
    to_hour: i64,
    scope: &Scope,
) -> Result<HourlyParts, ControlApiError> {
    let (total, blocked) = db
        .with_read_conn({
            let scope = scope.clone();
            move |conn| {
                conn.query_row(
                    "SELECT COALESCE(SUM(query_count), 0),
                            COALESCE(SUM(CASE WHEN answer_source = 'filter_block'
                                              THEN query_count ELSE 0 END), 0)
                     FROM stats_hourly
                     WHERE hour >= ?1 AND hour <= ?2
                       AND (?3 IS NULL OR node_id = ?3)
                       AND (?4 IS NULL OR profile_id = ?4)",
                    params![from_hour, to_hour, scope.node_id, scope.profile_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(db_err)
            }
        })
        .await?;
    Ok(HourlyParts {
        total,
        blocked,
        by_protocol: hourly_counts_by(db, "protocol", from_hour, to_hour, scope).await?,
        by_profile: hourly_counts_by(db, "profile_id", from_hour, to_hour, scope).await?,
        by_answer_source: hourly_counts_by(db, "answer_source", from_hour, to_hour, scope).await?,
    })
}

async fn hourly_counts_by(
    db: &Db,
    expr: &'static str,
    from_hour: i64,
    to_hour: i64,
    scope: &Scope,
) -> Result<BTreeMap<String, i64>, ControlApiError> {
    let scope = scope.clone();
    db.with_read_conn(move |conn| {
        let sql = format!(
            "SELECT {expr}, COALESCE(SUM(query_count), 0) FROM stats_hourly
             WHERE hour >= ?1 AND hour <= ?2
               AND (?3 IS NULL OR node_id = ?3)
               AND (?4 IS NULL OR profile_id = ?4) GROUP BY 1"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(
                params![from_hour, to_hour, scope.node_id, scope.profile_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(db_err)?;
        let mut counts = BTreeMap::new();
        for row in rows {
            let (key, count) = row.map_err(db_err)?;
            counts.insert(key, count);
        }
        Ok(counts)
    })
    .await
}

fn merge_counts(
    mut left: BTreeMap<String, i64>,
    right: BTreeMap<String, i64>,
) -> BTreeMap<String, i64> {
    for (key, count) in right {
        *left.entry(key).or_default() += count;
    }
    left
}

async fn active_client_count(
    db: &Db,
    from: i64,
    to: i64,
    scope: &Scope,
) -> Result<i64, ControlApiError> {
    let scope = scope.clone();
    db.with_read_conn(move |conn| {
        conn.query_row(
            "SELECT COUNT(DISTINCT COALESCE(device_id, client_id, client_name)) FROM query_log
             WHERE time >= ?1 AND time <= ?2
               AND COALESCE(device_id, client_id, client_name) IS NOT NULL
               AND (?3 IS NULL OR node_id = ?3)
               AND (?4 IS NULL OR profile_id = ?4)",
            params![from, to, scope.node_id, scope.profile_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(db_err)
    })
    .await
}

/// Indexed `COUNT(*)` — used to compare rollup coverage without a wide scan.
async fn raw_row_count(db: &Db, from: i64, to: i64, scope: &Scope) -> Result<i64, ControlApiError> {
    let scope = scope.clone();
    db.with_read_conn(move |conn| {
        conn.query_row(
            "SELECT COUNT(*) FROM query_log
             WHERE time >= ?1 AND time <= ?2
               AND (?3 IS NULL OR node_id = ?3)
               AND (?4 IS NULL OR profile_id = ?4)",
            params![from, to, scope.node_id, scope.profile_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(db_err)
    })
    .await
}

/// Overview answered from the daily rollups (see [`StatsOverview`]).
async fn rollup_overview(
    db: &Db,
    from: i64,
    to: i64,
    scope: Scope,
    dropped: u64,
    stream_dropped: u64,
) -> Result<StatsOverview, ControlApiError> {
    let from_day = from.div_euclid(MICROS_PER_DAY);
    let to_day = to.div_euclid(MICROS_PER_DAY);
    let (total, blocked) = db
        .with_read_conn({
            let scope = scope.clone();
            move |conn| {
                conn.query_row(
                    "SELECT COALESCE(SUM(query_count), 0),
                            COALESCE(SUM(CASE WHEN answer_source = 'filter_block'
                                              THEN query_count ELSE 0 END), 0)
                     FROM stats_daily
                     WHERE day >= ?1 AND day <= ?2
                       AND (?3 IS NULL OR node_id = ?3)
                       AND (?4 IS NULL OR profile_id = ?4)",
                    params![from_day, to_day, scope.node_id, scope.profile_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .map_err(db_err)
            }
        })
        .await?;
    let by_protocol = rollup_counts_by(db, "protocol", from_day, to_day, &scope).await?;
    let by_profile = rollup_counts_by(db, "profile_id", from_day, to_day, &scope).await?;
    let by_answer_source = rollup_counts_by(db, "answer_source", from_day, to_day, &scope).await?;
    Ok(StatsOverview {
        source: "rollup",
        from: format_micros(from),
        to: format_micros(to),
        total,
        allowed: total - blocked,
        blocked,
        allowed_ratio: ratio(total - blocked, total),
        active_clients: None,
        query_log_dropped: dropped,
        query_log_stream_dropped: stream_dropped,
        filter_hits: None,
        response_time_ms: None,
        by_protocol,
        by_view: BTreeMap::new(),
        by_profile,
        by_answer_source,
        by_rcode: BTreeMap::new(),
        dnssec: BTreeMap::new(),
    })
}

/// Sums rollup `query_count` per the fixed column `expr` over whole days.
async fn rollup_counts_by(
    db: &Db,
    expr: &'static str,
    from_day: i64,
    to_day: i64,
    scope: &Scope,
) -> Result<BTreeMap<String, i64>, ControlApiError> {
    let scope = scope.clone();
    db.with_read_conn(move |conn| {
        // `expr` is always a constant from this module, never user input.
        let sql = format!(
            "SELECT {expr}, COALESCE(SUM(query_count), 0) FROM stats_daily
             WHERE day >= ?1 AND day <= ?2
               AND (?3 IS NULL OR node_id = ?3)
               AND (?4 IS NULL OR profile_id = ?4) GROUP BY 1"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(
                params![from_day, to_day, scope.node_id, scope.profile_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(db_err)?;
        let mut counts = BTreeMap::new();
        for row in rows {
            let (key, count) = row.map_err(db_err)?;
            counts.insert(key, count);
        }
        Ok(counts)
    })
    .await
}

/// Streams the filtered query log as a response body.
///
/// The first page is fetched before the response is built so a storage failure
/// is a normal `control_api.query_log.export` 500; later pages are streamed
/// from SQLite in `rowid` order and written to the body incrementally.
pub(crate) async fn export_body(
    log: Arc<QueryLog>,
    filter: QueryLogFilter,
    format: ExportFormat,
) -> Result<Body, ControlApiError> {
    let first_page = log.export_records(&filter, 0, EXPORT_PAGE_ROWS).await?;
    let (tx, rx) = mpsc::channel::<Result<Bytes, ControlApiError>>(EXPORT_CHANNEL_DEPTH);
    tokio::spawn(async move {
        stream_export(&log, &filter, first_page, format, &tx).await;
    });
    Ok(Body::new(ChannelBody { rx }))
}

/// Writes the header (CSV) and every page to `tx` until the export ends or the
/// client disconnects.
async fn stream_export(
    log: &QueryLog,
    filter: &QueryLogFilter,
    first_page: Vec<(i64, String)>,
    format: ExportFormat,
    tx: &mpsc::Sender<Result<Bytes, ControlApiError>>,
) {
    if format == ExportFormat::Csv {
        let header = format!("{}\n", CSV_COLUMNS.join(","));
        if tx.send(Ok(Bytes::from(header))).await.is_err() {
            return;
        }
    }
    let mut page = first_page;
    while !page.is_empty() {
        let cursor = page.last().map_or(0, |(rowid, _)| *rowid);
        let chunk = match format {
            ExportFormat::Ndjson => Ok(ndjson_chunk(&page)),
            ExportFormat::Csv => csv_chunk(&page),
        };
        match chunk {
            Ok(chunk) => {
                if tx.send(Ok(Bytes::from(chunk))).await.is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = tx.send(Err(error)).await;
                return;
            }
        }
        page = match log.export_records(filter, cursor, EXPORT_PAGE_ROWS).await {
            Ok(page) => page,
            Err(error) => {
                let _ = tx.send(Err(error)).await;
                return;
            }
        };
    }
}

/// Renders one NDJSON chunk (stored records, one per line).
fn ndjson_chunk(page: &[(i64, String)]) -> String {
    let mut chunk = String::new();
    for (_, raw) in page {
        chunk.push_str(raw);
        chunk.push('\n');
    }
    chunk
}

/// Renders one CSV chunk.
fn csv_chunk(page: &[(i64, String)]) -> Result<String, ControlApiError> {
    let mut chunk = String::new();
    for (_, raw) in page {
        chunk.push_str(&csv_row(raw)?);
    }
    Ok(chunk)
}

/// Projects one stored record onto [`CSV_COLUMNS`].
fn csv_row(raw: &str) -> Result<String, ControlApiError> {
    let record: Json =
        serde_json::from_str(raw).map_err(|error| ControlApiError::QueryLogExport {
            message: format!("stored query-log record is not valid JSON: {error}"),
        })?;
    let fields = [
        json_field(&record, &["id"]),
        json_field(&record, &["time"]),
        json_field(&record, &["node_id"]),
        json_field(&record, &["listener_id"]),
        json_field(&record, &["protocol"]),
        json_field(&record, &["source_ip"]),
        json_field(&record, &["source_ip_truncated"]),
        json_field(&record, &["client_id"]),
        json_field(&record, &["client", "display_name"]),
        json_field(&record, &["query", "name"]),
        json_field(&record, &["query", "type"]),
        json_field(&record, &["query", "class"]),
        json_field(&record, &["view_id"]),
        json_field(&record, &["profile_id"]),
        json_field(&record, &["answer_source"]),
        json_field(&record, &["dnssec"]),
        json_field(&record, &["rcode"]),
        json_field(&record, &["answer_size"]),
    ];
    let mut row = fields
        .iter()
        .map(|field| csv_escape(field))
        .collect::<Vec<_>>()
        .join(",");
    row.push('\n');
    Ok(row)
}

/// Reads a nested JSON scalar as text (`""` for absent/null).
fn json_field(record: &Json, path: &[&str]) -> String {
    let mut current = record;
    for key in path {
        match current.get(*key) {
            Some(value) => current = value,
            None => return String::new(),
        }
    }
    match current {
        Json::Null => String::new(),
        Json::String(value) => value.clone(),
        other => other.to_string(),
    }
}

/// Quotes a CSV field when it contains a comma, quote or line break, and
/// neutralises spreadsheet formula injection (a leading `=`, `+`, `-`, `@`,
/// tab or CR) with the standard single-quote prefix.
fn csv_escape(field: &str) -> String {
    let field = if field
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'))
    {
        format!("'{field}")
    } else {
        field.to_owned()
    };
    if field
        .chars()
        .any(|ch| matches!(ch, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field
    }
}

/// Formats unix microseconds as RFC 3339 (or the raw value if out of range).
fn format_micros(micros: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000)
        .ok()
        .and_then(|time| {
            time.format(time::macros::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
            ))
            .ok()
        })
        .unwrap_or_else(|| format!("{micros}us"))
}

/// Nearest-rank percentile of `sorted` ascending values (`0.0` when empty).
///
/// Rank is `ceil(percentile * len)`, 1-based, then clamped to the sample.
fn nearest_rank(sorted: &[f64], percentile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (percentile * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// Response-time percentiles (milliseconds) from raw `timings.total_us`.
async fn response_time_ms(
    db: &Db,
    from: i64,
    to: i64,
    scope: &Scope,
) -> Result<ResponseTimeMs, ControlApiError> {
    let scope = scope.clone();
    let samples = db
        .with_read_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT json_extract(r.record, '$.timings.total_us')
                     FROM query_log
                     LEFT JOIN query_log_record r
                       ON r.node_id = query_log.node_id AND r.id = query_log.id
                     WHERE time >= ?1 AND time <= ?2
                       AND (?3 IS NULL OR query_log.node_id = ?3)
                       AND (?4 IS NULL OR profile_id = ?4)
                       AND json_extract(r.record, '$.timings.total_us') IS NOT NULL
                     ORDER BY 1",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![from, to, scope.node_id, scope.profile_id], |row| {
                    row.get::<_, f64>(0)
                })
                .map_err(db_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
        })
        .await?;
    let ms: Vec<f64> = samples.into_iter().map(|us| us / 1_000.0).collect();
    Ok(ResponseTimeMs {
        p50: nearest_rank(&ms, 0.50),
        p95: nearest_rank(&ms, 0.95),
    })
}

/// `part / whole`, or `0.0` when `whole` is not positive.
fn ratio(part: i64, whole: i64) -> f64 {
    if whole <= 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

/// Response body backed by a bounded channel of rendered chunks.
pub(crate) struct ChannelBody {
    pub(crate) rx: mpsc::Receiver<Result<Bytes, ControlApiError>>,
}

impl HttpBody for ChannelBody {
    type Data = Bytes;
    type Error = ControlApiError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut().rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Microseconds per day, for the query log's `time` column.
const MICROS_PER_DAY: i64 = 86_400_000_000;
/// Clients listed per domain (WX5).
const DOMAIN_TOP_CLIENTS: i64 = 10;

impl QueryLog {
    /// Per-domain detail over the raw query log (WX5). `None` when the name is
    /// not seen inside retention. `days` bounds the counts, the daily series and
    /// the top clients; `first_seen` and `last_seen` cover the whole retention.
    pub async fn domain_detail(
        &self,
        domain: &str,
        days: u32,
    ) -> Result<Option<Json>, ControlApiError> {
        let db = self.db();
        let name = domain.to_owned();
        let now_us = db.now_unix().saturating_mul(1_000_000);
        let from = now_us.saturating_sub(i64::from(days) * MICROS_PER_DAY);
        db.with_read_conn(move |conn| {
            use rusqlite::OptionalExtension as _;
            let (first, last): (Option<i64>, Option<i64>) = conn
                .query_row(
                    "SELECT MIN(time), MAX(time) FROM query_log WHERE query_name = ?1",
                    params![name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(db_err)?;
            let (Some(first), Some(last)) = (first, last) else {
                return Ok(None);
            };
            let (total, blocked): (i64, i64) = conn
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END), 0)
                     FROM query_log WHERE query_name = ?1 AND time >= ?2",
                    params![name, from],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(db_err)?;

            let mut stmt = conn
                .prepare(
                    "SELECT COALESCE(client_name, client_id, source_ip) AS who, COUNT(*)
                     FROM query_log WHERE query_name = ?1 AND time >= ?2
                     GROUP BY who ORDER BY COUNT(*) DESC, who ASC LIMIT ?3",
                )
                .map_err(db_err)?;
            let clients: Vec<Json> = stmt
                .query_map(params![name, from, DOMAIN_TOP_CLIENTS], |row| {
                    Ok(serde_json::json!({
                        "client": row.get::<_, String>(0)?,
                        "queries": row.get::<_, i64>(1)?,
                    }))
                })
                .map_err(db_err)?
                .collect::<Result<_, _>>()
                .map_err(db_err)?;

            let mut stmt = conn
                .prepare(
                    "SELECT time / ?4 AS day, COUNT(*),
                            COALESCE(SUM(CASE WHEN status = 2 THEN 1 ELSE 0 END), 0)
                     FROM query_log WHERE query_name = ?1 AND time >= ?2
                     GROUP BY day ORDER BY day",
                )
                .map_err(db_err)?;
            let daily: Vec<Json> = stmt
                .query_map(params![name, from, MICROS_PER_DAY, MICROS_PER_DAY], |row| {
                    let day: i64 = row.get(0)?;
                    Ok(serde_json::json!({
                        "day": format_day(day),
                        "total": row.get::<_, i64>(1)?,
                        "blocked": row.get::<_, i64>(2)?,
                    }))
                })
                .map_err(db_err)?
                .collect::<Result<_, _>>()
                .map_err(db_err)?;

            let last_decision = conn
                .query_row(
                    "SELECT id, time, status,
                            COALESCE((SELECT r.record FROM query_log_record r
                                      WHERE r.node_id = query_log.node_id
                                        AND r.id = query_log.id), '{}')
                     FROM query_log
                     WHERE query_name = ?1 ORDER BY time DESC, id DESC LIMIT 1",
                    params![name],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            read_status(row.get_ref(2)?),
                            row.get::<_, String>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(db_err)?
                .map(|(id, time, status, record)| {
                    let filter = serde_json::from_str::<Json>(&record)
                        .ok()
                        .and_then(|value| value.get("filter").cloned())
                        .unwrap_or(Json::Null);
                    serde_json::json!({
                        "id": id,
                        "time": format_micros(time),
                        "status": status.as_str(),
                        "rule_text": filter.get("rule_text").cloned().unwrap_or(Json::Null),
                        "source": filter.get("reason").cloned().unwrap_or(Json::Null),
                    })
                });

            Ok(Some(serde_json::json!({
                "domain": name,
                "retention_limited": true,
                "first_seen": format_micros(first),
                "last_seen": format_micros(last),
                "counts": { "total": total, "blocked": blocked, "allowed": total - blocked },
                "top_clients": clients,
                "daily": daily,
                "last_decision": last_decision,
            })))
        })
        .await
    }
}

/// `YYYY-MM-DD` for a day index (days since the Unix epoch).
fn format_day(day: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(day.saturating_mul(86_400))
        .map(|t| t.date().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_uses_ceil_of_percentile_times_len() {
        let samples = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(nearest_rank(&samples, 0.50), 2.0);
        assert_eq!(nearest_rank(&samples, 0.95), 4.0);
        assert_eq!(nearest_rank(&[], 0.50), 0.0);
    }

    #[test]
    fn csv_escape_quotes_only_when_needed() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_escape("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn csv_escape_neutralises_formula_injection() {
        for field in [
            "=1+1",
            "+cmd|' /C calc'!A0",
            "-2+3",
            "@SUM(A1)",
            "\t=HYPERLINK(\"http://example.net\")",
        ] {
            let escaped = csv_escape(field);
            assert!(
                !escaped.starts_with(&['=', '+', '-', '@', '\t'][..]),
                "{field:?} escaped to {escaped:?}"
            );
        }
        assert_eq!(csv_escape("=1+1"), "'=1+1");
        assert_eq!(csv_escape("+1+1"), "'+1+1");
    }

    #[test]
    fn json_field_reads_nested_scalars() {
        let record = serde_json::json!({
            "client": { "display_name": "iPhone" },
            "client_id": null,
            "answer_size": 184,
        });
        assert_eq!(json_field(&record, &["client", "display_name"]), "iPhone");
        assert_eq!(json_field(&record, &["client_id"]), "");
        assert_eq!(json_field(&record, &["missing"]), "");
        assert_eq!(json_field(&record, &["answer_size"]), "184");
    }

    #[test]
    fn ratio_is_zero_for_an_empty_denominator() {
        assert_eq!(ratio(0, 0), 0.0);
        assert_eq!(ratio(1, 4), 0.25);
    }
}

type MemoSlot = Arc<tokio::sync::Mutex<Option<(i64, Json)>>>;

/// Short-lived answers of the dashboard aggregations (one slot per request shape).
///
/// Each aggregation scans the whole window, and the dashboard asks for seven of them every poll
/// (from every open tab). A slot is also a lock, so identical concurrent requests compute once.
#[derive(Default)]
pub(crate) struct StatsMemo(Mutex<HashMap<String, MemoSlot>>);

impl QueryLog {
    /// Returns the answer for `key`, computing it only when none younger than `ttl_secs` exists.
    /// Errors are never kept.
    pub(crate) async fn memoized<T, F>(
        &self,
        key: String,
        ttl_secs: i64,
        compute: F,
    ) -> Result<Json, ControlApiError>
    where
        T: Serialize,
        F: Future<Output = Result<T, ControlApiError>>,
    {
        let slot = {
            let mut map = self
                .stats_memo
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Keys embed the window, so they drift; a bounded map is enough.
            if map.len() > 128 && !map.contains_key(&key) {
                map.clear();
            }
            Arc::clone(map.entry(key).or_default())
        };
        let mut guard = slot.lock().await;
        let now = self.db().now_unix();
        if let Some((at, value)) = guard.as_ref()
            && now.saturating_sub(*at) < ttl_secs
        {
            return Ok(value.clone());
        }
        let value =
            serde_json::to_value(compute.await?).map_err(|error| ControlApiError::Internal {
                message: error.to_string(),
            })?;
        *guard = Some((now, value.clone()));
        Ok(value)
    }
}
