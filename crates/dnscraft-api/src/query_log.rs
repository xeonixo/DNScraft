//! Query-log consumer, storage, filtering and "why blocked?" data (A12).
//!
//! The listener set publishes bounded [`QueryEvent`]s through
//! [`QueryLog::channel`]'s [`QueryLogSink`]. The sink never blocks: when the
//! bounded channel is full (or closed) it drops the event and increments its
//! [`QueryLogSink::dropped`] counter, which is surfaced as the stable
//! `control_api.query_log.dropped` code. [`QueryLog::run`] (or
//! [`QueryLog::flush_ready`] in tests) drains the channel and batch-inserts
//! into SQLite.
//!
//! On disk, closed enums and DNS type/class/rcode are integers; the JSON blob
//! is slim (no column duplicates). Pipeline `steps` / `selection`
//! for block and error rows live in `query_log_detail` and are merged only for
//! `GET /query-log/{id}` (and cluster outbox shipping). The public wire shape
//! stays stringly-typed — see [`crate::query_log_codec`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dnscraft_listeners::{QueryEvent, QueryEventSink};
use dnscraft_policy::DecisionStep;
use dnscraft_resolver::AnswerSource;
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use rusqlite::params;
use rusqlite::params_from_iter;
use rusqlite::types::Value;
use serde_json::{Value as Json, json};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use tokio::sync::{broadcast, mpsc};

use crate::config::{IpTruncate, QueryLogConfig};
use crate::error::ControlApiError;
use crate::query_log_codec::{
    self, AnswerSourceCode, ProtocolCode, StatusCode, WireColumns, hydrate_wire, parse_query_type,
    read_answer_source, read_protocol, read_query_class, read_query_type, read_rcode, read_status,
    split_record,
};
use crate::query_log_wire::{
    client_json, dnssec_str, filter_json, format_rfc3339_micros, selection_json, status_str,
    step_json, system_time_micros,
};
use crate::storage::{Db, db_err, kv_get, kv_set};

/// Columns selected when hydrating a stored row into the wire document.
const HYDRATE_COLS: &str = "id, node_id, listener_id, protocol, source_ip, source_ip_truncated,
    client_id, device_id, query_name, query_type, query_class, view_id, profile_id,
    status, answer_source, rcode,
    COALESCE((SELECT r.record FROM query_log_record r
              WHERE r.node_id = query_log.node_id AND r.id = query_log.id), '{}')";

/// Maps one `HYDRATE_COLS` (+ optional detail) row into the public wire JSON.
fn hydrate_from_row(
    row: &rusqlite::Row<'_>,
    detail: Option<Json>,
) -> rusqlite::Result<Result<Json, ControlApiError>> {
    let id: String = row.get(0)?;
    let node_id: String = row.get(1)?;
    let listener_id: String = row.get(2)?;
    let protocol = read_protocol(row.get_ref(3)?);
    let source_ip: String = row.get(4)?;
    let source_ip_truncated: i64 = row.get(5)?;
    let client_id: Option<String> = row.get(6)?;
    let device_id: Option<String> = row.get(7)?;
    let query_name: String = row.get(8)?;
    let query_type = read_query_type(row.get_ref(9)?);
    let query_class = read_query_class(row.get_ref(10)?);
    let view_id: String = row.get(11)?;
    let profile_id: String = row.get(12)?;
    let status = read_status(row.get_ref(13)?);
    let answer_source = read_answer_source(row.get_ref(14)?);
    let rcode = read_rcode(row.get_ref(15)?);
    let raw: String = row.get(16)?;
    let slim: Json = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(_) => {
            return Ok(Err(ControlApiError::QueryLogRead {
                message: "stored query-log record is not valid JSON".to_owned(),
            }));
        }
    };
    let cols = WireColumns {
        id: &id,
        node_id: &node_id,
        listener_id: &listener_id,
        protocol,
        source_ip: &source_ip,
        source_ip_truncated: source_ip_truncated != 0,
        client_id: client_id.as_deref(),
        device_id: device_id.as_deref(),
        query_name: &query_name,
        query_type,
        query_class,
        view_id: &view_id,
        profile_id: &profile_id,
        status,
        answer_source,
        rcode,
    };
    Ok(Ok(hydrate_wire(slim, detail, &cols)))
}

/// Largest batch drained from the channel before one SQLite transaction.
const BATCH_MAX: usize = 1024;

/// Live-stream queue per subscriber, in events (WX2).
const STREAM_QUEUE: usize = 512;
/// Live streams one principal may hold open (WX2).
pub const STREAM_PER_PRINCIPAL: usize = 4;
/// Live streams one node may serve in total (WX2).
pub const STREAM_PER_NODE: usize = 32;

/// Milliseconds in a day, used to turn [`QueryLogConfig::retention_days`] into
/// a microsecond window.
const MICROS_PER_DAY: i64 = 86_400_000_000;

/// `kv` key prefix for the next `seq` to allocate on a node.
const SEQ_ALLOC_PREFIX: &str = "query_log.seq_alloc.";
/// `kv` key prefix for the highest contiguously acknowledged `seq` on a node.
const ACKED_SEQ_PREFIX: &str = "query_log.acked_seq.";
/// Per-node `kv` key prefix for the contiguous-run cursor of ingested remote rows.
const CONTIGUOUS_SEQ_PREFIX: &str = "query_log.contiguous_seq.";

/// Client-directory data attached to a query-log record.
///
/// Control-api does not own a client directory; the binary supplies an
/// implementation of [`ClientEnricher`] backed by its `clients` engine. Keeping
/// this a narrow trait mirrors the other module adapters in
/// [`crate::modules`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientView {
    /// Directory client id.
    pub id: String,
    /// Display name (`"iPhone"`).
    pub display_name: String,
    /// Provenance (`"manual"` or `"unifi"`).
    pub source: String,
    /// MAC addresses in canonical form.
    pub macs: Vec<String>,
    /// VLAN id, when known.
    pub vlan_id: Option<u16>,
    /// VLAN name, when known.
    pub vlan_name: Option<String>,
    /// Per-client parent domain, when known.
    pub local_domain: Option<String>,
}

/// Resolves a source IP to client-directory data.
///
/// Called on the blocking pool for every inserted record; implementations must
/// be fast and allocation-light (a snapshot lookup, not network I/O).
pub trait ClientEnricher: Send + Sync {
    /// Returns the client matching `ip`, if any.
    fn by_ip(&self, ip: IpAddr) -> Option<ClientView>;
}

/// Column used to order query-log results.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OrderBy {
    /// Record time (default).
    #[default]
    Time,
    /// Client display name (falling back to the client id).
    Client,
    /// Queried name.
    Domain,
    /// Response code.
    Rcode,
}

/// Sort direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Order {
    /// Ascending.
    Asc,
    /// Descending (default).
    #[default]
    Desc,
}

/// Validated query-log filter and pagination parameters.
///
/// Built by the HTTP route or directly by an in-process caller (for example the
/// MCP backend). Times are unix microseconds.
#[derive(Clone, Debug, Default)]
pub struct QueryLogFilter {
    /// Lower time bound (inclusive).
    pub from_us: Option<i64>,
    /// Upper time bound (inclusive).
    pub to_us: Option<i64>,
    /// Exact originating node id.
    pub node_id: Option<String>,
    /// Client subnet in CIDR notation (a bare address means one host).
    pub subnet: Option<String>,
    /// Exact client id (DoH/DoT client id or directory id).
    pub client_id: Option<String>,
    /// Case-insensitive substring of the client display name.
    pub client_name_substr: Option<String>,
    /// Exact directory device key; matches UniFi/manual clients and DoH Client IDs linked to them.
    pub device_id: Option<String>,
    /// Exact normalized owner name (no trailing dot).
    pub domain: Option<String>,
    /// Case-insensitive substring of the owner name.
    pub domain_substr: Option<String>,
    /// Transport (`udp53`, `tcp53`, `dot`, `doh`, `doq`).
    pub protocol: Option<String>,
    /// Exact query type (`A`, `AAAA`, …).
    pub query_type: Option<String>,
    /// Exact policy view id.
    pub view_id: Option<String>,
    /// Exact policy profile id.
    pub profile_id: Option<String>,
    /// Derived outcome (`allowed`, `blocked`, `dnssec_bogus`, `servfail`) or
    /// `cache` (a resolve step answered from cache).
    pub status: Option<String>,
    /// Shorthand for `status = blocked`.
    pub only_blocked: bool,
    /// Return only rows with a client id, display name, or device key.
    pub only_with_clients: bool,
    /// Sort column.
    pub order_by: OrderBy,
    /// Sort direction.
    pub order: Order,
    /// Page size; clamped to the configured `max_rows_per_request`.
    pub limit: u32,
    /// Rows to skip.
    pub offset: u64,
}

/// One page of query-log records.
#[derive(Clone, Debug)]
pub struct QueryLogPage {
    /// Full record JSON documents (one per row).
    pub records: Vec<Json>,
    /// Whether at least one more row exists after this page.
    pub has_more: bool,
    /// Offset to request for the next page.
    pub next_offset: Option<u64>,
    /// Rows matching the filter, ignoring pagination.
    pub total: i64,
}

/// Sink half of the bounded query-log channel.
///
/// `try_send` never waits: a full or closed channel drops the event and
/// increments the counter behind [`Self::dropped`].
#[derive(Debug)]
pub struct QueryLogSink {
    tx: mpsc::Sender<QueryEvent>,
    dropped: AtomicU64,
}

impl QueryLogSink {
    /// Events dropped because the bounded channel was full or closed.
    ///
    /// This is the value surfaced as the informational
    /// `control_api.query_log.dropped` counter.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl QueryEventSink for QueryLogSink {
    fn try_send(&self, event: QueryEvent) -> bool {
        // `emit_event` already filters, but stay defensive: a non-loggable
        // event is never a drop.
        if !event.loggable {
            return true;
        }
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn events_dropped(&self) -> u64 {
        self.dropped()
    }
}

/// Query-log consumer, reader and retention owner.
pub struct QueryLog {
    db: Db,
    /// Bootstrap `[control_api.query_log]` values: the fallback for any
    /// setting a config version does not carry.
    bootstrap: QueryLogConfig,
    /// Active settings. Replaced by [`Self::apply_settings`] on every applied
    /// config version; never held across an `.await`.
    config: RwLock<QueryLogConfig>,
    node_id: String,
    enricher: Option<Arc<dyn ClientEnricher>>,
    sink: Option<Arc<QueryLogSink>>,
    stream_tx: broadcast::Sender<Arc<str>>,
    stream_dropped: AtomicU64,
    streams: Arc<StreamSlots>,
    pub(crate) stats_memo: crate::stats::StatsMemo,
}

/// Open live-stream counts, per principal and per node (WX2).
#[derive(Debug, Default)]
struct StreamSlots {
    per_principal: Mutex<HashMap<String, usize>>,
    total: Mutex<usize>,
}

/// Holds one live-stream slot; releases it on drop.
#[derive(Debug)]
pub(crate) struct StreamGuard {
    slots: Arc<StreamSlots>,
    principal: String,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let mut per = self
            .slots
            .per_principal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = per.get_mut(&self.principal) {
            *count -= 1;
            if *count == 0 {
                per.remove(&self.principal);
            }
        }
        let mut total = self
            .slots
            .total
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *total -= 1;
    }
}

impl QueryLog {
    /// Creates a query log over `db` with the given retention/privacy policy.
    pub fn new(db: Db, config: QueryLogConfig, node_id: impl Into<String>) -> Self {
        Self {
            db,
            bootstrap: config.clone(),
            config: RwLock::new(config),
            node_id: node_id.into(),
            enricher: None,
            sink: None,
            stream_tx: broadcast::channel(STREAM_QUEUE).0,
            stream_dropped: AtomicU64::new(0),
            streams: Arc::new(StreamSlots::default()),
            stats_memo: crate::stats::StatsMemo::default(),
        }
    }

    /// Subscribes to ids of newly stored rows (node-local inserts only).
    pub(crate) fn subscribe_stream(&self) -> broadcast::Receiver<Arc<str>> {
        self.stream_tx.subscribe()
    }

    /// Takes one live-stream slot for `principal`, or `None` past the limits.
    pub(crate) fn acquire_stream(&self, principal: &str) -> Option<StreamGuard> {
        let mut per = self
            .streams
            .per_principal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut total = self
            .streams
            .total
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = per.entry(principal.to_owned()).or_insert(0);
        if *count >= STREAM_PER_PRINCIPAL || *total >= STREAM_PER_NODE {
            if *count == 0 {
                per.remove(principal);
            }
            return None;
        }
        *count += 1;
        *total += 1;
        Some(StreamGuard {
            slots: Arc::clone(&self.streams),
            principal: principal.to_owned(),
        })
    }

    /// Returns the stored records among `ids` that match `filter`, oldest first.
    ///
    /// Uses the same filter SQL as [`Self::list`], so a stream never disagrees
    /// with the list endpoint about what matches.
    pub(crate) async fn stream_rows(
        &self,
        filter: &QueryLogFilter,
        ids: &[Arc<str>],
    ) -> Result<Vec<String>, ControlApiError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let (clause, clause_values) = filter_clause(filter);
        let ids: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let fetched = self
            .db
            .with_read_conn(move |conn| {
                let placeholders = vec!["?"; ids.len()].join(",");
                let sql = format!(
                    "SELECT {HYDRATE_COLS} FROM query_log
                     WHERE id IN ({placeholders}){clause}
                     ORDER BY time ASC, rowid ASC"
                );
                let mut values: Vec<Value> = ids.into_iter().map(Value::Text).collect();
                values.extend(clause_values);
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map(params_from_iter(values), |row| hydrate_from_row(row, None))
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await?;
        fetched
            .into_iter()
            .map(|result| result.map(|record| record.to_string()))
            .collect()
    }

    /// Attaches the sink returned by [`Self::channel`], so the stats overview
    /// can report `query_log.dropped` for this node.
    pub fn with_sink(mut self, sink: Arc<QueryLogSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Events the attached sink has dropped since process start (`0` without a sink).
    pub(crate) fn sink_dropped(&self) -> u64 {
        self.sink.as_ref().map_or(0, |sink| sink.dropped())
    }

    /// Attaches the client-directory enricher used at write time.
    pub fn with_client_enricher(mut self, enricher: Arc<dyn ClientEnricher>) -> Self {
        self.enricher = Some(enricher);
        self
    }

    /// Live-stream events skipped by lagging subscribers since process start
    /// (the `query_log.stream_dropped` counter).
    pub fn stream_dropped(&self) -> u64 {
        self.stream_dropped.load(Ordering::Relaxed)
    }

    /// Adds `count` to the stream-drop counter and logs it.
    pub(crate) fn record_stream_dropped(&self, count: u64) {
        self.stream_dropped.fetch_add(count, Ordering::Relaxed);
        tracing::warn!(
            counter = "query_log.stream_dropped",
            dropped = count,
            "live query-log subscriber lagged"
        );
    }

    /// A copy of the active query-log configuration.
    pub fn config(&self) -> QueryLogConfig {
        self.config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Applies the runtime `control_api_settings.query_log` values of a config
    /// version. A `None` falls back to the bootstrap value, not the hard default.
    ///
    /// Affects rows written from now on; stored rows keep their truncation.
    pub fn apply_settings(&self, retention_days: Option<u32>, ip_truncate: Option<IpTruncate>) {
        let mut config = self
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        config.retention_days = retention_days.unwrap_or(self.bootstrap.retention_days);
        config.ip_truncate = ip_truncate.unwrap_or(self.bootstrap.ip_truncate);
    }

    /// The underlying database handle (crate-internal, for stats and export).
    pub(crate) fn db(&self) -> &Db {
        &self.db
    }

    /// Creates the bounded channel and its non-blocking sink.
    pub fn channel(capacity: usize) -> (Arc<QueryLogSink>, mpsc::Receiver<QueryEvent>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Arc::new(QueryLogSink {
                tx,
                dropped: AtomicU64::new(0),
            }),
            rx,
        )
    }

    /// Drains `rx` forever, batch-inserting each burst until the channel closes.
    pub async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<QueryEvent>) {
        loop {
            let Some(first) = rx.recv().await else {
                break;
            };
            let mut events = Vec::with_capacity(BATCH_MAX.min(64));
            events.push(first);
            while events.len() < BATCH_MAX {
                match rx.try_recv() {
                    Ok(event) => events.push(event),
                    Err(_) => break,
                }
            }
            if let Err(error) = self.insert_batch(events).await {
                tracing::error!(error = %error, "query-log batch insert failed");
            }
        }
    }

    /// Inserts every event currently buffered in `rx` in one transaction.
    ///
    /// Returns the number of rows written. Deterministic counterpart of
    /// [`Self::run`] for tests (no wall-clock waits).
    pub async fn flush_ready(
        &self,
        rx: &mut mpsc::Receiver<QueryEvent>,
    ) -> Result<usize, ControlApiError> {
        let mut events = Vec::new();
        while events.len() < BATCH_MAX {
            match rx.try_recv() {
                Ok(event) => events.push(event),
                Err(_) => break,
            }
        }
        if events.is_empty() {
            return Ok(0);
        }
        self.insert_batch(events).await
    }

    /// Batch-inserts `events`, applying IP truncation, client enrichment and
    /// retention. Non-loggable events are skipped.
    pub async fn insert_batch(&self, events: Vec<QueryEvent>) -> Result<usize, ControlApiError> {
        let db = self.db.clone();
        let config = self.config();
        let node_id = self.node_id.clone();
        let enricher = self.enricher.clone();
        let now_us = self.db.now_unix().saturating_mul(1_000_000);
        let ids = db
            .with_conn(move |conn| {
                let mut rows = Vec::with_capacity(events.len());
                for event in &events {
                    if event.loggable {
                        rows.push(prepare_row(event, &node_id, &config, enricher.as_deref())?);
                    }
                }
                let cutoff = now_us.saturating_sub(
                    i64::from(config.retention_days).saturating_mul(MICROS_PER_DAY),
                );
                let tx = conn.transaction().map_err(db_err)?;
                // Retention is an indexed range delete; running it with each batch
                // keeps the window bounded without an extra timer task. Driven from
                // `query_log(time)`: an EXISTS probe per detail row scanned the whole
                // detail table (11 s on 190k rows) while holding the writer lock.
                tx.execute(
                    "DELETE FROM query_log_detail
                     WHERE (node_id, id) IN (
                         SELECT node_id, id FROM query_log WHERE time < ?1
                     )",
                    params![cutoff],
                )
                .map_err(db_err)?;
                tx.execute(
                    "DELETE FROM query_log_record
                     WHERE (node_id, id) IN (
                         SELECT node_id, id FROM query_log WHERE time < ?1
                     )",
                    params![cutoff],
                )
                .map_err(db_err)?;
                tx.execute("DELETE FROM query_log WHERE time < ?1", params![cutoff])
                    .map_err(db_err)?;
                // The per-node `seq` is allocated in this same transaction: a
                // crash can roll the rows and the cursor back together, never
                // leaving a logged query without an outbox position.
                let seq_key = outbox_key(SEQ_ALLOC_PREFIX, &node_id);
                let first_seq = read_counter(&tx, &seq_key, 1)?;
                {
                    let mut stmt = tx
                        .prepare(
                            "INSERT INTO query_log (
                             id, time, node_id, source_ip, query_name, listener_id,
                             protocol, source_ip_truncated, client_id, client_name,
                             query_type, query_class, view_id, profile_id, status,
                             answer_source, rcode, seq, device_id, cached
                         ) VALUES (
                             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                             ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
                         )",
                        )
                        .map_err(db_err)?;
                    let mut record_stmt = tx
                        .prepare(
                            "INSERT INTO query_log_record (node_id, id, record)
                             VALUES (?1, ?2, ?3)",
                        )
                        .map_err(db_err)?;
                    let mut detail_stmt = tx
                        .prepare(
                            "INSERT INTO query_log_detail (node_id, id, detail)
                             VALUES (?1, ?2, ?3)",
                        )
                        .map_err(db_err)?;
                    for (offset, row) in rows.iter().enumerate() {
                        let seq =
                            first_seq.saturating_add(i64::try_from(offset).unwrap_or(i64::MAX));
                        stmt.execute(params![
                            row.id,
                            row.time_us,
                            row.node_id,
                            row.source_ip,
                            row.query_name,
                            row.listener_id,
                            row.protocol,
                            row.source_ip_truncated,
                            row.client_id,
                            row.client_name,
                            row.query_type,
                            row.query_class,
                            row.view_id,
                            row.profile_id,
                            row.status,
                            row.answer_source,
                            row.rcode,
                            seq,
                            row.device_id,
                            row.cached,
                        ])
                        .map_err(db_err)?;
                        record_stmt
                            .execute(params![row.node_id, row.id, row.record])
                            .map_err(db_err)?;
                        if let Some(detail) = &row.detail {
                            detail_stmt
                                .execute(params![row.node_id, row.id, detail])
                                .map_err(db_err)?;
                        }
                    }
                }
                if !rows.is_empty() {
                    let next_alloc =
                        first_seq.saturating_add(i64::try_from(rows.len()).unwrap_or(i64::MAX));
                    kv_set(&tx, &seq_key, &next_alloc.to_string())?;
                }
                tx.commit().map_err(db_err)?;
                Ok(rows.into_iter().map(|row| row.id).collect::<Vec<_>>())
            })
            .await?;
        let written = ids.len();
        for id in ids {
            // No subscriber is a normal state; the DNS path never waits here.
            let _ = self.stream_tx.send(Arc::from(id));
        }
        Ok(written)
    }

    /// Deletes rows older than the configured retention window.
    ///
    /// Returns the number of deleted rows.
    pub async fn apply_retention(&self) -> Result<usize, ControlApiError> {
        let window = i64::from(self.config().retention_days).saturating_mul(MICROS_PER_DAY);
        let cutoff = self
            .db
            .now_unix()
            .saturating_mul(1_000_000)
            .saturating_sub(window);
        self.db
            .with_conn(move |conn| {
                conn.execute(
                    "DELETE FROM query_log_detail
                     WHERE (node_id, id) IN (
                         SELECT node_id, id FROM query_log WHERE time < ?1
                     )",
                    params![cutoff],
                )
                .map_err(db_err)?;
                conn.execute(
                    "DELETE FROM query_log_record
                     WHERE (node_id, id) IN (
                         SELECT node_id, id FROM query_log WHERE time < ?1
                     )",
                    params![cutoff],
                )
                .map_err(db_err)?;
                conn.execute("DELETE FROM query_log WHERE time < ?1", params![cutoff])
                    .map_err(db_err)
            })
            .await
    }

    /// Runs one filtered, ordered and paginated query.
    pub async fn list(&self, filter: &QueryLogFilter) -> Result<QueryLogPage, ControlApiError> {
        let limit = filter
            .limit
            .clamp(1, self.config().max_rows_per_request.max(1));
        let offset = i64::try_from(filter.offset).unwrap_or(i64::MAX);

        let (conditions, mut values) = filter_clause(filter);
        let total = {
            // ponytail: total is capped at TOTAL_CAP so a rare substring search stops
            // early instead of counting the whole table; exact counts need an index.
            let sql = format!(
                "SELECT COUNT(*) FROM (SELECT 1 FROM query_log WHERE 1 = 1{conditions} LIMIT {TOTAL_CAP})"
            );
            let values = values.clone();
            self.db
                .with_read_conn(move |conn| {
                    conn.query_row(&sql, params_from_iter(values), |row| row.get::<_, i64>(0))
                        .map_err(db_err)
                })
                .await
                .map_err(read_error)?
        };

        let mut sql = format!("SELECT {HYDRATE_COLS} FROM query_log WHERE 1 = 1");
        sql.push_str(&conditions);
        let column = match filter.order_by {
            OrderBy::Time => "time",
            OrderBy::Client => "COALESCE(client_name, client_id, '')",
            OrderBy::Domain => "query_name",
            OrderBy::Rcode => "rcode",
        };
        let direction = match filter.order {
            Order::Asc => "ASC",
            Order::Desc => "DESC",
        };
        // Only constant strings from the matches above are interpolated.
        sql.push_str(&format!(
            " ORDER BY {column} {direction}, id {direction} LIMIT ? OFFSET ?"
        ));
        // Probe one extra row to expose `has_more`. `total` is the separate COUNT above.
        values.push(Value::Integer(i64::from(limit) + 1));
        values.push(Value::Integer(offset));

        let fetched = self
            .db
            .with_read_conn(move |conn| {
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map(params_from_iter(values), |row| hydrate_from_row(row, None))
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
            .map_err(read_error)?;

        let has_more = fetched.len() > limit as usize;
        let mut records = Vec::with_capacity(fetched.len().min(limit as usize));
        for result in fetched.into_iter().take(limit as usize) {
            records.push(result?);
        }
        Ok(QueryLogPage {
            records,
            has_more,
            next_offset: has_more.then_some(filter.offset + u64::from(limit)),
            total,
        })
    }

    /// Reads one page of stored records for export.
    ///
    /// Rows are returned in insertion (`rowid`) order after `after_rowid`
    /// (exclusive), so the caller can loop until an empty page without
    /// materialising the whole export in memory. The filter's `limit`/`offset`
    /// are deliberately ignored: an export covers the whole filtered set.
    pub(crate) async fn export_records(
        &self,
        filter: &QueryLogFilter,
        after_rowid: i64,
        page: u32,
    ) -> Result<Vec<(i64, String)>, ControlApiError> {
        let (conditions, mut values) = filter_clause(filter);
        let sql = format!(
            "SELECT rowid, {HYDRATE_COLS} FROM query_log WHERE 1 = 1{conditions}
             AND rowid > ? ORDER BY rowid LIMIT ?"
        );
        values.push(Value::Integer(after_rowid));
        values.push(Value::Integer(i64::from(page.max(1))));
        let fetched = self
            .db
            .with_read_conn(move |conn| {
                let mut stmt = conn.prepare(&sql).map_err(db_err)?;
                let rows = stmt
                    .query_map(params_from_iter(values), |row| {
                        let rowid: i64 = row.get(0)?;
                        // Shift: hydrate_from_row expects cols starting at 0.
                        let record = {
                            let id: String = row.get(1)?;
                            let node_id: String = row.get(2)?;
                            let listener_id: String = row.get(3)?;
                            let protocol = read_protocol(row.get_ref(4)?);
                            let source_ip: String = row.get(5)?;
                            let source_ip_truncated: i64 = row.get(6)?;
                            let client_id: Option<String> = row.get(7)?;
                            let device_id: Option<String> = row.get(8)?;
                            let query_name: String = row.get(9)?;
                            let query_type = read_query_type(row.get_ref(10)?);
                            let query_class = read_query_class(row.get_ref(11)?);
                            let view_id: String = row.get(12)?;
                            let profile_id: String = row.get(13)?;
                            let status = read_status(row.get_ref(14)?);
                            let answer_source = read_answer_source(row.get_ref(15)?);
                            let rcode = read_rcode(row.get_ref(16)?);
                            let raw: String = row.get(17)?;
                            let slim: Json = serde_json::from_str(&raw).unwrap_or(json!({}));
                            let cols = WireColumns {
                                id: &id,
                                node_id: &node_id,
                                listener_id: &listener_id,
                                protocol,
                                source_ip: &source_ip,
                                source_ip_truncated: source_ip_truncated != 0,
                                client_id: client_id.as_deref(),
                                device_id: device_id.as_deref(),
                                query_name: &query_name,
                                query_type,
                                query_class,
                                view_id: &view_id,
                                profile_id: &profile_id,
                                status,
                                answer_source,
                                rcode,
                            };
                            hydrate_wire(slim, None, &cols)
                        };
                        Ok((rowid, record))
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
            .map_err(|error| ControlApiError::QueryLogExport {
                message: error.to_string(),
            })?;
        Ok(fetched
            .into_iter()
            .map(|(rowid, record)| (rowid, record.to_string()))
            .collect())
    }

    /// Loads one record by id, or `None` when it is absent (or aged out).
    ///
    /// Merges `query_log_detail` when present so "why blocked?" sees steps.
    pub async fn get(&self, id: &str) -> Result<Option<Json>, ControlApiError> {
        let id = id.to_owned();
        let raw = self
            .db
            .with_read_conn(move |conn| {
                use rusqlite::OptionalExtension as _;
                conn.query_row(
                    &format!(
                        "SELECT {HYDRATE_COLS},
                                (SELECT detail FROM query_log_detail d
                                 WHERE d.node_id = query_log.node_id AND d.id = query_log.id)
                         FROM query_log WHERE id = ?1"
                    ),
                    params![id],
                    |row| {
                        let detail: Option<String> = row.get(17)?;
                        let detail = detail.and_then(|raw| serde_json::from_str(&raw).ok());
                        hydrate_from_row(row, detail)
                    },
                )
                .optional()
                .map_err(db_err)
            })
            .await
            .map_err(read_error)?;
        match raw {
            None => Ok(None),
            Some(result) => result.map(Some),
        }
    }

    /// Returns up to `max` outbox rows starting at `from_seq`, ascending.
    ///
    /// Each tuple is `(seq, record id, wire document)`. The wire document is
    /// the stored query-log record plus the denormalised columns the master
    /// needs to re-insert it with the originating `node_id`, `time` and `seq`.
    /// Rows below `from_seq` (already acked) are skipped; an empty result
    /// means the local outbox has drained. Only rows for this node's id are
    /// considered — leftover seqs from a previous `node_id` on the same DB
    /// must not enter the outbox.
    pub async fn outbox_rows(
        &self,
        from_seq: i64,
        max: usize,
    ) -> Result<Vec<(i64, String, Json)>, ControlApiError> {
        let max = i64::try_from(max.max(1)).unwrap_or(i64::MAX);
        let node_id = self.node_id.clone();
        self.db
            .with_conn(move |conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT q.seq, q.id, q.time, q.source_ip, q.query_name, q.listener_id,
                                q.protocol, q.source_ip_truncated, q.client_id, q.client_name,
                                q.query_type, q.query_class, q.view_id, q.profile_id, q.status,
                                q.answer_source, q.rcode,
                                COALESCE((SELECT r.record FROM query_log_record r
                                          WHERE r.node_id = q.node_id AND r.id = q.id), '{}'),
                                d.detail
                         FROM query_log q
                         LEFT JOIN query_log_detail d
                           ON d.node_id = q.node_id AND d.id = q.id
                         WHERE q.node_id = ?1 AND q.seq IS NOT NULL AND q.seq >= ?2
                         ORDER BY q.seq LIMIT ?3",
                    )
                    .map_err(db_err)?;
                let rows = stmt
                    .query_map(params![node_id, from_seq, max], |row| {
                        let seq: i64 = row.get(0)?;
                        let id: String = row.get(1)?;
                        let time_us: i64 = row.get(2)?;
                        let source_ip: String = row.get(3)?;
                        let query_name: String = row.get(4)?;
                        let listener_id: String = row.get(5)?;
                        let protocol = read_protocol(row.get_ref(6)?);
                        let truncated = row.get::<_, i64>(7)? != 0;
                        let client_id: Option<String> = row.get(8)?;
                        let client_name: Option<String> = row.get(9)?;
                        let query_type = read_query_type(row.get_ref(10)?);
                        let query_class = read_query_class(row.get_ref(11)?);
                        let view_id: String = row.get(12)?;
                        let profile_id: String = row.get(13)?;
                        let status = read_status(row.get_ref(14)?);
                        let answer_source = read_answer_source(row.get_ref(15)?);
                        let rcode = read_rcode(row.get_ref(16)?);
                        let raw: String = row.get(17)?;
                        let detail = row
                            .get::<_, Option<String>>(18)?
                            .and_then(|raw| serde_json::from_str(&raw).ok());
                        let slim: Json = serde_json::from_str(&raw).unwrap_or(json!({}));
                        // Cluster wire stays stringly typed for protocol compat.
                        let wire = hydrate_wire(
                            slim,
                            detail,
                            &WireColumns {
                                id: &id,
                                node_id: "", // stamped by the master from the cert
                                listener_id: &listener_id,
                                protocol,
                                source_ip: &source_ip,
                                source_ip_truncated: truncated,
                                client_id: client_id.as_deref(),
                                device_id: None,
                                query_name: &query_name,
                                query_type,
                                query_class,
                                view_id: &view_id,
                                profile_id: &profile_id,
                                status,
                                answer_source,
                                rcode,
                            },
                        );
                        let document = json!({
                            "id": id,
                            "time_us": time_us,
                            "source_ip": source_ip,
                            "query_name": query_name,
                            "listener_id": listener_id,
                            "protocol": protocol.as_str(),
                            "source_ip_truncated": truncated,
                            "client_id": client_id,
                            "client_name": client_name,
                            "query_type": wire["query"]["type"].clone(),
                            "query_class": wire["query"]["class"].clone(),
                            "view_id": view_id,
                            "profile_id": profile_id,
                            "status": status.as_str(),
                            "answer_source": answer_source.as_str(),
                            "rcode": query_log_codec::rcode_to_str(rcode),
                            "record": wire,
                        });
                        Ok((seq, id, document))
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
    }

    /// Highest contiguous outbox `seq` stored for `node_id` (`0` when none).
    ///
    /// A gap (or a record dropped before insert) stops the cursor at the last
    /// sequence before it, so the master never acknowledges rows it does not
    /// have. Used by the master when a sub-node reconnects to compute the
    /// backfill cursor (`master_highest_log_seq`).
    pub async fn highest_remote_seq(&self, node_id: &str) -> Result<u64, ControlApiError> {
        let node_id = node_id.to_owned();
        let seq: i64 = self
            .db
            .with_conn(move |conn| highest_contiguous_seq(conn, &node_id))
            .await?;
        Ok(u64::try_from(seq).unwrap_or_default())
    }

    /// Inserts one contiguous log batch streamed by a sub-node.
    ///
    /// Records are re-inserted with the originating `node_id`, `time` and the
    /// batch's per-node `seq`, deduplicating on `(node_id, id)` and
    /// `(node_id, seq)` (`ON CONFLICT DO NOTHING`); the same record id is
    /// allowed on another node. A repeated `seq` carrying a different record
    /// id is rejected as `control_api.query_log.invalid`. Returns the highest
    /// *contiguous* `seq` stored for the node after the batch, so a gap never
    /// acknowledges rows past it.
    pub async fn ingest_remote(
        &self,
        node_id: &str,
        first_seq: u64,
        last_seq: u64,
        records: &[Json],
    ) -> Result<u64, ControlApiError> {
        let expected = last_seq
            .checked_sub(first_seq)
            .and_then(|span| span.checked_add(1));
        if expected != Some(records.len() as u64) {
            return Err(ControlApiError::QueryLogInvalid {
                reason: "first_seq/last_seq do not match the record count".to_owned(),
            });
        }
        let node_id = node_id.to_owned();
        let enricher = self.enricher.clone();
        let rows = records
            .iter()
            .enumerate()
            .map(|(offset, value)| {
                let mut row: RemoteRow =
                    serde_json::from_value(value.clone()).map_err(|error| {
                        ControlApiError::QueryLogInvalid {
                            reason: format!("invalid remote query-log record: {error}"),
                        }
                    })?;
                row.validate()?;
                let device_id = prepare_remote_row(&mut row, &node_id, enricher.as_deref());
                let seq = first_seq.checked_add(offset as u64).ok_or_else(|| {
                    ControlApiError::QueryLogInvalid {
                        reason: "log sequence number overflow".to_owned(),
                    }
                })?;
                Ok((row, seq, device_id))
            })
            .collect::<Result<Vec<_>, ControlApiError>>()?;

        let node_for_tx = node_id.clone();
        let batch_len = rows.len() as u64;
        let (highest, inserted_ids) = self
            .db
            .with_conn(move |conn| {
                let tx = conn.transaction().map_err(db_err)?;
                let mut duplicates = 0u64;
                let mut inserted_ids = Vec::with_capacity(rows.len());
                for (row, seq, device_id) in &rows {
                    let seq =
                        i64::try_from(*seq).map_err(|_| ControlApiError::QueryLogInvalid {
                            reason: "log sequence number out of range".to_owned(),
                        })?;
                    let existing: Option<String> = tx
                        .query_row(
                            "SELECT id FROM query_log WHERE node_id = ?1 AND seq = ?2",
                            params![node_for_tx, seq],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(db_err)?;
                    if let Some(existing) = existing {
                        if existing != row.id {
                            return Err(ControlApiError::QueryLogInvalid {
                                reason: format!(
                                    "sequence {seq} already carries a different record id"
                                ),
                            });
                        }
                        duplicates = duplicates.saturating_add(1);
                        continue;
                    }
                    let status = StatusCode::from_str(&row.status);
                    let (slim, detail) = split_record(row.record.clone(), status);
                    let cached = slim
                        .pointer("/steps")
                        .and_then(Json::as_array)
                        .into_iter()
                        .flatten()
                        .chain(
                            detail
                                .as_ref()
                                .and_then(|value| value.get("steps"))
                                .and_then(Json::as_array)
                                .into_iter()
                                .flatten(),
                        )
                        .any(|step| {
                            step.get("stage").and_then(Json::as_str) == Some("resolve")
                                && step.get("source").and_then(Json::as_str) == Some("cache")
                        });
                    let inserted = tx
                        .execute(
                            "INSERT INTO query_log (
                             id, time, node_id, source_ip, query_name, listener_id,
                             protocol, source_ip_truncated, client_id, client_name,
                             query_type, query_class, view_id, profile_id, status,
                             answer_source, rcode, seq, device_id, cached
                         ) VALUES (
                             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                             ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
                         ) ON CONFLICT DO NOTHING",
                            params![
                                row.id,
                                row.time_us,
                                node_for_tx,
                                row.source_ip,
                                row.query_name,
                                row.listener_id,
                                ProtocolCode::from_str(&row.protocol).as_i64(),
                                i64::from(row.source_ip_truncated),
                                row.client_id,
                                row.client_name,
                                parse_query_type(&row.query_type)
                                    .map(i64::from)
                                    .unwrap_or(0),
                                query_log_codec::parse_query_class(&row.query_class)
                                    .map(i64::from)
                                    .unwrap_or(1),
                                row.view_id,
                                row.profile_id,
                                status.as_i64(),
                                AnswerSourceCode::from_str(&row.answer_source).as_i64(),
                                query_log_codec::rcode_from_str(&row.rcode),
                                seq,
                                device_id,
                                i64::from(cached),
                            ],
                        )
                        .map_err(db_err)?;
                    if inserted == 0 {
                        duplicates = duplicates.saturating_add(1);
                    } else {
                        tx.execute(
                            "INSERT INTO query_log_record (node_id, id, record)
                             VALUES (?1, ?2, ?3)
                             ON CONFLICT(node_id, id) DO UPDATE SET record = excluded.record",
                            params![node_for_tx, row.id, slim.to_string()],
                        )
                        .map_err(db_err)?;
                        if let Some(detail) = detail {
                            tx.execute(
                                "INSERT INTO query_log_detail (node_id, id, detail)
                                 VALUES (?1, ?2, ?3)
                                 ON CONFLICT(node_id, id) DO UPDATE SET detail = excluded.detail",
                                params![node_for_tx, row.id, detail.to_string()],
                            )
                            .map_err(db_err)?;
                        }
                        inserted_ids.push(row.id.clone());
                    }
                }
                let highest = highest_contiguous_seq(&tx, &node_for_tx)?;
                store_contiguous_seq(&tx, &node_for_tx, highest)?;
                tx.commit().map_err(db_err)?;
                if duplicates > 0 {
                    tracing::debug!(
                        node_id = %node_for_tx,
                        duplicates,
                        batch_len,
                        "cluster log ingest skipped duplicate rows"
                    );
                }
                Ok((u64::try_from(highest).unwrap_or_default(), inserted_ids))
            })
            .await?;
        // Fan newly ingested remote rows into the live SSE stream so the
        // master's query-log UI sees sub-node traffic without a refresh.
        for id in inserted_ids {
            let _ = self.stream_tx.send(Arc::from(id));
        }
        Ok(highest)
    }

    /// Returns the next unacknowledged outbox `seq` for this node.
    ///
    /// This is the value the log sender resumes from (`acked + 1`). It is `1`
    /// before the first record is inserted. When the buffer's oldest retained
    /// row is already newer than `acked + 1` (the pruning dropped rows), the
    /// oldest row wins so the gap is reported instead of retried forever.
    pub async fn next_seq(&self) -> Result<i64, ControlApiError> {
        let key = outbox_key(ACKED_SEQ_PREFIX, &self.node_id);
        let node_id = self.node_id.clone();
        self.db
            .with_conn(move |conn| {
                let acked = read_counter(conn, &key, 0)?;
                let oldest: Option<i64> = conn
                    .query_row(
                        "SELECT MIN(seq) FROM query_log
                         WHERE node_id = ?1 AND seq IS NOT NULL",
                        params![node_id],
                        |row| row.get(0),
                    )
                    .map_err(db_err)?;
                Ok(oldest.map_or(acked.saturating_add(1), |oldest| {
                    acked.saturating_add(1).max(oldest)
                }))
            })
            .await
    }

    /// Detaches unacknowledged outbox rows recorded at or before `cutoff_us`
    /// (microseconds since the epoch) from the outbox, for the sub-node's
    /// `buffer_retention`. The rows stay in the local query log; only their
    /// `seq` is cleared, so [`Self::next_seq`] skips them and the gap is
    /// reported. Returns how many outbox rows were detached.
    ///
    /// Only this node's rows are touched. Seq numbers from another `node_id`
    /// that still sit in the same DB (for example after renaming `local` →
    /// the enrolled id) must not widen the prune window and wipe fresh rows.
    pub async fn prune_outbox_before(&self, cutoff_us: i64) -> Result<u64, ControlApiError> {
        let node_id = self.node_id.clone();
        self.db
            .transaction(move |conn| {
                let acked = read_counter(conn, &outbox_key(ACKED_SEQ_PREFIX, &node_id), 0)?;
                // Everything up to the newest expired unacknowledged row goes,
                // so the outbox keeps a contiguous tail.
                let changed = conn
                    .execute(
                        "UPDATE query_log SET seq = NULL
                         WHERE node_id = ?1
                           AND seq > ?2
                           AND seq <= (SELECT MAX(seq) FROM query_log
                                       WHERE node_id = ?1 AND seq > ?2 AND time < ?3)",
                        params![node_id, acked, cutoff_us],
                    )
                    .map_err(db_err)?;
                Ok(u64::try_from(changed).unwrap_or(u64::MAX))
            })
            .await
    }

    /// Advances the local outbox past a master cursor that is already ahead of
    /// this node's sequence allocator.
    ///
    /// That happens when the same mTLS `node_id` previously shipped under a
    /// different local allocator (for example rows stamped `local` while the
    /// cert said `waldo`): the master still holds a high contiguous seq, but
    /// this process allocates from a fresh, lower counter. Without a rebase,
    /// every new row sits below the master's cursor and is never sent — and a
    /// global prune of leftover foreign seqs can even clear them first.
    ///
    /// When `master_highest + 1` is already past the next local allocation,
    /// the allocator and ack cursor jump forward and any local outbox seqs at
    /// or below `master_highest` are detached (the rows stay in the query log).
    pub async fn rebase_outbox(&self, master_highest: u64) -> Result<bool, ControlApiError> {
        let node_id = self.node_id.clone();
        let master_highest =
            i64::try_from(master_highest).map_err(|_| ControlApiError::QueryLogInvalid {
                reason: "log sequence number out of range".to_owned(),
            })?;
        self.db
            .transaction(move |conn| {
                let alloc_key = outbox_key(SEQ_ALLOC_PREFIX, &node_id);
                let ack_key = outbox_key(ACKED_SEQ_PREFIX, &node_id);
                let next_alloc = read_counter(conn, &alloc_key, 1)?;
                let want_next = master_highest.saturating_add(1);
                if want_next <= next_alloc {
                    return Ok(false);
                }
                let acked = read_counter(conn, &ack_key, 0)?;
                if master_highest > acked {
                    kv_set(conn, &ack_key, &master_highest.to_string())?;
                }
                kv_set(conn, &alloc_key, &want_next.to_string())?;
                conn.execute(
                    "UPDATE query_log SET seq = NULL
                     WHERE node_id = ?1 AND seq IS NOT NULL AND seq <= ?2",
                    params![node_id, master_highest],
                )
                .map_err(db_err)?;
                Ok(true)
            })
            .await
    }

    /// Marks every record up to `seq` as acknowledged and returns the new
    /// contiguous cursor.
    ///
    /// The cursor only advances forward and never past the last allocated
    /// `seq`; a stale or repeated acknowledgement is a no-op. A `seq` beyond
    /// the last allocated record is rejected as `query_log.invalid`.
    pub async fn ack(&self, seq: i64) -> Result<i64, ControlApiError> {
        let node_id = self.node_id.clone();
        self.db
            .transaction(move |conn| {
                let ack_key = outbox_key(ACKED_SEQ_PREFIX, &node_id);
                let alloc_key = outbox_key(SEQ_ALLOC_PREFIX, &node_id);
                let acked = read_counter(conn, &ack_key, 0)?;
                if seq <= acked {
                    return Ok(acked);
                }
                let next_alloc = read_counter(conn, &alloc_key, 1)?;
                if seq >= next_alloc {
                    return Err(ControlApiError::QueryLogInvalid {
                        reason: format!(
                            "ack seq {seq} exceeds the last allocated seq {}",
                            next_alloc.saturating_sub(1)
                        ),
                    });
                }
                kv_set(conn, &ack_key, &seq.to_string())?;
                Ok(seq)
            })
            .await
    }
}

/// Builds a per-node outbox `kv` key.
fn outbox_key(prefix: &str, node_id: &str) -> String {
    format!("{prefix}{node_id}")
}

/// Highest `seq` in the node's contiguous run starting at its lowest stored
/// sequence (`0` when none).
///
/// Finds the first stored sequence with no `seq + 1` successor: a gap makes
/// every later sequence non-contiguous, so it is not acknowledged. The search
/// resumes from the cursor persisted by [`store_contiguous_seq`] — everything
/// below it was contiguous already — so a healthy stream costs a few index
/// probes instead of a scan of the node's whole retained log. Falls back to a
/// full scan when the cursor row was pruned.
fn highest_contiguous_seq(conn: &Connection, node_id: &str) -> Result<i64, ControlApiError> {
    let key = outbox_key(CONTIGUOUS_SEQ_PREFIX, node_id);
    let cursor = read_counter(conn, &key, 0)?;
    let start = if cursor > 0
        && conn
            .query_row(
                "SELECT 1 FROM query_log WHERE node_id = ?1 AND seq = ?2",
                params![node_id, cursor],
                |_| Ok(()),
            )
            .optional()
            .map_err(db_err)?
            .is_some()
    {
        cursor
    } else {
        0
    };
    conn.query_row(
        "SELECT COALESCE(MIN(q.seq), 0) FROM query_log q
         WHERE q.node_id = ?1 AND q.seq >= ?2
           AND NOT EXISTS (
               SELECT 1 FROM query_log n
               WHERE n.node_id = q.node_id AND n.seq = q.seq + 1
           )",
        params![node_id, start],
        |row| row.get(0),
    )
    .map_err(db_err)
}

/// Persists the contiguous-run cursor for [`highest_contiguous_seq`].
fn store_contiguous_seq(conn: &Connection, node_id: &str, seq: i64) -> Result<(), ControlApiError> {
    kv_set(
        conn,
        &outbox_key(CONTIGUOUS_SEQ_PREFIX, node_id),
        &seq.to_string(),
    )
}

/// Reads a persisted cursor value, or `default` when the key is absent.
fn read_counter(conn: &Connection, key: &str, default: i64) -> Result<i64, ControlApiError> {
    match kv_get(conn, key)? {
        None => Ok(default),
        Some(raw) => raw.parse::<i64>().map_err(|_| ControlApiError::Internal {
            message: format!("corrupt outbox cursor `{key}`"),
        }),
    }
}

/// Parses `addr/prefix` (or a bare address as a host route) into its parts.
pub fn parse_cidr(raw: &str) -> Option<(std::net::IpAddr, u8)> {
    let (addr, prefix) = match raw.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix.parse::<u8>().ok()?)),
        None => (raw, None),
    };
    let addr: std::net::IpAddr = addr.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(max);
    (prefix <= max).then_some((addr, prefix))
}

/// Whether `ip` lies inside `cidr`; unparsable input or a family mismatch never matches.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    use std::net::IpAddr;
    let (Some((net, prefix)), Ok(ip)) = (parse_cidr(cidr), ip.parse::<IpAddr>()) else {
        return false;
    };
    let (a, b, bits) = match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u128::from(u32::from(a)), u128::from(u32::from(b)), 32),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128),
        _ => return false,
    };
    let shift = bits - u32::from(prefix);
    shift >= 128 || (a >> shift) == (b >> shift)
}

/// Registers the `ip_in_cidr(ip, cidr)` SQL function the subnet filter uses.
pub(crate) fn register_sql_functions(conn: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    conn.create_scalar_function(
        "ip_in_cidr",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| Ok(ip_in_cidr(&ctx.get::<String>(0)?, &ctx.get::<String>(1)?)),
    )
}

/// Stamps the enrolled node id and re-enriches the client from the master's
/// directory before a remote row is stored.
fn prepare_remote_row(
    row: &mut RemoteRow,
    node_id: &str,
    enricher: Option<&dyn ClientEnricher>,
) -> Option<String> {
    if let Some(obj) = row.record.as_object_mut() {
        obj.insert("node_id".to_owned(), Json::String(node_id.to_owned()));
    }
    let mut device_id = row
        .record
        .get("device_id")
        .and_then(Json::as_str)
        .map(str::to_owned);
    let directory = enricher.and_then(|enricher| {
        row.source_ip
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| enricher.by_ip(ip))
    });
    if let Some(client) = directory {
        row.client_name = Some(client.display_name.clone());
        if matches!(client.source.as_str(), "unifi" | "manual") && !client.id.is_empty() {
            device_id = Some(client.id.clone());
        }
        if let Some(obj) = row.record.as_object_mut() {
            obj.insert("client".to_owned(), client_json(&client));
            if let Some(device_id) = &device_id {
                obj.insert("device_id".to_owned(), Json::String(device_id.clone()));
            }
        }
    } else if row.record.get("client").and_then(Json::as_object).is_none()
        && let Some(client) =
            resolve_client(None, row.client_id.as_deref(), row.client_name.as_deref())
    {
        row.client_name = Some(client.display_name.clone());
        if let Some(obj) = row.record.as_object_mut() {
            obj.insert("client".to_owned(), client_json(&client));
        }
    }
    device_id
}

/// Upper bound for [`QueryLogPage::total`]; a value equal to it means "at least".
const TOTAL_CAP: i64 = 10_000;

/// Builds the shared `WHERE` conditions for a [`QueryLogFilter`].
///
/// The returned suffix starts with `" AND "` and is appended to
/// `WHERE 1 = 1`. Every user value is a bind parameter; only fixed column names
/// are part of the SQL text.
fn filter_clause(filter: &QueryLogFilter) -> (String, Vec<Value>) {
    let mut sql = String::new();
    let mut values = Vec::new();
    if let Some(from_us) = filter.from_us {
        sql.push_str(" AND time >= ?");
        values.push(Value::Integer(from_us));
    }
    if let Some(to_us) = filter.to_us {
        sql.push_str(" AND time <= ?");
        values.push(Value::Integer(to_us));
    }
    if let Some(node_id) = &filter.node_id {
        sql.push_str(" AND node_id = ?");
        values.push(Value::Text(node_id.clone()));
    }
    if let Some(subnet) = &filter.subnet {
        sql.push_str(" AND ip_in_cidr(source_ip, ?)");
        values.push(Value::Text(subnet.clone()));
    }
    if let Some(client_id) = &filter.client_id {
        sql.push_str(" AND client_id = ?");
        values.push(Value::Text(client_id.clone()));
    }
    if let Some(device_id) = &filter.device_id {
        sql.push_str(" AND device_id = ?");
        values.push(Value::Text(device_id.clone()));
    }
    if let Some(needle) = &filter.client_name_substr {
        sql.push_str(" AND LOWER(client_name) LIKE ? ESCAPE '\\'");
        values.push(Value::Text(like_contains(needle)));
    }
    if let Some(domain) = &filter.domain {
        sql.push_str(" AND query_name = ?");
        values.push(Value::Text(normalize_name(domain)));
    }
    if let Some(needle) = &filter.domain_substr {
        // Skip-scan the distinct names through the (query_name, time) index (a few
        // 10k names even on millions of rows), then fetch rows by exact name. A plain
        // `query_name LIKE '%x%'` scans the whole table for every search.
        sql.push_str(
            " AND query_name IN (
                 WITH RECURSIVE n(name) AS (
                     SELECT MIN(query_name) FROM query_log
                     UNION ALL
                     SELECT (SELECT MIN(query_name) FROM query_log WHERE query_name > n.name)
                     FROM n WHERE name IS NOT NULL
                 )
                 SELECT name FROM n WHERE name LIKE ? ESCAPE '\\'
             )",
        );
        values.push(Value::Text(like_contains(needle)));
    }
    if let Some(protocol) = &filter.protocol {
        sql.push_str(" AND protocol = ?");
        values.push(Value::Integer(ProtocolCode::from_str(protocol).as_i64()));
    }
    if let Some(query_type) = &filter.query_type {
        if let Some(code) = parse_query_type(query_type) {
            sql.push_str(" AND query_type = ?");
            values.push(Value::Integer(i64::from(code)));
        } else {
            // Unknown mnemonic: match nothing rather than scan as text.
            sql.push_str(" AND 0");
        }
    }
    if let Some(view_id) = &filter.view_id {
        sql.push_str(" AND view_id = ?");
        values.push(Value::Text(view_id.clone()));
    }
    if let Some(profile_id) = &filter.profile_id {
        sql.push_str(" AND profile_id = ?");
        values.push(Value::Text(profile_id.clone()));
    }
    if let Some(status) = &filter.status {
        if status == "cache" {
            // New rows set `cached`; legacy fat blobs still expose steps in record.
            sql.push_str(
                " AND (cached = 1 OR EXISTS (
                     SELECT 1 FROM query_log_record r, json_each(r.record, '$.steps') AS step
                     WHERE r.node_id = query_log.node_id AND r.id = query_log.id
                       AND json_extract(step.value, '$.stage') = 'resolve'
                       AND json_extract(step.value, '$.source') = 'cache'
                   ) OR EXISTS (
                     SELECT 1 FROM query_log_detail d, json_each(d.detail, '$.steps') AS step
                     WHERE d.node_id = query_log.node_id AND d.id = query_log.id
                       AND json_extract(step.value, '$.stage') = 'resolve'
                       AND json_extract(step.value, '$.source') = 'cache'
                   ))",
            );
        } else {
            sql.push_str(" AND status = ?");
            values.push(Value::Integer(StatusCode::from_str(status).as_i64()));
        }
    }
    if filter.only_blocked {
        sql.push_str(" AND status = ?");
        values.push(Value::Integer(StatusCode::Blocked.as_i64()));
    }
    if filter.only_with_clients {
        sql.push_str(
            " AND (client_name IS NOT NULL OR client_id IS NOT NULL OR device_id IS NOT NULL)",
        );
    }
    (sql, values)
}

/// Denormalised insert row plus its full JSON record.
/// One query-log row as streamed by a sub-node.
///
/// The shape is the wire document produced by [`QueryLog::outbox_rows`]: the
/// denormalised columns plus the stored record document. `node_id` and `seq`
/// come from the batch envelope, never from this payload.
#[derive(serde::Deserialize)]
struct RemoteRow {
    id: String,
    time_us: i64,
    source_ip: String,
    query_name: String,
    listener_id: String,
    protocol: String,
    source_ip_truncated: bool,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_name: Option<String>,
    query_type: String,
    query_class: String,
    view_id: String,
    profile_id: String,
    status: String,
    answer_source: String,
    rcode: String,
    #[serde(default = "empty_record")]
    record: Json,
}

/// Per-field limits for a streamed log row. A faulty or malicious node must
/// not be able to bloat the master's database with oversized strings or a
/// deeply padded record document.
const MAX_REMOTE_ID: usize = 64;
const MAX_REMOTE_QUERY_NAME: usize = 255;
const MAX_REMOTE_LABEL: usize = 128;
const MAX_REMOTE_RECORD_BYTES: usize = 64 * 1024;

impl RemoteRow {
    /// Rejects a row whose fields exceed the documented bounds or carry a
    /// value outside the protocol's enums.
    fn validate(&self) -> Result<(), ControlApiError> {
        let invalid = |reason: &str| ControlApiError::QueryLogInvalid {
            reason: reason.to_owned(),
        };
        if self.id.len() > MAX_REMOTE_ID {
            return Err(invalid("remote log id is too long"));
        }
        if self.source_ip.parse::<IpAddr>().is_err() {
            return Err(invalid("remote log source_ip is not an IP address"));
        }
        if self.query_name.len() > MAX_REMOTE_QUERY_NAME {
            return Err(invalid("remote log query_name is too long"));
        }
        for (name, value) in [
            ("listener_id", &self.listener_id),
            ("query_type", &self.query_type),
            ("query_class", &self.query_class),
            ("view_id", &self.view_id),
            ("profile_id", &self.profile_id),
            ("answer_source", &self.answer_source),
            ("rcode", &self.rcode),
        ] {
            if value.len() > MAX_REMOTE_LABEL {
                return Err(invalid(&format!("remote log {name} is too long")));
            }
        }
        if self
            .client_id
            .as_ref()
            .is_some_and(|value| value.len() > MAX_REMOTE_LABEL)
        {
            return Err(invalid("remote log client_id is too long"));
        }
        if self
            .client_name
            .as_ref()
            .is_some_and(|value| value.len() > MAX_REMOTE_LABEL)
        {
            return Err(invalid("remote log client_name is too long"));
        }
        if self
            .record
            .get("device_id")
            .and_then(Json::as_str)
            .is_some_and(|value| value.len() > MAX_REMOTE_LABEL)
        {
            return Err(invalid("remote log device_id is too long"));
        }
        if !matches!(
            self.protocol.as_str(),
            "udp53" | "tcp53" | "dot" | "doh" | "doq"
        ) {
            return Err(invalid("remote log protocol is not a known protocol"));
        }
        if !matches!(
            self.status.as_str(),
            "blocked" | "servfail" | "dnssec_bogus" | "allowed"
        ) {
            return Err(invalid("remote log status is not a known status"));
        }
        let record_size = serde_json::to_string(&self.record)
            .map_err(|_| invalid("remote log record is not serializable"))?
            .len();
        if record_size > MAX_REMOTE_RECORD_BYTES {
            return Err(invalid("remote log record is too large"));
        }
        Ok(())
    }
}

fn empty_record() -> Json {
    json!({})
}

struct PreparedRow {
    id: String,
    time_us: i64,
    node_id: String,
    source_ip: String,
    query_name: String,
    listener_id: String,
    protocol: i64,
    source_ip_truncated: bool,
    client_id: Option<String>,
    client_name: Option<String>,
    device_id: Option<String>,
    query_type: i64,
    query_class: i64,
    view_id: String,
    profile_id: String,
    status: i64,
    answer_source: i64,
    rcode: i64,
    record: String,
    detail: Option<String>,
    cached: i64,
}

fn prepare_row(
    event: &QueryEvent,
    node_id: &str,
    config: &QueryLogConfig,
    enricher: Option<&dyn ClientEnricher>,
) -> Result<PreparedRow, ControlApiError> {
    let id = new_id()?;
    let (source_ip, truncated) = truncate_ip(event.source, config.ip_truncate);
    let client_id = event
        .client_id
        .as_ref()
        .or(event.decision.client_id.as_ref())
        .map(|id| id.as_str().to_owned());
    let directory = enricher.and_then(|enricher| enricher.by_ip(event.source));
    // The directory client id is the stable device key; a registered DoH Client ID
    // carries the same id in `client_device`.
    let device_id = directory
        .as_ref()
        .filter(|client| {
            matches!(client.source.as_str(), "unifi" | "manual") && !client.id.is_empty()
        })
        .map(|client| client.id.clone())
        .or_else(|| event.decision.client_device.as_deref().map(str::to_owned));
    let client = resolve_client(
        directory,
        client_id.as_deref(),
        event.decision.client_label.as_deref(),
    );
    let client_name = client.as_ref().map(|client| client.display_name.clone());
    let query_name = normalize_name(&event.query.name.to_string());
    let protocol = ProtocolCode::from_dns(event.protocol);
    let status = StatusCode::from_str(status_str(&event.decision, event.rcode));
    let answer_source = AnswerSourceCode::from_origin(event.decision.answer_source);
    let decision = &event.decision;
    let cached = decision.steps.iter().any(|step| {
        matches!(
            step,
            DecisionStep::Resolve {
                source: AnswerSource::Cache,
                ..
            }
        )
    });
    let mut record = json!({
        "client": client.as_ref().map(client_json),
        "filter_set": decision.filter_set.as_str(),
        "filter": decision.filter.as_ref().map(filter_json),
        "dnssec": decision.dnssec.map(dnssec_str),
        "forward_zone": decision.forward_zone.as_ref().map(|zone| zone.as_str()),
        "answer_size": event.answer_size,
        "time": format_rfc3339_micros(event.time),
        "selection": selection_json(decision.selection),
        "steps": decision.steps.iter().map(step_json).collect::<Vec<_>>(),
        "timings": {
            "select_us": decision.timings.select_us,
            "filter_us": decision.timings.filter_us,
            "resolve_us": decision.timings.resolve_us,
            "total_us": decision.timings.total_us,
        },
    });
    // Omitted when empty (blocked / failed answers): keeps the stored row small.
    if !event.answers.is_empty() {
        record["answers"] = event
            .answers
            .iter()
            .map(|answer| json!({ "type": answer.rtype, "data": answer.data, "ttl": answer.ttl }))
            .collect();
    }
    if let Some(peer_ip) = event.peer_ip {
        let (peer, _) = truncate_ip(peer_ip, config.ip_truncate);
        record["peer_ip"] = json!(peer.to_string());
    }
    let (slim, detail) = split_record(record, status);
    Ok(PreparedRow {
        id,
        time_us: system_time_micros(event.time),
        node_id: node_id.to_owned(),
        source_ip: source_ip.to_string(),
        query_name,
        listener_id: event.listener_id.as_str().to_owned(),
        protocol: protocol.as_i64(),
        source_ip_truncated: truncated,
        client_id,
        client_name,
        device_id,
        query_type: i64::from(event.query.qtype.value()),
        query_class: i64::from(event.query.qclass.value()),
        view_id: decision.view_id.as_str().to_owned(),
        profile_id: decision.profile_id.as_str().to_owned(),
        status: status.as_i64(),
        answer_source: answer_source.as_i64(),
        rcode: i64::from(event.rcode.value()),
        record: slim.to_string(),
        detail: detail.map(|value| value.to_string()),
        cached: i64::from(cached),
    })
}

/// Applies the configured truncation to one source address.
///
/// `last_octet` only affects IPv4 (`x.x.x.0`); `last_group` only affects IPv6
/// (first 48 bits). The boolean is true when the address was actually changed.
fn truncate_ip(ip: IpAddr, mode: IpTruncate) -> (IpAddr, bool) {
    match (ip, mode) {
        (IpAddr::V4(v4), IpTruncate::LastOctet) => {
            let octets = v4.octets();
            (
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 0)),
                true,
            )
        }
        (IpAddr::V6(v6), IpTruncate::LastGroup) => {
            let segments = v6.segments();
            (
                IpAddr::V6(Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    0,
                    0,
                    0,
                    0,
                    0,
                )),
                true,
            )
        }
        (ip, _) => (ip, false),
    }
}

/// Normalizes an owner name for storage/filtering (lowercase, no trailing dot).
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Builds a `LIKE` needle that treats `%`, `_` and `\` as literals.
fn like_contains(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len() + 2);
    escaped.push('%');
    for ch in raw.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch.to_ascii_lowercase());
    }
    escaped.push('%');
    escaped
}

pub(crate) use crate::query_log_wire::{decision_record_json, resolve_client};

/// Generates an opaque, UUID-shaped record id (16 random bytes, v4 layout).
pub(crate) fn new_id() -> Result<String, ControlApiError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ControlApiError::Internal {
            message: "query-log id generation failed".to_owned(),
        })?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
}

/// Maps a storage failure on a query-log read to `control_api.query_log.read`
/// (GA17), not the generic internal error.
fn read_error(error: ControlApiError) -> ControlApiError {
    ControlApiError::QueryLogRead {
        message: error.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use dnscraft_common::clock::ManualClock;

    #[test]
    fn cidr_matching() {
        assert!(ip_in_cidr("172.20.20.163", "172.20.20.0/24"));
        assert!(!ip_in_cidr("172.20.21.1", "172.20.20.0/24"));
        assert!(ip_in_cidr("10.0.0.7", "10.0.0.7"));
        assert!(ip_in_cidr("1.2.3.4", "0.0.0.0/0"));
        assert!(ip_in_cidr(
            "fd20:1082:556b:f13c::f2b9",
            "fd20:1082:556b::/48"
        ));
        assert!(!ip_in_cidr("fd20:1082:556b::1", "172.20.20.0/24"));
        assert!(!ip_in_cidr("garbage", "10.0.0.0/8"));
        assert!(parse_cidr("10.0.0.0/33").is_none());
    }

    #[test]
    fn storage_failures_on_reads_use_the_query_log_read_code() {
        let storage = ControlApiError::Internal {
            message: "disk I/O error".to_owned(),
        };
        assert_eq!(read_error(storage).code(), "control_api.query_log.read");
    }
    use dnscraft_filtering::SetId;
    use dnscraft_policy::{
        AnswerOrigin, ChainHop, DecisionRecord, DecisionTimings, DnsProtocol, ListenerId,
        ProfileId, SelectionCause, ViewId,
    };
    use dnscraft_proto::{Class, Name, Rcode, RecordType};
    use dnscraft_resolver::{DnssecStatus, Query};

    fn event(name: &str, time: SystemTime) -> QueryEvent {
        QueryEvent {
            time,
            protocol: DnsProtocol::Udp53,
            listener_id: ListenerId::new("lan-udp").unwrap(),
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            peer_ip: None,
            client_id: None,
            query: Query {
                name: Name::from_ascii(&format!("{name}.example.com.")).unwrap(),
                qtype: RecordType::A,
                qclass: Class::IN,
            },
            rcode: Rcode::NOERROR,
            answer_size: 100,
            answers: Vec::new(),
            duration: Duration::from_millis(1),
            decision: DecisionRecord {
                view_id: ViewId::new("lan").unwrap(),
                profile_id: ProfileId::new("default").unwrap(),
                selection: SelectionCause::Default,
                client_id: None,
                client_label: None,
                client_device: None,
                filter_set: SetId::new("default").unwrap(),
                steps: Vec::new(),
                filter: None,
                forward_zone: None,
                dnssec: Some(DnssecStatus::Insecure),
                answer_source: AnswerOrigin::Resolver,
                timings: DecisionTimings {
                    select_us: 0,
                    filter_us: 0,
                    resolve_us: 0,
                    total_us: 0,
                },
                rcode: Rcode::NOERROR,
            },
            loggable: true,
        }
    }

    async fn stored_seqs(db: &Db) -> Vec<i64> {
        db.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT seq FROM query_log ORDER BY seq")
                .map_err(db_err)?;
            let rows = stmt.query_map([], |row| row.get(0)).map_err(db_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn seq_is_monotonic_and_allocated_in_the_insert_transaction() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let db = Db::open_in_memory(Arc::new(ManualClock::new(now)))
            .await
            .unwrap();
        let log = QueryLog::new(db.clone(), QueryLogConfig::default(), "node-a");

        log.insert_batch(vec![event("a", now), event("b", now), event("c", now)])
            .await
            .unwrap();
        assert_eq!(stored_seqs(&db).await, vec![1, 2, 3]);

        // Fail the second batch mid-transaction: no row and no `seq`
        // allocation may survive.
        db.with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_bad BEFORE INSERT ON query_log
                 WHEN NEW.query_name = 'bad.example.com'
                 BEGIN SELECT RAISE(ABORT, 'boom'); END;",
            )
            .map_err(db_err)
        })
        .await
        .unwrap();
        assert!(
            log.insert_batch(vec![event("d", now), event("bad", now), event("e", now)])
                .await
                .is_err()
        );
        assert_eq!(stored_seqs(&db).await, vec![1, 2, 3]);

        // The rolled-back allocation is reused: the next batch starts at 4.
        db.with_conn(|conn| conn.execute_batch("DROP TRIGGER fail_bad").map_err(db_err))
            .await
            .unwrap();
        log.insert_batch(vec![event("f", now)]).await.unwrap();
        assert_eq!(stored_seqs(&db).await, vec![1, 2, 3, 4]);
    }

    fn directory_client(name: &str) -> ClientView {
        ClientView {
            id: "dir-1".to_owned(),
            display_name: name.to_owned(),
            source: "manual".to_owned(),
            ..ClientView::default()
        }
    }

    #[test]
    fn client_label_is_used_when_no_directory_match() {
        let client = resolve_client(None, Some("anna-phone"), Some("Anna's iPhone")).unwrap();
        assert_eq!(client.id, "anna-phone");
        assert_eq!(client.display_name, "Anna's iPhone");
        assert_eq!(client.source, "client_id");
        assert!(client.macs.is_empty());
        assert_eq!(client.vlan_id, None);
        assert_eq!(client.local_domain, None);
    }

    #[test]
    fn directory_name_wins_over_client_label() {
        let client = resolve_client(
            Some(directory_client("iPhone")),
            Some("anna-phone"),
            Some("Anna's iPhone"),
        )
        .unwrap();
        assert_eq!(client.id, "dir-1");
        assert_eq!(client.display_name, "iPhone");
        assert_eq!(client.source, "manual");
    }

    #[test]
    fn client_id_without_label_uses_the_id_as_the_name() {
        let client = resolve_client(None, Some("anna-phone"), None).unwrap();
        assert_eq!(client.id, "anna-phone");
        assert_eq!(client.display_name, "anna-phone");
        assert_eq!(client.source, "client_id");
        assert_eq!(resolve_client(None, None, Some("Anna's iPhone")), None);
        assert_eq!(resolve_client(None, None, None), None);
        let directory = directory_client("iPhone");
        assert_eq!(
            resolve_client(Some(directory.clone()), None, None),
            Some(directory)
        );
    }

    #[test]
    fn cname_chain_step_json_lists_each_hop_and_addresses() {
        use dnscraft_filtering::{ListId, Reason, RuleSource, Verdict};
        let reason = Reason {
            rule: std::sync::Arc::from("||tracker.example.test^"),
            source: RuleSource::List {
                list: ListId::new("ads").unwrap(),
                line: 3,
            },
            important: false,
        };
        let step = DecisionStep::CnameChain {
            hops: vec![
                ChainHop {
                    name: "a.example.test".into(),
                    verdict: Verdict::Pass,
                },
                ChainHop {
                    name: "tracker.example.test".into(),
                    verdict: Verdict::Blocked(reason),
                },
            ],
            addresses: vec!["192.0.2.1".parse().unwrap()],
        };
        assert_eq!(
            step_json(&step),
            json!({
                "stage": "cname_chain",
                "verdict": "resolved",
                "hops": [
                    {
                        "name": "a.example.test",
                        "verdict": "pass",
                        "rule_text": null,
                        "list_id": null,
                        "source": null,
                        "important": false,
                    },
                    {
                        "name": "tracker.example.test",
                        "verdict": "blocked",
                        "rule_text": "||tracker.example.test^",
                        "list_id": "ads",
                        "source": "list",
                        "important": false,
                    },
                ],
                "addresses": ["192.0.2.1"],
            })
        );
    }
}
