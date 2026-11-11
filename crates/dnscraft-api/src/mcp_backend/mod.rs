//! [`McpBackend`](dnscraft_mcp::backend::McpBackend) implementation backed by
//! the control-api services and module engines.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use dnscraft_filtering::{
    DomainName, FilterEngine, TempAllow,
};
use dnscraft_listeners::ListenersStatus;
use dnscraft_mcp::ProtectedDomains;
use dnscraft_mcp::backend::{BackendError, McpBackend};
use dnscraft_mcp::dto::{
    AddRuleParams, AddRuleResult, AuditEntry, AuditResult, CancelTempAllowParams,
    CancelTempAllowResult, ClassifyDomainResult, ClientListParams, ClientListResult,
    DeleteZoneRecordParams, DeleteZoneRecordResult, DnssecCounts, DomainStatsParams,
    DomainZoneSummary, ExplainBlockResult, FilterListSummary, FilterSetSummary,
    FilteringStatus, FlushCacheParams, FlushCacheResult, ListAlertsResult,
    ListBlockedServicesResult, ListDomainZonesResult, ListFilterListsResult, ListFilterSetsResult,
    ListListenersResult, ListPolicyRecordsResult, ListPolicyViewsResult,
    ListResolverUpstreamsResult, ListRulesParams, ListRulesResult, ListZoneRecordsResult, NodeStatus, PauseDuration, PauseParams, PauseResult, PolicyViewSummary,
    QType, QueryDetail,
    QueryLogResult, QueryLogSearch, RemoveRuleParams, RemoveRuleResult,
    ResolveClientParams, ResolverStatus, ResumeResult, Selection, SetBlockedServiceParams,
    SetBlockedServiceResult, StatsParams, StatsPeriod, StatsResult, StatsTimeseriesParams, TempAllowParams, TempAllowResult,
    TestQueryResult, TlsStatus, TokenInfo, UpstreamStatusItem, ZoneRecord,
    ZoneRecordWriteParams, ZoneRecordWriteResult,
};
use dnscraft_mcp::tracker_kind::tracker_kind;
use dnscraft_proto::Name;
use dnscraft_resolver::{FlushScope, PrimingStatus, Resolver};
use serde_json::{Value, json};

use crate::api::clients_routes::ClientDirectory;
use crate::api::config_routes::array;
use crate::api::filter_routes::ServiceCatalogProvider;
use crate::audit::Audit;
use crate::config_apply::{ConfigActor, ConfigService, MutationAudit};
use crate::error::ControlApiError;
use crate::query_log::{QueryLog, QueryLogFilter};
use crate::server::AppState;
use crate::stats::{StatsScope, TopBy};
use crate::tls::TlsAdmin;
use crate::tls::TlsStatusProvider;
use dnscraft_common::clock::Clock;

mod rules;
mod shared;
mod snapshot;

pub(crate) use rules::{explain, list_mcp_rules, run_test_query};
pub(crate) use shared::{rfc3339, stored_time};
pub(crate) use snapshot::{
    PROPOSAL_LIFETIME, active_rule, add_proposal_to_snapshot, add_rule_to_snapshot,
    append_custom_rule, canonical_allow_domain, canonical_block_rule, duration_error,
    duration_exceeds, engine_error, exception_rule_text, find_proposal, mcp_error,
    parse_set, protected_for, reject_protected, remove_rule_from_snapshot, resolve_set_for_write,
    set_mut, take_proposal, unknown_set,
};

use rules::{find_stored_rule, stored_rule_info};
use shared::{
    backend_error, client_info, code_err, duration_secs, json_opt_str, json_str, listener_status,
    map_mcp_scope, non_empty, parse_time, query_entry, query_log_error, query_order, query_order_by,
};
use snapshot::{prepare_add, prepare_remove, upstream_state_str};


/// Master broadcast handle shared with [`AppState`](crate::AppState).
///
/// Starts empty: a standalone node or sub-node never attaches a handle, and
/// every broadcast is then a no-op.
pub(crate) type SharedClusterBroadcast = Arc<Mutex<Option<dnscraft_cluster::ClusterBroadcast>>>;

/// Reads the live listener-set status (GM4). The binary passes a closure over
/// its listener set, so the backend never owns the set.
pub type ListenersSource = Arc<dyn Fn() -> ListenersStatus + Send + Sync>;

/// Active alerts for MCP (`list_alerts` / `dnscraft://alerts`).
pub type AlertsSource = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<Value>> + Send>>
        + Send
        + Sync,
>;

/// Service handles the MCP backend needs.
///
/// The production assembler builds this with [`mcp_backend_inner`] and attaches
/// it with [`AppState::with_mcp_backend`](crate::AppState::with_mcp_backend).
#[derive(Clone)]
pub struct McpBackendInner {
    pub(crate) policy: Option<Arc<dnscraft_policy::PolicyEngine>>,
    pub(crate) filter: Option<Arc<FilterEngine>>,
    pub(crate) query_log: Option<Arc<QueryLog>>,
    pub(crate) tokens: Option<crate::api::auth::TokenStore>,
    pub(crate) audit: Option<Arc<Audit>>,
    pub(crate) config: Option<Arc<ConfigService>>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) tls: Option<Arc<dyn TlsStatusProvider>>,
    /// Recursive resolver for the `resolver` block of `get_status` (GM4).
    pub(crate) resolver: Option<Arc<Resolver>>,
    /// Client directory for `list_clients` (GM3).
    pub(crate) clients: Option<Arc<dyn ClientDirectory>>,
    /// Listener-set status for the `listeners` block of `get_status` (GM4).
    pub(crate) listeners: Option<ListenersSource>,
    pub(crate) node_id: String,
    pub(crate) version: String,
    pub(crate) start_time: std::time::Instant,
    /// MCP limits, protected-domain additions and the write-tools gate.
    pub(crate) mcp_config: dnscraft_mcp::McpConfig,
    /// OIDC issuer URL whose host is protected, when OIDC is enabled.
    pub(crate) oidc_issuer: Option<String>,
    /// Master broadcast handle; `None` on a standalone or sub-node runtime.
    pub(crate) cluster_broadcast: SharedClusterBroadcast,
    /// Optional alerts collector wired at MCP mount time.
    pub(crate) list_alerts: Option<AlertsSource>,
    /// Public DNS zone admin (optional).
    pub(crate) tls_admin: Option<Arc<dyn TlsAdmin>>,
    /// Blocked-services catalog (optional).
    pub(crate) service_catalog: Option<Arc<dyn ServiceCatalogProvider>>,
}

/// Builds the production MCP backend's inner handle (D3).
///
/// The `dnscraft` binary is the only caller. It hands over the live engines and
/// stores plus the status providers the tools read; no secret material (token
/// plaintext, OIDC client secret, TLS private key) is accepted or stored. The
/// backend validates tokens against `tokens` and writes through `config` under
/// its apply lock.
///
/// `query_log` is `None` until the SQLite query-log consumer lands (AS12);
/// the log-reading tools then report `control_api.internal` until it is wired.
/// A standalone node leaves the cluster broadcast handle empty.
///
/// `clients`, `resolver` and `listeners` back `list_clients` and the
/// `resolver`/`listeners` blocks of `get_status` (GM3/GM4).
#[allow(clippy::too_many_arguments)]
pub fn mcp_backend_inner(
    filter: Arc<FilterEngine>,
    policy: Arc<dnscraft_policy::PolicyEngine>,
    query_log: Option<Arc<QueryLog>>,
    config: Arc<ConfigService>,
    audit: Arc<Audit>,
    tokens: crate::api::auth::TokenStore,
    clock: Arc<dyn Clock>,
    tls: Option<Arc<dyn TlsStatusProvider>>,
    clients: Arc<dyn ClientDirectory>,
    resolver: Arc<Resolver>,
    listeners: ListenersSource,
    node_id: impl Into<String>,
    version: impl Into<String>,
    mcp_config: dnscraft_mcp::McpConfig,
    oidc_issuer: Option<String>,
    tls_admin: Option<Arc<dyn TlsAdmin>>,
    service_catalog: Option<Arc<dyn ServiceCatalogProvider>>,
) -> Arc<McpBackendInner> {
    Arc::new(McpBackendInner {
        policy: Some(policy),
        filter: Some(filter),
        query_log,
        tokens: Some(tokens),
        audit: Some(audit),
        config: Some(config),
        clock,
        tls,
        resolver: Some(resolver),
        clients: Some(clients),
        listeners: Some(listeners),
        node_id: node_id.into(),
        version: version.into(),
        start_time: std::time::Instant::now(),
        mcp_config,
        oidc_issuer,
        cluster_broadcast: Arc::new(Mutex::new(None)),
        list_alerts: None,
        tls_admin,
        service_catalog,
    })
}

impl McpBackendInner {
    /// Attach an alerts source (typically `collect_alerts` on [`AppState`]).
    pub(crate) fn with_list_alerts(self: Arc<Self>, source: AlertsSource) -> Arc<Self> {
        Arc::new(Self {
            list_alerts: Some(source),
            ..(*self).clone()
        })
    }

    /// Attaches (or replaces) the master broadcast handle.
    pub(crate) fn attach_cluster_broadcast(&self, broadcast: dnscraft_cluster::ClusterBroadcast) {
        *self
            .cluster_broadcast
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(broadcast);
    }

    /// Pushes a volatile runtime command to connected sub-nodes, if master.
    fn broadcast_runtime_command(&self, kind: &str, payload: &Value) {
        let broadcast = self
            .cluster_broadcast
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(broadcast) = broadcast {
            broadcast.broadcast_runtime_command(kind, payload);
        }
    }
}

pub(crate) struct ControlMcpBackend {
    inner: Arc<McpBackendInner>,
}

impl ControlMcpBackend {
    pub fn new(inner: Arc<McpBackendInner>) -> Self {
        Self { inner }
    }

    async fn write_zone_record(
        &self,
        params: ZoneRecordWriteParams,
        update: bool,
    ) -> Result<ZoneRecordWriteResult, BackendError> {
        let admin = self
            .inner
            .tls_admin
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "domain zones not configured".into(),
            })?;
        let body = json!({
            "name": params.name,
            "type": params.r#type,
            "content": params.content,
            "proxied": params.proxied.unwrap_or(false),
            "ttl": params.ttl.unwrap_or(1),
        });
        let record = if update {
            let record_id = params.record_id.as_deref().ok_or(BackendError::Internal {
                message: "record_id required".into(),
            })?;
            admin
                .update_domain_zone_record(&params.zone_id, record_id, body)
                .await
        } else {
            admin.create_domain_zone_record(&params.zone_id, body).await
        }
        .map_err(|err| BackendError::Internal {
            message: err.to_string(),
        })?;
        Ok(ZoneRecordWriteResult {
            zone_id: params.zone_id,
            record: ZoneRecord {
                id: record
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                name: record
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                r#type: record
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                content: record
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
                proxied: record
                    .get("proxied")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                ttl: record.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            },
        })
    }

    fn filter_engine(&self) -> Result<&Arc<FilterEngine>, BackendError> {
        self.inner
            .filter
            .as_ref()
            .ok_or_else(|| BackendError::Internal {
                message: "filter engine not configured".into(),
            })
    }

    fn policy_engine(&self) -> Result<&Arc<dnscraft_policy::PolicyEngine>, BackendError> {
        self.inner
            .policy
            .as_ref()
            .ok_or_else(|| BackendError::Internal {
                message: "policy engine not configured".into(),
            })
    }

    fn config_service(&self) -> Result<&Arc<ConfigService>, BackendError> {
        self.inner
            .config
            .as_ref()
            .ok_or_else(|| BackendError::Internal {
                message: "config service not configured".into(),
            })
    }

    /// The current stored config snapshot, if any.
    async fn current_snapshot(&self) -> Result<Option<Value>, BackendError> {
        match &self.inner.config {
            Some(service) => Ok(service
                .current()
                .await
                .map(|(_, snapshot)| snapshot)
                .map_err(|e| BackendError::Internal {
                    message: e.code().to_owned(),
                })?),
            None => Ok(None),
        }
    }

    /// Protected domains from the current config plus the owner's additions.
    fn protected(&self, snapshot: Option<&Value>) -> Result<ProtectedDomains, BackendError> {
        protected_for(
            snapshot,
            self.inner.oidc_issuer.as_deref(),
            self.inner.mcp_config.protected_domains.iter().cloned(),
        )
        .map_err(backend_error)
    }
}

/// Builds a read-only backend over `query_log` for integration tests.
///
/// Engines and stores that the read tools do not need are left unconfigured.
#[doc(hidden)]
pub fn mcp_backend_for_test(query_log: Option<Arc<QueryLog>>) -> Arc<dyn McpBackend> {
    Arc::new(ControlMcpBackend::new(Arc::new(McpBackendInner {
        policy: None,
        filter: None,
        query_log,
        tokens: None,
        audit: None,
        config: None,
        clock: Arc::new(dnscraft_common::clock::SystemClock),
        tls: None,
        resolver: None,
        clients: None,
        listeners: None,
        node_id: "test".to_owned(),
        version: "0.0.0".to_owned(),
        start_time: std::time::Instant::now(),
        mcp_config: dnscraft_mcp::McpConfig::default(),
        oidc_issuer: None,
        cluster_broadcast: Arc::new(Mutex::new(None)),
        list_alerts: None,
        tls_admin: None,
        service_catalog: None,
    })))
}

/// Builds a fully-wired backend with the write-side services, for integration
/// tests only.
///
/// [`mcp_backend_for_test`] deliberately leaves the write services unconfigured
/// (the read tools never touch them). This variant wires the engines and stores
/// the read and write tools need, so the real backend can be exercised without
/// a production assembler. Not part of the supported public API.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn mcp_backend_for_test_writes(
    filter: Arc<FilterEngine>,
    policy: Option<Arc<dnscraft_policy::PolicyEngine>>,
    query_log: Option<Arc<QueryLog>>,
    config: Arc<ConfigService>,
    audit: Option<Arc<Audit>>,
    tokens: Option<crate::api::auth::TokenStore>,
    clock: Arc<dyn Clock>,
    mcp_config: dnscraft_mcp::McpConfig,
    oidc_issuer: Option<String>,
) -> Arc<dyn McpBackend> {
    mcp_backend_for_test_writes_with_broadcast(
        filter,
        policy,
        query_log,
        config,
        audit,
        tokens,
        clock,
        mcp_config,
        oidc_issuer,
        Arc::new(Mutex::new(None)),
    )
}

/// [`mcp_backend_for_test_writes`] sharing a caller-supplied broadcast handle,
/// so a test master can attach its [`ClusterBroadcast`](dnscraft_cluster::ClusterBroadcast).
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn mcp_backend_for_test_writes_with_broadcast(
    filter: Arc<FilterEngine>,
    policy: Option<Arc<dnscraft_policy::PolicyEngine>>,
    query_log: Option<Arc<QueryLog>>,
    config: Arc<ConfigService>,
    audit: Option<Arc<Audit>>,
    tokens: Option<crate::api::auth::TokenStore>,
    clock: Arc<dyn Clock>,
    mcp_config: dnscraft_mcp::McpConfig,
    oidc_issuer: Option<String>,
    cluster_broadcast: Arc<Mutex<Option<dnscraft_cluster::ClusterBroadcast>>>,
) -> Arc<dyn McpBackend> {
    Arc::new(ControlMcpBackend::new(Arc::new(McpBackendInner {
        policy,
        filter: Some(filter),
        query_log,
        tokens,
        audit,
        config: Some(config),
        clock,
        tls: None,
        resolver: None,
        clients: None,
        listeners: None,
        node_id: "test".to_owned(),
        version: "0.0.0".to_owned(),
        start_time: std::time::Instant::now(),
        mcp_config,
        oidc_issuer,
        cluster_broadcast,
        list_alerts: None,
        tls_admin: None,
        service_catalog: None,
    })))
}

// ---- trait impl ----

#[async_trait]
impl McpBackend for ControlMcpBackend {
    async fn validate_token(&self, token: &str) -> Result<TokenInfo, BackendError> {
        let store = self.inner.tokens.as_ref().ok_or(BackendError::Internal {
            message: "token store not configured".into(),
        })?;
        match store.authenticate(token).await {
            Ok(principal) => {
                if principal.scope().family() != crate::api::auth::EndpointFamily::Mcp {
                    return Err(BackendError::InvalidScope);
                }
                Ok(TokenInfo {
                    token_id: principal.id().to_owned(),
                    scope: map_mcp_scope(principal.scope()),
                    actor_id: principal.actor_id().to_owned(),
                })
            }
            Err(ControlApiError::AuthUnauthenticated) => Err(BackendError::Unauthenticated),
            Err(e) => Err(BackendError::Internal {
                message: format!("token validation: {}", e.code()),
            }),
        }
    }

    async fn search_query_log(
        &self,
        params: QueryLogSearch,
    ) -> Result<QueryLogResult, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let from_us = parse_time(params.from.as_deref(), "from")?;
        // The MCP bound is exclusive; the query-log filter's is inclusive.
        let to_us = parse_time(params.to.as_deref(), "to")?.map(|to| to.saturating_sub(1));
        let filter = QueryLogFilter {
            from_us,
            to_us,
            node_id: None,
            subnet: None,
            client_id: non_empty(params.client_id),
            client_name_substr: non_empty(params.client_name_substr),
            device_id: None,
            domain: non_empty(params.domain),
            domain_substr: non_empty(params.domain_substr),
            protocol: non_empty(params.protocol),
            query_type: None,
            view_id: non_empty(params.view_id),
            profile_id: non_empty(params.profile_id),
            status: non_empty(params.status),
            only_blocked: params.only_blocked,
            only_with_clients: false,
            order_by: query_order_by(&params.order_by),
            order: query_order(&params.order),
            limit: params.limit,
            offset: u64::from(params.offset),
        };
        let page = log.list(&filter).await.map_err(query_log_error)?;
        Ok(QueryLogResult {
            queries: page.records.iter().map(query_entry).collect(),
            has_more: page.has_more,
            next_offset: page.next_offset.map(|offset| offset as u32),
        })
    }

    async fn get_query(&self, id: &str) -> Result<QueryDetail, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let row = log.get(id).await.map_err(query_log_error)?;
        let row = row.ok_or(BackendError::NotFound {
            what: format!("query {id}"),
        })?;
        Ok(QueryDetail {
            id: json_str(&row, "id"),
            view_id: json_str(&row, "view_id"),
            profile_id: json_str(&row, "profile_id"),
            selection: Selection {
                cause: json_str(&row["selection"], "cause"),
                prefix: json_opt_str(&row["selection"], "prefix"),
                client_id: json_opt_str(&row["selection"], "client_id"),
            },
            steps: row["steps"]
                .as_array()
                .map(|steps| {
                    steps
                        .iter()
                        .map(|s| dnscraft_mcp::dto::DecisionStep {
                            stage: json_str(s, "stage"),
                            verdict: json_str(s, "verdict"),
                            rule: json_opt_str(s, "rule"),
                            list_id: json_opt_str(s, "list_id"),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            filter: json_opt_filter(row.get("filter")),
            dnssec: json_opt_str(&row, "dnssec"),
            answer_source: json_str(&row, "answer_source"),
            rcode: json_str(&row, "rcode"),
            timings: dnscraft_mcp::dto::DecisionTimings {
                select_us: row["timings"]["select_us"].as_u64().unwrap_or(0),
                filter_us: row["timings"]["filter_us"].as_u64().unwrap_or(0),
                total_us: row["timings"]["total_us"].as_u64().unwrap_or(0),
            },
        })
    }

    async fn explain_block(
        &self,
        domain: &str,
        profile_id: Option<&str>,
        qtype: QType,
    ) -> Result<ExplainBlockResult, BackendError> {
        let snapshot = self.current_snapshot().await?;
        explain(
            self.filter_engine()?,
            snapshot.as_ref(),
            self.inner.clock.now(),
            domain,
            profile_id,
            qtype,
        )
        .map_err(backend_error)
    }

    async fn test_query(
        &self,
        params: dnscraft_mcp::dto::TestQueryParams,
    ) -> Result<TestQueryResult, BackendError> {
        run_test_query(
            self.policy_engine()?,
            &params,
            Some(self.inner.node_id.as_str()),
        )
        .await
        .map(|(result, _)| result)
        .map_err(backend_error)
    }

    async fn get_stats(&self, params: StatsParams) -> Result<StatsResult, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let from_us = parse_time(params.from.as_deref(), "from")?;
        // The MCP bound is exclusive; the stats window is inclusive.
        let to_us = parse_time(params.to.as_deref(), "to")?.map(|to| to.saturating_sub(1));
        let stats_err = |what: &str, e: ControlApiError| BackendError::Internal {
            message: format!("{what}: {}", e.code()),
        };
        // GM6: the optional profile filter scopes every stats block.
        let scope = StatsScope {
            node_id: None,
            profile_id: params.profile_id.as_deref(),
        };
        let overview = log
            .stats_overview_scoped(from_us, to_us, scope)
            .await
            .map_err(|e| stats_err("stats overview", e))?;
        let top_clients = log
            .top_clients_scoped(from_us, to_us, scope, 10, TopBy::Queries)
            .await
            .map_err(|e| stats_err("stats top clients", e))?;
        let top_blocked = log
            .top_blocked_domains_scoped(from_us, to_us, scope, 10)
            .await
            .map_err(|e| stats_err("stats top blocked domains", e))?;
        let cache = log
            .cache_stats_scoped(from_us, to_us, scope)
            .await
            .map_err(|e| stats_err("stats cache", e))?;
        let count = |key: &str| overview.dnssec.get(key).copied().unwrap_or(0).max(0) as u64;
        Ok(StatsResult {
            period: StatsPeriod {
                from: overview.from.clone(),
                to: overview.to.clone(),
            },
            total_queries: overview.total.max(0) as u64,
            blocked_queries: overview.blocked.max(0) as u64,
            allowed_queries: overview.allowed.max(0) as u64,
            blocked_ratio: if overview.total <= 0 {
                0.0
            } else {
                overview.blocked as f64 / overview.total as f64
            },
            top_blocked_domains: top_blocked
                .domains
                .into_iter()
                .map(|domain| dnscraft_mcp::dto::TopDomain {
                    domain: domain.domain,
                    count: domain.blocked.max(0) as u64,
                })
                .collect(),
            top_clients: top_clients
                .clients
                .into_iter()
                .map(|client| dnscraft_mcp::dto::TopClient {
                    client_name: client.client_name,
                    queries: client.queries.max(0) as u64,
                })
                .collect(),
            cache_hit_ratio: cache.hit_ratio,
            dnssec: DnssecCounts {
                secure: count("secure"),
                insecure: count("insecure"),
                bogus: count("bogus"),
            },
        })
    }

    async fn list_clients(
        &self,
        params: dnscraft_mcp::dto::ClientListParams,
    ) -> Result<dnscraft_mcp::dto::ClientListResult, BackendError> {
        // GM3: filter the directory snapshot, then page it.
        let directory = self.inner.clients.clone();
        let matching: Vec<dnscraft_mcp::dto::ClientInfo> = directory
            .map(|d| d.clients())
            .unwrap_or_default()
            .iter()
            .filter(|c| {
                params
                    .source
                    .as_deref()
                    .is_none_or(|source| source == c.source)
            })
            .filter(|c| {
                params
                    .name_substr
                    .as_deref()
                    .is_none_or(|needle| c.name.to_lowercase().contains(&needle.to_lowercase()))
            })
            .map(client_info)
            .collect();
        let offset = params.offset as usize;
        let page: Vec<_> = matching
            .iter()
            .skip(offset)
            .take(params.limit as usize)
            .cloned()
            .collect();
        let next = offset + page.len();
        let has_more = next < matching.len();
        Ok(dnscraft_mcp::dto::ClientListResult {
            clients: page,
            has_more,
            next_offset: has_more.then_some(next as u32),
        })
    }

    async fn get_status(&self) -> Result<NodeStatus, BackendError> {
        let uptime = self.inner.start_time.elapsed().as_secs();
        // GM4: resolver state and listener bindings come from the live handles.
        let (primed, cache_size) = match self.inner.resolver.as_ref() {
            Some(resolver) => (
                matches!(resolver.priming_status(), PrimingStatus::Primed { .. }),
                resolver.stats().cache_entries,
            ),
            None => (false, 0),
        };
        let listeners = self
            .inner
            .listeners
            .as_ref()
            .map(|source| source().listeners.iter().map(listener_status).collect())
            .unwrap_or_default();
        let tls = self
            .inner
            .tls
            .as_ref()
            .map(|p| {
                let status = p.status();
                TlsStatus {
                    mode: status.mode.as_str().to_owned(),
                    cert_expiry: status.not_after.map(rfc3339).unwrap_or_default(),
                    fingerprint: status.fingerprint,
                }
            })
            .unwrap_or_default();
        // Filter-list counters come from the engine's per-list status. The
        // rule count is the parsed list rules only (custom and MCP-created
        // rules are not included).
        let filtering = match self.inner.filter.as_ref() {
            Some(filter) => {
                let lists = filter.list_status();
                let loaded: Vec<_> = lists.iter().filter(|l| l.last_success.is_some()).collect();
                FilteringStatus {
                    lists_loaded: loaded.len() as u64,
                    rules_active: loaded.iter().map(|l| l.rules_parsed).sum(),
                    last_update: loaded
                        .iter()
                        .filter_map(|l| l.last_success)
                        .max()
                        .map(rfc3339)
                        .unwrap_or_default(),
                }
            }
            None => FilteringStatus {
                lists_loaded: 0,
                rules_active: 0,
                last_update: String::new(),
            },
        };
        Ok(NodeStatus {
            node_id: self.inner.node_id.clone(),
            version: self.inner.version.clone(),
            uptime_seconds: uptime,
            resolver: ResolverStatus { primed, cache_size },
            listeners,
            tls,
            filtering,
        })
    }

    async fn list_mcp_rules(
        &self,
        params: ListRulesParams,
    ) -> Result<ListRulesResult, BackendError> {
        let snapshot = match &self.inner.config {
            Some(service) => {
                service
                    .current()
                    .await
                    .map_err(|e| BackendError::Internal {
                        message: e.code().to_owned(),
                    })?
                    .1
            }
            None => None,
        };
        list_mcp_rules(
            self.filter_engine()?,
            snapshot.as_ref(),
            self.inner.clock.now(),
            &params,
        )
        .map_err(backend_error)
    }

    async fn allow_temporarily(
        &self,
        params: TempAllowParams,
    ) -> Result<TempAllowResult, BackendError> {
        let filter = self.filter_engine()?;
        if let Some(error) = duration_error(
            params.duration.seconds(),
            self.inner.mcp_config.max_temporary_allow_duration,
        ) {
            return Err(backend_error(error));
        }
        let domain = canonical_allow_domain(&params.domain).map_err(backend_error)?;

        // Hold the config apply lock across the snapshot read, the protected
        // check and the engine mutation, so a concurrent config replace cannot
        // swap the snapshot between the check and the allow (TOCTOU).
        let service = self.inner.config.as_ref();
        let _guard = match service {
            Some(service) => Some(service.apply_guard().await),
            None => None,
        };
        let snapshot = match service {
            Some(service) => {
                service
                    .current()
                    .await
                    .map_err(|e| BackendError::Internal {
                        message: e.code().to_owned(),
                    })?
                    .1
            }
            None => None,
        };
        let set = resolve_set_for_write(snapshot.as_ref(), params.filter_set_id.as_deref())
            .map_err(backend_error)?;
        let protected = self.protected(snapshot.as_ref())?;
        reject_protected(&protected, domain.as_str(), params.include_subdomains)
            .map_err(backend_error)?;

        let now = self.inner.clock.now();
        let until = now + duration_secs(params.duration);
        let rule = TempAllow {
            domain: domain.clone(),
            include_subdomains: params.include_subdomains,
            until,
            created_at: now,
        };
        filter
            .allow_temporarily(&set, rule)
            .map_err(|err| backend_error(engine_error(err, set.as_str())))?;
        self.inner.broadcast_runtime_command(
            "temporary_allow",
            &json!({
                "filter_set_id": set.as_str(),
                "domain": domain.as_str(),
                "include_subdomains": params.include_subdomains,
                "expires_at": rfc3339(until),
            }),
        );
        Ok(TempAllowResult {
            created_at: rfc3339(now),
            expires_at: rfc3339(until),
            filter_set_id: set.as_str().to_owned(),
        })
    }

    async fn add_custom_rule(&self, params: AddRuleParams) -> Result<AddRuleResult, BackendError> {
        let service = self.config_service()?;
        let actor = ConfigActor::new(params.token_id.clone(), "token");
        let failure_after = json!({
            "domain": params.domain.clone(),
            "include_subdomains": params.include_subdomains,
            "filter_set_id": params.filter_set_id.clone(),
            "reason": params.reason.clone(),
        });

        // Everything before the mutation is validated up front so its failure
        // can be audited; the mutation closure then only depends on the locked
        // snapshot (protected coverage + cap).
        let (set, domain, rule_text, lifetime) =
            match prepare_add(&params, self.inner.mcp_config.max_block_rule_lifetime) {
                Ok(prepared) => prepared,
                Err(err) => {
                    service
                        .record_action(
                            &actor,
                            "mcp.add_rule",
                            None,
                            Some(&failure_after),
                            Some(err.code()),
                        )
                        .await;
                    return Err(backend_error(err));
                }
            };
        let now = self.inner.clock.now();
        let expires_at = now + lifetime;
        let created_secs = dnscraft_common::clock::unix_seconds(now);
        let expires_secs = dnscraft_common::clock::unix_seconds(expires_at);
        let rule_id = crate::query_log::new_id().map_err(backend_error)?;
        let cap = self.inner.mcp_config.max_custom_rules_per_set as usize;
        let include = params.include_subdomains;
        let token_id = params.token_id.clone();
        let reason = params.reason.clone();
        let issuer = self.inner.oidc_issuer.clone();
        let extra = self.inner.mcp_config.protected_domains.clone();
        let rule_id_for_audit = rule_id.clone();
        let rule_text_for_audit = rule_text.clone();
        let set_str = set.as_str().to_owned();
        let set_for_audit = set_str.clone();
        let domain_for_audit = domain.as_str().to_owned();
        let created_for_audit = rfc3339(now);
        let expires_for_audit = rfc3339(expires_at);

        let version = service
            .mutate_audited(
                &actor,
                "mcp.add_rule",
                Some(failure_after),
                move |snapshot| {
                    let protected = protected_for(Some(snapshot), issuer.as_deref(), extra)?;
                    reject_protected(&protected, domain.as_str(), include)?;
                    add_rule_to_snapshot(
                        snapshot,
                        &set,
                        &domain,
                        include,
                        &rule_id_for_audit,
                        created_secs,
                        expires_secs,
                        &token_id,
                        cap,
                        now,
                    )?;
                    Ok(Some(MutationAudit {
                        before: None,
                        after: json!({
                            "domain": domain_for_audit,
                            "include_subdomains": include,
                            "filter_set_id": set_for_audit,
                            "reason": reason,
                            "rule_text": rule_text_for_audit,
                            "rule_id": rule_id_for_audit,
                            "created_at": created_for_audit,
                            "expires_at": expires_for_audit,
                            "config_version": Value::Null,
                        }),
                    }))
                },
            )
            .await
            .map_err(backend_error)?;
        let version = version
            .and_then(|version| u64::try_from(version).ok())
            .ok_or_else(|| BackendError::Internal {
                message: "custom-rule mutation stored no config version".into(),
            })?;
        Ok(AddRuleResult {
            rule_id,
            rule_text,
            filter_set_id: set_str,
            created_at: rfc3339(now),
            expires_at: rfc3339(expires_at),
            config_version: Some(version),
        })
    }

    async fn propose_exception(
        &self,
        params: dnscraft_mcp::dto::ProposeExceptionParams,
    ) -> Result<dnscraft_mcp::dto::ProposeExceptionResult, BackendError> {
        let service = self.config_service()?;
        let actor = ConfigActor::new(params.token_id.clone(), "token");
        let failure_after = json!({
            "domain": params.domain.clone(),
            "include_subdomains": params.include_subdomains,
            "filter_set_id": params.filter_set_id.clone(),
            "reason": params.reason.clone(),
        });
        let prepared = parse_set(params.filter_set_id.as_deref())
            .and_then(|set| canonical_allow_domain(&params.domain).map(|domain| (set, domain)));
        let (set, domain) = match prepared {
            Ok(prepared) => prepared,
            Err(err) => {
                service
                    .record_action(
                        &actor,
                        "mcp.propose_exception",
                        None,
                        Some(&failure_after),
                        Some(err.code()),
                    )
                    .await;
                return Err(backend_error(err));
            }
        };
        let now = self.inner.clock.now();
        let expires_at = now + PROPOSAL_LIFETIME;
        let created_secs = dnscraft_common::clock::unix_seconds(now);
        let expires_secs = dnscraft_common::clock::unix_seconds(expires_at);
        let proposal_id = crate::query_log::new_id().map_err(backend_error)?;
        let include = params.include_subdomains;
        let issuer = self.inner.oidc_issuer.clone();
        let extra = self.inner.mcp_config.protected_domains.clone();
        let (set_for_mutation, domain_for_mutation) = (set.clone(), domain.clone());
        let (id_for_mutation, reason, token_id) = (
            proposal_id.clone(),
            params.reason.clone(),
            params.token_id.clone(),
        );
        let after = json!({
            "proposal_id": proposal_id,
            "domain": domain.as_str(),
            "include_subdomains": include,
            "filter_set_id": set.as_str(),
            "reason": params.reason,
            "created_at": rfc3339(now),
            "expires_at": rfc3339(expires_at),
        });

        let version = service
            .mutate_audited(
                &actor,
                "mcp.propose_exception",
                Some(failure_after),
                move |snapshot| {
                    let protected = protected_for(Some(snapshot), issuer.as_deref(), extra)?;
                    reject_protected(&protected, domain_for_mutation.as_str(), include)?;
                    let added = add_proposal_to_snapshot(
                        snapshot,
                        &set_for_mutation,
                        &domain_for_mutation,
                        include,
                        &reason,
                        &id_for_mutation,
                        created_secs,
                        expires_secs,
                        &token_id,
                        now,
                    )?;
                    Ok(added.then_some(MutationAudit {
                        before: None,
                        after,
                    }))
                },
            )
            .await
            .map_err(backend_error)?;
        if version.is_some() {
            return Ok(dnscraft_mcp::dto::ProposeExceptionResult {
                proposal_id,
                filter_set_id: set.as_str().to_owned(),
                created_at: rfc3339(now),
                expires_at: rfc3339(expires_at),
            });
        }
        // The same name was already pending: report that proposal.
        let existing = self
            .current_snapshot()
            .await?
            .and_then(|snapshot| find_proposal(&snapshot, &set, &domain, include, now))
            .ok_or_else(|| BackendError::Internal {
                message: "pending proposal vanished".into(),
            })?;
        let time = |key: &str| {
            existing
                .get(key)
                .and_then(stored_time)
                .map(rfc3339)
                .unwrap_or_default()
        };
        Ok(dnscraft_mcp::dto::ProposeExceptionResult {
            proposal_id: json_str(&existing, "id"),
            filter_set_id: set.as_str().to_owned(),
            created_at: time("created_at"),
            expires_at: time("expires_at"),
        })
    }

    async fn find_mcp_rule(
        &self,
        domain: &str,
        filter_set_id: Option<&str>,
    ) -> Result<Option<dnscraft_mcp::dto::McpRuleInfo>, BackendError> {
        let set = parse_set(filter_set_id).map_err(backend_error)?;
        let domain =
            DomainName::parse(domain).map_err(|_| code_err("filter_name.invalid_char", domain))?;
        let Some(snapshot) = self.current_snapshot().await? else {
            return Ok(None);
        };
        let rule = find_stored_rule(&snapshot, &set, &domain).map_err(backend_error)?;
        Ok(rule.and_then(|rule| stored_rule_info(rule, set.as_str())))
    }

    async fn remove_custom_rule(
        &self,
        params: RemoveRuleParams,
    ) -> Result<RemoveRuleResult, BackendError> {
        let service = self.config_service()?;
        let actor = ConfigActor::new(params.token_id.clone(), "token");
        let failure_after = json!({
            "domain": params.domain.clone(),
            "filter_set_id": params.filter_set_id.clone(),
            "removed": false,
            "config_version": Value::Null,
        });
        let (set, domain) = match prepare_remove(&params) {
            Ok(prepared) => prepared,
            Err(err) => {
                service
                    .record_action(
                        &actor,
                        "mcp.remove_rule",
                        None,
                        Some(&failure_after),
                        Some(err.code()),
                    )
                    .await;
                return Err(backend_error(err));
            }
        };
        let set_str = set.as_str().to_owned();
        let issuer = self.inner.oidc_issuer.clone();
        let extra = self.inner.mcp_config.protected_domains.clone();
        let version = service
            .mutate_audited(
                &actor,
                "mcp.remove_rule",
                Some(failure_after),
                move |snapshot| {
                    let protected = protected_for(Some(snapshot), issuer.as_deref(), extra)?;
                    let stored = find_stored_rule(snapshot, &set, &domain)?;
                    let before = stored.map(|rule| {
                        json!({
                            "domain": rule
                                .get("domain")
                                .and_then(Value::as_str)
                                .unwrap_or(domain.as_str()),
                            "include_subdomains": rule
                                .get("include_subdomains")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            "filter_set_id": set.as_str(),
                            "rule_id": rule.get("id").and_then(Value::as_str).unwrap_or_default(),
                        })
                    });
                    let removed = remove_rule_from_snapshot(snapshot, &set, &domain, &protected)?;
                    if !removed {
                        return Ok(None);
                    }
                    let rule_id = before
                        .as_ref()
                        .and_then(|before| before.get("rule_id"))
                        .cloned()
                        .unwrap_or(Value::Null);
                    Ok(Some(MutationAudit {
                        before,
                        after: json!({
                            "domain": domain.as_str(),
                            "filter_set_id": set.as_str(),
                            "removed": true,
                            "rule_id": rule_id,
                            "config_version": Value::Null,
                        }),
                    }))
                },
            )
            .await
            .map_err(backend_error)?;
        let removed = version.is_some();
        let config_version = version
            .map(|version| {
                u64::try_from(version).map_err(|_| BackendError::Internal {
                    message: "negative config version".into(),
                })
            })
            .transpose()?;
        Ok(RemoveRuleResult {
            removed,
            filter_set_id: set_str,
            config_version,
        })
    }

    async fn pause_filter_set(&self, params: PauseParams) -> Result<PauseResult, BackendError> {
        if let Some(error) = duration_error(
            params.duration.seconds(),
            self.inner.mcp_config.max_pause_duration,
        ) {
            return Err(backend_error(error));
        }
        let set = parse_set(params.filter_set_id.as_deref()).map_err(backend_error)?;
        let until = self.inner.clock.now() + duration_secs(params.duration);
        self.filter_engine()?
            .set_paused_until(&set, Some(until))
            .map_err(|err| backend_error(engine_error(err, set.as_str())))?;
        self.inner.broadcast_runtime_command(
            "pause",
            &json!({
                "filter_set_id": set.as_str(),
                "expires_at": rfc3339(until),
            }),
        );
        Ok(PauseResult {
            filter_set_id: set.as_str().to_owned(),
            paused_until: rfc3339(until),
        })
    }

    async fn resume_filter_set(
        &self,
        filter_set_id: Option<&str>,
    ) -> Result<ResumeResult, BackendError> {
        let set = parse_set(filter_set_id).map_err(backend_error)?;
        let filter = self.filter_engine()?;
        let was = filter.paused_until(&set).map(rfc3339);
        filter
            .set_paused_until(&set, None)
            .map_err(|err| backend_error(engine_error(err, set.as_str())))?;
        self.inner
            .broadcast_runtime_command("resume", &json!({ "filter_set_id": set.as_str() }));
        Ok(ResumeResult {
            filter_set_id: set.as_str().to_owned(),
            resumed: was.is_some(),
            was_paused_until: was,
        })
    }

    async fn classify_domain(&self, domain: &str) -> Result<ClassifyDomainResult, BackendError> {
        let canonical = canonical_allow_domain(domain).map_err(backend_error)?;
        let domain_str = canonical.as_str().to_owned();
        let filter = self.filter_engine()?;
        if let Some(db) = filter.trackers()
            && let Some(info) = db.lookup(&domain_str)
        {
            let kind = tracker_kind(&info.category);
            return Ok(ClassifyDomainResult {
                domain: domain_str,
                kind: kind.as_str().to_owned(),
                category: Some(info.category.clone()),
                name: Some(info.name.clone()),
                source: "trackers_db".to_owned(),
            });
        }
        Ok(ClassifyDomainResult {
            domain: domain_str,
            kind: "unknown".to_owned(),
            category: None,
            name: None,
            source: "none".to_owned(),
        })
    }

    async fn list_alerts(&self) -> Result<ListAlertsResult, BackendError> {
        let items = if let Some(source) = &self.inner.list_alerts {
            (source)().await
        } else {
            Vec::new()
        };
        Ok(ListAlertsResult {
            active_count: items.len() as u64,
            items,
        })
    }

    async fn list_filter_lists(&self) -> Result<ListFilterListsResult, BackendError> {
        let snapshot = self.current_snapshot().await?;
        let filter_lists = snapshot
            .as_ref()
            .map(|s| array(s, "filtering", "lists"))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|list| {
                Some(FilterListSummary {
                    id: list.get("id")?.as_str()?.to_owned(),
                    name: list
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    enabled: list
                        .get("enabled")
                        .and_then(|e| e.as_bool())
                        .unwrap_or(true),
                })
            })
            .collect();
        Ok(ListFilterListsResult { filter_lists })
    }

    async fn list_filter_sets(&self) -> Result<ListFilterSetsResult, BackendError> {
        let snapshot = self.current_snapshot().await?;
        let filter_sets = snapshot
            .as_ref()
            .map(|s| array(s, "filtering", "sets"))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|set| {
                Some(FilterSetSummary {
                    id: set.get("id")?.as_str()?.to_owned(),
                    name: set
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_owned(),
                })
            })
            .collect();
        Ok(ListFilterSetsResult { filter_sets })
    }

    async fn list_policy_views(&self) -> Result<ListPolicyViewsResult, BackendError> {
        let snapshot = self.current_snapshot().await?;
        let views = snapshot
            .as_ref()
            .map(|s| array(s, "policy", "views"))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|view| {
                Some(PolicyViewSummary {
                    id: view.get("id")?.as_str()?.to_owned(),
                    profile_id: view
                        .get("profile")
                        .and_then(|p| p.get("id"))
                        .and_then(|id| id.as_str())
                        .unwrap_or("default")
                        .to_owned(),
                    is_default: view
                        .get("is_default")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                })
            })
            .collect();
        Ok(ListPolicyViewsResult { views })
    }

    async fn list_resolver_upstreams(&self) -> Result<ListResolverUpstreamsResult, BackendError> {
        let resolver = self.inner.resolver.as_ref().ok_or(BackendError::Internal {
            message: "resolver not configured".into(),
        })?;
        let items = resolver
            .upstreams()
            .iter()
            .map(|upstream| UpstreamStatusItem {
                address: upstream.name.clone(),
                state: upstream_state_str(upstream.state).to_owned(),
            })
            .collect();
        Ok(ListResolverUpstreamsResult { items })
    }

    async fn list_blocked_services(
        &self,
        locale: Option<&str>,
    ) -> Result<ListBlockedServicesResult, BackendError> {
        let locale = locale.unwrap_or("en");
        let Some(provider) = self.inner.service_catalog.as_ref() else {
            return Ok(ListBlockedServicesResult {
                available: false,
                items: Vec::new(),
            });
        };
        let Some(catalog) = provider.catalog() else {
            return Ok(ListBlockedServicesResult {
                available: false,
                items: Vec::new(),
            });
        };
        let snapshot = self.current_snapshot().await?;
        let sets = snapshot
            .as_ref()
            .map(|s| array(s, "filtering", "sets"))
            .unwrap_or_default();
        let items: Vec<Value> = catalog
            .services()
            .iter()
            .map(|info| {
                let enabled: serde_json::Map<String, Value> = sets
                    .iter()
                    .filter_map(|set| {
                        let id = set.get("id")?.as_str()?;
                        let on = set
                            .get("services")
                            .and_then(Value::as_array)
                            .is_some_and(|list| list.iter().any(|s| s.as_str() == Some(&*info.id)));
                        Some((id.to_owned(), Value::Bool(on)))
                    })
                    .collect();
                json!({
                    "id": &*info.id,
                    "name": catalog.translated_name(&info.id, locale).unwrap_or(&info.name),
                    "enabled": enabled,
                })
            })
            .collect();
        Ok(ListBlockedServicesResult {
            available: true,
            items,
        })
    }

    async fn list_domain_zones(&self) -> Result<ListDomainZonesResult, BackendError> {
        let admin = self
            .inner
            .tls_admin
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "domain zones not configured".into(),
            })?;
        let attached =
            admin
                .attached_domain_zones()
                .await
                .map_err(|err| BackendError::Internal {
                    message: err.to_string(),
                })?;
        let zones = attached
            .get("zones")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|zone| {
                        let name = zone.get("name")?.as_str()?;
                        let id = zone.get("id").and_then(|v| v.as_str()).unwrap_or(name);
                        Some(DomainZoneSummary {
                            id: id.to_owned(),
                            name: name.to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(ListDomainZonesResult { zones })
    }

    async fn list_zone_records(
        &self,
        zone_id: &str,
    ) -> Result<ListZoneRecordsResult, BackendError> {
        let admin = self
            .inner
            .tls_admin
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "domain zones not configured".into(),
            })?;
        let page = admin
            .domain_zone_records(zone_id, 1, 100, None)
            .await
            .map_err(|err| BackendError::Internal {
                message: err.to_string(),
            })?;
        let records = page
            .get("records")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        Some(ZoneRecord {
                            id: row.get("id")?.as_str()?.to_owned(),
                            name: row.get("name")?.as_str()?.to_owned(),
                            r#type: row.get("type")?.as_str()?.to_owned(),
                            content: row.get("content")?.as_str()?.to_owned(),
                            proxied: row
                                .get("proxied")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                            ttl: row.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(ListZoneRecordsResult {
            zone_id: zone_id.to_owned(),
            records,
        })
    }

    async fn list_listeners(&self) -> Result<ListListenersResult, BackendError> {
        let snapshot = self.current_snapshot().await?;
        Ok(ListListenersResult {
            listeners: snapshot
                .as_ref()
                .map(|s| array(s, "listeners", "listeners"))
                .unwrap_or_default(),
        })
    }

    async fn list_policy_records(&self) -> Result<ListPolicyRecordsResult, BackendError> {
        let snapshot = self.current_snapshot().await?;
        let records = snapshot
            .as_ref()
            .and_then(|s| s.get("policy"))
            .and_then(|p| p.get("records"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|item| {
                serde_json::from_value::<dnscraft_policy::ViewRecordConfig>(item)
                    .ok()
                    .and_then(|record| serde_json::to_value(record).ok())
            })
            .collect();
        Ok(ListPolicyRecordsResult { records })
    }

    async fn upsert_policy_record(
        &self,
        params: dnscraft_mcp::dto::UpsertPolicyRecordParams,
    ) -> Result<dnscraft_mcp::dto::UpsertPolicyRecordResult, BackendError> {
        use crate::api::policy_routes::{RecordBody, upsert_policy_record};
        use std::sync::{Arc, Mutex};
        let service = self.config_service()?;
        let body = RecordBody {
            name: params.name,
            rtype: params.r#type,
            ttl: params.ttl,
            rdata: params.rdata,
            overrides: params.overrides.unwrap_or_default(),
            comment: params.comment,
            tags: params.tags,
        };
        let actor = ConfigActor::new("mcp", "token");
        let stored = Arc::new(Mutex::new(Value::Null));
        let stored_slot = Arc::clone(&stored);
        let version = service
            .mutate(&actor, "mcp.upsert_policy_record", move |snapshot| {
                let record = upsert_policy_record(snapshot, body)?;
                *stored_slot.lock().unwrap_or_else(|e| e.into_inner()) = record;
                Ok(true)
            })
            .await
            .map_err(backend_error)?;
        let record = stored.lock().unwrap_or_else(|e| e.into_inner()).clone();
        Ok(dnscraft_mcp::dto::UpsertPolicyRecordResult {
            version: version.unwrap_or(0) as u64,
            record,
        })
    }

    async fn delete_policy_record(
        &self,
        params: dnscraft_mcp::dto::DeletePolicyRecordParams,
    ) -> Result<dnscraft_mcp::dto::DeletePolicyRecordResult, BackendError> {
        use crate::api::policy_routes::{RecordKey, delete_policy_record};
        let service = self.config_service()?;
        let key = RecordKey {
            name: params.name.clone(),
            rtype: params.r#type.clone(),
        };
        let actor = ConfigActor::new("mcp", "token");
        let version = service
            .mutate(&actor, "mcp.delete_policy_record", move |snapshot| {
                delete_policy_record(snapshot, key)?;
                Ok(true)
            })
            .await
            .map_err(backend_error)?;
        Ok(dnscraft_mcp::dto::DeletePolicyRecordResult {
            deleted: true,
            version: version.unwrap_or(0) as u64,
            name: params.name,
            r#type: params.r#type,
        })
    }

    async fn get_domain_stats(&self, params: DomainStatsParams) -> Result<Value, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let domain = DomainName::parse(&params.domain).map_err(|_| {
            backend_error(mcp_error(
                "control_api.stats.invalid_domain",
                json!({ "domain": params.domain }),
            ))
        })?;
        let days = 7_u32;
        let detail = log
            .domain_detail(domain.as_str(), days)
            .await
            .map_err(|e| BackendError::Internal {
                message: e.code().to_owned(),
            })?;
        detail.ok_or(BackendError::NotFound {
            what: format!("domain {}", domain.as_str()),
        })
    }

    async fn get_stats_timeseries(
        &self,
        params: StatsTimeseriesParams,
    ) -> Result<Value, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let from_us = parse_time(params.from.as_deref(), "from")?;
        let to_us = parse_time(params.to.as_deref(), "to")?.map(|to| to.saturating_sub(1));
        let scope = StatsScope {
            node_id: None,
            profile_id: params.profile_id.as_deref(),
        };
        log.timeseries_scoped(from_us, to_us, scope, "hour")
            .await
            .map_err(|e| BackendError::Internal {
                message: e.code().to_owned(),
            })
            .map(|series| serde_json::to_value(series).unwrap_or(Value::Null))
    }

    async fn resolve_client(
        &self,
        params: ResolveClientParams,
    ) -> Result<ClientListResult, BackendError> {
        let page = self
            .list_clients(ClientListParams {
                limit: 500,
                offset: 0,
                name_substr: None,
                source: None,
            })
            .await?;
        let query = params.query.trim();
        let matches: Vec<_> = page
            .clients
            .into_iter()
            .filter(|client| {
                client.display_name.eq_ignore_ascii_case(query)
                    || client.addresses.iter().any(|addr| addr == query)
            })
            .collect();
        if matches.len() > 1 {
            return Err(BackendError::Coded {
                code: "mcp.ambiguous_client".to_owned(),
                params: Some(json!({
                    "query": query,
                    "candidates": matches.iter().map(|c| json!({
                        "id": c.id,
                        "display_name": c.display_name,
                    })).collect::<Vec<_>>(),
                })),
            });
        }
        Ok(ClientListResult {
            clients: matches,
            has_more: false,
            next_offset: None,
        })
    }

    async fn cancel_temporary_allow(
        &self,
        params: CancelTempAllowParams,
    ) -> Result<CancelTempAllowResult, BackendError> {
        let filter = self.filter_engine()?;
        let domain = canonical_allow_domain(&params.domain).map_err(backend_error)?;
        let snapshot = self.current_snapshot().await?;
        let set = resolve_set_for_write(snapshot.as_ref(), params.filter_set_id.as_deref())
            .map_err(backend_error)?;
        let removed = filter
            .remove_temporary_allow(&set, &domain)
            .map_err(|err| backend_error(engine_error(err, set.as_str())))?;
        self.inner.broadcast_runtime_command(
            "remove_temporary_allow",
            &json!({
                "filter_set_id": set.as_str(),
                "domain": domain.as_str(),
            }),
        );
        Ok(CancelTempAllowResult {
            removed,
            filter_set_id: set.as_str().to_owned(),
        })
    }

    async fn flush_cache(
        &self,
        params: FlushCacheParams,
    ) -> Result<FlushCacheResult, BackendError> {
        let resolver = self.inner.resolver.as_ref().ok_or(BackendError::Internal {
            message: "resolver not configured".into(),
        })?;
        let scope = match params.domain.as_deref() {
            None => FlushScope::All,
            Some(raw) => {
                let domain = DomainName::parse(raw).map_err(|_| {
                    backend_error(mcp_error(
                        "control_api.resolver.flush.invalid_domain",
                        json!({ "domain": raw }),
                    ))
                })?;
                FlushScope::Domain(Name::from_ascii(domain.as_str()).map_err(|_| {
                    backend_error(mcp_error(
                        "control_api.resolver.flush.invalid_domain",
                        json!({ "domain": raw }),
                    ))
                })?)
            }
        };
        let _report = resolver.flush(scope);
        Ok(FlushCacheResult {
            flushed: true,
            domain: params.domain,
        })
    }

    async fn set_blocked_service(
        &self,
        params: SetBlockedServiceParams,
    ) -> Result<SetBlockedServiceResult, BackendError> {
        let service = self.config_service()?;
        let snapshot = self.current_snapshot().await?;
        let set = resolve_set_for_write(snapshot.as_ref(), params.filter_set_id.as_deref())
            .map_err(backend_error)?;
        let set_id = set.as_str().to_owned();
        let set_for_mut = set_id.clone();
        let service_id = params.service_id.clone();
        let enabled = params.enabled;
        let actor = ConfigActor::new("mcp", "token");
        let version = service
            .mutate(&actor, "mcp.set_blocked_service", move |snapshot| {
                let set =
                    set_mut(snapshot, &set_for_mut).ok_or_else(|| unknown_set(&set_for_mut))?;
                let list = set
                    .as_object_mut()
                    .ok_or_else(|| {
                        mcp_error(
                            "filtering.config.invalid",
                            json!({ "reason": "set not object" }),
                        )
                    })?
                    .entry("services")
                    .or_insert_with(|| json!([]));
                let list = list.as_array_mut().ok_or_else(|| {
                    mcp_error(
                        "filtering.config.invalid",
                        json!({ "reason": "services not array" }),
                    )
                })?;
                list.retain(|id| id.as_str() != Some(service_id.as_str()));
                if enabled {
                    list.push(json!(service_id));
                }
                Ok(true)
            })
            .await
            .map_err(backend_error)?;
        Ok(SetBlockedServiceResult {
            service_id: params.service_id,
            filter_set_id: set_id,
            enabled: params.enabled,
            config_version: version.map(|v| v as u64),
        })
    }

    async fn create_zone_record(
        &self,
        params: ZoneRecordWriteParams,
    ) -> Result<ZoneRecordWriteResult, BackendError> {
        self.write_zone_record(params, false).await
    }

    async fn update_zone_record(
        &self,
        params: ZoneRecordWriteParams,
    ) -> Result<ZoneRecordWriteResult, BackendError> {
        self.write_zone_record(params, true).await
    }

    async fn delete_zone_record(
        &self,
        params: DeleteZoneRecordParams,
    ) -> Result<DeleteZoneRecordResult, BackendError> {
        let admin = self
            .inner
            .tls_admin
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "domain zones not configured".into(),
            })?;
        admin
            .delete_domain_zone_record(&params.zone_id, &params.record_id)
            .await
            .map_err(|err| BackendError::Internal {
                message: err.to_string(),
            })?;
        Ok(DeleteZoneRecordResult {
            deleted: true,
            zone_id: params.zone_id,
            record_id: params.record_id,
        })
    }

    async fn record_audit(&self, entry: AuditEntry) -> Result<(), BackendError> {
        let audit = self.inner.audit.as_ref().ok_or(BackendError::Internal {
            message: "audit log not configured".into(),
        })?;
        let result = match entry.result {
            AuditResult::Success => "success".to_owned(),
            AuditResult::Error => "error".to_owned(),
        };
        // The audit DTO has no `config_version` field. A committed add/remove
        // reports its new version inside `after`, so lift it into the stored
        // record instead of losing it.
        let config_version = entry.after.get("config_version").and_then(Value::as_i64);
        audit
            .record_config_change(crate::audit::ConfigChangeRecord {
                node_id: self.inner.node_id.clone(),
                actor_id: entry.actor_id,
                actor_type: "token".to_owned(),
                action: entry.action,
                before: entry.before,
                after: Some(entry.after),
                config_version,
                result,
                error_code: entry.error_code,
            })
            .await
            .map_err(|_| BackendError::Internal {
                message: "audit write failed".into(),
            })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cluster runtime commands (volatile state, never a config version)
// ---------------------------------------------------------------------------

impl AppState {
    /// Applies a volatile cluster runtime command to the local filter engine.
    ///
    /// `kind` is `"pause"`, `"resume"`, `"temporary_allow"` or
    /// `"remove_temporary_allow"`. `payload` carries `filter_set_id` and, for
    /// `pause`/`temporary_allow`, a `duration` (`PT5M`/`PT15M`/`PT1H`) and/or
    /// an absolute `expires_at`; `temporary_allow` also carries `domain` and
    /// `include_subdomains`. `remove_temporary_allow` carries `domain`.
    ///
    /// Runtime commands change no config version and write no audit entry: they
    /// are volatile, last-command-wins state applied straight to the
    /// [`FilterEngine`], using the same limits and engine calls as the MCP
    /// write tools. Module error codes are returned unchanged.
    pub async fn apply_runtime_command(
        &self,
        kind: &str,
        payload: &Value,
    ) -> Result<(), ControlApiError> {
        match kind {
            "pause" => self.apply_runtime_pause(payload).await,
            "resume" => self.apply_runtime_resume(payload),
            "temporary_allow" => self.apply_runtime_temporary_allow(payload).await,
            "remove_temporary_allow" => self.apply_runtime_remove_temporary_allow(payload),
            other => Err(mcp_error(
                "mcp.invalid_input",
                json!({ "reason": format!("unknown runtime command kind: {other}") }),
            )),
        }
    }

    fn runtime_filter(&self) -> Result<&Arc<FilterEngine>, ControlApiError> {
        self.filter_engine()
            .ok_or_else(|| ControlApiError::Internal {
                message: "filter engine is not configured".to_owned(),
            })
    }

    async fn apply_runtime_pause(&self, payload: &Value) -> Result<(), ControlApiError> {
        let set = parse_set(payload.get("filter_set_id").and_then(Value::as_str))?;
        let until = runtime_until(
            payload,
            self.clock().now(),
            self.mcp_config().max_pause_duration,
        )?;
        self.runtime_filter()?
            .set_paused_until(&set, Some(until))
            .map_err(|err| engine_error(err, set.as_str()))
    }

    fn apply_runtime_resume(&self, payload: &Value) -> Result<(), ControlApiError> {
        let set = parse_set(payload.get("filter_set_id").and_then(Value::as_str))?;
        self.runtime_filter()?
            .set_paused_until(&set, None)
            .map_err(|err| engine_error(err, set.as_str()))
    }

    async fn apply_runtime_temporary_allow(&self, payload: &Value) -> Result<(), ControlApiError> {
        let duration = runtime_duration(payload, self.mcp_config().max_temporary_allow_duration)?;
        let domain = canonical_allow_domain(runtime_str(payload, "domain")?)?;
        let include_subdomains = payload
            .get("include_subdomains")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let set = parse_set(payload.get("filter_set_id").and_then(Value::as_str))?;
        let until = runtime_until_with(
            duration,
            runtime_expires_at(payload)?,
            self.clock().now(),
            self.mcp_config().max_temporary_allow_duration,
        )?;

        // Same sequence as `ControlMcpBackend::allow_temporarily`: hold the
        // apply lock across the snapshot read, the protected check and the
        // engine mutation so a concurrent config replace cannot interleave.
        let _guard = match self.config_service() {
            Some(service) => Some(service.apply_guard().await),
            None => None,
        };
        let snapshot = match self.config_service() {
            Some(service) => service.current().await?.1,
            None => None,
        };
        let issuer = self.oidc_issuer();
        let protected = protected_for(
            snapshot.as_ref(),
            issuer.as_deref(),
            self.mcp_config().protected_domains.iter().cloned(),
        )?;
        reject_protected(&protected, domain.as_str(), include_subdomains)?;

        let rule = TempAllow {
            domain,
            include_subdomains,
            until,
            created_at: self.clock().now(),
        };
        self.runtime_filter()?
            .allow_temporarily(&set, rule)
            .map_err(|err| engine_error(err, set.as_str()))
    }

    /// Drops a temporary allow on this node. Missing is success: a peer may
    /// already have expired it, and the command is last-command-wins.
    fn apply_runtime_remove_temporary_allow(&self, payload: &Value) -> Result<(), ControlApiError> {
        let domain = canonical_allow_domain(runtime_str(payload, "domain")?)?;
        let set = parse_set(payload.get("filter_set_id").and_then(Value::as_str))?;
        self.runtime_filter()?
            .remove_temporary_allow(&set, &domain)
            .map_err(|err| engine_error(err, set.as_str()))?;
        Ok(())
    }
}

fn runtime_str<'a>(payload: &'a Value, field: &str) -> Result<&'a str, ControlApiError> {
    payload.get(field).and_then(Value::as_str).ok_or_else(|| {
        mcp_error(
            "mcp.invalid_input",
            json!({ "reason": format!("`{field}` is required") }),
        )
    })
}

/// Parses the fixed MCP duration set and applies the configured maximum.
fn runtime_duration(
    payload: &Value,
    maximum: Duration,
) -> Result<Option<PauseDuration>, ControlApiError> {
    let Some(raw) = payload.get("duration") else {
        return Ok(None);
    };
    let duration: PauseDuration = serde_json::from_value(raw.clone()).map_err(|_| {
        mcp_error(
            "mcp.invalid_input",
            json!({ "reason": "`duration` must be one of PT5M, PT15M, PT1H" }),
        )
    })?;
    if let Some(error) = duration_error(duration.seconds(), maximum) {
        return Err(error);
    }
    Ok(Some(duration))
}

fn runtime_expires_at(payload: &Value) -> Result<Option<SystemTime>, ControlApiError> {
    payload
        .get("expires_at")
        .map(|value| {
            stored_time(value).ok_or_else(|| {
                mcp_error(
                    "mcp.invalid_input",
                    json!({ "reason": "`expires_at` must be unix seconds or an RFC 3339 timestamp" }),
                )
            })
        })
        .transpose()
}

/// Resolves and validates the absolute deadline of a runtime command.
fn runtime_until(
    payload: &Value,
    now: SystemTime,
    maximum: Duration,
) -> Result<SystemTime, ControlApiError> {
    runtime_until_with(
        runtime_duration(payload, maximum)?,
        runtime_expires_at(payload)?,
        now,
        maximum,
    )
}

/// `duration` is validated against `maximum` exactly like the MCP write tools.
/// `expires_at` is the master's broadcast deadline; when both are present it
/// may only shorten the local deadline, never extend it. Without a `duration`
/// the remaining lifetime still has to fit the configured maximum.
fn runtime_until_with(
    duration: Option<PauseDuration>,
    expires_at: Option<SystemTime>,
    now: SystemTime,
    maximum: Duration,
) -> Result<SystemTime, ControlApiError> {
    match (duration, expires_at) {
        (Some(duration), Some(expires_at)) => {
            let latest = now + Duration::from_secs(duration.seconds());
            if expires_at > latest {
                return Err(mcp_error(
                    "mcp.invalid_input",
                    json!({ "reason": "`expires_at` extends past `duration`" }),
                ));
            }
            Ok(expires_at)
        }
        (Some(duration), None) => Ok(now + Duration::from_secs(duration.seconds())),
        (None, Some(expires_at)) => {
            let remaining = expires_at.duration_since(now).unwrap_or(Duration::ZERO);
            if remaining > maximum {
                return Err(duration_exceeds(remaining, maximum));
            }
            Ok(expires_at)
        }
        (None, None) => Err(mcp_error(
            "mcp.invalid_input",
            json!({ "reason": "`duration` or `expires_at` is required" }),
        )),
    }
}

fn json_opt_filter(opt: Option<&Value>) -> Option<dnscraft_mcp::dto::DecisionFilter> {
    let f = opt?;
    Some(dnscraft_mcp::dto::DecisionFilter {
        reason: f
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        block_mode: f
            .get("block_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        rule_text: f
            .get("rule_text")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        list_id: f.get("list_id").and_then(|v| v.as_str()).map(str::to_owned),
        important: f
            .get("important")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use super::shared::rdata_str;

    /// GM14: TXT strings are quoted and escaped; SOA and SRV show every field.
    #[test]
    fn test_query_answers_render_txt_soa_and_srv() {
        let txt = dnscraft_proto::RData::TXT(vec![
            b"v=spf1 \"x\"".to_vec().into_boxed_slice(),
            b"a\\b\x01".to_vec().into_boxed_slice(),
        ]);
        assert_eq!(rdata_str(&txt), r#""v=spf1 \"x\"" "a\\b\001""#);
        let srv = dnscraft_proto::RData::SRV {
            priority: 10,
            weight: 5,
            port: 443,
            target: dnscraft_proto::Name::from_ascii("svc.example.com").unwrap(),
        };
        assert_eq!(rdata_str(&srv), "10 5 443 svc.example.com.");
        let soa = dnscraft_proto::RData::SOA {
            mname: dnscraft_proto::Name::from_ascii("ns.example.com").unwrap(),
            rname: dnscraft_proto::Name::from_ascii("admin.example.com").unwrap(),
            serial: 7,
            refresh: 1,
            retry: 2,
            expire: 3,
            minimum: 4,
        };
        assert_eq!(
            rdata_str(&soa),
            "ns.example.com. admin.example.com. 7 1 2 3 4"
        );
    }

    /// GM12: a query-log read failure keeps its stable code.
    #[test]
    fn query_log_read_failures_keep_their_code() {
        let err = query_log_error(ControlApiError::QueryLogRead {
            message: "disk".into(),
        });
        assert_eq!(err.code(), "control_api.query_log.read");
        let other = query_log_error(ControlApiError::Internal {
            message: "x".into(),
        });
        assert_eq!(other.code(), "control_api.internal");
    }

    #[test]
    fn resolve_set_for_write_asks_when_multiple_sets_and_id_omitted() {
        let snapshot = json!({
            "filtering": {
                "sets": [
                    { "id": "default", "name": "Default" },
                    { "id": "kids", "name": "Kids" }
                ]
            }
        });
        let err = resolve_set_for_write(Some(&snapshot), None).unwrap_err();
        assert_eq!(err.code(), "mcp.needs_clarification");
    }

    #[test]
    fn resolve_set_for_write_uses_explicit_or_single_set() {
        let snapshot = json!({
            "filtering": {
                "sets": [
                    { "id": "kids", "name": "Kids" }
                ]
            }
        });
        assert_eq!(
            resolve_set_for_write(Some(&snapshot), None)
                .unwrap()
                .as_str(),
            "kids"
        );
        assert_eq!(
            resolve_set_for_write(Some(&snapshot), Some("kids"))
                .unwrap()
                .as_str(),
            "kids"
        );
    }
}
