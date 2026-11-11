//! Shared MCP DTO / time / error mapping helpers.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnscraft_filtering::BlockMode;
use dnscraft_mcp::backend::BackendError;
use dnscraft_mcp::dto::{
    PauseDuration, QType, QueryClient, QueryLogEntry, QueryLogFilter as McpQueryLogFilter,
    QueryName, QueryTimings, Selection, TokenScope,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::api::auth::roles::Scope;
use crate::api::clients_routes::DirectoryClient;
use crate::api::query_log_routes::parse_timestamp;
use crate::error::ControlApiError;
use crate::query_log::{Order, OrderBy};

/// Maps one directory entry onto the MCP `client_list` shape (GM3).
pub(crate) fn client_info(client: &DirectoryClient) -> dnscraft_mcp::dto::ClientInfo {
    dnscraft_mcp::dto::ClientInfo {
        id: client.id.clone(),
        display_name: client.name.clone(),
        source: client.source.to_owned(),
        addresses: client.ips.iter().map(ToString::to_string).collect(),
        macs: client.macs.clone(),
        vlan: client.vlan.map(|id| dnscraft_mcp::dto::VlanInfo {
            id: u32::from(id),
            name: String::new(),
        }),
        local_domain: (!client.local_domain.is_empty()).then(|| client.local_domain.clone()),
    }
}

/// Maps one listener binding onto the MCP `get_status` shape (GM4).
pub(crate) fn listener_status(
    listener: &dnscraft_listeners::ListenerStatus,
) -> dnscraft_mcp::dto::ListenerStatus {
    dnscraft_mcp::dto::ListenerStatus {
        id: listener.id.as_str().to_owned(),
        protocol: listener.protocol.as_str().to_owned(),
        bind: listener
            .bound
            .unwrap_or(listener.configured_address)
            .to_string(),
        status: match &listener.error {
            Some(error) => error.code().to_owned(),
            None => "running".to_owned(),
        },
    }
}

pub(crate) fn rfc3339(ts: SystemTime) -> String {
    dnscraft_common::time_fmt::rfc3339(ts)
}

pub(crate) fn duration_secs(d: PauseDuration) -> Duration {
    Duration::from_secs(d.seconds())
}

pub(crate) fn map_mcp_scope(scope: Scope) -> TokenScope {
    match scope {
        Scope::McpRead => TokenScope::McpRead,
        Scope::McpWrite => TokenScope::McpWrite,
        _ => TokenScope::McpRead,
    }
}

pub(crate) fn filter_qtype(qtype: QType) -> u16 {
    match qtype {
        QType::A => 1,
        QType::Aaaa => 28,
        QType::Cname => 5,
        QType::Mx => 15,
        QType::Txt => 16,
        QType::Srv => 33,
        QType::Https => 65,
    }
}

pub(crate) fn record_qtype(rt: dnscraft_proto::RecordType) -> QType {
    match rt.0 {
        28 => QType::Aaaa,
        5 => QType::Cname,
        15 => QType::Mx,
        16 => QType::Txt,
        33 => QType::Srv,
        65 => QType::Https,
        _ => QType::A,
    }
}

pub(crate) fn block_mode_str(m: &BlockMode) -> String {
    match m {
        BlockMode::Refused => "refused".to_owned(),
        BlockMode::NxDomain => "nxdomain".to_owned(),
        BlockMode::NullIp => "null_ip".to_owned(),
        BlockMode::CustomIp { .. } => "custom_ip".to_owned(),
    }
}

pub(crate) fn reason_source_str(src: &dnscraft_filtering::RuleSource) -> String {
    match src {
        dnscraft_filtering::RuleSource::List { list, line } => format!("list:{list}:line {line}"),
        dnscraft_filtering::RuleSource::Custom { set, line } => format!("set:{set}:line {line}"),
        dnscraft_filtering::RuleSource::Mcp { set, id } => format!("mcp:{set}:{id}"),
        dnscraft_filtering::RuleSource::Service { id } => format!("service:{id}"),
        _ => "unknown".to_owned(),
    }
}

pub(crate) fn policy_protocol(s: &str) -> dnscraft_policy::DnsProtocol {
    match s {
        "tcp53" => dnscraft_policy::DnsProtocol::Tcp53,
        "dot" => dnscraft_policy::DnsProtocol::DoT,
        "doh" => dnscraft_policy::DnsProtocol::DoH,
        "doq" => dnscraft_policy::DnsProtocol::DoQ,
        _ => dnscraft_policy::DnsProtocol::Udp53,
    }
}

pub(crate) fn dnssec_status_str(s: &dnscraft_resolver::DnssecStatus) -> &'static str {
    match s {
        dnscraft_resolver::DnssecStatus::Secure => "secure",
        dnscraft_resolver::DnssecStatus::Insecure => "insecure",
        dnscraft_resolver::DnssecStatus::Bogus => "bogus",
        dnscraft_resolver::DnssecStatus::Indeterminate => "indeterminate",
    }
}

pub(crate) fn json_str(val: &Value, key: &str) -> String {
    val[key].as_str().unwrap_or_default().to_owned()
}

pub(crate) fn json_opt_str(val: &Value, key: &str) -> Option<String> {
    val[key].as_str().map(str::to_owned)
}

pub(crate) fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

pub(crate) fn parse_time(raw: Option<&str>, field: &str) -> Result<Option<i64>, BackendError> {
    raw.map(|raw| parse_timestamp(raw, field))
        .transpose()
        .map_err(|e| BackendError::Coded {
            code: e.code().to_owned(),
            params: None,
        })
}

/// Maps a query-log read failure: a read failure keeps its stable
/// `control_api.query_log.read` code, anything else is internal.
pub(crate) fn query_log_error(err: ControlApiError) -> BackendError {
    match err {
        ControlApiError::QueryLogRead { .. } => BackendError::Coded {
            code: err.code().to_owned(),
            params: None,
        },
        other => BackendError::Internal {
            message: other.code().to_owned(),
        },
    }
}

pub(crate) fn query_order_by(raw: &str) -> OrderBy {
    match raw {
        "client" => OrderBy::Client,
        "domain" => OrderBy::Domain,
        "rcode" => OrderBy::Rcode,
        _ => OrderBy::Time,
    }
}

pub(crate) fn query_order(raw: &str) -> Order {
    match raw {
        "asc" => Order::Asc,
        _ => Order::Desc,
    }
}

/// Maps a stored query-type string (`RecordType`'s display form) to a DTO type.
pub(crate) fn qtype_from_str(raw: &str) -> QType {
    match raw {
        "AAAA" => QType::Aaaa,
        "CNAME" => QType::Cname,
        "MX" => QType::Mx,
        "TXT" => QType::Txt,
        "SRV" => QType::Srv,
        "HTTPS" => QType::Https,
        _ => QType::A,
    }
}

pub(crate) fn query_entry(record: &Value) -> QueryLogEntry {
    let client = &record["client"];
    let query = &record["query"];
    QueryLogEntry {
        id: json_str(record, "id"),
        time: json_str(record, "time"),
        client: QueryClient {
            id: json_str(client, "id"),
            display_name: json_str(client, "display_name"),
            source: json_str(client, "source"),
        },
        query: QueryName {
            name: json_str(query, "name"),
            qtype: qtype_from_str(&json_str(query, "type")),
        },
        profile_id: json_str(record, "profile_id"),
        answer_source: json_str(record, "answer_source"),
        filter: record
            .get("filter")
            .filter(|filter| !filter.is_null())
            .map(|filter| McpQueryLogFilter {
                reason: json_str(filter, "reason"),
                rule_text: json_opt_str(filter, "rule_text"),
                list_id: json_opt_str(filter, "list_id"),
            }),
        rcode: json_str(record, "rcode"),
        timings: QueryTimings {
            total_us: record["timings"]["total_us"].as_u64().unwrap_or(0),
        },
    }
}

pub(crate) fn code_err(code: &str, domain: &str) -> BackendError {
    BackendError::Coded {
        code: code.to_owned(),
        params: Some(json!({ "domain": domain })),
    }
}

pub(crate) fn rdata_str(rdata: &dnscraft_proto::RData) -> String {
    match rdata {
        dnscraft_proto::RData::A(ip) => ip.to_string(),
        dnscraft_proto::RData::AAAA(ip) => ip.to_string(),
        dnscraft_proto::RData::CNAME(name) => name.to_string(),
        dnscraft_proto::RData::NS(name) => name.to_string(),
        dnscraft_proto::RData::PTR(name) => name.to_string(),
        dnscraft_proto::RData::MX {
            preference,
            exchange,
        } => {
            format!("{preference} {exchange}")
        }
        dnscraft_proto::RData::TXT(strings) => strings
            .iter()
            .map(|string| format!("\"{}\"", txt_escape(string)))
            .collect::<Vec<_>>()
            .join(" "),
        dnscraft_proto::RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
        dnscraft_proto::RData::SRV {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        _ => "<rdata>".to_owned(),
    }
}

/// Escapes one TXT character-string in zone-file presentation form: quote and
/// backslash are backslash-escaped, non-printable bytes become `\DDD`.
pub(crate) fn txt_escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x20..=0x7e => out.push(char::from(byte)),
            other => out.push_str(&format!("\\{other:03}")),
        }
    }
    out
}

pub(crate) fn selection_cause_json(cause: &dnscraft_policy::SelectionCause) -> Selection {
    match cause {
        dnscraft_policy::SelectionCause::Subnet {
            network,
            prefix_len,
        } => Selection {
            cause: "subnet".to_owned(),
            prefix: Some(format!("{network}/{prefix_len}")),
            client_id: None,
        },
        dnscraft_policy::SelectionCause::ClientId => Selection {
            cause: "client_id".to_owned(),
            prefix: None,
            client_id: None,
        },
        dnscraft_policy::SelectionCause::Default => Selection {
            cause: "default".to_owned(),
            prefix: None,
            client_id: None,
        },
    }
}

/// Maps a control-api error onto the MCP backend's coded-error shape.
pub(crate) fn backend_error(err: ControlApiError) -> BackendError {
    match err {
        ControlApiError::Module { code, params } => BackendError::Coded {
            code: code.to_owned(),
            params,
        },
        other => BackendError::Internal {
            message: other.code().to_owned(),
        },
    }
}

/// Parses a stored `created_at`/`expires_at`: unix seconds or RFC 3339.
pub(crate) fn stored_time(value: &Value) -> Option<SystemTime> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds)),
        Value::String(raw) => OffsetDateTime::parse(raw, &Rfc3339)
            .ok()
            .and_then(|time| u64::try_from(time.unix_timestamp()).ok())
            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds)),
        _ => None,
    }
}
