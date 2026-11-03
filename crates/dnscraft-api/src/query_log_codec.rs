//! Compact on-disk encoding for query-log rows.
//!
//! Wire / API values stay human-readable strings (`"blocked"`, `"udp53"`, …).
//! SQLite stores closed enums and DNS type/class as integers; the fat
//! "why blocked?" payload (`steps` / `selection`) lives in
//! [`query_log_detail`](super::query_log) and is merged only on demand.
//! Compact `timings` stay on the slim row so latency stats need no join.

use dnscraft_policy::{AnswerOrigin, DnsProtocol};
use dnscraft_proto::{Class, Rcode, RecordType};
use serde_json::{Map, Value as Json, json};

/// Stored `status` column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum StatusCode {
    /// Unknown / legacy garbage.
    Unknown = 0,
    Allowed = 1,
    Blocked = 2,
    Servfail = 3,
    DnssecBogus = 4,
}

impl StatusCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "",
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Servfail => "servfail",
            Self::DnssecBogus => "dnssec_bogus",
        }
    }

    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }

    pub(crate) fn from_str(raw: &str) -> Self {
        match raw {
            "allowed" => Self::Allowed,
            "blocked" => Self::Blocked,
            "servfail" => Self::Servfail,
            "dnssec_bogus" => Self::DnssecBogus,
            _ => Self::Unknown,
        }
    }

    pub(crate) fn from_i64(raw: i64) -> Self {
        match raw {
            1 => Self::Allowed,
            2 => Self::Blocked,
            3 => Self::Servfail,
            4 => Self::DnssecBogus,
            _ => Self::Unknown,
        }
    }

    /// Whether the row keeps a detail blob (steps / selection / timings).
    pub(crate) const fn needs_detail(self) -> bool {
        matches!(self, Self::Blocked | Self::Servfail | Self::DnssecBogus)
    }
}

/// Stored `protocol` column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ProtocolCode {
    Unknown = 0,
    Udp53 = 1,
    Tcp53 = 2,
    Dot = 3,
    Doh = 4,
    Doq = 5,
}

impl ProtocolCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "",
            Self::Udp53 => "udp53",
            Self::Tcp53 => "tcp53",
            Self::Dot => "dot",
            Self::Doh => "doh",
            Self::Doq => "doq",
        }
    }

    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }

    pub(crate) fn from_str(raw: &str) -> Self {
        match raw {
            "udp53" => Self::Udp53,
            "tcp53" => Self::Tcp53,
            "dot" => Self::Dot,
            "doh" => Self::Doh,
            "doq" => Self::Doq,
            _ => Self::Unknown,
        }
    }

    pub(crate) fn from_i64(raw: i64) -> Self {
        match raw {
            1 => Self::Udp53,
            2 => Self::Tcp53,
            3 => Self::Dot,
            4 => Self::Doh,
            5 => Self::Doq,
            _ => Self::Unknown,
        }
    }

    pub(crate) fn from_dns(protocol: DnsProtocol) -> Self {
        match protocol {
            DnsProtocol::Udp53 => Self::Udp53,
            DnsProtocol::Tcp53 => Self::Tcp53,
            DnsProtocol::DoT => Self::Dot,
            DnsProtocol::DoH => Self::Doh,
            DnsProtocol::DoQ => Self::Doq,
        }
    }
}

/// Stored `answer_source` column (policy [`AnswerOrigin`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum AnswerSourceCode {
    Unknown = 0,
    Resolver = 1,
    SynthAny = 2,
    ResolveError = 3,
    LocalView = 4,
    LocalClient = 5,
    Bypass = 6,
    FilterBlock = 7,
    ListenerDdr = 8,
}

impl AnswerSourceCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "",
            Self::Resolver => "resolver",
            Self::SynthAny => "synth_any",
            Self::ResolveError => "resolve_error",
            Self::LocalView => "local_view",
            Self::LocalClient => "local_client",
            Self::Bypass => "bypass",
            Self::FilterBlock => "filter_block",
            Self::ListenerDdr => "listener_ddr",
        }
    }

    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }

    pub(crate) fn from_str(raw: &str) -> Self {
        match raw {
            "resolver" => Self::Resolver,
            "synth_any" => Self::SynthAny,
            "resolve_error" => Self::ResolveError,
            "local_view" => Self::LocalView,
            "local_client" => Self::LocalClient,
            "bypass" => Self::Bypass,
            "filter_block" => Self::FilterBlock,
            "listener_ddr" => Self::ListenerDdr,
            _ => Self::Unknown,
        }
    }

    pub(crate) fn from_i64(raw: i64) -> Self {
        match raw {
            1 => Self::Resolver,
            2 => Self::SynthAny,
            3 => Self::ResolveError,
            4 => Self::LocalView,
            5 => Self::LocalClient,
            6 => Self::Bypass,
            7 => Self::FilterBlock,
            8 => Self::ListenerDdr,
            _ => Self::Unknown,
        }
    }

    pub(crate) fn from_origin(origin: AnswerOrigin) -> Self {
        match origin {
            AnswerOrigin::Resolver => Self::Resolver,
            AnswerOrigin::SynthAny => Self::SynthAny,
            AnswerOrigin::ResolveError => Self::ResolveError,
            AnswerOrigin::LocalView => Self::LocalView,
            AnswerOrigin::LocalClient => Self::LocalClient,
            AnswerOrigin::Bypass => Self::Bypass,
            AnswerOrigin::Filter => Self::FilterBlock,
            AnswerOrigin::ListenerDdr => Self::ListenerDdr,
        }
    }
}

/// Keys that live only in `query_log_detail` for block/error rows.
pub(crate) const DETAIL_KEYS: &[&str] = &["steps", "selection"];

/// Keys duplicated by denormalised columns — omitted from the slim JSON blob.
const COLUMN_KEYS: &[&str] = &[
    "id",
    "node_id",
    "listener_id",
    "protocol",
    "source_ip",
    "source_ip_truncated",
    "client_id",
    "device_id",
    "query",
    "view_id",
    "profile_id",
    "answer_source",
    "status",
    "rcode",
];

/// Parses a query-type filter token (`A`, `AAAA`, `TYPE1234`) into its wire value.
pub(crate) fn parse_query_type(raw: &str) -> Option<u16> {
    let upper = raw.to_ascii_uppercase();
    let value = match upper.as_str() {
        "A" => RecordType::A,
        "NS" => RecordType::NS,
        "CNAME" => RecordType::CNAME,
        "SOA" => RecordType::SOA,
        "PTR" => RecordType::PTR,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "AAAA" => RecordType::AAAA,
        "SRV" => RecordType::SRV,
        "DNAME" => RecordType::DNAME,
        "OPT" => RecordType::OPT,
        "DS" => RecordType::DS,
        "RRSIG" => RecordType::RRSIG,
        "NSEC" => RecordType::NSEC,
        "DNSKEY" => RecordType::DNSKEY,
        "NSEC3" => RecordType::NSEC3,
        "NSEC3PARAM" => RecordType::NSEC3PARAM,
        "SVCB" => RecordType::SVCB,
        "HTTPS" => RecordType::HTTPS,
        "ANY" => RecordType::ANY,
        "CAA" => RecordType::CAA,
        other => {
            let digits = other.strip_prefix("TYPE")?;
            let n: u16 = digits.parse().ok()?;
            return Some(n);
        }
    };
    Some(value.value())
}

/// Parses a query-class filter token (`IN`, `CLASS1`).
pub(crate) fn parse_query_class(raw: &str) -> Option<u16> {
    let upper = raw.to_ascii_uppercase();
    match upper.as_str() {
        "IN" => Some(Class::IN.value()),
        "CH" => Some(Class::CH.value()),
        "NONE" => Some(Class::NONE.value()),
        "ANY" => Some(Class::ANY.value()),
        other => other.strip_prefix("CLASS")?.parse().ok(),
    }
}

/// Rcode wire mnemonic → numeric code (unknown names stay `u16::MAX` sentinel).
pub(crate) fn rcode_from_str(raw: &str) -> i64 {
    match raw {
        "NOERROR" => i64::from(Rcode::NOERROR.value()),
        "FORMERR" => 1,
        "SERVFAIL" => i64::from(Rcode::SERVFAIL.value()),
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        "YXDOMAIN" => 6,
        "YXRRSET" => 7,
        "NXRRSET" => 8,
        "NOTAUTH" => 9,
        "NOTZONE" => 10,
        other => other
            .strip_prefix("RCODE")
            .and_then(|digits| digits.parse::<u16>().ok())
            .map(i64::from)
            .unwrap_or(-1),
    }
}

pub(crate) fn rcode_to_str(code: i64) -> String {
    if code < 0 {
        return String::new();
    }
    Rcode(code as u16).to_string()
}

/// Splits a (possibly legacy fat) document into slim storage + optional detail.
pub(crate) fn split_record(mut record: Json, status: StatusCode) -> (Json, Option<Json>) {
    let Some(obj) = record.as_object_mut() else {
        return (record, None);
    };
    for key in COLUMN_KEYS {
        obj.remove(*key);
    }
    if !status.needs_detail() {
        for key in DETAIL_KEYS {
            obj.remove(*key);
        }
        obj.remove("filter");
        return (record, None);
    }
    let mut detail = Map::new();
    for key in DETAIL_KEYS {
        if let Some(value) = obj.remove(*key) {
            detail.insert((*key).to_owned(), value);
        }
    }
    let detail = (!detail.is_empty()).then_some(Json::Object(detail));
    (record, detail)
}

/// Rebuilds the public wire document from denormalised columns + slim JSON
/// (+ optional detail).
pub(crate) fn hydrate_wire(
    slim: Json,
    detail: Option<Json>,
    cols: &WireColumns<'_>,
) -> Json {
    let mut record = match slim {
        Json::Object(map) => map,
        other => {
            let mut map = Map::new();
            map.insert("_raw".to_owned(), other);
            map
        }
    };
    // Columns always win over anything left in a legacy fat blob.
    record.insert("id".to_owned(), json!(cols.id));
    record.insert("node_id".to_owned(), json!(cols.node_id));
    record.insert("listener_id".to_owned(), json!(cols.listener_id));
    record.insert("protocol".to_owned(), json!(cols.protocol.as_str()));
    record.insert("source_ip".to_owned(), json!(cols.source_ip));
    record.insert(
        "source_ip_truncated".to_owned(),
        json!(cols.source_ip_truncated),
    );
    if let Some(client_id) = cols.client_id {
        record.insert("client_id".to_owned(), json!(client_id));
    }
    if let Some(device_id) = cols.device_id {
        record.insert("device_id".to_owned(), json!(device_id));
    }
    record.insert(
        "query".to_owned(),
        json!({
            "name": cols.query_name,
            "type": RecordType(cols.query_type as u16).to_string(),
            "class": Class(cols.query_class as u16).to_string(),
        }),
    );
    record.insert("view_id".to_owned(), json!(cols.view_id));
    record.insert("profile_id".to_owned(), json!(cols.profile_id));
    record.insert(
        "answer_source".to_owned(),
        json!(cols.answer_source.as_str()),
    );
    record.insert("status".to_owned(), json!(cols.status.as_str()));
    record.insert("rcode".to_owned(), json!(rcode_to_str(cols.rcode)));

    if let Some(Json::Object(detail)) = detail {
        for (key, value) in detail {
            record.entry(key).or_insert(value);
        }
    }
    // Rows without detail drop these keys; the wire contract (and the UI) expects them present.
    record.entry("steps").or_insert_with(|| json!([]));
    record.entry("selection").or_insert_with(|| json!({ "cause": "default" }));
    record.entry("filter").or_insert(Json::Null);
    Json::Object(record)
}

/// Denormalised fields needed to rebuild the wire document.
pub(crate) struct WireColumns<'a> {
    pub id: &'a str,
    pub node_id: &'a str,
    pub listener_id: &'a str,
    pub protocol: ProtocolCode,
    pub source_ip: &'a str,
    pub source_ip_truncated: bool,
    pub client_id: Option<&'a str>,
    pub device_id: Option<&'a str>,
    pub query_name: &'a str,
    pub query_type: i64,
    pub query_class: i64,
    pub view_id: &'a str,
    pub profile_id: &'a str,
    pub status: StatusCode,
    pub answer_source: AnswerSourceCode,
    pub rcode: i64,
}

/// Reads a SQLite cell that may still hold a legacy TEXT enum.
pub(crate) fn read_status(value: rusqlite::types::ValueRef<'_>) -> StatusCode {
    match value {
        rusqlite::types::ValueRef::Integer(v) => StatusCode::from_i64(v),
        rusqlite::types::ValueRef::Text(bytes) => {
            StatusCode::from_str(&String::from_utf8_lossy(bytes))
        }
        _ => StatusCode::Unknown,
    }
}

pub(crate) fn read_protocol(value: rusqlite::types::ValueRef<'_>) -> ProtocolCode {
    match value {
        rusqlite::types::ValueRef::Integer(v) => ProtocolCode::from_i64(v),
        rusqlite::types::ValueRef::Text(bytes) => {
            ProtocolCode::from_str(&String::from_utf8_lossy(bytes))
        }
        _ => ProtocolCode::Unknown,
    }
}

pub(crate) fn read_answer_source(value: rusqlite::types::ValueRef<'_>) -> AnswerSourceCode {
    match value {
        rusqlite::types::ValueRef::Integer(v) => AnswerSourceCode::from_i64(v),
        rusqlite::types::ValueRef::Text(bytes) => {
            AnswerSourceCode::from_str(&String::from_utf8_lossy(bytes))
        }
        _ => AnswerSourceCode::Unknown,
    }
}

pub(crate) fn read_rcode(value: rusqlite::types::ValueRef<'_>) -> i64 {
    match value {
        rusqlite::types::ValueRef::Integer(v) => v,
        rusqlite::types::ValueRef::Text(bytes) => {
            rcode_from_str(&String::from_utf8_lossy(bytes))
        }
        _ => -1,
    }
}

pub(crate) fn read_query_type(value: rusqlite::types::ValueRef<'_>) -> i64 {
    match value {
        rusqlite::types::ValueRef::Integer(v) => v,
        rusqlite::types::ValueRef::Text(bytes) => parse_query_type(&String::from_utf8_lossy(bytes))
            .map(i64::from)
            .unwrap_or(0),
        _ => 0,
    }
}

pub(crate) fn read_query_class(value: rusqlite::types::ValueRef<'_>) -> i64 {
    match value {
        rusqlite::types::ValueRef::Integer(v) => v,
        rusqlite::types::ValueRef::Text(bytes) => parse_query_class(&String::from_utf8_lossy(bytes))
            .map(i64::from)
            .unwrap_or(1),
        _ => 1,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn split_strips_column_dupes_and_parks_detail() {
        let fat = json!({
            "id": "abc",
            "status": "blocked",
            "protocol": "udp53",
            "steps": [{"stage": "filter_qname"}],
            "selection": {"cause": "default"},
            "timings": {"total_us": 1},
            "filter": {"block_mode": "nxdomain"},
            "answer_size": 12,
            "client": {"display_name": "phone"},
        });
        let (slim, detail) = split_record(fat, StatusCode::Blocked);
        assert!(slim.get("id").is_none());
        assert!(slim.get("status").is_none());
        assert!(slim.get("steps").is_none());
        assert_eq!(slim["timings"]["total_us"], 1);
        assert_eq!(slim["filter"]["block_mode"], "nxdomain");
        assert_eq!(slim["answer_size"], 12);
        let detail = detail.expect("detail");
        assert!(detail.get("steps").is_some());
        assert!(detail.get("selection").is_some());
        assert!(detail.get("timings").is_none());
    }

    #[test]
    fn allowed_rows_drop_detail_keys() {
        let fat = json!({
            "steps": [{"stage": "resolve"}],
            "timings": {"total_us": 3},
            "answer_size": 40,
        });
        let (slim, detail) = split_record(fat, StatusCode::Allowed);
        assert!(detail.is_none());
        assert!(slim.get("steps").is_none());
        assert_eq!(slim["timings"]["total_us"], 3);
        assert_eq!(slim["answer_size"], 40);
    }

    #[test]
    fn hydrate_rebuilds_wire_shape() {
        let slim = json!({"answer_size": 10, "filter": {"block_mode": "nxdomain"}});
        let detail = json!({"steps": [{"stage": "filter_qname"}]});
        let cols = WireColumns {
            id: "id1",
            node_id: "dns1",
            listener_id: "lan",
            protocol: ProtocolCode::Udp53,
            source_ip: "192.0.2.1",
            source_ip_truncated: false,
            client_id: None,
            device_id: None,
            query_name: "ads.example",
            query_type: i64::from(RecordType::A.value()),
            query_class: i64::from(Class::IN.value()),
            view_id: "default",
            profile_id: "default",
            status: StatusCode::Blocked,
            answer_source: AnswerSourceCode::FilterBlock,
            rcode: 3,
        };
        let wire = hydrate_wire(slim, Some(detail), &cols);
        assert_eq!(wire["status"], "blocked");
        assert_eq!(wire["protocol"], "udp53");
        assert_eq!(wire["query"]["type"], "A");
        assert_eq!(wire["rcode"], "NXDOMAIN");
        assert_eq!(wire["steps"][0]["stage"], "filter_qname");
        assert_eq!(wire["filter"]["block_mode"], "nxdomain");
    }

    #[test]
    fn hydrate_fills_dropped_detail_keys_for_detail_less_rows() {
        let cols = WireColumns {
            id: "id2",
            node_id: "dns1",
            listener_id: "lan",
            protocol: ProtocolCode::Udp53,
            source_ip: "192.0.2.1",
            source_ip_truncated: false,
            client_id: None,
            device_id: None,
            query_name: "ok.example",
            query_type: i64::from(RecordType::A.value()),
            query_class: i64::from(Class::IN.value()),
            view_id: "default",
            profile_id: "default",
            status: StatusCode::Allowed,
            answer_source: AnswerSourceCode::Resolver,
            rcode: 0,
        };
        let wire = hydrate_wire(json!({"answer_size": 10}), None, &cols);
        assert_eq!(wire["steps"], json!([]));
        assert_eq!(wire["selection"]["cause"], "default");
        assert!(wire["filter"].is_null());
    }
}
