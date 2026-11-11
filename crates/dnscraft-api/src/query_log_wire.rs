//! Query-log wire JSON helpers (decision records, steps, status labels).

use std::time::{SystemTime, UNIX_EPOCH};

use dnscraft_filtering::{BlockMode, Reason, RuleSource, Verdict};
use dnscraft_policy::{
    AnswerOrigin, ChainHop, DecisionRecord, DecisionStep, FilterHit, SelectionCause,
};
use dnscraft_proto::Rcode;
use dnscraft_resolver::{AnswerSource, DnssecStatus};
use serde_json::{Value as Json, json};
use time::OffsetDateTime;

use crate::query_log::ClientView;

/// Serializes a decision record in the query-log shape (the full record used
/// by `POST /api/v1/policy/test-query`).
pub(crate) fn decision_record_json(decision: &DecisionRecord) -> Json {
    json!({
        "view_id": decision.view_id.to_string(),
        "profile_id": decision.profile_id.to_string(),
        "filter_set_id": decision.filter_set.as_str(),
        "selection": selection_json(decision.selection),
        "client_id": decision.client_id.as_ref().map(ToString::to_string),
        "client": resolve_client(
            None,
            decision.client_id.as_ref().map(|id| id.as_str()),
            decision.client_label.as_deref(),
        )
        .as_ref()
        .map(client_json),
        "steps": decision.steps.iter().map(step_json).collect::<Vec<_>>(),
        "filter": decision.filter.as_ref().map(filter_json),
        "forward_zone": decision.forward_zone.as_ref().map(ToString::to_string),
        "dnssec": decision.dnssec.map(dnssec_str),
        "answer_source": answer_origin_str(decision.answer_source),
        "timings": {
            "select_us": decision.timings.select_us,
            "filter_us": decision.timings.filter_us,
            "resolve_us": decision.timings.resolve_us,
            "total_us": decision.timings.total_us,
        },
        "rcode": decision.rcode.to_string(),
    })
}

/// Derives the documented outcome label from the decision and response code.
pub(crate) fn status_str(decision: &DecisionRecord, rcode: Rcode) -> &'static str {
    if decision
        .filter
        .as_ref()
        .is_some_and(|hit| hit.block_mode.is_some())
    {
        "blocked"
    } else if rcode == Rcode::SERVFAIL {
        "servfail"
    } else if decision.dnssec == Some(DnssecStatus::Bogus) {
        "dnssec_bogus"
    } else {
        "allowed"
    }
}

pub(crate) fn answer_origin_str(origin: AnswerOrigin) -> &'static str {
    match origin {
        AnswerOrigin::Resolver => "resolver",
        AnswerOrigin::SynthAny => "synth_any",
        AnswerOrigin::ResolveError => "resolve_error",
        AnswerOrigin::LocalView => "local_view",
        AnswerOrigin::LocalClient => "local_client",
        AnswerOrigin::Bypass => "bypass",
        AnswerOrigin::Filter => "filter_block",
        AnswerOrigin::ListenerDdr => "listener_ddr",
    }
}

pub(crate) fn answer_source_str(source: AnswerSource) -> &'static str {
    match source {
        AnswerSource::Cache => "cache",
        AnswerSource::Recursion => "recursion",
        AnswerSource::Stale => "stale",
    }
}

pub(crate) fn dnssec_str(status: DnssecStatus) -> &'static str {
    match status {
        DnssecStatus::Secure => "secure",
        DnssecStatus::Insecure => "insecure",
        DnssecStatus::Bogus => "bogus",
        DnssecStatus::Indeterminate => "indeterminate",
    }
}

pub(crate) fn block_mode_str(mode: BlockMode) -> &'static str {
    match mode {
        BlockMode::Refused => "refused",
        BlockMode::NxDomain => "nxdomain",
        BlockMode::NullIp => "null_ip",
        BlockMode::CustomIp { .. } => "custom_ip",
    }
}

/// Picks the client shown for a record. A directory match by source IP wins;
/// otherwise a registered Client ID stands in (label when present, else the id).
pub(crate) fn resolve_client(
    directory: Option<ClientView>,
    client_id: Option<&str>,
    label: Option<&str>,
) -> Option<ClientView> {
    directory.or_else(|| {
        let id = client_id?;
        Some(ClientView {
            id: id.to_owned(),
            display_name: label.unwrap_or(id).to_owned(),
            source: "client_id".to_owned(),
            ..ClientView::default()
        })
    })
}

pub(crate) fn client_json(client: &ClientView) -> Json {
    json!({
        "id": client.id,
        "display_name": client.display_name,
        "source": client.source,
        "macs": client.macs,
        "vlan_id": client.vlan_id,
        "vlan_name": client.vlan_name,
        "local_domain": client.local_domain,
    })
}

pub(crate) fn selection_json(cause: SelectionCause) -> Json {
    match cause {
        SelectionCause::Subnet {
            network,
            prefix_len,
        } => json!({
            "cause": "subnet",
            "prefix": format!("{network}/{prefix_len}"),
        }),
        SelectionCause::ClientId => json!({ "cause": "client_id" }),
        SelectionCause::Default => json!({ "cause": "default" }),
    }
}

pub(crate) fn filter_json(hit: &FilterHit) -> Json {
    let (source, list_id) = source_parts(&hit.reason.source);
    json!({
        // The spec calls this a filter reason; the engine exposes provenance
        // (list/custom/service/temporary_allow/mcp) rather than a category.
        "reason": source,
        "block_mode": hit.block_mode.map(block_mode_str),
        "rule_text": hit.reason.rule.as_ref(),
        "list_id": list_id,
        "important": hit.reason.important,
    })
}

/// Provenance label and list id for a rule source; shared by `filter_json` and
/// `chain_hop_json`.
pub(crate) fn source_parts(source: &RuleSource) -> (&'static str, Option<String>) {
    match source {
        RuleSource::List { list, .. } => ("list", Some(list.as_str().to_owned())),
        RuleSource::Custom { .. } => ("custom", None),
        RuleSource::Service { id } => ("service", Some(id.to_string())),
        RuleSource::TemporaryAllow => ("temporary_allow", None),
        RuleSource::Mcp { .. } => ("mcp", None),
    }
}

pub(crate) fn chain_hop_json(hop: &ChainHop) -> Json {
    let (verdict, reason): (&str, Option<&Reason>) = match &hop.verdict {
        Verdict::Pass => ("pass", None),
        Verdict::Allowed(r) => ("allowed", Some(r)),
        Verdict::Blocked(r) => ("blocked", Some(r)),
        Verdict::Rewrite(_, r) => ("rewritten", Some(r)),
    };
    let (source, list_id) = match reason {
        Some(r) => {
            let (source, list_id) = source_parts(&r.source);
            (Some(source), list_id)
        }
        None => (None, None),
    };
    json!({
        "name": hop.name,
        "verdict": verdict,
        "rule_text": reason.map(|r| r.rule.as_ref()),
        "list_id": list_id,
        "source": source,
        "important": reason.is_some_and(|r| r.important),
    })
}

pub(crate) fn step_json(step: &DecisionStep) -> Json {
    match step {
        DecisionStep::Selected { cause } => json!({
            "stage": "select",
            "verdict": "selected",
            "selection": selection_json(*cause),
        }),
        DecisionStep::AnySynth => json!({ "stage": "any_synth", "verdict": "synth" }),
        DecisionStep::LocalView => json!({ "stage": "local_view", "verdict": "answered" }),
        DecisionStep::LocalClient => json!({ "stage": "local_client", "verdict": "answered" }),
        DecisionStep::SpecialUseNxdomain => {
            json!({ "stage": "special_use_nxdomain", "verdict": "nxdomain" })
        }
        DecisionStep::Bypass => json!({ "stage": "bypass", "verdict": "answered" }),
        DecisionStep::ProtectionPaused { .. } => {
            json!({ "stage": "protection_paused", "verdict": "paused" })
        }
        DecisionStep::FilterBlocked => {
            json!({ "stage": "filter_qname", "verdict": "blocked" })
        }
        DecisionStep::FilterRewrite => {
            json!({ "stage": "filter_qname", "verdict": "rewritten" })
        }
        DecisionStep::FilterSkipped { reason } => {
            json!({ "stage": "filter_qname", "verdict": "skipped", "reason": reason })
        }
        DecisionStep::AnswerChainBlocked => {
            json!({ "stage": "answer_chain", "verdict": "blocked" })
        }
        DecisionStep::AnswerIpBlocked => {
            json!({ "stage": "answer_ip", "verdict": "blocked" })
        }
        DecisionStep::CnameChain { hops, addresses } => json!({
            "stage": "cname_chain",
            "verdict": "resolved",
            "hops": hops.iter().map(chain_hop_json).collect::<Vec<_>>(),
            "addresses": addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }),
        DecisionStep::RebindSkipped { .. } => {
            json!({ "stage": "rebind", "verdict": "skipped" })
        }
        DecisionStep::RebindStripped { count } => {
            json!({ "stage": "rebind", "verdict": "stripped", "count": count })
        }
        DecisionStep::AaaaSuppressed => {
            json!({ "stage": "aaaa_suppressed", "verdict": "suppressed" })
        }
        DecisionStep::Resolve { source, dnssec } => json!({
            "stage": "resolve",
            "verdict": "resolved",
            "source": answer_source_str(*source),
            "dnssec": dnssec_str(*dnssec),
        }),
        DecisionStep::ResolveFailed { cause_code } => json!({
            "stage": "resolve",
            "verdict": "failed",
            "cause_code": cause_code,
        }),
        DecisionStep::SafeSearchRewrite { provider, target } => json!({
            "stage": "safesearch",
            "verdict": "rewritten",
            "provider": provider.as_ref(),
            "target": target.as_ref(),
        }),
        DecisionStep::ScheduleActive { id, filter_set } => json!({
            "stage": "schedule",
            "verdict": "active",
            "id": id.as_ref(),
            "filter_set": filter_set.as_str(),
        }),
    }
}

/// Returns microseconds since the unix epoch (negative before it).
pub(crate) fn system_time_micros(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_micros()).unwrap_or(i64::MAX),
    }
}

/// Formats [`SystemTime`] as RFC 3339 with microsecond precision and a `Z`
/// suffix.
pub(crate) fn format_rfc3339_micros(time: SystemTime) -> String {
    let odt = OffsetDateTime::from(time);
    let (year, month_day, time_part) = (odt.year(), odt.month() as u8, odt.time());
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        year,
        month_day,
        odt.day(),
        time_part.hour(),
        time_part.minute(),
        time_part.second(),
        time_part.nanosecond() / 1000,
    )
}
