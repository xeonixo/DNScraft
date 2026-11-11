//! Read-side MCP helpers: explain-block, list rules, test-query.

use std::net::IpAddr;
use std::time::SystemTime;

use dnscraft_filtering::{DomainName, FilterEngine, SetId, Verdict};
use dnscraft_mcp::dto::{
    AnswerRecord, ExplainBlockResult, ExplainReason, ListRulesParams, ListRulesResult, McpRuleInfo,
    PauseInfo, QType, Selection, SynthesizedAnswer, TempAllowInfo, TestQueryFilter, TestQueryResult,
};
use dnscraft_policy::RequestContext;
use serde_json::{Value, json};

use crate::error::ControlApiError;

use super::shared::{
    block_mode_str, dnssec_status_str, filter_qtype, policy_protocol, rdata_str, reason_source_str,
    record_qtype, rfc3339, selection_cause_json, stored_time,
};
use super::snapshot::{mcp_error, parse_set, unknown_set};

fn paginate<T: Clone>(all: Vec<T>, limit: u32, offset: u32) -> (Vec<T>, bool, Option<u32>) {
    let skip = (offset as usize).min(all.len());
    let page = &all[skip..];
    let count = page.len().min(limit as usize);
    let has_more = count < page.len();
    (
        page[..count].to_vec(),
        has_more,
        has_more.then(|| offset.saturating_add(count as u32)),
    )
}

/// Resolves `explain_block`'s `profile_id` to the filter set configured on that
/// profile (the same `profile.filter_set` the policy engine applies).
///
/// A missing `profile_id` means the default filter set. An unknown or
/// unparsable profile is `policy.config.invalid`; a profile whose `filter_set`
/// is not a valid set id is `policy.config.unknown_filter_set`.
pub(crate) fn explain_target(
    snapshot: Option<&Value>,
    profile_id: Option<&str>,
) -> Result<(String, SetId), ControlApiError> {
    let Some(profile_id) = profile_id else {
        let set = parse_set(None)?;
        let name = set.as_str().to_owned();
        return Ok((name, set));
    };
    let profile = snapshot
        .and_then(|snapshot| snapshot.get("policy"))
        .and_then(|policy| policy.get("profiles"))
        .and_then(Value::as_array)
        .and_then(|profiles| {
            profiles
                .iter()
                .find(|profile| profile.get("id").and_then(Value::as_str) == Some(profile_id))
        })
        .ok_or_else(|| {
            mcp_error(
                "policy.config.invalid",
                json!({ "reason": "unknown profile", "id": profile_id }),
            )
        })?;
    let raw = profile
        .get("filter_set")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            mcp_error(
                "policy.config.invalid",
                json!({ "reason": "profile has no filter_set", "id": profile_id }),
            )
        })?;
    let set = SetId::new(raw).map_err(|_| unknown_set(raw))?;
    Ok((profile_id.to_owned(), set))
}

/// Explains a filtered name against the current filtering engine state.
///
/// Shared by the MCP tool and `POST /api/v1/filtering/explain-block` so the two
/// surfaces cannot drift. `profile_id` names a policy profile; its configured
/// `filter_set` is what the engine is asked about.
pub(crate) fn explain(
    filter: &FilterEngine,
    snapshot: Option<&Value>,
    now: SystemTime,
    domain: &str,
    profile_id: Option<&str>,
    qtype: QType,
) -> Result<ExplainBlockResult, ControlApiError> {
    let name = DomainName::parse(domain).map_err(|_| ControlApiError::Module {
        code: "filter_name.invalid_char",
        params: Some(json!({ "domain": domain })),
    })?;
    let (profile_out, set) = explain_target(snapshot, profile_id)?;
    let verdict = filter
        .match_name(&set, &name, filter_qtype(qtype), now)
        .map_err(|_| unknown_set(set.as_str()))?;
    let set_str = set.as_str().to_owned();
    let (verdict, reason) = match &verdict {
        Verdict::Pass | Verdict::Allowed(_) => ("allowed".to_owned(), None),
        Verdict::Blocked(reason) => (
            "blocked".to_owned(),
            Some(ExplainReason {
                rule_text: reason.rule.to_string(),
                source: reason_source_str(&reason.source),
                important: reason.important,
                block_mode: filter
                    .snapshot()
                    .block_mode(&set)
                    .map(|mode| block_mode_str(&mode))
                    .unwrap_or_default(),
            }),
        ),
        Verdict::Rewrite(_, _) => ("allowed".to_owned(), None),
    };
    Ok(ExplainBlockResult {
        domain: name.as_str().to_owned(),
        profile_id: profile_out,
        filter_set_id: set_str,
        verdict,
        reason,
    })
}

/// Lists MCP-managed entries for one filter set.
///
/// Shared by the MCP tool and `GET /api/v1/filtering/mcp-rules`. Stored rules
/// are read from `snapshot`; temporary allows and pauses come from the engine.
pub(crate) fn list_mcp_rules(
    filter: &FilterEngine,
    snapshot: Option<&Value>,
    now: SystemTime,
    params: &ListRulesParams,
) -> Result<ListRulesResult, ControlApiError> {
    let set = parse_set(params.filter_set_id.as_deref())?;
    let set_str = set.as_str().to_owned();
    let mut result = ListRulesResult {
        filter_set_id: set_str.clone(),
        kind: params.kind.clone(),
        ..Default::default()
    };
    match params.kind.as_str() {
        "temporary_allows" => {
            let allows = filter
                .list_temporary_allows(&set, now)
                .map_err(|_| unknown_set(set.as_str()))?;
            let all: Vec<_> = allows
                .into_iter()
                .map(|allow| TempAllowInfo {
                    domain: allow.domain.to_string(),
                    include_subdomains: allow.include_subdomains,
                    created_at: rfc3339(allow.created_at),
                    expires_at: rfc3339(allow.until),
                    filter_set_id: set_str.clone(),
                })
                .collect();
            let (page, has_more, next_offset) = paginate(all, params.limit, params.offset);
            result.temporary_allows = page;
            result.has_more = has_more;
            result.next_offset = next_offset;
        }
        "pauses" => {
            let all: Vec<_> = filter
                .paused_until(&set)
                .filter(|until| *until > now)
                .map(|until| PauseInfo {
                    filter_set_id: set_str.clone(),
                    paused_until: rfc3339(until),
                })
                .into_iter()
                .collect();
            let (page, has_more, next_offset) = paginate(all, params.limit, params.offset);
            result.pauses = page;
            result.has_more = has_more;
            result.next_offset = next_offset;
        }
        "rules" => {
            let stored = snapshot.and_then(|snapshot| {
                snapshot
                    .get("filtering")
                    .and_then(|section| section.get("sets"))
                    .and_then(Value::as_array)
                    .and_then(|sets| {
                        sets.iter()
                            .find(|set| set.get("id").and_then(Value::as_str) == Some(&set_str))
                    })
            });
            if snapshot.is_some() && stored.is_none() {
                return Err(unknown_set(set.as_str()));
            }
            let all: Vec<_> = stored
                .and_then(|set| set.get("mcp_rules"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|rule| rule_info(rule, &set_str, now))
                .collect();
            let (page, has_more, next_offset) = paginate(all, params.limit, params.offset);
            result.rules = page;
            result.has_more = has_more;
            result.next_offset = next_offset;
        }
        _ => {
            return Err(ControlApiError::Module {
                code: "mcp.invalid_input",
                params: Some(json!({
                    "reason": "kind must be rules, temporary_allows or pauses"
                })),
            });
        }
    }
    Ok(result)
}

/// Converts one stored `mcp_rules[]` entry, dropping expired or malformed ones.
pub(crate) fn rule_info(rule: &Value, set_str: &str, now: SystemTime) -> Option<McpRuleInfo> {
    let expires_at = stored_time(rule.get("expires_at")?)?;
    if expires_at <= now {
        return None;
    }
    stored_rule_info(rule, set_str)
}

/// Converts one stored `mcp_rules[]` entry regardless of expiry.
///
/// `find_mcp_rule` uses this so an expired rule can still be removed (the tool
/// then checks its stored coverage flag before deleting it).
pub(crate) fn stored_rule_info(rule: &Value, set_str: &str) -> Option<McpRuleInfo> {
    let domain = DomainName::parse(rule.get("domain")?.as_str()?).ok()?;
    let include_subdomains = rule.get("include_subdomains")?.as_bool()?;
    let created_at = stored_time(rule.get("created_at")?)?;
    let expires_at = stored_time(rule.get("expires_at")?)?;
    Some(McpRuleInfo {
        id: rule
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        domain: domain.to_string(),
        include_subdomains,
        rule_text: format!("{}{}^", if include_subdomains { "||" } else { "|" }, domain),
        created_at: rfc3339(created_at),
        expires_at: rfc3339(expires_at),
        filter_set_id: set_str.to_owned(),
    })
}

/// Finds the stored rule for `domain` in `set`, expired or not.
///
/// An existing snapshot without the set is `policy.config.unknown_filter_set`,
/// matching every other per-set operation. A snapshot with no set at all (a
/// fresh install) simply has no rule.
pub(crate) fn find_stored_rule<'a>(
    snapshot: &'a Value,
    set: &SetId,
    domain: &DomainName,
) -> Result<Option<&'a Value>, ControlApiError> {
    let Some(stored_set) = snapshot
        .get("filtering")
        .and_then(|section| section.get("sets"))
        .and_then(Value::as_array)
        .and_then(|sets| {
            sets.iter()
                .find(|set_value| set_value.get("id").and_then(Value::as_str) == Some(set.as_str()))
        })
    else {
        return Err(unknown_set(set.as_str()));
    };
    Ok(stored_set
        .get("mcp_rules")
        .and_then(Value::as_array)
        .and_then(|rules| {
            rules.iter().find(|rule| {
                rule.get("domain")
                    .and_then(Value::as_str)
                    .and_then(|raw| DomainName::parse(raw).ok())
                    .is_some_and(|stored| stored.as_str() == domain.as_str())
            })
        }))
}

/// Runs a dry-run query and returns the tool-shaped result plus the full
/// decision record (including the synthesized answer).
///
/// `node_id` is the process identity listeners stamp on live queries. Without
/// it, node-restricted views never match (same as a request with no node).
pub(crate) async fn run_test_query(
    policy: &dnscraft_policy::PolicyEngine,
    params: &dnscraft_mcp::dto::TestQueryParams,
    node_id: Option<&str>,
) -> Result<(TestQueryResult, Value), ControlApiError> {
    let source_ip: IpAddr = match params.source_ip.as_deref() {
        Some(raw) => raw.parse().map_err(|_| {
            mcp_error(
                "mcp.invalid_input",
                json!({ "reason": "source_ip must be an IP address" }),
            )
        })?,
        None => IpAddr::from([127, 0, 0, 1]),
    };
    let listener_id =
        dnscraft_policy::ListenerId::new("mcp-test").map_err(|_| ControlApiError::Internal {
            message: "invalid listener id".to_owned(),
        })?;
    let name =
        dnscraft_proto::Name::from_ascii(&params.domain).map_err(|_| ControlApiError::Module {
            code: "filter_name.invalid_char",
            params: Some(json!({ "domain": params.domain })),
        })?;
    let node_id = match node_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            Some(
                dnscraft_policy::NodeId::new(raw).map_err(|_| ControlApiError::Internal {
                    message: format!("invalid process node id: {raw}"),
                })?,
            )
        }
        None => None,
    };
    let client_id = match params
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(raw) => Some(dnscraft_policy::ClientId::new(raw).map_err(|_| {
            mcp_error(
                "mcp.invalid_input",
                json!({ "reason": "client_id must match [a-z0-9-]{1,63}" }),
            )
        })?),
    };
    let ctx = RequestContext {
        source_ip,
        protocol: policy_protocol(&params.protocol),
        listener_id,
        node_id,
        client_id,
        query: dnscraft_resolver::Query {
            name,
            qtype: dnscraft_proto::RecordType(filter_qtype(params.qtype)),
            qclass: dnscraft_proto::Class::IN,
        },
        flags: dnscraft_policy::ClientFlags::default(),
        test_query: true,
    };
    let answer = policy
        .handle(ctx)
        .await
        .map_err(|e| ControlApiError::Module {
            code: e.code(),
            params: None,
        })?;
    let record = &answer.record;
    let verdict = record.filter.as_ref().map_or("allowed", |_| "blocked");
    let filter_dto = record.filter.as_ref().map(|f| TestQueryFilter {
        rule_text: f.reason.rule.to_string(),
        list_id: match &f.reason.source {
            dnscraft_filtering::RuleSource::List { list, .. } => Some(list.to_string()),
            _ => None,
        },
        block_mode: f
            .block_mode
            .as_ref()
            .map(block_mode_str)
            .unwrap_or_default(),
    });
    let records: Vec<AnswerRecord> = answer
        .message
        .answers
        .iter()
        .map(|r| AnswerRecord {
            name: r.name.to_string(),
            qtype: record_qtype(r.rtype()),
            ttl: r.ttl,
            data: rdata_str(&r.rdata),
        })
        .collect();
    let rcode = answer.message.rcode().to_string();
    let records_json = serde_json::to_value(&records).map_err(|e| ControlApiError::Internal {
        message: format!("serialize test-query answer: {e}"),
    })?;
    let mut decision = crate::query_log::decision_record_json(record);
    decision["answer"] = json!({ "rcode": rcode, "records": records_json });
    let sel = selection_cause_json(&record.selection);
    let result = TestQueryResult {
        view_id: record.view_id.to_string(),
        profile_id: record.profile_id.to_string(),
        selection: Selection {
            cause: sel.cause,
            prefix: sel.prefix,
            client_id: record.client_id.as_ref().map(|id| id.to_string()),
        },
        verdict: verdict.to_owned(),
        filter: filter_dto,
        answer: SynthesizedAnswer { rcode, records },
        dnssec: record
            .dnssec
            .as_ref()
            .map(|s| dnssec_status_str(s).to_owned()),
        timings: dnscraft_mcp::dto::DecisionTimings {
            select_us: record.timings.select_us,
            filter_us: record.timings.filter_us,
            total_us: record.timings.select_us
                + record.timings.filter_us
                + record.timings.resolve_us,
        },
    };
    Ok((result, decision))
}

