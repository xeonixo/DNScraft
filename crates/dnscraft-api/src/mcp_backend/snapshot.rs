//! Snapshot mutation helpers for MCP write paths (rules, proposals, protected domains).

use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    DomainName, RecordTypeSel, RuleAction, RuleSpec, SetId, build_rule,
};
use dnscraft_mcp::ProtectedDomains;
use dnscraft_mcp::dto::{AddRuleParams, RemoveRuleParams};
use dnscraft_resolver::UpstreamState;
use serde_json::{Value, json};

use crate::api::config_routes::array;
use crate::error::ControlApiError;

use super::shared::stored_time;

pub(crate) fn mcp_error(code: &'static str, params: Value) -> ControlApiError {
    ControlApiError::Module {
        code,
        params: Some(params),
    }
}

/// `policy.config.unknown_filter_set` for `id`.
pub(crate) fn unknown_set(id: &str) -> ControlApiError {
    mcp_error(
        "policy.config.unknown_filter_set",
        json!({ "filter_set_id": id }),
    )
}

/// Maps a filtering builder error onto its forwarded module code.
pub(crate) fn build_error(err: dnscraft_filtering::BuildError) -> ControlApiError {
    let params = err
        .params()
        .into_iter()
        .map(|(key, value)| (key.to_owned(), Value::String(value)))
        .collect::<serde_json::Map<_, _>>();
    mcp_error(err.code(), Value::Object(params))
}

/// Strictly parses a write target set id (default `default`).
///
/// Unlike the read-side [`resolve_set`], an invalid id is an error: a write
/// must never silently land in the default set.
pub(crate) fn parse_set(id: Option<&str>) -> Result<SetId, ControlApiError> {
    let raw = id.unwrap_or("default");
    SetId::new(raw).map_err(|_| unknown_set(raw))
}

/// Resolves a write target set, asking for clarification when several exist.
pub(crate) fn resolve_set_for_write(
    snapshot: Option<&Value>,
    filter_set_id: Option<&str>,
) -> Result<SetId, ControlApiError> {
    if filter_set_id.is_some() {
        return parse_set(filter_set_id);
    }
    let ids: Vec<String> = snapshot
        .map(|s| array(s, "filtering", "sets"))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|set| set.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    match ids.len() {
        0 => parse_set(None),
        1 => parse_set(Some(&ids[0])),
        _ => Err(mcp_error(
            "mcp.needs_clarification",
            json!({
                "reason": "multiple filter sets; specify filter_set_id",
                "candidates": ids.iter().map(|id| json!({ "filter_set_id": id })).collect::<Vec<_>>(),
            }),
        )),
    }
}

pub(crate) fn upstream_state_str(state: UpstreamState) -> &'static str {
    match state {
        UpstreamState::Up => "up",
        UpstreamState::Degraded => "degraded",
        UpstreamState::Down => "down",
        UpstreamState::Unknown => "unknown",
    }
}

/// Validates the non-snapshot parts of an `add_rule` request.
///
/// Returns the target set, canonical domain, reported rule text and the
/// requested lifetime. Doing this before the audited mutation lets every
/// rejection be audited by the caller.
pub(crate) fn prepare_add(
    params: &AddRuleParams,
    maximum: Duration,
) -> Result<(SetId, DomainName, String, Duration), ControlApiError> {
    let set = parse_set(params.filter_set_id.as_deref())?;
    let (domain, rule_text) = canonical_block_rule(&params.domain, params.include_subdomains)?;
    let requested = Duration::from_secs(params.lifetime_seconds);
    if requested.is_zero() || requested > maximum {
        return Err(duration_exceeds(requested, maximum));
    }
    Ok((set, domain, rule_text, requested))
}

/// Validates the non-snapshot parts of a `remove_rule` request.
pub(crate) fn prepare_remove(params: &RemoveRuleParams) -> Result<(SetId, DomainName), ControlApiError> {
    let set = parse_set(params.filter_set_id.as_deref())?;
    let domain = DomainName::parse(&params.domain).map_err(|_| {
        mcp_error(
            "filter_name.invalid_char",
            json!({ "domain": params.domain }),
        )
    })?;
    Ok((set, domain))
}

/// A mutable filter set from the stored snapshot, if it exists.
pub(crate) fn set_mut<'a>(snapshot: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    snapshot
        .get_mut("filtering")?
        .get_mut("sets")?
        .as_array_mut()?
        .iter_mut()
        .find(|set| set.get("id").and_then(Value::as_str) == Some(id))
}

/// Whether a stored rule has not expired at `now`.
pub(crate) fn active_rule(rule: &Value, now: SystemTime) -> bool {
    rule.get("expires_at")
        .and_then(stored_time)
        .is_none_or(|expires| expires > now)
}

/// Protected domains derived from `snapshot` plus the owner's additions.
pub(crate) fn protected_for(
    snapshot: Option<&Value>,
    oidc_issuer: Option<&str>,
    extra: impl IntoIterator<Item = String>,
) -> Result<ProtectedDomains, ControlApiError> {
    crate::protected_list::derive_protected_domains(snapshot, oidc_issuer, extra).map_err(|err| {
        ControlApiError::Module {
            code: err.code(),
            params: err.params(),
        }
    })
}

/// Rejects a target covered by the protected-domain list.
///
/// The error names only the submitted target; the matched protected entry is
/// logged server-side and never returned, so a derived infrastructure host
/// (OIDC issuer, forward-zone apex, filter-list host, …) cannot be read back
/// through the error `params`.
pub(crate) fn reject_protected(
    protected: &ProtectedDomains,
    domain: &str,
    include: bool,
) -> Result<(), ControlApiError> {
    if let Some(hit) = protected.check(domain, include) {
        tracing::warn!(
            submitted = %domain,
            matched = %hit,
            "protected domain rejected"
        );
        return Err(mcp_error(
            "mcp.protected_domain",
            json!({ "domain": domain }),
        ));
    }
    Ok(())
}

/// Canonicalises a temporary-allow target with the filtering builder.
pub(crate) fn canonical_allow_domain(raw: &str) -> Result<DomainName, ControlApiError> {
    let spec = RuleSpec {
        action: RuleAction::Allow,
        domain: raw.to_owned(),
        include_subdomains: false,
        record_types: RecordTypeSel::default(),
        important: false,
        rewrite: None,
    }
    .normalized()
    .map_err(build_error)?;
    let domain = DomainName::parse(&spec.domain)
        .map_err(|_| mcp_error("filter_name.invalid_char", json!({ "domain": raw })))?;
    if domain.label_count() < 2 {
        return Err(mcp_error(
            "mcp.domain_too_broad",
            json!({ "domain": domain.as_str() }),
        ));
    }
    Ok(domain)
}

/// Canonicalises a block-rule target and builds its rule text.
///
/// Returns the canonical domain and the `|`/`||` rule text the MCP tool
/// reports, using the same filtering builder as the config path so the two
/// cannot drift.
pub(crate) fn canonical_block_rule(
    raw: &str,
    include_subdomains: bool,
) -> Result<(DomainName, String), ControlApiError> {
    let spec = RuleSpec {
        action: RuleAction::Block,
        domain: raw.to_owned(),
        include_subdomains,
        record_types: RecordTypeSel::default(),
        important: false,
        rewrite: None,
    }
    .normalized()
    .map_err(build_error)?;
    let domain = DomainName::parse(&spec.domain)
        .map_err(|_| mcp_error("filter_name.invalid_char", json!({ "domain": spec.domain })))?;
    if domain.label_count() < 2 {
        return Err(mcp_error(
            "mcp.domain_too_broad",
            json!({ "domain": domain.as_str() }),
        ));
    }
    let rule_text = build_rule(&spec).map_err(build_error)?;
    Ok((domain, rule_text))
}

/// `mcp.duration_exceeds_maximum` for a requested and a configured maximum
/// duration.
pub(crate) fn duration_exceeds(requested: Duration, maximum: Duration) -> ControlApiError {
    mcp_error(
        "mcp.duration_exceeds_maximum",
        json!({
            "requested": iso_duration(requested),
            "maximum": iso_duration(maximum),
        }),
    )
}

/// Rejects a fixed-set duration above the configured maximum.
pub(crate) fn duration_error(requested_secs: u64, maximum: Duration) -> Option<ControlApiError> {
    (requested_secs > maximum.as_secs())
        .then(|| duration_exceeds(Duration::from_secs(requested_secs), maximum))
}

/// Renders a duration in its canonical ISO 8601 form.
pub(crate) fn iso_duration(duration: Duration) -> String {
    match duration.as_secs() {
        300 => "PT5M".to_owned(),
        900 => "PT15M".to_owned(),
        3600 => "PT1H".to_owned(),
        seconds => format!("PT{seconds}S"),
    }
}

/// Maps a filtering engine error; anything but an unknown set is internal.
pub(crate) fn engine_error(err: dnscraft_filtering::FilterError, set: &str) -> ControlApiError {
    match err {
        dnscraft_filtering::FilterError::UnknownSet(_) => unknown_set(set),
        other => ControlApiError::Internal {
            message: other.to_string(),
        },
    }
}

/// Appends one MCP block rule to a filter set in `snapshot`.
///
/// Expired entries are pruned first, so the stored array cannot grow without
/// bound and the cap counts only rules that are still active. The cap is
/// enforced here, inside the caller's config apply lock, so two concurrent
/// adds cannot both pass.
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_rule_to_snapshot(
    snapshot: &mut Value,
    set: &SetId,
    domain: &DomainName,
    include_subdomains: bool,
    rule_id: &str,
    created_secs: i64,
    expires_secs: i64,
    token_id: &str,
    cap: usize,
    now: SystemTime,
) -> Result<(), ControlApiError> {
    let set_value = set_mut(snapshot, set.as_str()).ok_or_else(|| unknown_set(set.as_str()))?;
    let rules = set_value
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "filter set is not an object".to_owned(),
        })?
        .entry("mcp_rules")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "mcp_rules is not an array".to_owned(),
        })?;
    rules.retain(|rule| active_rule(rule, now));
    if rules.len() >= cap {
        return Err(mcp_error(
            "mcp.rule_limit_exceeded",
            json!({ "filter_set_id": set.as_str(), "max": cap }),
        ));
    }
    rules.push(json!({
        "id": rule_id,
        "domain": domain.as_str(),
        "include_subdomains": include_subdomains,
        "created_at": created_secs,
        "expires_at": expires_secs,
        "token_id": token_id,
    }));
    Ok(())
}

/// How long a proposed exception waits for the owner.
pub(crate) const PROPOSAL_LIFETIME: Duration = Duration::from_secs(7 * 24 * 3600);
/// Pending proposals per filter set; bounds what an assistant can queue.
const PROPOSAL_CAP: usize = 20;

/// Whether `proposal` is for exactly this name and subdomain flag.
pub(crate) fn same_proposal(proposal: &Value, domain: &str, include_subdomains: bool) -> bool {
    proposal.get("domain").and_then(Value::as_str) == Some(domain)
        && proposal.get("include_subdomains").and_then(Value::as_bool) == Some(include_subdomains)
}

/// The pending proposal for this name in a filter set, if any.
pub(crate) fn find_proposal(
    snapshot: &Value,
    set: &SetId,
    domain: &DomainName,
    include_subdomains: bool,
    now: SystemTime,
) -> Option<Value> {
    snapshot
        .get("filtering")?
        .get("sets")?
        .as_array()?
        .iter()
        .find(|s| s.get("id").and_then(Value::as_str) == Some(set.as_str()))?
        .get("mcp_proposals")?
        .as_array()?
        .iter()
        .find(|p| active_rule(p, now) && same_proposal(p, domain.as_str(), include_subdomains))
        .cloned()
}

/// Appends a pending exception proposal to a filter set in `snapshot`.
///
/// Returns `false` without a change when the same name is already pending, so
/// repeating a proposal is harmless. Expired proposals are pruned first; the
/// cap counts only live ones.
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_proposal_to_snapshot(
    snapshot: &mut Value,
    set: &SetId,
    domain: &DomainName,
    include_subdomains: bool,
    reason: &str,
    proposal_id: &str,
    created_secs: i64,
    expires_secs: i64,
    token_id: &str,
    now: SystemTime,
) -> Result<bool, ControlApiError> {
    let set_value = set_mut(snapshot, set.as_str()).ok_or_else(|| unknown_set(set.as_str()))?;
    let proposals = set_value
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "filter set is not an object".to_owned(),
        })?
        .entry("mcp_proposals")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "mcp_proposals is not an array".to_owned(),
        })?;
    proposals.retain(|p| active_rule(p, now));
    if proposals
        .iter()
        .any(|p| same_proposal(p, domain.as_str(), include_subdomains))
    {
        return Ok(false);
    }
    if proposals.len() >= PROPOSAL_CAP {
        return Err(mcp_error(
            "mcp.rule_limit_exceeded",
            json!({ "filter_set_id": set.as_str(), "max": PROPOSAL_CAP }),
        ));
    }
    proposals.push(json!({
        "id": proposal_id,
        "domain": domain.as_str(),
        "include_subdomains": include_subdomains,
        "reason": reason,
        "created_at": created_secs,
        "expires_at": expires_secs,
        "token_id": token_id,
    }));
    Ok(true)
}

/// Removes the live proposal `id` from whichever filter set holds it.
///
/// Returns the set id and the stored proposal; an unknown or expired id is
/// `control_api.not_found`.
pub(crate) fn take_proposal(
    snapshot: &mut Value,
    id: &str,
    now: SystemTime,
) -> Result<(String, Value), ControlApiError> {
    let sets = snapshot
        .get_mut("filtering")
        .and_then(|f| f.get_mut("sets"))
        .and_then(Value::as_array_mut);
    for set in sets.into_iter().flatten() {
        let set_id = set
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let Some(proposals) = set.get_mut("mcp_proposals").and_then(Value::as_array_mut) else {
            continue;
        };
        if let Some(pos) = proposals
            .iter()
            .position(|p| p.get("id").and_then(Value::as_str) == Some(id) && active_rule(p, now))
        {
            return Ok((set_id, proposals.remove(pos)));
        }
    }
    Err(ControlApiError::NotFound {
        what: "mcp proposal".to_owned(),
    })
}

/// The allow rule text a confirmed proposal adds to the set's custom rules.
pub(crate) fn exception_rule_text(
    domain: &str,
    include_subdomains: bool,
) -> Result<String, ControlApiError> {
    let spec = RuleSpec {
        action: RuleAction::Allow,
        domain: domain.to_owned(),
        include_subdomains,
        record_types: RecordTypeSel::default(),
        important: false,
        rewrite: None,
    }
    .normalized()
    .map_err(build_error)?;
    build_rule(&spec).map_err(build_error)
}

/// Appends `rule_text` as its own line to a set's custom rules, once.
pub(crate) fn append_custom_rule(
    snapshot: &mut Value,
    set: &str,
    rule_text: &str,
) -> Result<(), ControlApiError> {
    let rules = set_mut(snapshot, set)
        .and_then(|s| s.get_mut("custom_rules"))
        .ok_or_else(|| unknown_set(set))?;
    let current = rules.as_str().unwrap_or_default();
    if current.lines().any(|line| line.trim() == rule_text) {
        return Ok(());
    }
    let sep = if current.is_empty() || current.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    *rules = Value::String(format!("{current}{sep}{rule_text}\n"));
    Ok(())
}

/// Removes every stored MCP rule for `domain` from a filter set.
///
/// Returns whether anything was removed. Each matched rule is checked against
/// `protected` with its own stored `include_subdomains` flag (not a caller
/// value); one protected hit aborts the whole removal.
pub(crate) fn remove_rule_from_snapshot(
    snapshot: &mut Value,
    set: &SetId,
    domain: &DomainName,
    protected: &ProtectedDomains,
) -> Result<bool, ControlApiError> {
    let set_value = set_mut(snapshot, set.as_str()).ok_or_else(|| unknown_set(set.as_str()))?;
    let Some(rules) = set_value
        .as_object_mut()
        .and_then(|set| set.get_mut("mcp_rules"))
        .and_then(Value::as_array_mut)
    else {
        return Ok(false);
    };
    let existing = std::mem::take(rules);
    let mut kept = Vec::with_capacity(existing.len());
    let mut removed = false;
    for rule in existing {
        let matches = rule
            .get("domain")
            .and_then(Value::as_str)
            .and_then(|raw| DomainName::parse(raw).ok())
            .is_some_and(|stored| stored.as_str() == domain.as_str());
        if !matches {
            kept.push(rule);
            continue;
        }
        let include = rule
            .get("include_subdomains")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // The stored flag decides coverage, not the request.
        reject_protected(protected, domain.as_str(), include)?;
        removed = true;
    }
    *rules = kept;
    Ok(removed)
}

