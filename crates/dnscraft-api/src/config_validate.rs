//! Config snapshot validation, merge and field-diff helpers.
//!
//! Kept separate from [`crate::config_apply`] so the apply/rollback service
//! stays focused on the transactional apply path. Callers that only need the
//! list-source safety checks import from here (or via re-exports).

use std::collections::{BTreeSet, HashSet};

use serde_json::{Map, Value, json};

use crate::config::IpTruncate;
use crate::error::ControlApiError;

/// Top-level sections a snapshot may contain. `resolver` is carried for
/// cross-module validation only (forward-zone ids); it is not applied here.
const TOP_LEVEL_KEYS: [&str; 8] = [
    "filtering",
    "clients",
    "policy",
    "listeners",
    "tls",
    "resolver",
    // Runtime settings owned by the control API (update check, backups).
    "control_api_settings",
    // Webhook notification channels (WX7); secrets are kept outside the snapshot.
    "notifications",
];

/// Sections every config replace must provide.
const REQUIRED_SECTIONS: [&str; 5] = ["filtering", "clients", "policy", "listeners", "tls"];

/// Fields accepted inside one `filtering.sets[]` entry.
/// A set's pause is runtime state (SPEC-mcp § pauses), never a config field.
const FILTER_SET_KEYS: [&str; 8] = [
    "id",
    "name",
    "lists",
    "custom_rules",
    "services",
    "block_mode",
    "mcp_rules",
    "mcp_proposals",
];

/// Fields accepted inside one `mcp_proposals[]` entry.
const MCP_PROPOSAL_KEYS: [&str; 7] = [
    "id",
    "domain",
    "include_subdomains",
    "reason",
    "created_at",
    "expires_at",
    "token_id",
];

/// Fields accepted inside one `mcp_rules[]` entry.
const MCP_RULE_KEYS: [&str; 6] = [
    "id",
    "domain",
    "include_subdomains",
    "created_at",
    "expires_at",
    "token_id",
];

/// Cross-module validation performed before any module apply.
///
/// Checks list references, duplicate ids, view → profile references,
/// profile → filter-set references and profile → forward-zone references. A
/// missing `resolver` section disables the forward-zone check (nothing to
/// compare against); set/profile references are always checked.
pub(crate) fn validate_cross_module(snapshot: &Value) -> Result<(), ControlApiError> {
    let filtering = snapshot.get("filtering");
    let lists = filtering
        .and_then(|value| value.get("lists"))
        .and_then(Value::as_array);
    let sets = filtering
        .and_then(|value| value.get("sets"))
        .and_then(Value::as_array);

    let mut list_ids = HashSet::new();
    if let Some(lists) = lists {
        for list in lists {
            let Some(id) = list.get("id").and_then(Value::as_str) else {
                continue;
            };
            if !list_ids.insert(id) {
                return Err(module_error(
                    "filter_set.duplicate_list",
                    json!({ "id": id }),
                ));
            }
        }
    }

    let mut set_ids = HashSet::new();
    if let Some(sets) = sets {
        for set in sets {
            let Some(id) = set.get("id").and_then(Value::as_str) else {
                continue;
            };
            if !set_ids.insert(id) {
                return Err(module_error(
                    "filter_set.duplicate_set",
                    json!({ "id": id }),
                ));
            }
            if let Some(references) = set.get("lists").and_then(Value::as_array) {
                for reference in references.iter().filter_map(Value::as_str) {
                    if !list_ids.contains(reference) {
                        return Err(module_error(
                            "filter_set.unknown_list",
                            json!({ "set": id, "list": reference }),
                        ));
                    }
                }
            }
        }
    }

    let policy = snapshot.get("policy");
    let profiles = policy
        .and_then(|value| value.get("profiles"))
        .and_then(Value::as_array);
    let mut profile_ids = HashSet::new();
    if let Some(profiles) = profiles {
        for profile in profiles {
            if let Some(id) = profile.get("id").and_then(Value::as_str)
                && !profile_ids.insert(id)
            {
                return Err(module_error(
                    "policy.config.invalid",
                    json!({ "reason": "duplicate profile id", "id": id }),
                ));
            }
        }
    }

    if let Some(views) = policy
        .and_then(|value| value.get("views"))
        .and_then(Value::as_array)
    {
        let mut view_ids = HashSet::new();
        for view in views {
            if let Some(id) = view.get("id").and_then(Value::as_str)
                && !view_ids.insert(id)
            {
                return Err(module_error(
                    "policy.config.invalid",
                    json!({ "reason": "duplicate view id", "id": id }),
                ));
            }
            if let Some(profile) = view.get("profile").and_then(Value::as_str)
                && !profile_ids.contains(profile)
            {
                return Err(module_error(
                    "policy.config.invalid",
                    json!({ "reason": "view references unknown profile", "profile": profile }),
                ));
            }
        }
    }

    let resolver_zone_ids = snapshot
        .get("resolver")
        .and_then(|value| value.get("forward_zones"))
        .and_then(Value::as_array)
        .map(|zones| {
            zones
                .iter()
                .filter_map(|zone| {
                    zone.as_str()
                        .or_else(|| zone.get("id").and_then(Value::as_str))
                })
                .collect::<HashSet<_>>()
        });

    if let Some(profiles) = profiles {
        for profile in profiles {
            let id = profile.get("id").and_then(Value::as_str).unwrap_or("-");
            if let Some(filter_set) = profile.get("filter_set").and_then(Value::as_str)
                && !set_ids.contains(filter_set)
            {
                return Err(module_error(
                    "policy.config.unknown_filter_set",
                    json!({ "id": filter_set }),
                ));
            }
            if let Some(zone_ids) = &resolver_zone_ids
                && let Some(zone) = profile
                    .get("forward_zones")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .find(|zone| !zone_ids.contains(zone))
            {
                return Err(module_error(
                    "policy.config.unknown_forward_zone",
                    json!({ "id": zone, "profile": id }),
                ));
            }
        }
    }
    Ok(())
}

/// Builds a forwarded module error with non-secret `params`.
/// The five required sections, empty. Used when a mutation starts on a fresh
/// install; closures then reject references to missing sets like any replace.
pub(crate) fn empty_snapshot() -> Value {
    json!({
        "filtering": {},
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": {},
    })
}

pub(crate) fn module_error(code: &'static str, params: Value) -> ControlApiError {
    ControlApiError::Module {
        code,
        params: Some(params),
    }
}

/// Section and sub-key diff (`section` or `section.key`) of `next` against
/// `previous`. Only key names are returned, never values, so secrets cannot
/// leak through a dry run.
pub(crate) fn diff_snapshots(previous: Option<&Value>, next: Option<&Value>) -> Value {
    let none = Map::new();
    let old = previous.and_then(Value::as_object).unwrap_or(&none);
    let new = next.and_then(Value::as_object).unwrap_or(&none);
    let mut changed_sections = Vec::new();
    let (mut added, mut removed, mut changed) = (Vec::new(), Vec::new(), Vec::new());
    let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    for name in names {
        let (before, after) = (old.get(name), new.get(name));
        if before == after {
            continue;
        }
        changed_sections.push(name.clone());
        match (before, after) {
            (None, _) => added.push(name.clone()),
            (_, None) => removed.push(name.clone()),
            (Some(Value::Object(b)), Some(Value::Object(a))) => {
                for key in b.keys().chain(a.keys()).collect::<BTreeSet<_>>() {
                    let path = format!("{name}.{key}");
                    match (b.get(key.as_str()), a.get(key.as_str())) {
                        (None, Some(_)) => added.push(path),
                        (Some(_), None) => removed.push(path),
                        (Some(x), Some(y)) if x != y => changed.push(path),
                        _ => {}
                    }
                }
            }
            _ => changed.push(name.clone()),
        }
    }
    json!({
        "changed_sections": changed_sections,
        "added": added,
        "removed": removed,
        "changed": changed,
    })
}

/// Checks the raw `If-Match` value against the current version.
///
/// Accepts `*`, `"5"`, `5`, and the weak form `W/"5"`. A missing header means
/// "no precondition". A malformed header or a mismatch is
/// `control_api.config.version`.
pub(crate) fn check_if_match(raw: Option<&str>, current: Option<i64>) -> Result<(), ControlApiError> {
    let Some(raw) = raw else {
        return Ok(());
    };
    let raw = raw.trim();
    if raw == "*" {
        return match current {
            Some(_) => Ok(()),
            None => Err(ControlApiError::ConfigVersion {
                message: "If-Match: * but no config version exists".to_owned(),
            }),
        };
    }
    let value = raw.strip_prefix("W/").unwrap_or(raw).trim();
    let value = value.trim_matches('"');
    let Ok(version) = value.parse::<i64>() else {
        return Err(ControlApiError::ConfigVersion {
            message: format!("invalid If-Match value `{raw}`"),
        });
    };
    if Some(version) == current {
        Ok(())
    } else {
        Err(ControlApiError::ConfigVersion {
            message: format!("If-Match version {version} is not the current version"),
        })
    }
}

/// The MCP switches editable at runtime; applied over the TOML at startup.
pub const MCP_SETTING_KEYS: [&str; 3] = ["enabled", "write_tools_enabled", "legacy_session_mode"];

/// `control_api_settings.web_access`: `public_enabled` plus an optional CIDR allowlist.
pub(crate) fn validate_web_access(value: &Value) -> Result<(), ControlApiError> {
    let Some(object) = value.as_object() else {
        return Err(config_invalid(
            "control_api_settings.web_access must be an object",
        ));
    };
    if !object.get("public_enabled").is_some_and(Value::is_boolean) {
        return Err(config_invalid(
            "control_api_settings.web_access.public_enabled must be a boolean",
        ));
    }
    if let Some(list) = object.get("allowed_cidrs") {
        let Some(items) = list.as_array() else {
            return Err(config_invalid(
                "control_api_settings.web_access.allowed_cidrs must be an array of CIDR strings",
            ));
        };
        if items.iter().any(|item| !item.is_string()) {
            return Err(config_invalid(
                "control_api_settings.web_access.allowed_cidrs entries must be strings",
            ));
        }
        let cidrs = items.iter().filter_map(Value::as_str);
        if let Err(error) = dnscraft_listeners::parse_public_cidrs(cidrs) {
            return Err(config_invalid(format!(
                "control_api_settings.web_access.allowed_cidrs: {error}"
            )));
        }
    }
    for key in object.keys() {
        if key != "public_enabled" && key != "allowed_cidrs" {
            return Err(config_invalid(format!(
                "unknown field `control_api_settings.web_access.{key}`"
            )));
        }
    }
    Ok(())
}

/// Validates the non-secret runtime keys of `control_api_settings` (GA15).
///
/// Accepted: `update_check` (bool), `web_access` (`public_enabled`, optional `allowed_cidrs`),
/// `backups` (`enabled`,
/// `retention_count`), `query_log` (`retention_days` 1..=3650, `ip_truncate`,
/// `stdout_queries`), `mcp` (boolean `enabled`, `write_tools_enabled`,
/// `legacy_session_mode`) and `oidc` (`enabled`, `issuer`, `client_id`,
/// `admin_group`, `groups_claim`, `token_skew_seconds` 5..=300).
/// Secrets stay out of the snapshot (write-only `PUT /auth/oidc/client-secret`).
pub(crate) fn validate_control_api_settings(settings: &Value) -> Result<(), ControlApiError> {
    let Some(map) = settings.as_object() else {
        return Err(config_invalid("control_api_settings must be an object"));
    };
    for (key, value) in map {
        match key.as_str() {
            "update_check" => {
                if !value.is_boolean() {
                    return Err(config_invalid(
                        "control_api_settings.update_check must be a boolean",
                    ));
                }
            }
            "web_access" => validate_web_access(value)?,
            "backups" => {
                let backups: crate::system::BackupSettings = serde_json::from_value(value.clone())
                    .map_err(|error| {
                        config_invalid(format!("control_api_settings.backups: {error}"))
                    })?;
                if backups.retention_count == 0
                    || backups.retention_count > crate::system::BACKUP_RETENTION_MAX
                {
                    return Err(config_invalid(
                        "control_api_settings.backups.retention_count is out of range",
                    ));
                }
            }
            "query_log" => {
                let object = value.as_object().ok_or_else(|| {
                    config_invalid("control_api_settings.query_log must be an object")
                })?;
                if object.is_empty() {
                    return Err(config_invalid(
                        "control_api_settings.query_log must set retention_days, ip_truncate or stdout_queries",
                    ));
                }
                for (field, field_value) in object {
                    match field.as_str() {
                        "retention_days" => {
                            if !field_value
                                .as_u64()
                                .is_some_and(|d| (1..=3650).contains(&d))
                            {
                                return Err(config_invalid(
                                    "control_api_settings.query_log.retention_days must be 1..=3650",
                                ));
                            }
                        }
                        "ip_truncate" => {
                            let name = field_value.as_str().ok_or_else(|| {
                                config_invalid(
                                    "control_api_settings.query_log.ip_truncate must be a string",
                                )
                            })?;
                            IpTruncate::parse(name).map_err(|_| {
                                config_invalid(
                                    "control_api_settings.query_log.ip_truncate must be `none`, `last_octet` or `last_group`",
                                )
                            })?;
                        }
                        "stdout_queries" => {
                            if !field_value.is_boolean() {
                                return Err(config_invalid(
                                    "control_api_settings.query_log.stdout_queries must be a boolean",
                                ));
                            }
                        }
                        other => {
                            return Err(config_invalid(format!(
                                "unknown field `control_api_settings.query_log.{other}`"
                            )));
                        }
                    }
                }
            }
            "oidc" => {
                let object = value
                    .as_object()
                    .ok_or_else(|| config_invalid("control_api_settings.oidc must be an object"))?;
                for (field, field_value) in object {
                    match field.as_str() {
                        "enabled" => {
                            if !field_value.is_boolean() {
                                return Err(config_invalid(
                                    "control_api_settings.oidc.enabled must be a boolean",
                                ));
                            }
                        }
                        "issuer" | "client_id" | "admin_group" | "groups_claim" => {
                            if !field_value.is_string() {
                                return Err(config_invalid(format!(
                                    "control_api_settings.oidc.{field} must be a string"
                                )));
                            }
                        }
                        "token_skew_seconds" => {
                            if !field_value.as_u64().is_some_and(|s| (5..=300).contains(&s)) {
                                return Err(config_invalid(
                                    "control_api_settings.oidc.token_skew_seconds must be 5..=300",
                                ));
                            }
                        }
                        other => {
                            return Err(config_invalid(format!(
                                "unknown field `control_api_settings.oidc.{other}`"
                            )));
                        }
                    }
                }
            }
            "mcp" => {
                let object = value
                    .as_object()
                    .ok_or_else(|| config_invalid("control_api_settings.mcp must be an object"))?;
                for (field, field_value) in object {
                    if !MCP_SETTING_KEYS.contains(&field.as_str()) {
                        return Err(config_invalid(format!(
                            "unknown field `control_api_settings.mcp.{field}`"
                        )));
                    }
                    if !field_value.is_boolean() {
                        return Err(config_invalid(format!(
                            "control_api_settings.mcp.{field} must be a boolean"
                        )));
                    }
                }
            }
            other => {
                return Err(config_invalid(format!(
                    "unknown field `control_api_settings.{other}`"
                )));
            }
        }
    }
    Ok(())
}

/// Rejects unknown top-level fields, requires the five applied sections, and
/// applies the `mcp_rules` merge to every filter set.
pub(crate) fn merge_mcp_rules(body: Value, stored: Option<&Value>) -> Result<Value, ControlApiError> {
    let Value::Object(mut snapshot) = body else {
        return Err(config_invalid("config body must be a JSON object"));
    };
    for key in snapshot.keys() {
        if !TOP_LEVEL_KEYS.contains(&key.as_str()) {
            return Err(config_invalid(format!("unknown field `{key}`")));
        }
    }
    if let Some(settings) = snapshot.get(crate::system::SETTINGS_SECTION) {
        validate_control_api_settings(settings)?;
    }
    if let Some(section) = snapshot.get(crate::webhooks::SECTION) {
        crate::webhooks::validate_section(section).map_err(ControlApiError::from)?;
    }
    for section in REQUIRED_SECTIONS {
        match snapshot.get(section) {
            Some(Value::Object(_)) => {}
            Some(_) => {
                return Err(config_invalid(format!("`{section}` must be a JSON object")));
            }
            None => {
                return Err(config_invalid(format!(
                    "missing required field `{section}`"
                )));
            }
        }
    }
    if let Some(resolver) = snapshot.get("resolver")
        && !resolver.is_object()
    {
        return Err(config_invalid("`resolver` must be a JSON object"));
    }

    let stored_sets = stored
        .and_then(|value| value.get("filtering"))
        .and_then(|value| value.get("sets"))
        .and_then(Value::as_array);
    if let Some(Value::Object(filtering)) = snapshot.get_mut("filtering")
        && let Some(sets) = filtering.get_mut("sets")
    {
        let Value::Array(sets) = sets else {
            return Err(config_invalid("`filtering.sets` must be an array"));
        };
        for set in sets.iter_mut() {
            let Value::Object(set) = set else {
                return Err(config_invalid(
                    "each `filtering.sets` entry must be an object",
                ));
            };
            for key in set.keys() {
                if !FILTER_SET_KEYS.contains(&key.as_str()) {
                    return Err(config_invalid(format!(
                        "unknown field `{key}` in `filtering.sets`"
                    )));
                }
            }
            merge_set_rules(set, stored_sets)?;
        }
    }

    // A full snapshot may carry local filter-list sources directly. Apply the
    // same traversal/SSRF guards as `PUT /api/v1/filter-lists`; otherwise the
    // raw config path would be a bypass.
    if let Some(Value::Object(filtering)) = snapshot.get("filtering")
        && let Some(Value::Array(lists)) = filtering.get("lists")
    {
        for list in lists {
            let Some(source) = list.get("source").and_then(Value::as_object) else {
                continue;
            };
            if let Some(file) = source.get("file").and_then(Value::as_str)
                && !list_source_path_is_safe(file)
            {
                return Err(config_invalid(
                    "filter list `source.file` must be a relative path without `..` components",
                ));
            }
            if let Some(url) = source.get("url").and_then(Value::as_str)
                && !list_source_url_is_safe(url)
            {
                return Err(config_invalid(
                    "filter list `source.url` must be an https:// URL whose host is not loopback/private",
                ));
            }
        }
    }
    Ok(Value::Object(snapshot))
}

/// Whether a client-supplied local filter-list source path is a safe relative
/// path: non-empty, with no `..`, root, or prefix components. An absolute path
/// (`/etc/passwd`) would let a raw snapshot read arbitrary files from the data
/// directory, so it is rejected too.
///
/// `file` sources are an admin-only filtering feature. Rejecting absolute and
/// parent components here covers both the per-list route and a raw
/// `PUT /config` snapshot, so the two validation paths cannot drift. The data
/// directory itself is a server-side bootstrap value and is never accepted
/// from a request.
pub(crate) fn list_source_path_is_safe(path: &str) -> bool {
    let path = std::path::Path::new(path);
    !path.as_os_str().is_empty()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
}

/// Whether a client-supplied filter-list source URL is an `https://` URL whose
/// host is not an internal IP literal. A literal loopback/private/link-local/
/// ULA/CGNAT host is rejected to block SSRF against the node's own services
/// (e.g. `169.254.169.254` cloud metadata); a hostname passes because it is
/// expected to resolve to a public address (a hostname that resolves privately
/// is a fetch-time concern, not config validation).
pub(crate) fn list_source_url_is_safe(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => !crate::config::is_internal_bind(std::net::IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => !crate::config::is_internal_bind(std::net::IpAddr::V6(ip)),
        Some(url::Host::Domain(_)) => true,
        None => false,
    }
}

/// Applies the per-set `mcp_rules` merge rule to one filter-set object.
pub(crate) fn merge_set_rules(
    set: &mut Map<String, Value>,
    stored_sets: Option<&Vec<Value>>,
) -> Result<(), ControlApiError> {
    for (field, allowed) in [
        ("mcp_rules", &MCP_RULE_KEYS[..]),
        ("mcp_proposals", &MCP_PROPOSAL_KEYS[..]),
    ] {
        match set.get(field) {
            None => {
                let id = set.get("id").and_then(Value::as_str);
                let carried = stored_sets
                    .and_then(|sets| {
                        sets.iter()
                            .find(|stored| stored.get("id").and_then(Value::as_str) == id)
                    })
                    .and_then(|stored| stored.get(field))
                    .cloned()
                    .unwrap_or_else(|| Value::Array(Vec::new()));
                set.insert(field.to_owned(), carried);
            }
            Some(Value::Array(entries)) => {
                for entry in entries {
                    let Value::Object(entry) = entry else {
                        return Err(config_invalid(format!(
                            "each `{field}` entry must be an object"
                        )));
                    };
                    for key in entry.keys() {
                        if !allowed.contains(&key.as_str()) {
                            return Err(config_invalid(format!(
                                "unknown field `{key}` in `{field}`"
                            )));
                        }
                    }
                }
            }
            Some(_) => {
                return Err(config_invalid(format!("`{field}` must be an array")));
            }
        }
    }
    Ok(())
}

/// Builds `control_api.config.invalid`.
pub(crate) fn config_invalid(reason: impl Into<String>) -> ControlApiError {
    ControlApiError::ConfigInvalid {
        reason: reason.into(),
    }
}
