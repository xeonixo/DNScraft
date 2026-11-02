//! UniFi Network Integration API (`/proxy/network/integration/v1/…`).
//!
//! Fetches sites, networks (with optional details), and paged connected clients.
//! Defensive parsing: unknown fields ignored; bad rows skipped and counted.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use ipnet::IpNet;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Semaphore;

use crate::error::ClientsError;
use crate::gateway::GatewayClient;
use crate::merge::{MAX_CLIENT_COUNT, NetworkInfo, UnifiObservation};
use crate::types::{ClientId, MacAddr};

/// Integration API path prefix on the gateway.
pub const INTEGRATION_PREFIX: &str = "/proxy/network/integration/v1";

const PAGE_LIMIT: usize = 200;
/// Hard page bound: enough for [`MAX_CLIENT_COUNT`] at `PAGE_LIMIT`, plus one.
const MAX_PAGES: usize = MAX_CLIENT_COUNT / PAGE_LIMIT + 1;
/// Soft cap for concurrent network-details GETs (list remains sparse per OpenAPI).
const DETAILS_CONCURRENCY: usize = 8;

/// Result of one Integration fetch.
#[derive(Clone, Debug)]
pub struct IntegrationFetch {
    /// Resolved site UUID.
    pub site_id: String,
    /// Networks (details merged when available).
    pub networks: Vec<NetworkInfo>,
    /// Connected clients as normalised observations (singular `ipAddress`).
    pub observations: Vec<UnifiObservation>,
    /// Rows skipped due to missing id / unparseable fields.
    pub skipped_rows: u64,
}

/// Defensively parses one Integration clients page (`{"data":[…],…}`).
///
/// Never panics on odd row shapes: unknown fields are ignored, bad rows are
/// skipped and counted. A completely unusable body yields
/// [`ClientsError::HttpBody`].
pub fn parse_clients_page_json(body: &[u8]) -> Result<(Vec<UnifiObservation>, u64), ClientsError> {
    let page: ListPage<Value> =
        serde_json::from_slice(body).map_err(|e| ClientsError::HttpBody {
            message: format!("clients JSON: {e}"),
        })?;
    let mut out = Vec::new();
    let mut skipped = 0u64;
    for row in &page.data {
        match parse_client_row(row) {
            Some(obs) => out.push(obs),
            None => skipped += 1,
        }
    }
    Ok((out, skipped))
}

/// Fetches sites → networks → paged clients for one site.
///
/// When `configured_site` is `None`, the sole site is auto-picked; two or more
/// sites without a configured id → [`ClientsError::ConfigInvalid`].
pub async fn fetch(
    gw: &GatewayClient,
    configured_site: Option<&str>,
) -> Result<IntegrationFetch, ClientsError> {
    let site_id = resolve_site(gw, configured_site).await?;
    validate_path_id(&site_id, "site_id")?;
    let networks = fetch_networks(gw, &site_id).await?;
    let (observations, skipped_rows) = fetch_clients(gw, &site_id).await?;
    Ok(IntegrationFetch {
        site_id,
        networks,
        observations,
        skipped_rows,
    })
}

/// Path segment check for Integration `siteId` / `networkId` (OpenAPI uuid).
///
/// Same charset as classic site keys so a hostile body cannot inject `/` or `?`
/// into request paths.
pub(crate) fn validate_path_id(id: &str, field: &str) -> Result<(), ClientsError> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(ClientsError::config(format!(
            "{field} rejected (expected [A-Za-z0-9_-]{{1,64}})"
        )))
    }
}

async fn resolve_site(
    gw: &GatewayClient,
    configured: Option<&str>,
) -> Result<String, ClientsError> {
    let sites = fetch_all_sites(gw).await?;
    match configured {
        Some(want) => {
            if sites.iter().any(|s| s.id == want) {
                Ok(want.to_owned())
            } else {
                Err(ClientsError::config(format!(
                    "configured site_id `{want}` not found in UniFi sites"
                )))
            }
        }
        None => match sites.as_slice() {
            [] => Err(ClientsError::config("no UniFi sites returned")),
            [one] => Ok(one.id.clone()),
            _ => Err(ClientsError::config(
                "multiple UniFi sites; set unifi.site_id",
            )),
        },
    }
}

async fn fetch_all_sites(gw: &GatewayClient) -> Result<Vec<SiteRow>, ClientsError> {
    let mut sites = Vec::new();
    let mut offset = 0usize;
    for page_idx in 0..MAX_PAGES {
        let path = format!("{INTEGRATION_PREFIX}/sites?offset={offset}&limit={PAGE_LIMIT}");
        let body = gw.get(&path).await?;
        let page: ListPage<SiteRow> =
            serde_json::from_slice(&body).map_err(|e| ClientsError::HttpBody {
                message: format!("sites JSON: {e}"),
            })?;
        let count = page.data.len();
        sites.extend(page.data);
        if count < PAGE_LIMIT {
            break;
        }
        offset = offset.saturating_add(PAGE_LIMIT);
        if page_idx + 1 == MAX_PAGES {
            return Err(ClientsError::SyncPartial {
                message: format!("sites pagination exceeded {MAX_PAGES} pages"),
            });
        }
    }
    Ok(sites)
}

struct NetworkOverview {
    id: String,
    name: String,
    vlan_id: Option<u16>,
}

async fn fetch_networks(
    gw: &GatewayClient,
    site_id: &str,
) -> Result<Vec<NetworkInfo>, ClientsError> {
    let overviews = fetch_network_overviews(gw, site_id).await?;
    enrich_network_details(gw, site_id, overviews).await
}

async fn fetch_network_overviews(
    gw: &GatewayClient,
    site_id: &str,
) -> Result<Vec<NetworkOverview>, ClientsError> {
    let mut overviews = Vec::new();
    let mut offset = 0usize;
    for page_idx in 0..MAX_PAGES {
        let path = format!(
            "{INTEGRATION_PREFIX}/sites/{site_id}/networks?offset={offset}&limit={PAGE_LIMIT}"
        );
        let body = match gw.get(&path).await {
            Ok(b) => b,
            Err(e) if page_idx > 0 => {
                return Err(ClientsError::SyncPartial {
                    message: format!("networks page offset={offset}: {}", e.code()),
                });
            }
            Err(e) => return Err(e),
        };
        let page: ListPage<Value> = serde_json::from_slice(&body).map_err(|e| {
            if page_idx > 0 {
                ClientsError::SyncPartial {
                    message: format!("networks page offset={offset} JSON: {e}"),
                }
            } else {
                ClientsError::HttpBody {
                    message: format!("networks JSON: {e}"),
                }
            }
        })?;
        let count = page.data.len();
        for row in page.data {
            let Some(id) = row.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            if validate_path_id(id, "network_id").is_err() {
                continue;
            }
            let name = row
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(id)
                .to_owned();
            let vlan_id = row.get("vlanId").and_then(|v| v.as_u64()).map(|n| n as u16);
            overviews.push(NetworkOverview {
                id: id.to_owned(),
                name,
                vlan_id,
            });
        }
        if count < PAGE_LIMIT {
            break;
        }
        offset = offset.saturating_add(PAGE_LIMIT);
        if page_idx + 1 == MAX_PAGES {
            return Err(ClientsError::SyncPartial {
                message: format!("networks pagination exceeded {MAX_PAGES} pages"),
            });
        }
    }
    Ok(overviews)
}

async fn enrich_network_details(
    gw: &GatewayClient,
    site_id: &str,
    overviews: Vec<NetworkOverview>,
) -> Result<Vec<NetworkInfo>, ClientsError> {
    if overviews.is_empty() {
        return Ok(Vec::new());
    }

    let slots = Arc::new(Semaphore::new(DETAILS_CONCURRENCY));
    let mut joins = tokio::task::JoinSet::new();
    let site_id = site_id.to_owned();

    for (idx, overview) in overviews.into_iter().enumerate() {
        let gw = gw.clone();
        let slots = Arc::clone(&slots);
        let site_id = site_id.clone();
        joins.spawn(async move {
            let permit = match slots.acquire().await {
                Ok(p) => p,
                Err(_) => {
                    // Semaphore is never closed; treat as soft failure.
                    return (
                        idx,
                        NetworkInfo {
                            id: overview.id,
                            name: overview.name,
                            vlan_id: overview.vlan_id,
                            ipv4_prefix: None,
                            ipv6_prefix: None,
                            domain_name: None,
                        },
                    );
                }
            };
            let details_path =
                format!("{INTEGRATION_PREFIX}/sites/{site_id}/networks/{}", overview.id);
            let (ipv4_prefix, ipv6_prefix, domain_name) = match gw.get(&details_path).await {
                Ok(bytes) => parse_network_details(&bytes),
                Err(_) => (None, None, None),
            };
            drop(permit);
            (
                idx,
                NetworkInfo {
                    id: overview.id,
                    name: overview.name,
                    vlan_id: overview.vlan_id,
                    ipv4_prefix,
                    ipv6_prefix,
                    domain_name,
                },
            )
        });
    }

    let mut slotted: Vec<(usize, NetworkInfo)> = Vec::new();
    while let Some(joined) = joins.join_next().await {
        match joined {
            Ok(pair) => slotted.push(pair),
            Err(e) => {
                return Err(ClientsError::HttpBody {
                    message: format!("network details task failed: {e}"),
                });
            }
        }
    }
    slotted.sort_by_key(|(idx, _)| *idx);
    Ok(slotted.into_iter().map(|(_, n)| n).collect())
}

fn parse_network_details(bytes: &[u8]) -> (Option<IpNet>, Option<IpNet>, Option<String>) {
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        return (None, None, None);
    };
    // Details may be wrapped in `{ "data": { … } }` or be the object itself.
    let obj = v.get("data").unwrap_or(&v);

    let ipv4 = obj
        .pointer("/ipv4Configuration/hostIpAddress")
        .and_then(|x| x.as_str())
        .zip(
            obj.pointer("/ipv4Configuration/prefixLength")
                .and_then(|x| x.as_u64()),
        )
        .and_then(|(host, len)| {
            let addr = IpAddr::from_str(host).ok()?;
            IpNet::new(addr, len as u8).ok()
        });

    let ipv6 = obj
        .pointer("/ipv6Configuration/hostIpAddress")
        .and_then(|x| x.as_str())
        .zip(
            obj.pointer("/ipv6Configuration/prefixLength")
                .and_then(|x| x.as_u64()),
        )
        .and_then(|(host, len)| {
            let addr = IpAddr::from_str(host).ok()?;
            IpNet::new(addr, len as u8).ok()
        });

    // OpenAPI 10.6.106: Gateway Managed IPv4 DHCP Server Configuration.domainName
    // lives under ipv4Configuration.dhcpConfiguration. Fallbacks keep older
    // fixtures / classic-shaped payloads working.
    let domain = obj
        .pointer("/ipv4Configuration/dhcpConfiguration/domainName")
        .or_else(|| obj.pointer("/dhcpConfiguration/domainName"))
        .or_else(|| obj.get("domainName"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    (ipv4, ipv6, domain)
}

async fn fetch_clients(
    gw: &GatewayClient,
    site_id: &str,
) -> Result<(Vec<UnifiObservation>, u64), ClientsError> {
    let mut observations = Vec::new();
    let mut skipped = 0u64;
    let mut offset = 0usize;

    for page_idx in 0..MAX_PAGES {
        let path = format!(
            "{INTEGRATION_PREFIX}/sites/{site_id}/clients?offset={offset}&limit={PAGE_LIMIT}"
        );
        let body = match gw.get(&path).await {
            Ok(b) => b,
            Err(e) if page_idx > 0 => {
                return Err(ClientsError::SyncPartial {
                    message: format!("clients page offset={offset}: {}", e.code()),
                });
            }
            Err(e) => return Err(e),
        };

        let page: ListPage<Value> = serde_json::from_slice(&body).map_err(|e| {
            if page_idx > 0 {
                ClientsError::SyncPartial {
                    message: format!("clients page offset={offset} JSON: {e}"),
                }
            } else {
                ClientsError::HttpBody {
                    message: format!("clients JSON: {e}"),
                }
            }
        })?;

        let count = page.data.len();
        for row in page.data {
            match parse_client_row(&row) {
                Some(obs) => observations.push(obs),
                None => skipped += 1,
            }
        }

        if count < PAGE_LIMIT {
            break;
        }
        offset = offset.saturating_add(PAGE_LIMIT);
        if page_idx + 1 == MAX_PAGES {
            return Err(ClientsError::SyncPartial {
                message: format!("clients pagination exceeded {MAX_PAGES} pages"),
            });
        }
    }

    Ok((observations, skipped))
}

fn parse_client_row(row: &Value) -> Option<UnifiObservation> {
    let id_str = row.get("id")?.as_str()?;
    let id = ClientId::new(id_str).ok()?;
    let display_name = row
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id_str)
        .to_owned();

    let mut addresses = Vec::new();
    if let Some(ip) = row.get("ipAddress").and_then(|v| v.as_str())
        && let Ok(addr) = IpAddr::from_str(ip)
    {
        addresses.push(addr);
    }

    let mut macs = Vec::new();
    if let Some(m) = row.get("macAddress").and_then(|v| v.as_str())
        && let Ok(mac) = MacAddr::parse(m)
    {
        macs.push(mac);
    }

    let last_seen = row
        .get("connectedAt")
        .and_then(|v| v.as_str())
        .and_then(parse_connected_at);

    Some(UnifiObservation {
        id,
        display_name,
        macs,
        addresses,
        network_id: None, // not on Integration client schemas
        last_seen,
        online: true,
    })
}

fn parse_connected_at(s: &str) -> Option<SystemTime> {
    let odt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    let secs = odt.unix_timestamp();
    if secs < 0 {
        return None;
    }
    Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct ListPage<T> {
    #[serde(default)]
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct SiteRow {
    id: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn domain_name_from_ipv4_dhcp_configuration() {
        let body = br#"{
            "ipv4Configuration": {
                "hostIpAddress": "198.51.100.1",
                "prefixLength": 24,
                "dhcpConfiguration": {
                    "mode": "SERVER",
                    "domainName": "iot.home.arpa"
                }
            }
        }"#;
        let (v4, _, domain) = parse_network_details(body);
        assert!(v4.is_some());
        assert_eq!(domain.as_deref(), Some("iot.home.arpa"));
    }

    #[test]
    fn domain_name_fallback_top_level_still_works() {
        let body = br#"{ "domainName": "legacy.example" }"#;
        let (_, _, domain) = parse_network_details(body);
        assert_eq!(domain.as_deref(), Some("legacy.example"));
    }

    #[test]
    fn path_id_rejects_traversal() {
        assert!(validate_path_id("11111111-1111-1111-1111-111111111111", "site_id").is_ok());
        assert_eq!(
            validate_path_id("../evil", "site_id").unwrap_err().code(),
            "clients.config.invalid"
        );
        assert_eq!(
            validate_path_id("bad id", "network_id")
                .unwrap_err()
                .code(),
            "clients.config.invalid"
        );
    }
}
