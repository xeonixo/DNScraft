//! Minimal OAuth 2.1 authorization server for the MCP endpoint.
//!
//! Lets MCP clients (Claude, ChatGPT, Cursor, Perplexity, desktop loopback, …)
//! sign in through the owner's browser session (OIDC or break-glass) instead of
//! a pasted token. The result is an ordinary MCP-scoped bearer token, so
//! `/mcp/v1` validation, revocation and the token list are unchanged.
//!
//! - Public clients only, PKCE `S256` mandatory, no client secrets.
//! - Built-in vendor redirect allowlist (exact + ChatGPT callback-id prefix)
//!   plus loopback and owner `oauth_extra_redirect_uris`.
//! - Advertises RFC 9207 issuer identification so ChatGPT can use its stable
//!   redirect; authorize responses include `iss`.
//! - Dynamic client registration remembers `client_id` and its redirect URIs
//!   (bounded). Consent + PKCE + allowlist carry the security.
//! - Authorization codes live in memory for 60 s and are single-use.
//! - Access tokens live 1 h; refresh tokens live 30 d (not rotated on refresh).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::{Value, json};

use super::auth::{Role, Scope, csrf_matches, csrf_token_for, session_cookie_value};
use crate::server::AppState;

const CODE_TTL: Duration = Duration::from_secs(60);
const ACCESS_TTL: Duration = Duration::from_secs(3600);
const REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// Exact redirect URIs for known MCP hosts (docs as of 2026-11).
const ALLOWED_REDIRECTS: &[&str] = &[
    // Claude hosted surfaces
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    // ChatGPT stable callback (when AS advertises RFC 9207 iss support)
    "https://chatgpt.com/connector_platform_oauth_redirect",
    // Cursor desktop / agents
    "http://localhost:8787/callback",
    "https://www.cursor.com/agents/mcp/oauth/callback",
    "cursor://anysphere.cursor-mcp/oauth/callback",
    // Perplexity custom connectors
    "https://www.perplexity.ai/rest/connections/oauth_callback",
    "https://enterprise.perplexity.ai/rest/connections/oauth_callback",
    // VS Code
    "http://127.0.0.1:33418/",
    "https://vscode.dev/redirect/",
];
/// Most registered clients remembered; the oldest is forgotten first.
const MAX_REGISTERED_CLIENTS: usize = 1000;

/// Clients registered in this process as `(client_id, redirect_uris)`.
// ponytail: process-global list, oldest-first eviction, linear scan at 1000 entries.
// Keeps AppState unchanged; a restart forgets clients, which then re-register.
static REGISTERED_CLIENTS: Mutex<Vec<(String, Vec<String>)>> = Mutex::new(Vec::new());
static CLIENTS_LOADED: Mutex<bool> = Mutex::new(false);

fn ensure_clients_loaded(state: &AppState) {
    let mut loaded = CLIENTS_LOADED
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if *loaded {
        return;
    }
    if let Some(path) = state
        .mcp_config()
        .oauth_clients_path
        .as_deref()
        .filter(|p| !p.is_empty())
        && let Ok(data) = std::fs::read_to_string(path)
        && let Ok(parsed) = serde_json::from_str::<Vec<(String, Vec<String>)>>(&data)
    {
        let mut clients = REGISTERED_CLIENTS
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *clients = parsed;
    }
    *loaded = true;
}

fn persist_clients(state: &AppState) {
    let Some(path) = state
        .mcp_config()
        .oauth_clients_path
        .as_deref()
        .filter(|p| !p.is_empty())
    else {
        return;
    };
    let clients = REGISTERED_CLIENTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if let Ok(json) = serde_json::to_string(&*clients) {
        let _ = std::fs::write(path, json);
    }
}

fn remember_client(state: &AppState, client_id: String, redirect_uris: Vec<String>) {
    ensure_clients_loaded(state);
    let mut clients = REGISTERED_CLIENTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if clients.len() >= MAX_REGISTERED_CLIENTS {
        clients.remove(0);
    }
    clients.push((client_id, redirect_uris));
    drop(clients);
    persist_clients(state);
}

/// Whether `client_id` was registered with `redirect_uri`.
fn client_allows(state: &AppState, client_id: &str, redirect_uri: &str) -> bool {
    ensure_clients_loaded(state);
    REGISTERED_CLIENTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .any(|(id, uris)| id == client_id && uris.iter().any(|uri| uri == redirect_uri))
}

/// One issued, not yet redeemed authorization code.
pub(crate) struct PendingCode {
    challenge: String,
    redirect_uri: String,
    actor_id: String,
    scope: Scope,
    expires: Instant,
}

/// In-memory code store shared by the authorize and token endpoints.
pub(crate) type OAuthCodes = Arc<Mutex<HashMap<String, PendingCode>>>;

/// The public base URL: the first configured MCP origin, else the request's
/// `Host` (and trusted `X-Forwarded-Proto`).
fn public_base(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(url) = state
        .mcp_config()
        .public_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
    {
        return url.trim_end_matches('/').to_owned();
    }
    if let Some(origin) = state.mcp_config().allowed_origins.first() {
        return origin.trim_end_matches('/').to_owned();
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    format!("{proto}://{host}")
}

/// A plain-http redirect to a loopback address (Claude Code, Cursor desktop, …).
fn is_loopback(uri: &str) -> bool {
    url::Url::parse(uri).is_ok_and(|u| {
        u.scheme() == "http"
            && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
            && u.fragment().is_none()
    })
}

/// ChatGPT's per-connection callback: exactly one path segment after the prefix.
fn is_chatgpt_callback_id(uri: &str) -> bool {
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    if url.scheme() != "https" || url.host_str() != Some("chatgpt.com") || url.fragment().is_some()
    {
        return false;
    }
    let path = url.path().trim_end_matches('/');
    let Some(rest) = path.strip_prefix("/connector/oauth/") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn redirect_allowed(uri: &str, state: &AppState) -> bool {
    ALLOWED_REDIRECTS.contains(&uri)
        || is_loopback(uri)
        || is_chatgpt_callback_id(uri)
        || state
            .mcp_config()
            .oauth_extra_redirect_uris
            .iter()
            .any(|extra| extra == uri)
}

fn random_hex(len: usize) -> Option<String> {
    let mut bytes = vec![0u8; len];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    let mut res = (status, Json(json!({ "error": error }))).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Every OAuth route, with `state` applied.
pub(crate) fn routes(state: AppState) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp/v1",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(server_metadata),
        )
        .route("/oauth/register", post(register))
        .route(
            "/oauth/authorize",
            get(authorize_page).post(authorize_decision),
        )
        .route("/oauth/token", post(token))
        .with_state(state)
}

/// `GET /.well-known/oauth-protected-resource[/mcp/v1]`.
pub(crate) async fn protected_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    let base = public_base(&state, &headers);
    Json(json!({
        "resource": format!("{base}/mcp/v1"),
        "authorization_servers": [base],
        "scopes_supported": ["mcp:read", "mcp:write"],
        "bearer_methods_supported": ["header"],
    }))
}

/// `GET /.well-known/oauth-authorization-server`.
pub(crate) async fn server_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    let base = public_base(&state, &headers);
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp:read", "mcp:write"],
        // ChatGPT uses the stable connector redirect when this is true and
        // authorize responses carry a matching `iss` (RFC 9207).
        "authorization_response_iss_parameter_supported": true,
    }))
}

/// `POST /oauth/register`: stateless dynamic client registration.
pub(crate) async fn register(State(state): State<AppState>, Json(body): Json<Value>) -> Response {
    let uris: Vec<&str> = body
        .get("redirect_uris")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if uris.is_empty() || !uris.iter().all(|u| redirect_allowed(u, &state)) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    }
    let Some(client_id) = random_hex(16) else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    remember_client(
        &state,
        client_id.clone(),
        uris.iter().map(|uri| (*uri).to_owned()).collect(),
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "redirect_uris": uris,
            "client_name": body.get("client_name").and_then(Value::as_str).unwrap_or("MCP client"),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub(crate) struct AuthorizeParams {
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: String,
}

impl AuthorizeParams {
    /// With a `client_id` it must be a registered client with this redirect URI.
    /// Without one, only a loopback redirect is accepted.
    fn client_ok(&self, state: &AppState) -> bool {
        if self.client_id.is_empty() {
            is_loopback(&self.redirect_uri)
        } else {
            client_allows(state, &self.client_id, &self.redirect_uri)
        }
    }

    fn valid(&self, state: &AppState) -> bool {
        self.response_type == "code"
            && redirect_allowed(&self.redirect_uri, state)
            && self.client_ok(state)
            && self.code_challenge_method == "S256"
            && !self.code_challenge.is_empty()
    }
}

fn scope_from_consent(f: &HashMap<String, String>, write_tools_enabled: bool) -> Option<Scope> {
    let read = f.contains_key("scope_read");
    let write = f.contains_key("scope_write");
    if write && !write_tools_enabled {
        return None;
    }
    if !read && !write {
        return None;
    }
    if write {
        Some(Scope::McpWrite)
    } else {
        Some(Scope::McpRead)
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn page(status: StatusCode, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"de\"><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>DNScraft</title>\
         <body style=\"font-family:system-ui;max-width:32rem;margin:3rem auto;padding:0 1rem\">{body}</body></html>"
    );
    let mut res = (status, html).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        ),
    );
    res
}

/// The admin session behind the request, as its cookie and actor id.
async fn admin_session(state: &AppState, headers: &HeaderMap) -> Option<(String, String)> {
    let cookie = session_cookie_value(headers)?;
    let principal = state
        .auth_state()?
        .sessions()
        .validate(&cookie)
        .await
        .ok()?;
    (principal.role == Role::Admin).then_some((cookie, principal.actor_id))
}

/// `GET /oauth/authorize`: the consent page.
pub(crate) async fn authorize_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    if !p.valid(&state) {
        return page(StatusCode::BAD_REQUEST, "<h1>Ungültige Anfrage</h1>");
    }
    let Some((cookie, _)) = admin_session(&state, &headers).await else {
        return page(
            StatusCode::UNAUTHORIZED,
            "<h1>Anmeldung nötig</h1><p>Melde dich zuerst als Administrator im \
             <a href=\"/\" target=\"_blank\">DNScraft-Web-UI</a> an (auch per SSO) \
             und lade diese Seite danach neu.</p>",
        );
    };
    let csrf = csrf_token_for(&cookie);
    let hidden = |name: &str, value: &str| {
        format!(
            "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
            escape(value)
        )
    };
    let host = url::Url::parse(&p.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    let write_on = state.mcp_config().write_tools_enabled;
    let scope_fields = if write_on {
        "<p><label><input type=\"checkbox\" name=\"scope_read\" value=\"1\" checked> \
         MCP lesen (<code>mcp:read</code>)</label></p>\
         <p><label><input type=\"checkbox\" name=\"scope_write\" value=\"1\" checked> \
         MCP schreiben (<code>mcp:write</code>)</label></p>"
    } else {
        "<p><label><input type=\"checkbox\" name=\"scope_read\" value=\"1\" checked> \
         MCP lesen (<code>mcp:read</code>)</label></p>"
    };
    page(
        StatusCode::OK,
        &format!(
            "<h1>Zugriff erlauben?</h1>\
             <p>Eine KI-Anwendung (Claude, ChatGPT, Cursor, Perplexity, …) möchte über MCP \
             auf diesen DNScraft-Knoten zugreifen. Zugriffstoken laufen nach 1 Stunde ab; \
             ein Refresh-Token gilt 30 Tage und lässt sich in den API-Tokens widerrufen.</p>\
             {scope_fields}\
             <p style=\"font-size:1.2rem\">Rückgabe an Host: <strong><code>{}</code></strong></p>\
             <p>Vollständige Weiterleitung: <code>{}</code></p>\
             <form method=\"post\" action=\"/oauth/authorize\">{}{}{}{}{}{}\
             <button name=\"decision\" value=\"allow\">Erlauben</button> \
             <button name=\"decision\" value=\"deny\">Ablehnen</button></form>",
            escape(&host),
            escape(&p.redirect_uri),
            hidden("csrf", csrf.expose()),
            hidden("client_id", &p.client_id),
            hidden("redirect_uri", &p.redirect_uri),
            hidden("state", &p.state),
            hidden("code_challenge", &p.code_challenge),
            hidden("code_challenge_method", &p.code_challenge_method),
        ),
    )
}

fn form(body: &Bytes) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

fn redirect(base: &str, params: &[(&str, &str)]) -> Response {
    let Ok(mut url) = url::Url::parse(base) else {
        return page(StatusCode::BAD_REQUEST, "<h1>Ungültige Anfrage</h1>");
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in params.iter().filter(|(_, v)| !v.is_empty()) {
            q.append_pair(k, v);
        }
    }
    let mut res = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(url.as_str()) {
        res.headers_mut().insert(header::LOCATION, v);
    }
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// `POST /oauth/authorize`: the owner's decision.
pub(crate) async fn authorize_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let f = form(&body);
    let get = |k: &str| f.get(k).map(String::as_str).unwrap_or_default();
    let params = AuthorizeParams {
        response_type: "code".to_owned(),
        client_id: get("client_id").to_owned(),
        redirect_uri: get("redirect_uri").to_owned(),
        state: get("state").to_owned(),
        code_challenge: get("code_challenge").to_owned(),
        code_challenge_method: get("code_challenge_method").to_owned(),
    };
    let Some((cookie, actor_id)) = admin_session(&state, &headers).await else {
        return page(StatusCode::UNAUTHORIZED, "<h1>Anmeldung nötig</h1>");
    };
    if !params.valid(&state) || !csrf_matches(&cookie, get("csrf")) {
        return page(StatusCode::BAD_REQUEST, "<h1>Ungültige Anfrage</h1>");
    }
    let result = if get("decision") == "allow" {
        "ok"
    } else {
        "denied"
    };
    crate::audit::record_auth_event(
        state.db(),
        &actor_id,
        "user",
        "oauth.authorize",
        "mcp",
        result,
        None,
    )
    .await;
    let iss = public_base(&state, &headers);
    if result == "denied" {
        return redirect(
            &params.redirect_uri,
            &[
                ("error", "access_denied"),
                ("state", &params.state),
                ("iss", &iss),
            ],
        );
    }
    let Some(scope) = scope_from_consent(&f, state.mcp_config().write_tools_enabled) else {
        return page(StatusCode::BAD_REQUEST, "<h1>Ungültige Anfrage</h1>");
    };
    let Some(code) = random_hex(32) else {
        return page(StatusCode::INTERNAL_SERVER_ERROR, "<h1>Fehler</h1>");
    };
    {
        let mut codes = state
            .oauth_codes()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        codes.retain(|_, c| c.expires > now);
        codes.insert(
            code.clone(),
            PendingCode {
                challenge: params.code_challenge.clone(),
                redirect_uri: params.redirect_uri.clone(),
                actor_id,
                scope,
                expires: now + CODE_TTL,
            },
        );
    }
    redirect(
        &params.redirect_uri,
        &[("code", &code), ("state", &params.state), ("iss", &iss)],
    )
}

/// `POST /oauth/token`: `authorization_code` (PKCE) and `refresh_token` grants.
pub(crate) async fn token(State(state): State<AppState>, body: Bytes) -> Response {
    let f = form(&body);
    let get = |k: &str| f.get(k).map(String::as_str).unwrap_or_default();
    let Some(tokens) = state.auth_state().map(|a| a.tokens()) else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let grant = get("grant_type");
    let token_json = if grant == "authorization_code" {
        let pending = state
            .oauth_codes()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(get("code"));
        let challenge =
            URL_SAFE_NO_PAD.encode(digest(&SHA256, get("code_verifier").as_bytes()));
        let Some(pending) = pending.filter(|c| {
            c.expires > Instant::now()
                && c.redirect_uri == get("redirect_uri")
                && c.challenge == challenge
        }) else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
        };
        let scope = pending.scope;
        let Ok(access) = tokens
            .create(
                pending.actor_id.clone(),
                "OAuth (MCP)".to_owned(),
                scope,
                Some(ACCESS_TTL),
            )
            .await
        else {
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        let Ok(refresh) = tokens
            .create(
                pending.actor_id,
                "OAuth refresh (MCP)".to_owned(),
                scope,
                Some(REFRESH_TTL),
            )
            .await
        else {
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        json!({
            "access_token": access.plaintext().expose(),
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL.as_secs(),
            "scope": scope.as_str(),
            "refresh_token": refresh.plaintext().expose(),
        })
    } else if grant == "refresh_token" {
        let refresh = get("refresh_token");
        if refresh.is_empty() {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        let Ok(principal) = tokens.authenticate(refresh).await else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
        };
        if !matches!(principal.scope(), Scope::McpRead | Scope::McpWrite) {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }
        let scope = principal.scope();
        let Ok(access) = tokens
            .create(
                principal.actor_id().to_owned(),
                "OAuth (MCP)".to_owned(),
                scope,
                Some(ACCESS_TTL),
            )
            .await
        else {
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        };
        json!({
            "access_token": access.plaintext().expose(),
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL.as_secs(),
            "scope": scope.as_str(),
            "refresh_token": refresh,
        })
    } else {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    };
    let mut res = Json(token_json).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Points a 401 from `/mcp/v1` at the OAuth metadata so clients can sign in.
pub(crate) async fn www_authenticate(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let is_mcp = req.uri().path().starts_with("/mcp/v1");
    let base = public_base(&state, req.headers());
    let mut res = next.run(req).await;
    if is_mcp && res.status() == StatusCode::UNAUTHORIZED {
        let value =
            format!("Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource\"");
        if let Ok(v) = HeaderValue::from_str(&value) {
            res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
    }
    res
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::SystemTime;

    use axum::body::Body;
    use axum::http::Request;
    use dnscraft_common::clock::ManualClock;
    use tower::ServiceExt as _;

    use super::*;
    use crate::api::auth::{AuthState, SessionStore, TokenStore};
    use crate::storage::Db;

    const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
    const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier";

    async fn app() -> (Router, String) {
        let db = Db::open_in_memory(Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH)))
            .await
            .unwrap();
        let sessions = SessionStore::new(
            db.clone(),
            Duration::from_secs(3600),
            Duration::from_secs(43200),
        );
        let tokens = TokenStore::new(db.clone(), Duration::from_secs(365 * 24 * 3600));
        let admin = sessions
            .create("owner".to_owned(), Role::Admin)
            .await
            .unwrap();
        let cookie = admin.cookie().expose().to_owned();
        let state = AppState::new()
            .with_db(db)
            .with_auth(AuthState::new(sessions, tokens));
        (routes(state), cookie)
    }

    fn challenge() -> String {
        URL_SAFE_NO_PAD.encode(digest(&SHA256, VERIFIER.as_bytes()))
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let res = app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn post_form(path: &str, cookie: Option<&str>, body: String) -> Request<Body> {
        let mut req =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, format!("dnscraft_session={c}"));
        }
        req.body(Body::from(body)).unwrap()
    }

    /// Registers a client for [`REDIRECT`] and returns its `client_id`.
    async fn register_client(app: &Router) -> String {
        let req = Request::post("/oauth/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "redirect_uris": [REDIRECT] }).to_string(),
            ))
            .unwrap();
        let (status, _, body) = send(app, req).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let json: Value = serde_json::from_str(&body).unwrap();
        json["client_id"].as_str().unwrap().to_owned()
    }

    fn consent_form_for(cookie: &str, client_id: &str, redirect: &str, decision: &str) -> String {
        let mut s = url::form_urlencoded::Serializer::new(String::new());
        s.append_pair("csrf", csrf_token_for(cookie).expose())
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect)
            .append_pair("state", "xyz")
            .append_pair("code_challenge", &challenge())
            .append_pair("code_challenge_method", "S256")
            .append_pair("scope_read", "1")
            .append_pair("decision", decision);
        s.finish()
    }

    fn consent_form(cookie: &str, client_id: &str, decision: &str) -> String {
        consent_form_for(cookie, client_id, REDIRECT, decision)
    }

    fn token_form(code: &str) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", REDIRECT)
            .append_pair("code_verifier", VERIFIER)
            .finish()
    }

    fn code_from(headers: &HeaderMap) -> String {
        let location = headers.get(header::LOCATION).unwrap().to_str().unwrap();
        let url = url::Url::parse(location).unwrap();
        assert!(location.starts_with(REDIRECT));
        assert!(
            url.query_pairs().any(|(k, v)| k == "iss" && !v.is_empty()),
            "authorize redirect must carry iss: {location}"
        );
        url.query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned()
    }

    #[tokio::test]
    async fn full_flow_issues_a_single_use_mcp_token() {
        let (app, cookie) = app().await;
        let client_id = register_client(&app).await;
        let (status, headers, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form(&cookie, &client_id, "allow"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let code = code_from(&headers);

        let (status, _, body) =
            send(&app, post_form("/oauth/token", None, token_form(&code))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["scope"], "mcp:read");
        assert_eq!(json["expires_in"], 3600);
        assert_eq!(json["access_token"].as_str().unwrap().len(), 64);
        assert!(json["refresh_token"].as_str().is_some());

        let (status, _, _) = send(&app, post_form("/oauth/token", None, token_form(&code))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "code is single-use");
    }

    #[tokio::test]
    async fn refresh_token_extends_access_without_rotation() {
        let (app, cookie) = app().await;
        let client_id = register_client(&app).await;
        let (_, headers, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form(&cookie, &client_id, "allow"),
            ),
        )
        .await;
        let code = code_from(&headers);
        let (_, _, body) = send(&app, post_form("/oauth/token", None, token_form(&code))).await;
        let issued: Value = serde_json::from_str(&body).unwrap();
        let refresh = issued["refresh_token"].as_str().unwrap();
        let access1 = issued["access_token"].as_str().unwrap().to_owned();

        let refresh_body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", refresh)
            .finish();
        let (status, _, body) = send(&app, post_form("/oauth/token", None, refresh_body)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["refresh_token"], refresh);
        assert_ne!(json["access_token"].as_str().unwrap(), access1);
    }

    #[tokio::test]
    async fn wrong_verifier_csrf_and_anonymous_are_refused() {
        let (app, cookie) = app().await;
        let client_id = register_client(&app).await;
        let (_, headers, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form(&cookie, &client_id, "allow"),
            ),
        )
        .await;
        let code = code_from(&headers);
        let bad = token_form(&code).replace("verifier-", "other-");
        let (status, _, _) = send(&app, post_form("/oauth/token", None, bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let forged = consent_form(&cookie, &client_id, "allow")
            .replace(csrf_token_for(&cookie).expose(), "nope");
        let (status, _, _) = send(&app, post_form("/oauth/authorize", Some(&cookie), forged)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                None,
                consent_form(&cookie, &client_id, "allow"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unregistered_or_mismatched_clients_are_refused() {
        let (app, cookie) = app().await;
        let client_id = register_client(&app).await;

        // An unknown client_id is refused even for an allowed redirect.
        let (status, _, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form(&cookie, "not-registered", "allow"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // A registered client may not redirect to a URI it did not register.
        let other = "https://claude.com/api/mcp/auth_callback";
        let (status, _, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form_for(&cookie, &client_id, other, "allow"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Without a client_id only a loopback redirect is accepted.
        let (status, _, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form_for(&cookie, "", REDIRECT, "allow"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let loopback = "http://127.0.0.1:53682/callback";
        let (status, _, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form_for(&cookie, "", loopback, "allow"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn deny_redirects_with_access_denied_and_register_checks_redirects() {
        let (app, cookie) = app().await;
        let client_id = register_client(&app).await;
        let (status, headers, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form(&cookie, &client_id, "deny"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = headers.get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(location.contains("error=access_denied"));
        assert!(location.contains("iss="), "{location}");

        let register = |uri: &str| {
            Request::post("/oauth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "redirect_uris": [uri] }).to_string()))
                .unwrap()
        };
        assert_eq!(send(&app, register(REDIRECT)).await.0, StatusCode::CREATED);
        assert_eq!(
            send(&app, register("https://evil.example/cb")).await.0,
            StatusCode::BAD_REQUEST
        );
        for uri in [
            "https://chatgpt.com/connector_platform_oauth_redirect",
            "https://chatgpt.com/connector/oauth/abc123",
            "https://www.cursor.com/agents/mcp/oauth/callback",
            "http://localhost:8787/callback",
            "https://www.perplexity.ai/rest/connections/oauth_callback",
            "https://enterprise.perplexity.ai/rest/connections/oauth_callback",
        ] {
            assert_eq!(send(&app, register(uri)).await.0, StatusCode::CREATED, "{uri}");
        }
        assert_eq!(
            send(
                &app,
                register("https://chatgpt.com/connector/oauth/../evil")
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(&app, register("https://evil.chatgpt.com/connector/oauth/x")).await.0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn metadata_advertises_iss_support_and_refresh() {
        let (app, _) = app().await;
        let (status, _, body) = send(
            &app,
            Request::get("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["authorization_response_iss_parameter_supported"], true);
        assert!(
            json["grant_types_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|g| g == "refresh_token")
        );
    }

    #[test]
    fn chatgpt_callback_id_matching_is_strict() {
        assert!(is_chatgpt_callback_id(
            "https://chatgpt.com/connector/oauth/callback_abc-123"
        ));
        assert!(!is_chatgpt_callback_id(
            "https://chatgpt.com/connector/oauth/a/b"
        ));
        assert!(!is_chatgpt_callback_id(
            "https://evil.example/connector/oauth/abc"
        ));
        assert!(!is_chatgpt_callback_id(
            "http://chatgpt.com/connector/oauth/abc"
        ));
    }
}
