//! The relay server.
//!
//! Jobs, all of them dumb on purpose:
//! - invite-only sign-up and device login (bearer token, stored only as a hash)
//! - a directory of public KeyPackages, each single-use one handed out once
//! - per-chat sequencing: exactly one Commit per epoch, messages only in the
//!   current epoch, and one agreed order per chat
//! - a mailbox per device that keeps ciphertext until the device acknowledges
//!   it, or 30 days at most
//! - live delivery: a WebSocket that says "you have mail" (never the mail
//!   itself) and forwards encrypted typing signals without storing them
//! - content-free web push to wake devices that aren't connected
//! - encrypted photo storage, deleted after 30 days
//!
//! It never decrypts anything, and it never logs request bodies.

pub mod db;
pub mod hub;
pub mod push;
mod stream;

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{DefaultBodyLimit, FromRequestParts, MatchedPath, Path as UrlPath, Query, Request, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE},
        request::Parts,
        HeaderValue, Method, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hub::Hub;
use messenger_protocol::*;
use push::{Push, PushOutcome};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

/// Delivered or not, mail older than this is deleted.
pub const MAILBOX_RETENTION_SECS: i64 = 30 * 24 * 3600;
/// How long an invite code stays valid.
pub const INVITE_TTL_SECS: i64 = 7 * 24 * 3600;
/// Upper bounds that keep a misbehaving client from filling the disk.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_HANDSHAKE_BYTES: usize = 1024 * 1024;
pub const MAX_KEY_PACKAGES_PER_DEVICE: i64 = 500;
/// Encrypted photos and files.
pub const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;
/// Delivered or not, attachments older than this are deleted.
pub const BLOB_RETENTION_SECS: i64 = 30 * 24 * 3600;

/// Settings that differ between deployments.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Web app origins allowed to call the API from a browser, such as
    /// `https://app.example.com`. Empty means same-origin only.
    pub allowed_origins: Vec<String>,
    /// Contact for push services, `mailto:` or `https:` (RFC 8292).
    pub vapid_subject: String,
    /// Push service hosts the relay may call; `.suffix` matches subdomains.
    pub push_hosts: Vec<String>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            allowed_origins: Vec::new(),
            vapid_subject: "mailto:admin@localhost".into(),
            push_hosts: push::DEFAULT_PUSH_HOSTS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl RelayConfig {
    /// `RELAY_ALLOWED_ORIGINS` and `RELAY_PUSH_HOSTS` are comma-separated;
    /// `RELAY_VAPID_SUBJECT` is a single `mailto:` or `https:` URL.
    pub fn from_env() -> Self {
        let list = |name: &str| -> Option<Vec<String>> {
            std::env::var(name).ok().map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
        };
        let default = RelayConfig::default();
        RelayConfig {
            allowed_origins: list("RELAY_ALLOWED_ORIGINS").unwrap_or_default(),
            vapid_subject: std::env::var("RELAY_VAPID_SUBJECT").unwrap_or(default.vapid_subject),
            push_hosts: list("RELAY_PUSH_HOSTS").unwrap_or(default.push_hosts),
        }
    }
}

pub struct Relay {
    db: Mutex<Connection>,
    hub: Hub,
    push: Push,
    config: RelayConfig,
}

impl Relay {
    pub fn open(path: &Path) -> anyhow::Result<Arc<Self>> {
        Self::open_with(path, RelayConfig::default())
    }

    pub fn open_with(path: &Path, config: RelayConfig) -> anyhow::Result<Arc<Self>> {
        let conn = db::open(path)?;
        // The VAPID key is made once and kept: browsers bind subscriptions
        // to it, so changing it would silently break every subscription.
        let stored: Option<Vec<u8>> = conn
            .query_row("SELECT value FROM server_keys WHERE name = 'vapid'", [], |r| r.get(0))
            .optional()?;
        let private_key: [u8; 32] = match stored {
            Some(bytes) => bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored VAPID key is corrupt"))?,
            None => {
                let key = Push::generate_private_key();
                conn.execute(
                    "INSERT INTO server_keys (name, value) VALUES ('vapid', ?1)",
                    [key.as_slice()],
                )?;
                key
            }
        };
        let push = Push::new(&private_key, config.vapid_subject.clone(), config.push_hosts.clone())?;
        Ok(Arc::new(Relay {
            db: Mutex::new(conn),
            hub: Hub::default(),
            push,
            config,
        }))
    }

    fn with_db<T>(&self, f: impl FnOnce(&mut Connection) -> T) -> T {
        let mut guard = self.db.lock().expect("relay database lock poisoned");
        f(&mut guard)
    }

    /// The device a token belongs to, if any.
    fn authenticate(&self, token: &str) -> Result<Option<AuthDevice>, rusqlite::Error> {
        let hash = sha256(token.as_bytes());
        self.with_db(|conn| {
            let found: Option<(String, String)> = conn
                .query_row(
                    "SELECT id, user_id FROM devices WHERE token_hash = ?1",
                    [&hash],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((device_id, _)) = &found {
                conn.execute(
                    "UPDATE devices SET last_seen = ?1 WHERE id = ?2",
                    params![now(), device_id],
                )?;
            }
            Ok(found.map(|(device_id, user_id)| AuthDevice { device_id, user_id }))
        })
    }

    /// Tells devices they have mail: over their live connection if they
    /// have one, otherwise (when `wake` is set) with an empty web push.
    fn notify(self: &Arc<Self>, devices: &[String], wake: bool) {
        for device in devices {
            if self.hub.send(device, &ServerFrame::Mail) || !wake {
                continue;
            }
            if !self.push.should_send(device) {
                continue;
            }
            let endpoint: Option<String> = self
                .with_db(|c| {
                    c.query_row(
                        "SELECT endpoint FROM push_subscriptions WHERE device_id = ?1",
                        [device],
                        |r| r.get(0),
                    )
                    .optional()
                })
                .unwrap_or(None);
            let Some(endpoint) = endpoint else { continue };
            let relay = self.clone();
            let device = device.clone();
            tokio::spawn(async move {
                match relay.push.send(&endpoint, now()).await {
                    PushOutcome::Sent => {}
                    PushOutcome::Gone => {
                        let _ = relay.with_db(|c| {
                            c.execute("DELETE FROM push_subscriptions WHERE device_id = ?1", [&device])
                        });
                    }
                    PushOutcome::Failed(e) => tracing::warn!("web push failed: {e}"),
                }
            });
        }
    }

    /// Passes an encrypted typing signal to the chat's other connected
    /// devices. Never stored, never pushed.
    fn forward_typing(&self, sender: &AuthDevice, chat_id: &str, payload: Bytes) {
        if payload.0.is_empty() || payload.0.len() > 1024 {
            return;
        }
        let members = self.with_db(|c| chat_members(c, chat_id)).unwrap_or_default();
        if !members.contains(&sender.device_id) {
            return;
        }
        let frame = ServerFrame::Typing {
            chat_id: chat_id.to_owned(),
            payload,
        };
        for m in members.iter().filter(|m| **m != sender.device_id) {
            self.hub.send(m, &frame);
        }
    }

    fn has_mail(&self, device_id: &str) -> bool {
        self.with_db(|c| {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM mailbox WHERE device_id = ?1)",
                [device_id],
                |r| r.get::<_, bool>(0),
            )
        })
        .unwrap_or(false)
    }

    /// When nobody has signed up yet, mint an invite code for the first user.
    /// Returns `None` once the relay has users; after that, users invite
    /// each other.
    pub fn bootstrap_invite(&self) -> anyhow::Result<Option<String>> {
        self.with_db(|conn| {
            let users: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
            if users > 0 {
                return Ok(None);
            }
            let code = new_invite_code();
            conn.execute(
                "INSERT INTO invites (code_hash, created_by, used_by, expires_at) VALUES (?1, NULL, NULL, ?2)",
                params![sha256(code.as_bytes()), now() + INVITE_TTL_SECS],
            )?;
            Ok(Some(code))
        })
    }

    /// Items waiting in mailboxes across all devices.
    pub fn pending_mail(&self) -> anyhow::Result<u64> {
        self.with_db(|conn| {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM mailbox", [], |r| r.get(0))?;
            Ok(n as u64)
        })
    }

    /// Deletes mail older than [`MAILBOX_RETENTION_SECS`] and expired,
    /// unused invites. Runs every hour from [`serve`].
    pub fn purge_expired(&self) -> anyhow::Result<usize> {
        self.with_db(|conn| {
            let cutoff = now() - MAILBOX_RETENTION_SECS;
            let mail = conn.execute("DELETE FROM mailbox WHERE created_at < ?1", [cutoff])?;
            let invites = conn.execute(
                "DELETE FROM invites WHERE used_by IS NULL AND expires_at < ?1",
                [now()],
            )?;
            let blobs = conn.execute(
                "DELETE FROM blobs WHERE created_at < ?1",
                [now() - BLOB_RETENTION_SECS],
            )?;
            Ok(mail + invites + blobs)
        })
    }
}

/// Build the HTTP API.
pub fn router(relay: Arc<Relay>) -> Router {
    let cors = cors_layer(&relay.config.allowed_origins);
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/accounts", post(register))
        .route("/v1/invites", post(create_invite))
        .route("/v1/key-packages", post(upload_key_packages))
        .route("/v1/key-packages/count", get(key_package_count))
        .route("/v1/users/{username}/key-packages/claim", post(claim_key_packages))
        .route("/v1/chats", post(create_chat))
        .route("/v1/chats/{chat_id}/commits", post(submit_commit))
        .route("/v1/chats/{chat_id}/messages", post(send_message))
        .route("/v1/mailbox", get(fetch_mailbox))
        .route("/v1/mailbox/ack", post(ack_mailbox))
        .route("/v1/stream", get(stream::stream))
        .route("/v1/push/key", get(vapid_key))
        .route("/v1/devices/me/push", put(set_push).delete(delete_push))
        .route(
            "/v1/blobs",
            post(upload_blob).layer(DefaultBodyLimit::max(MAX_BLOB_BYTES)),
        )
        .route("/v1/blobs/{blob_id}", get(download_blob))
        .layer(middleware::from_fn(log_requests))
        .with_state(relay);
    match cors {
        Some(cors) => router.layer(cors),
        None => router,
    }
}

/// Lets the web app, served from its own origin, call the API.
fn cors_layer(origins: &[String]) -> Option<CorsLayer> {
    let origins: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
    if origins.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([AUTHORIZATION, CONTENT_TYPE])
            .max_age(Duration::from_secs(3600)),
    )
}

/// Serve the API on `listener` and purge expired data every hour.
pub async fn serve(listener: TcpListener, relay: Arc<Relay>) -> std::io::Result<()> {
    let purger = relay.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            if let Err(e) = purger.purge_expired() {
                tracing::warn!("purge failed: {e}");
            }
        }
    });
    axum::serve(listener, router(relay)).await
}

/// Logs the route template, status and timing. Never bodies, never the
/// usernames or chat ids inside the URL.
async fn log_requests(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "<unmatched>".into());
    let started = Instant::now();
    let res = next.run(req).await;
    tracing::info!(
        "{} {} -> {} in {}ms",
        method,
        route,
        res.status().as_u16(),
        started.elapsed().as_millis()
    );
    res
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
    current_epoch: Option<u64>,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
            current_epoch: None,
        }
    }
    fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, m)
    }
    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "missing or unknown device token")
    }
    fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, m)
    }
    fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, m)
    }
    fn epoch_conflict(current: u64) -> Self {
        ApiError {
            status: StatusCode::CONFLICT,
            message: "the chat moved to a newer epoch; catch up and retry".into(),
            current_epoch: Some(current),
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!("database error: {e}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorResponse {
            error: self.message,
            current_epoch: self.current_epoch,
        };
        (self.status, Json(body)).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// The signed-in device, from `Authorization: Bearer <device token>`.
pub struct AuthDevice {
    pub device_id: String,
    pub user_id: String,
}

impl FromRequestParts<Arc<Relay>> for AuthDevice {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        relay: &Arc<Relay>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(ApiError::unauthorized)?;
        relay.authenticate(token)?.ok_or_else(ApiError::unauthorized)
    }
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

async fn register(
    State(relay): State<Arc<Relay>>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<RegisterResponse> {
    validate_username(&req.username)?;
    relay.with_db(|conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let code_hash = sha256(req.invite_code.trim().as_bytes());
        let invite: Option<(Option<String>, i64)> = tx
            .query_row(
                "SELECT used_by, expires_at FROM invites WHERE code_hash = ?1",
                [&code_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match invite {
            Some((None, expires_at)) if expires_at >= now() => {}
            _ => return Err(ApiError::forbidden("invite code is invalid, used or expired")),
        }
        let taken: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1)",
                [&req.username],
                |r| r.get(0),
            )?;
        if taken {
            return Err(ApiError::new(StatusCode::CONFLICT, "username is taken"));
        }

        let user_id = random_id();
        let device_id = random_id();
        let token = new_token();
        let t = now();
        tx.execute(
            "INSERT INTO users (id, username, created_at) VALUES (?1, ?2, ?3)",
            params![user_id, req.username, t],
        )?;
        tx.execute(
            "INSERT INTO devices (id, user_id, token_hash, created_at, last_seen) VALUES (?1, ?2, ?3, ?4, ?4)",
            params![device_id, user_id, sha256(token.as_bytes()), t],
        )?;
        tx.execute(
            "UPDATE invites SET used_by = ?1 WHERE code_hash = ?2",
            params![user_id, code_hash],
        )?;
        tx.commit()?;
        Ok(Json(RegisterResponse {
            user_id,
            device_id,
            device_token: token,
        }))
    })
}

async fn create_invite(State(relay): State<Arc<Relay>>, me: AuthDevice) -> ApiResult<InviteResponse> {
    let code = new_invite_code();
    let expires_at = now() + INVITE_TTL_SECS;
    relay.with_db(|conn| {
        conn.execute(
            "INSERT INTO invites (code_hash, created_by, used_by, expires_at) VALUES (?1, ?2, NULL, ?3)",
            params![sha256(code.as_bytes()), me.user_id, expires_at],
        )?;
        Ok(Json(InviteResponse { code, expires_at }))
    })
}

// ---------------------------------------------------------------------------
// Key directory
// ---------------------------------------------------------------------------

async fn upload_key_packages(
    State(relay): State<Arc<Relay>>,
    me: AuthDevice,
    Json(req): Json<UploadKeyPackagesRequest>,
) -> ApiResult<KeyPackageCount> {
    if req.key_packages.len() > 200 {
        return Err(ApiError::bad_request("upload at most 200 KeyPackages at a time"));
    }
    if req
        .key_packages
        .iter()
        .chain(req.last_resort.iter())
        .any(|kp| kp.0.is_empty() || kp.0.len() > 16 * 1024)
    {
        return Err(ApiError::bad_request("KeyPackage is empty or too large"));
    }
    relay.with_db(|conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let have: i64 = tx.query_row(
            "SELECT COUNT(*) FROM key_packages WHERE device_id = ?1 AND last_resort = 0",
            [&me.device_id],
            |r| r.get(0),
        )?;
        if have + req.key_packages.len() as i64 > MAX_KEY_PACKAGES_PER_DEVICE {
            return Err(ApiError::bad_request("too many unclaimed KeyPackages"));
        }
        for kp in &req.key_packages {
            tx.execute(
                "INSERT INTO key_packages (device_id, data, last_resort) VALUES (?1, ?2, 0)",
                params![me.device_id, kp.0],
            )?;
        }
        if let Some(kp) = &req.last_resort {
            tx.execute(
                "DELETE FROM key_packages WHERE device_id = ?1 AND last_resort = 1",
                [&me.device_id],
            )?;
            tx.execute(
                "INSERT INTO key_packages (device_id, data, last_resort) VALUES (?1, ?2, 1)",
                params![me.device_id, kp.0],
            )?;
        }
        let available: i64 = tx.query_row(
            "SELECT COUNT(*) FROM key_packages WHERE device_id = ?1 AND last_resort = 0",
            [&me.device_id],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(Json(KeyPackageCount {
            available: available as u64,
        }))
    })
}

async fn key_package_count(State(relay): State<Arc<Relay>>, me: AuthDevice) -> ApiResult<KeyPackageCount> {
    relay.with_db(|conn| {
        let available: i64 = conn.query_row(
            "SELECT COUNT(*) FROM key_packages WHERE device_id = ?1 AND last_resort = 0",
            [&me.device_id],
            |r| r.get(0),
        )?;
        Ok(Json(KeyPackageCount {
            available: available as u64,
        }))
    })
}

async fn claim_key_packages(
    State(relay): State<Arc<Relay>>,
    _me: AuthDevice,
    UrlPath(username): UrlPath<String>,
) -> ApiResult<ClaimKeyPackagesResponse> {
    relay.with_db(|conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user_id: String = tx
            .query_row("SELECT id FROM users WHERE username = ?1", [&username], |r| r.get(0))
            .optional()?
            .ok_or_else(|| ApiError::not_found("no such user"))?;
        let device_ids: Vec<String> = {
            let mut stmt = tx.prepare("SELECT id FROM devices WHERE user_id = ?1 ORDER BY created_at")?;
            let rows = stmt.query_map([&user_id], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut devices = Vec::new();
        for device_id in device_ids {
            // Prefer a single-use package and delete it as it's handed out;
            // fall back to the reusable last-resort package.
            let single: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT id, data FROM key_packages WHERE device_id = ?1 AND last_resort = 0 ORDER BY id LIMIT 1",
                    [&device_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let data = match single {
                Some((id, data)) => {
                    tx.execute("DELETE FROM key_packages WHERE id = ?1", [id])?;
                    Some(data)
                }
                None => tx
                    .query_row(
                        "SELECT data FROM key_packages WHERE device_id = ?1 AND last_resort = 1",
                        [&device_id],
                        |r| r.get(0),
                    )
                    .optional()?,
            };
            if let Some(data) = data {
                devices.push(ClaimedKeyPackage {
                    device_id,
                    key_package: Bytes(data),
                });
            }
        }
        tx.commit()?;
        if devices.is_empty() {
            return Err(ApiError::not_found("that user has no KeyPackages available"));
        }
        Ok(Json(ClaimKeyPackagesResponse { username, devices }))
    })
}

// ---------------------------------------------------------------------------
// Chats
// ---------------------------------------------------------------------------

async fn create_chat(
    State(relay): State<Arc<Relay>>,
    me: AuthDevice,
    Json(req): Json<CreateChatRequest>,
) -> ApiResult<serde_json::Value> {
    validate_chat_id(&req.chat_id)?;
    relay.with_db(|conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO chats (id, epoch, next_seq, created_at) VALUES (?1, 0, 1, ?2)",
            params![req.chat_id, now()],
        )?;
        if inserted == 0 {
            return Err(ApiError::new(StatusCode::CONFLICT, "chat id already exists"));
        }
        tx.execute(
            "INSERT INTO chat_members (chat_id, device_id) VALUES (?1, ?2)",
            params![req.chat_id, me.device_id],
        )?;
        tx.commit()?;
        Ok(Json(serde_json::json!({ "chat_id": req.chat_id, "epoch": 0 })))
    })
}

struct ChatRow {
    epoch: u64,
    next_seq: u64,
    last_commit_hash: Option<Vec<u8>>,
}

fn load_chat(conn: &Connection, chat_id: &str) -> Result<ChatRow, ApiError> {
    conn.query_row(
        "SELECT epoch, next_seq, last_commit_hash FROM chats WHERE id = ?1",
        [chat_id],
        |r| {
            Ok(ChatRow {
                epoch: r.get::<_, i64>(0)? as u64,
                next_seq: r.get::<_, i64>(1)? as u64,
                last_commit_hash: r.get(2)?,
            })
        },
    )
    .optional()?
    .ok_or_else(|| ApiError::not_found("no such chat"))
}

fn chat_members(conn: &Connection, chat_id: &str) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT device_id FROM chat_members WHERE chat_id = ?1 ORDER BY device_id")?;
    let rows = stmt.query_map([chat_id], |r| r.get(0))?;
    rows.collect()
}

fn deliver(
    conn: &Connection,
    device_id: &str,
    chat_id: &str,
    chat_seq: u64,
    kind: MailKind,
    payload: &[u8],
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO mailbox (device_id, chat_id, chat_seq, kind, payload, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![device_id, chat_id, chat_seq as i64, kind.as_str(), payload, now()],
    )?;
    Ok(())
}

async fn submit_commit(
    State(relay): State<Arc<Relay>>,
    me: AuthDevice,
    UrlPath(chat_id): UrlPath<String>,
    Json(req): Json<CommitRequest>,
) -> ApiResult<CommitResponse> {
    if req.commit.0.is_empty() || req.commit.0.len() > MAX_HANDSHAKE_BYTES {
        return Err(ApiError::bad_request("commit is empty or too large"));
    }
    if req.added_devices.is_empty() != req.welcome.is_none() {
        return Err(ApiError::bad_request("a Welcome is required exactly when devices are added"));
    }
    if let Some(w) = &req.welcome {
        if w.0.len() > MAX_HANDSHAKE_BYTES {
            return Err(ApiError::bad_request("welcome is too large"));
        }
    }
    if req.removed_devices.contains(&me.device_id) {
        return Err(ApiError::bad_request("a device can't commit its own removal"));
    }
    let commit_hash = sha256(&req.commit.0);

    let (response, commit_to, welcome_to) = relay.with_db(|conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let chat = load_chat(&tx, &chat_id)?;
        let members = chat_members(&tx, &chat_id)?;
        if !members.contains(&me.device_id) {
            return Err(ApiError::forbidden("not a member of this chat"));
        }

        // A retry of a Commit we already accepted (say the response got lost)
        // succeeds again instead of failing as a conflict.
        if chat.last_commit_hash.as_deref() == Some(commit_hash.as_slice())
            && chat.epoch == req.epoch + 1
        {
            let response = CommitResponse {
                epoch: chat.epoch,
                chat_seq: chat.next_seq - 1,
            };
            return Ok((response, Vec::new(), Vec::new()));
        }
        if chat.epoch != req.epoch {
            return Err(ApiError::epoch_conflict(chat.epoch));
        }

        for (i, d) in req.added_devices.iter().enumerate() {
            if members.contains(d) || req.added_devices[..i].contains(d) {
                return Err(ApiError::bad_request("device is already a member"));
            }
            let exists: bool =
                tx.query_row("SELECT EXISTS(SELECT 1 FROM devices WHERE id = ?1)", [d], |r| r.get(0))?;
            if !exists {
                return Err(ApiError::bad_request("unknown device in added_devices"));
            }
        }
        for d in &req.removed_devices {
            if !members.contains(d) {
                return Err(ApiError::bad_request("device in removed_devices is not a member"));
            }
        }

        let seq = chat.next_seq;
        // Everyone who was in the chat gets the Commit, including anyone being
        // removed, so their device learns it's out.
        for m in members.iter().filter(|m| **m != me.device_id) {
            deliver(&tx, m, &chat_id, seq, MailKind::Commit, &req.commit.0)?;
        }
        if let Some(welcome) = &req.welcome {
            for d in &req.added_devices {
                tx.execute(
                    "INSERT INTO chat_members (chat_id, device_id) VALUES (?1, ?2)",
                    params![chat_id, d],
                )?;
                deliver(&tx, d, &chat_id, seq, MailKind::Welcome, &welcome.0)?;
            }
        }
        for d in &req.removed_devices {
            tx.execute(
                "DELETE FROM chat_members WHERE chat_id = ?1 AND device_id = ?2",
                params![chat_id, d],
            )?;
        }
        tx.execute(
            "UPDATE chats SET epoch = epoch + 1, next_seq = next_seq + 1, last_commit_hash = ?1 WHERE id = ?2",
            params![commit_hash, chat_id],
        )?;
        tx.commit()?;
        let commit_to: Vec<String> = members.into_iter().filter(|m| *m != me.device_id).collect();
        let response = CommitResponse {
            epoch: chat.epoch + 1,
            chat_seq: seq,
        };
        Ok((response, commit_to, req.added_devices.clone()))
    })?;
    // Key changes are silent (no push); being added to a chat wakes you up.
    relay.notify(&commit_to, false);
    relay.notify(&welcome_to, true);
    Ok(Json(response))
}

async fn send_message(
    State(relay): State<Arc<Relay>>,
    me: AuthDevice,
    UrlPath(chat_id): UrlPath<String>,
    Json(req): Json<SendMessageRequest>,
) -> ApiResult<SendMessageResponse> {
    if req.ciphertext.0.is_empty() || req.ciphertext.0.len() > MAX_MESSAGE_BYTES {
        return Err(ApiError::bad_request("message is empty or too large"));
    }
    let (response, recipients) = relay.with_db(|conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let chat = load_chat(&tx, &chat_id)?;
        let members = chat_members(&tx, &chat_id)?;
        if !members.contains(&me.device_id) {
            return Err(ApiError::forbidden("not a member of this chat"));
        }
        if chat.epoch != req.epoch {
            return Err(ApiError::epoch_conflict(chat.epoch));
        }
        let seq = chat.next_seq;
        let recipients: Vec<String> = members.into_iter().filter(|m| *m != me.device_id).collect();
        for m in &recipients {
            deliver(&tx, m, &chat_id, seq, MailKind::Message, &req.ciphertext.0)?;
        }
        tx.execute("UPDATE chats SET next_seq = next_seq + 1 WHERE id = ?1", [&chat_id])?;
        tx.commit()?;
        Ok::<_, ApiError>((SendMessageResponse { chat_seq: seq }, recipients))
    })?;
    relay.notify(&recipients, true);
    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Web push subscriptions
// ---------------------------------------------------------------------------

async fn vapid_key(State(relay): State<Arc<Relay>>) -> Json<VapidKeyResponse> {
    Json(VapidKeyResponse {
        public_key: relay.push.public_key().to_owned(),
    })
}

async fn set_push(
    State(relay): State<Arc<Relay>>,
    me: AuthDevice,
    Json(sub): Json<PushSubscription>,
) -> ApiResult<serde_json::Value> {
    if sub.endpoint.len() > 2048 || !relay.push.endpoint_allowed(&sub.endpoint) {
        return Err(ApiError::bad_request("push endpoint isn't at a known push service"));
    }
    relay.with_db(|conn| {
        conn.execute(
            "INSERT INTO push_subscriptions (device_id, endpoint, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(device_id) DO UPDATE SET endpoint = excluded.endpoint, updated_at = excluded.updated_at",
            params![me.device_id, sub.endpoint, now()],
        )?;
        Ok(Json(serde_json::json!({ "ok": true })))
    })
}

async fn delete_push(State(relay): State<Arc<Relay>>, me: AuthDevice) -> ApiResult<serde_json::Value> {
    relay.with_db(|conn| {
        conn.execute("DELETE FROM push_subscriptions WHERE device_id = ?1", [&me.device_id])?;
        Ok(Json(serde_json::json!({ "ok": true })))
    })
}

// ---------------------------------------------------------------------------
// Encrypted attachments
// ---------------------------------------------------------------------------

async fn upload_blob(
    State(relay): State<Arc<Relay>>,
    me: AuthDevice,
    body: axum::body::Bytes,
) -> ApiResult<BlobResponse> {
    if body.is_empty() {
        return Err(ApiError::bad_request("empty upload"));
    }
    let id = random_id();
    relay.with_db(|conn| {
        conn.execute(
            "INSERT INTO blobs (id, uploader, data, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, me.device_id, body.as_ref(), now()],
        )?;
        Ok(Json(BlobResponse {
            id,
            size: body.len() as u64,
        }))
    })
}

async fn download_blob(
    State(relay): State<Arc<Relay>>,
    _me: AuthDevice,
    UrlPath(blob_id): UrlPath<String>,
) -> Result<Response, ApiError> {
    if blob_id.len() != 32 || !blob_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::not_found("no such attachment"));
    }
    let data: Option<Vec<u8>> = relay.with_db(|conn| {
        conn.query_row("SELECT data FROM blobs WHERE id = ?1", [&blob_id], |r| r.get(0))
            .optional()
    })?;
    let data = data.ok_or_else(|| ApiError::not_found("no such attachment"))?;
    Ok((
        [
            (CONTENT_TYPE, "application/octet-stream"),
            // Ciphertext never changes for a given id.
            (CACHE_CONTROL, "private, max-age=2592000, immutable"),
        ],
        data,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Mailbox
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MailboxQuery {
    after: Option<u64>,
    limit: Option<u32>,
}

async fn fetch_mailbox(
    State(relay): State<Arc<Relay>>,
    me: AuthDevice,
    Query(q): Query<MailboxQuery>,
) -> ApiResult<MailboxResponse> {
    let after = q.after.unwrap_or(0) as i64;
    let limit = q.limit.unwrap_or(200).clamp(1, 500) as i64;
    relay.with_db(|conn| {
        let mut stmt = conn.prepare(
            "SELECT id, chat_id, chat_seq, kind, payload, created_at FROM mailbox
             WHERE device_id = ?1 AND id > ?2 ORDER BY id LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![me.device_id, after, limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut items = Vec::new();
        for row in rows {
            let (id, chat_id, chat_seq, kind, payload, created_at) = row?;
            let kind = MailKind::parse(&kind)
                .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "bad mail kind"))?;
            items.push(MailItem {
                id: id as u64,
                chat_id,
                chat_seq: chat_seq as u64,
                kind,
                payload: Bytes(payload),
                created_at,
            });
        }
        Ok(Json(MailboxResponse { items }))
    })
}

async fn ack_mailbox(
    State(relay): State<Arc<Relay>>,
    me: AuthDevice,
    Json(req): Json<AckRequest>,
) -> ApiResult<serde_json::Value> {
    relay.with_db(|conn| {
        let deleted = conn.execute(
            "DELETE FROM mailbox WHERE device_id = ?1 AND id <= ?2",
            params![me.device_id, req.up_to as i64],
        )?;
        Ok(Json(serde_json::json!({ "deleted": deleted })))
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn random_id() -> String {
    hex::encode(random_bytes::<16>())
}

fn new_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

/// Like `7f3a9-c21d0-88b4e-0a6f2`: 80 random bits, easy to read aloud.
fn new_invite_code() -> String {
    let hex = hex::encode(random_bytes::<10>());
    hex.as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).expect("hex is ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

fn validate_username(name: &str) -> Result<(), ApiError> {
    let ok_len = (3..=32).contains(&name.len());
    let ok_chars = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' || c == '-');
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "username must be 3-32 characters: lowercase letters, digits, '_', '.' or '-'",
        ))
    }
}

fn validate_chat_id(id: &str) -> Result<(), ApiError> {
    let ok = (16..=64).contains(&id.len()) && id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request("chat id must be 16-64 lowercase hex characters"))
    }
}
