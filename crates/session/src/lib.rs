//! What the app does, on every platform.
//!
//! A [`Session`] is one signed-in device. It drives the encryption core
//! against the relay: signing up, starting chats, sending text and photos,
//! syncing, receipts, typing and verification. It never touches the network
//! or the disk itself; the platform supplies both through [`Platform`]. The
//! command-line client and the tests use reqwest and an encrypted file, the
//! web app uses the browser's fetch and IndexedDB through WebAssembly, and
//! the iPhone app will bring its own.
//!
//! The rules that keep keys safe live here, once:
//! - state is saved before any ciphertext leaves the device, and before mail
//!   is acknowledged (the relay deletes what we acknowledge);
//! - a Commit is saved as "in flight" before it's sent and settled (merged
//!   or discarded) before anything else touches the network, so a crash or a
//!   dropped connection can't leave this device in a different epoch from
//!   the rest of the chat.

use std::collections::{BTreeMap, BTreeSet};

use messenger_core::OutgoingCommit;
pub use messenger_core::{
    device_of, open_attachment, username_of, Attachment, Body, ChatInfo, ChatMessage, Contact, CoreError, Engine,
    Event, Notice, ReceiptStatus, VerifyOutcome,
};
use messenger_protocol::*;
pub use messenger_protocol::{PushSubscription, PushSubscriptionKeys};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::value::RawValue;

/// Single-use KeyPackages to keep on the relay.
pub const KEY_PACKAGE_BATCH: usize = 20;
/// Top the pool back up when it falls below this.
pub const KEY_PACKAGE_LOW_WATER: u64 = 5;
/// Replace everything on the relay this often, well inside the 12 weeks
/// after which KeyPackages expire.
pub const KEY_PACKAGE_REFRESH_MS: i64 = 28 * 24 * 3600 * 1000;
/// Largest photo we'll send: the relay's limit minus the encryption overhead.
pub const MAX_PHOTO_BYTES: usize = MAX_BLOB_BYTES - 12 - 16;
/// Thumbnails travel inside the encrypted message, so keep them small.
pub const MAX_THUMBNAIL_CHARS: usize = 24 * 1024;
/// How many times to catch up and retry when the chat moved on meanwhile.
const MAX_EPOCH_RETRIES: usize = 5;
/// How many times to resend the same Commit after a network error.
const TRANSPORT_RETRIES: u64 = 3;
const MAILBOX_PAGE: usize = 200;
const STATE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// What the platform provides
// ---------------------------------------------------------------------------

/// One HTTP request to the relay.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    /// The device token, sent as `Authorization: Bearer …`.
    pub bearer: Option<String>,
    pub content_type: Option<&'static str>,
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Network, storage and time, supplied by each platform.
#[allow(async_fn_in_trait)]
pub trait Platform {
    /// Performs one request. `Err` means no answer arrived (offline, DNS,
    /// TLS, a dropped connection), not an HTTP error status.
    async fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, String>;
    /// Replaces the saved state, which holds private keys and history: keep
    /// it encrypted at rest. Must be durable once it returns.
    async fn save(&self, state: &[u8]) -> Result<(), String>;
    async fn sleep(&self, ms: u64);
    fn now_ms(&self) -> i64;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("couldn't reach the relay: {0}")]
    Offline(String),
    #[error("the relay said no: {message} ({status})")]
    Relay { status: u16, message: String },
    #[error("couldn't save: {0}")]
    Storage(String),
    #[error("{0}")]
    Invalid(String),
    #[error("the chat kept changing while sending; try again")]
    TooManyConflicts,
}

pub type Result<T, E = SessionError> = std::result::Result<T, E>;

enum ApiError {
    /// 409: the chat moved to a newer epoch.
    Conflict,
    Status {
        status: u16,
        message: String,
    },
    Offline(String),
}

impl From<ApiError> for SessionError {
    fn from(e: ApiError) -> Self {
        match e {
            ApiError::Conflict => SessionError::Relay {
                status: 409,
                message: "the chat moved on".into(),
            },
            ApiError::Status { status, message } => SessionError::Relay { status, message },
            ApiError::Offline(e) => SessionError::Offline(e),
        }
    }
}

fn invalid(msg: impl Into<String>) -> SessionError {
    SessionError::Invalid(msg.into())
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    /// Let people see when you've read their messages.
    pub read_receipts: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { read_receipts: true }
    }
}

/// One row of the chat list.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ChatSummary {
    pub chat_id: String,
    /// False once this device was removed.
    pub active: bool,
    /// Everyone in the chat, as `username/device` identities.
    pub members: Vec<String>,
    /// The other people's names, for a title.
    pub title: String,
    pub last: Option<ChatMessage>,
    pub unread: usize,
}

/// About a photo being sent. The app reads the size and makes the thumbnail.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImageInfo {
    pub mime: String,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    /// A tiny preview as a `data:` URL or base64, shown while loading.
    #[serde(default)]
    pub thumbnail: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
}

/// A photo encrypted and ready to upload: see [`Session::prepare_photo`].
#[derive(Clone, Debug)]
pub struct PhotoUpload {
    pub request: HttpRequest,
    key: String,
    sha256: String,
    size: u64,
    info: ImageInfo,
}

/// What a frame on the relay's live stream means.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamUpdate {
    /// Signed in; sync now to catch up.
    Ready,
    /// Something arrived; sync.
    Mail,
    Typing {
        chat_id: String,
        who: String,
    },
    Error {
        error: String,
    },
    /// Nothing for the app (a stale or forged typing signal, say).
    Ignored,
}

// ---------------------------------------------------------------------------
// Saved state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InFlightCommit {
    chat_id: String,
    request: CommitRequest,
    /// The history line to add once it lands.
    notice: Option<Notice>,
}

#[derive(Serialize, Deserialize)]
struct Saved {
    v: u32,
    relay_url: String,
    device_token: String,
    engine: Box<RawValue>,
    #[serde(default)]
    in_flight: Option<InFlightCommit>,
    #[serde(default)]
    receipts_due: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    profile_due: BTreeSet<String>,
    #[serde(default)]
    key_packages_refreshed_ms: i64,
    #[serde(default)]
    settings: Settings,
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

pub struct Session<P: Platform> {
    platform: P,
    relay_url: String,
    token: String,
    engine: Engine,
    in_flight: Option<InFlightCommit>,
    /// Delivery receipts we owe, by chat.
    receipts_due: BTreeMap<String, Vec<String>>,
    /// Chats that should hear our display name.
    profile_due: BTreeSet<String>,
    key_packages_refreshed_ms: i64,
    settings: Settings,
    /// Joined a chat since the last check, which used up a KeyPackage.
    key_packages_used: bool,
    events: Vec<Event>,
}

impl<P: Platform> Session<P> {
    /// Signs up with an invite code. The new device is saved through the
    /// platform before this returns.
    pub async fn register(platform: P, relay_url: &str, invite_code: &str, username: &str) -> Result<Self> {
        validate_username(username)?;
        let relay_url = relay_url.trim().trim_end_matches('/').to_owned();
        if !(relay_url.starts_with("https://") || relay_url.starts_with("http://")) {
            return Err(invalid("the relay address should start with https://"));
        }
        let mut engine = Engine::new(username)?;
        let body = json_body(&RegisterRequest {
            invite_code: invite_code.trim().to_owned(),
            username: username.to_owned(),
        });
        let res: RegisterResponse =
            decode(relay_request(&platform, &relay_url, None, "POST", "/v1/accounts", Some(body)).await?)?;
        engine.set_device_id(&res.device_id);
        let mut session = Session {
            platform,
            relay_url,
            token: res.device_token,
            engine,
            in_flight: None,
            receipts_due: BTreeMap::new(),
            profile_due: BTreeSet::new(),
            key_packages_refreshed_ms: 0,
            settings: Settings::default(),
            key_packages_used: false,
            events: Vec::new(),
        };
        session.save().await?;
        session.publish_key_packages(true).await?;
        Ok(session)
    }

    /// Picks up from saved state, such as after a restart. Doesn't touch the
    /// network.
    pub fn open(platform: P, saved: &[u8]) -> Result<Self> {
        let saved: Saved = serde_json::from_slice(saved)
            .map_err(|e| SessionError::Storage(format!("saved state is unreadable: {e}")))?;
        if saved.v != STATE_VERSION {
            return Err(SessionError::Storage(format!(
                "saved state is version {}, this app reads {STATE_VERSION}",
                saved.v
            )));
        }
        let engine = Engine::import_state(saved.engine.get().as_bytes())?;
        Ok(Session {
            platform,
            relay_url: saved.relay_url,
            token: saved.device_token,
            engine,
            in_flight: saved.in_flight,
            receipts_due: saved.receipts_due,
            profile_due: saved.profile_due,
            key_packages_refreshed_ms: saved.key_packages_refreshed_ms,
            settings: saved.settings,
            key_packages_used: false,
            events: Vec::new(),
        })
    }

    /// Everything this device knows, as bytes for [`Platform::save`]. Holds
    /// private keys and plaintext history.
    pub fn export(&self) -> Result<Vec<u8>> {
        let engine =
            String::from_utf8(self.engine.export_state()?).map_err(|e| SessionError::Storage(e.to_string()))?;
        let saved = Saved {
            v: STATE_VERSION,
            relay_url: self.relay_url.clone(),
            device_token: self.token.clone(),
            engine: RawValue::from_string(engine).map_err(|e| SessionError::Storage(e.to_string()))?,
            in_flight: self.in_flight.clone(),
            receipts_due: self.receipts_due.clone(),
            profile_due: self.profile_due.clone(),
            key_packages_refreshed_ms: self.key_packages_refreshed_ms,
            settings: self.settings.clone(),
        };
        serde_json::to_vec(&saved).map_err(|e| SessionError::Storage(e.to_string()))
    }

    async fn save(&self) -> Result<()> {
        let bytes = self.export()?;
        self.platform.save(&bytes).await.map_err(SessionError::Storage)
    }

    // -----------------------------------------------------------------------
    // Reading state
    // -----------------------------------------------------------------------

    /// Read-only access to everything the core knows: members, history,
    /// contacts, safety numbers. Changes go through the session.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn platform(&self) -> &P {
        &self.platform
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    pub fn username(&self) -> &str {
        self.engine.username()
    }

    pub fn identity(&self) -> Result<String> {
        Ok(self.engine.identity()?)
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Everything that happened since the last call (or the last sync).
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// What to call someone: the name they chose, else their username.
    pub fn name_of(&self, username: &str) -> String {
        if username == self.engine.username() {
            return self.engine.display_name().unwrap_or(username).to_owned();
        }
        self.engine
            .contact(username)
            .and_then(|c| c.display_name.clone())
            .unwrap_or_else(|| username.to_owned())
    }

    /// The chat list, most recent first.
    pub fn chat_list(&self) -> Vec<ChatSummary> {
        let me = self.engine.username();
        let mut out: Vec<ChatSummary> = self
            .engine
            .chats()
            .into_iter()
            .map(|c| {
                let members = self.engine.members(&c.chat_id).unwrap_or_default();
                let mut people: Vec<&str> = members.iter().map(|m| username_of(m)).filter(|u| *u != me).collect();
                people.dedup();
                let title = if people.is_empty() {
                    "Just you".to_owned()
                } else {
                    people.iter().map(|u| self.name_of(u)).collect::<Vec<_>>().join(", ")
                };
                ChatSummary {
                    last: self.engine.last_message(&c.chat_id).cloned(),
                    unread: self.engine.unread_count(&c.chat_id),
                    chat_id: c.chat_id,
                    active: c.active,
                    members,
                    title,
                }
            })
            .collect();
        out.sort_by_key(|s| std::cmp::Reverse(s.last.as_ref().map(|m| m.sent_at_ms).unwrap_or(i64::MAX)));
        out
    }

    // -----------------------------------------------------------------------
    // Talking to the relay
    // -----------------------------------------------------------------------

    async fn request(
        &self,
        method: &'static str,
        path: &str,
        body: Option<(&'static str, Vec<u8>)>,
    ) -> Result<Vec<u8>, ApiError> {
        relay_request(&self.platform, &self.relay_url, Some(&self.token), method, path, body).await
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        decode(self.request("GET", path, None).await?)
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, ApiError> {
        decode(self.request("POST", path, Some(json_body(body))).await?)
    }

    /// Mints an invite code for a friend.
    pub async fn invite(&self) -> Result<String> {
        let res: InviteResponse = self.post("/v1/invites", &serde_json::json!({})).await?;
        Ok(res.code)
    }

    // -----------------------------------------------------------------------
    // KeyPackages
    // -----------------------------------------------------------------------

    /// Uploads a fresh batch and a new last-resort package. With `replace`,
    /// the relay drops our older unclaimed ones first.
    async fn publish_key_packages(&mut self, replace: bool) -> Result<u64> {
        let (single_use, last_resort) = self.engine.generate_key_packages(KEY_PACKAGE_BATCH, true)?;
        // The private halves must be saved before the public halves go out.
        self.save().await?;
        let res: KeyPackageCount = self
            .post(
                "/v1/key-packages",
                &UploadKeyPackagesRequest {
                    key_packages: single_use.into_iter().map(Bytes).collect(),
                    last_resort: last_resort.map(Bytes),
                    replace,
                },
            )
            .await?;
        if replace {
            self.key_packages_refreshed_ms = self.platform.now_ms();
            self.save().await?;
        }
        Ok(res.available)
    }

    fn key_packages_stale(&self) -> bool {
        self.platform.now_ms() - self.key_packages_refreshed_ms >= KEY_PACKAGE_REFRESH_MS
    }

    /// How many of our single-use KeyPackages are waiting on the relay.
    pub async fn key_packages_available(&self) -> Result<u64> {
        let res: KeyPackageCount = self.get("/v1/key-packages/count").await?;
        Ok(res.available)
    }

    /// Tops the relay's pool of our KeyPackages up, or replaces it when
    /// they're getting old.
    pub async fn ensure_key_packages(&mut self) -> Result<()> {
        if self.key_packages_stale() {
            self.publish_key_packages(true).await?;
            return Ok(());
        }
        let res: KeyPackageCount = self.get("/v1/key-packages/count").await?;
        if res.available < KEY_PACKAGE_LOW_WATER {
            self.publish_key_packages(false).await?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chats and members
    // -----------------------------------------------------------------------

    /// Starts a chat with these people (an empty list is fine).
    pub async fn create_chat<S: AsRef<str>>(&mut self, usernames: &[S]) -> Result<String> {
        for u in usernames {
            validate_username(u.as_ref())?;
        }
        self.settle().await?;
        let chat_id = self.engine.create_chat()?;
        self.save().await?;
        let created: Result<serde_json::Value, ApiError> = self
            .post(
                "/v1/chats",
                &CreateChatRequest {
                    chat_id: chat_id.clone(),
                },
            )
            .await;
        if let Err(e) = created {
            self.engine.forget_chat(&chat_id)?;
            self.save().await?;
            return Err(e.into());
        }
        if !usernames.is_empty() {
            if let Err(e) = self.add_members(&chat_id, usernames).await {
                // Don't leave an empty chat behind, unless the add is still
                // in flight and may yet land.
                if self.in_flight.is_none() {
                    self.engine.forget_chat(&chat_id)?;
                    self.save().await?;
                }
                return Err(e);
            }
        }
        Ok(chat_id)
    }

    /// Adds every device of each person to the chat.
    pub async fn add_members<S: AsRef<str>>(&mut self, chat_id: &str, usernames: &[S]) -> Result<()> {
        self.settle().await?;
        let present = self.engine.members(chat_id)?;
        let mut invitees = Vec::new();
        for u in usernames {
            let u = u.as_ref();
            validate_username(u)?;
            if u == self.engine.username() {
                return Err(invalid("you're already in this chat"));
            }
            let claimed: ClaimKeyPackagesResponse = self
                .post(&format!("/v1/users/{u}/key-packages/claim"), &serde_json::json!({}))
                .await
                .map_err(|e| match e {
                    ApiError::Status { status: 404, .. } => invalid(format!("there's no one called {u} here")),
                    e => e.into(),
                })?;
            let new: Vec<_> = claimed
                .devices
                .into_iter()
                .filter(|d| !present.contains(&format!("{u}/{}", d.device_id)))
                .collect();
            if new.is_empty() {
                return Err(invalid(format!("{u} is already in this chat")));
            }
            for d in new {
                invitees.push((u.to_owned(), d.device_id, d.key_package.0));
            }
        }
        let added = invitees.iter().map(|(u, d, _)| format!("{u}/{d}")).collect();
        let notice = Notice::MembersChanged {
            added,
            removed: Vec::new(),
        };
        self.commit(chat_id, Some(notice), |engine| engine.add_members(chat_id, &invitees))
            .await?;
        // Tell the newcomers our name.
        self.flush_owed().await
    }

    /// Removes every device of each person from the chat.
    pub async fn remove_members<S: AsRef<str>>(&mut self, chat_id: &str, usernames: &[S]) -> Result<()> {
        self.settle().await?;
        let names: Vec<&str> = usernames.iter().map(|u| u.as_ref()).collect();
        let devices: Vec<String> = self
            .engine
            .members(chat_id)?
            .iter()
            .filter(|id| names.contains(&username_of(id)))
            .map(|id| device_of(id).to_owned())
            .collect();
        if devices.is_empty() {
            return Err(invalid(format!("{} isn't in this chat", names.join(", "))));
        }
        self.remove_devices(chat_id, &devices).await
    }

    /// Removes specific devices, such as one flagged by
    /// [`Event::NotYourDevice`].
    pub async fn remove_devices(&mut self, chat_id: &str, device_ids: &[String]) -> Result<()> {
        self.settle().await?;
        if device_ids.iter().any(|d| Some(d.as_str()) == self.engine.device_id()) {
            return Err(invalid("you can't remove yourself"));
        }
        let removed = self
            .engine
            .members(chat_id)?
            .into_iter()
            .filter(|id| device_ids.iter().any(|d| d == device_of(id)))
            .collect();
        let notice = Notice::MembersChanged {
            added: Vec::new(),
            removed,
        };
        self.commit(chat_id, Some(notice), |engine| {
            Ok((engine.remove_members(chat_id, device_ids)?, Vec::new()))
        })
        .await
    }

    /// Replaces this device's keys in the chat (post-compromise security).
    pub async fn rotate_keys(&mut self, chat_id: &str) -> Result<()> {
        self.commit(chat_id, None, |engine| Ok((engine.self_update(chat_id)?, Vec::new())))
            .await
    }

    /// Deletes a chat and its history from this device.
    pub async fn forget_chat(&mut self, chat_id: &str) -> Result<()> {
        if self.in_flight.as_ref().is_some_and(|c| c.chat_id == chat_id) {
            self.in_flight = None;
        }
        self.engine.forget_chat(chat_id)?;
        self.receipts_due.remove(chat_id);
        self.profile_due.remove(chat_id);
        self.save().await
    }

    /// Makes a Commit and gets it accepted, catching up and making it again
    /// whenever another Commit wins the epoch first.
    async fn commit(
        &mut self,
        chat_id: &str,
        notice: Option<Notice>,
        make: impl Fn(&mut Engine) -> Result<(OutgoingCommit, Vec<Event>), CoreError>,
    ) -> Result<()> {
        self.settle().await?;
        // The relay only takes a Commit from a device that has read
        // everything waiting for it in the chat, so catch up first.
        self.sync_inbox().await?;
        for _ in 0..MAX_EPOCH_RETRIES {
            let (out, events) = make(&mut self.engine)?;
            let now = self.platform.now_ms();
            for e in events {
                self.absorb(e, now)?;
            }
            self.in_flight = Some(InFlightCommit {
                chat_id: chat_id.to_owned(),
                request: CommitRequest {
                    epoch: out.epoch,
                    commit: Bytes(out.commit),
                    welcome: out.welcome.map(Bytes),
                    added_devices: out.added_devices,
                    removed_devices: out.removed_devices,
                },
                notice: notice.clone(),
            });
            // Saved before it's sent: after a crash, settle() finds out
            // whether it landed.
            self.save().await?;
            if self.submit_in_flight().await? {
                return Ok(());
            }
            self.sync_inbox().await?;
        }
        Err(SessionError::TooManyConflicts)
    }

    /// Sends the in-flight Commit, then merges or discards it depending on
    /// the answer. `Ok(true)`: it landed. `Ok(false)`: another Commit won.
    /// No answer at all leaves it in flight for the next [`Self::settle`].
    async fn submit_in_flight(&mut self) -> Result<bool> {
        let Some(c) = self.in_flight.clone() else {
            return Ok(true);
        };
        let path = format!("/v1/chats/{}/commits", c.chat_id);
        let mut res: Result<CommitResponse, ApiError> = self.post(&path, &c.request).await;
        // Resend the very same bytes after a network error or a server
        // hiccup: the relay recognizes a Commit it already accepted.
        for attempt in 1..=TRANSPORT_RETRIES {
            if !retryable(&res) {
                break;
            }
            self.platform.sleep(250 * attempt).await;
            res = self.post(&path, &c.request).await;
        }
        match res {
            Ok(_) => {
                self.engine.confirm_commit(&c.chat_id)?;
                if matches!(&c.notice, Some(Notice::MembersChanged { added, .. }) if !added.is_empty()) {
                    // Newcomers should learn what to call us.
                    self.profile_due.insert(c.chat_id.clone());
                }
                if let Some(notice) = c.notice {
                    let me = self.engine.identity()?;
                    self.engine
                        .record_notice(&c.chat_id, &me, notice, self.platform.now_ms())?;
                }
                self.in_flight = None;
                self.save().await?;
                Ok(true)
            }
            // Still no clear answer: leave it in flight for next time.
            Err(e) if is_transient(&e) => Err(e.into()),
            Err(e) => {
                // The relay definitely didn't apply it.
                self.engine.abort_commit(&c.chat_id)?;
                self.in_flight = None;
                self.save().await?;
                match e {
                    ApiError::Conflict => Ok(false),
                    e => Err(e.into()),
                }
            }
        }
    }

    /// Finishes a Commit left in flight by a crash or a dropped connection.
    /// Runs before anything else that touches the network.
    async fn settle(&mut self) -> Result<()> {
        if self.in_flight.is_some() {
            self.submit_in_flight().await?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Sending
    // -----------------------------------------------------------------------

    /// Encrypts and sends anything. If the chat moved on meanwhile, catches
    /// up and re-encrypts for the new epoch. Returns the history entry for
    /// text and photos.
    pub async fn send(&mut self, chat_id: &str, body: Body) -> Result<Option<ChatMessage>> {
        self.settle().await?;
        let draft = self.engine.new_draft(body, self.platform.now_ms())?;
        for _ in 0..MAX_EPOCH_RETRIES {
            let out = self.engine.encrypt(chat_id, &draft)?;
            // The ratchet moved: save before the ciphertext leaves.
            self.save().await?;
            let req = SendMessageRequest {
                epoch: out.epoch,
                ciphertext: Bytes(out.ciphertext),
                silent: out.silent,
            };
            match self
                .post::<_, SendMessageResponse>(&format!("/v1/chats/{chat_id}/messages"), &req)
                .await
            {
                Ok(_) => {
                    let msg = self.engine.record_sent(chat_id, &draft)?;
                    self.save().await?;
                    return Ok(msg);
                }
                Err(ApiError::Conflict) => self.sync_inbox().await?,
                Err(e) => return Err(e.into()),
            }
        }
        Err(SessionError::TooManyConflicts)
    }

    pub async fn send_text(&mut self, chat_id: &str, text: &str) -> Result<ChatMessage> {
        if text.trim().is_empty() {
            return Err(invalid("nothing to send"));
        }
        self.send(chat_id, Body::Text { text: text.to_owned() })
            .await?
            .ok_or_else(|| invalid("text wasn't recorded"))
    }

    /// Encrypts a photo, uploads it, and sends the key in a message.
    pub async fn send_image(&mut self, chat_id: &str, bytes: &[u8], info: ImageInfo) -> Result<ChatMessage> {
        let upload = self.prepare_photo(chat_id, bytes, info)?;
        let response = self
            .platform
            .fetch(upload.request.clone())
            .await
            .map_err(SessionError::Offline)?;
        self.send_uploaded_photo(chat_id, upload, response).await
    }

    /// First half of [`Self::send_image`]: checks and encrypts the photo, and
    /// builds the upload. A platform can run the upload without holding the
    /// session, then finish with [`Self::send_uploaded_photo`].
    pub fn prepare_photo(&self, chat_id: &str, bytes: &[u8], info: ImageInfo) -> Result<PhotoUpload> {
        if bytes.is_empty() || bytes.len() > MAX_PHOTO_BYTES {
            return Err(invalid("photos can be up to 10 MB"));
        }
        if !info.mime.starts_with("image/") {
            return Err(invalid("that isn't a photo"));
        }
        if info.thumbnail.as_ref().is_some_and(|t| t.len() > MAX_THUMBNAIL_CHARS) {
            return Err(invalid("the thumbnail is too big"));
        }
        if !self.engine.is_active(chat_id) {
            return Err(CoreError::NotAMember(chat_id.to_owned()).into());
        }
        let sealed = self.engine.seal_attachment(bytes)?;
        Ok(PhotoUpload {
            request: HttpRequest {
                method: "POST",
                url: format!("{}/v1/blobs", self.relay_url),
                bearer: Some(self.token.clone()),
                content_type: Some("application/octet-stream"),
                body: Some(sealed.ciphertext),
            },
            key: sealed.key,
            sha256: sealed.sha256,
            size: bytes.len() as u64,
            info,
        })
    }

    /// Second half of [`Self::send_image`]: given the relay's answer to the
    /// upload, sends the message carrying the photo's key.
    pub async fn send_uploaded_photo(
        &mut self,
        chat_id: &str,
        upload: PhotoUpload,
        response: HttpResponse,
    ) -> Result<ChatMessage> {
        let uploaded: BlobResponse = decode(check_status(response)?)?;
        let attachment = Attachment {
            blob_id: uploaded.id,
            key: upload.key,
            sha256: upload.sha256,
            mime: upload.info.mime,
            size: upload.size,
            width: upload.info.width,
            height: upload.info.height,
            thumbnail: upload.info.thumbnail,
        };
        let caption = upload.info.caption.filter(|c| !c.trim().is_empty());
        self.send(chat_id, Body::Image { attachment, caption })
            .await?
            .ok_or_else(|| invalid("photo wasn't recorded"))
    }

    /// Downloads a photo and checks and decrypts it.
    pub async fn fetch_attachment(&self, attachment: &Attachment) -> Result<Vec<u8>> {
        let request = self.attachment_request(attachment)?;
        let response = self.platform.fetch(request).await.map_err(SessionError::Offline)?;
        Ok(open_attachment(&check_status(response)?, attachment)?)
    }

    /// The request that downloads a photo's ciphertext, so a platform can
    /// fetch it without holding the session. Check the answer with
    /// [`open_attachment`].
    pub fn attachment_request(&self, attachment: &Attachment) -> Result<HttpRequest> {
        let id = &attachment.blob_id;
        if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
            return Err(invalid("that attachment's id is malformed"));
        }
        Ok(HttpRequest {
            method: "GET",
            url: format!("{}/v1/blobs/{id}", self.relay_url),
            bearer: Some(self.token.clone()),
            content_type: None,
            body: None,
        })
    }

    /// Marks a chat read, and tells the senders if read receipts are on.
    pub async fn mark_read(&mut self, chat_id: &str) -> Result<()> {
        let ids = self.engine.mark_read(chat_id);
        if ids.is_empty() {
            return Ok(());
        }
        self.save().await?;
        if self.settings.read_receipts && self.engine.is_active(chat_id) {
            self.send(
                chat_id,
                Body::Receipt {
                    status: ReceiptStatus::Read,
                    ids,
                },
            )
            .await?;
        }
        Ok(())
    }

    /// Sets the name friends see, and tells every chat.
    pub async fn set_display_name(&mut self, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(invalid("names can be 1 to 64 characters"));
        }
        self.engine.set_display_name(name);
        for c in self.engine.chats() {
            if c.active {
                self.profile_due.insert(c.chat_id);
            }
        }
        self.save().await?;
        self.flush_owed().await
    }

    pub async fn set_read_receipts(&mut self, on: bool) -> Result<()> {
        self.settings.read_receipts = on;
        self.save().await
    }

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    /// After scanning a friend's QR code in person.
    pub async fn verify_code(&mut self, code: &str) -> Result<VerifyOutcome> {
        let outcome = self.engine.verify_code(code.trim())?;
        self.save().await?;
        Ok(outcome)
    }

    /// After comparing safety numbers on a call instead of scanning.
    pub async fn mark_verified(&mut self, username: &str) -> Result<()> {
        self.engine.mark_verified(username)?;
        self.save().await
    }

    /// Accepts a verified friend's new identity key without meeting up.
    pub async fn reset_verification(&mut self, username: &str) -> Result<()> {
        self.engine.reset_verification(username);
        self.save().await
    }

    // -----------------------------------------------------------------------
    // Receiving
    // -----------------------------------------------------------------------

    /// Fetches and processes everything waiting on the relay, then sends
    /// what that calls for (delivery receipts, our name to new chats).
    /// Returns everything that happened since the last call.
    pub async fn sync(&mut self) -> Result<Vec<Event>> {
        self.settle().await?;
        self.sync_inbox().await?;
        self.flush_owed().await?;
        Ok(self.take_events())
    }

    /// Processes the mailbox until it's empty. Sends nothing.
    async fn sync_inbox(&mut self) -> Result<()> {
        loop {
            let page: MailboxResponse = self.get(&format!("/v1/mailbox?after=0&limit={MAILBOX_PAGE}")).await?;
            let Some(last) = page.items.last().map(|i| i.id) else {
                return Ok(());
            };
            let full_page = page.items.len() >= MAILBOX_PAGE;
            let now = self.platform.now_ms();
            for item in page.items {
                let outcome = match item.kind {
                    MailKind::Welcome => self.engine.handle_welcome(&item.chat_id, &item.payload.0),
                    MailKind::Commit | MailKind::Message => {
                        self.engine.handle_group_message(&item.chat_id, &item.payload.0)
                    }
                };
                let events = outcome.unwrap_or_else(|e| {
                    vec![Event::Dropped {
                        chat_id: item.chat_id.clone(),
                        reason: e.to_string(),
                    }]
                });
                for e in events {
                    self.absorb(e, now)?;
                }
            }
            // Saved before acknowledging: the relay deletes what we acknowledge.
            self.save().await?;
            let _: serde_json::Value = self.post("/v1/mailbox/ack", &AckRequest { up_to: last }).await?;
            if !full_page {
                return Ok(());
            }
        }
    }

    /// Notes what an event means for later: a line in the chat's history, a
    /// receipt owed, our name owed to a chat that just gained people.
    fn absorb(&mut self, event: Event, now: i64) -> Result<()> {
        if let Some((chat_id, sender, notice)) = self.engine.notice_for(&event) {
            self.engine.record_notice(&chat_id, &sender, notice, now)?;
        }
        match &event {
            Event::Message(m) => self
                .receipts_due
                .entry(m.chat_id.clone())
                .or_default()
                .push(m.id.clone()),
            Event::JoinedChat { chat_id, .. } => {
                self.profile_due.insert(chat_id.clone());
                self.key_packages_used = true;
            }
            Event::MembersChanged { chat_id, added, .. } if !added.is_empty() => {
                self.profile_due.insert(chat_id.clone());
            }
            Event::RemovedFromChat { chat_id, .. } => {
                self.receipts_due.remove(chat_id);
                self.profile_due.remove(chat_id);
            }
            _ => {}
        }
        self.events.push(event);
        Ok(())
    }

    /// Sends what we owe. Best effort: one chat that can't be reached never
    /// stops the rest, and anything left over waits for the next sync.
    async fn flush_owed(&mut self) -> Result<()> {
        let mut offline = false;
        let mut changed = false;
        let chats: Vec<String> = self.receipts_due.keys().cloned().collect();
        for chat_id in chats {
            let ids = self.receipts_due.get(&chat_id).cloned().unwrap_or_default();
            if self.engine.is_active(&chat_id) && !ids.is_empty() {
                let receipt = Body::Receipt {
                    status: ReceiptStatus::Delivered,
                    ids: ids.clone(),
                };
                match self.send(&chat_id, receipt).await {
                    Err(SessionError::Offline(_)) => {
                        offline = true;
                        break;
                    }
                    Err(SessionError::Storage(e)) => return Err(SessionError::Storage(e)),
                    _ => {}
                }
            }
            // Anything that arrived while sending stays owed.
            if let Some(left) = self.receipts_due.get_mut(&chat_id) {
                left.retain(|id| !ids.contains(id));
                if left.is_empty() {
                    self.receipts_due.remove(&chat_id);
                }
            }
            changed = true;
        }
        if !offline {
            let name = self.engine.display_name().map(str::to_owned);
            let chats: Vec<String> = self.profile_due.iter().cloned().collect();
            for chat_id in chats {
                if let Some(name) = &name {
                    if self.engine.is_active(&chat_id) {
                        let profile = Body::Profile {
                            display_name: name.clone(),
                        };
                        match self.send(&chat_id, profile).await {
                            Err(SessionError::Offline(_)) => {
                                offline = true;
                                break;
                            }
                            Err(SessionError::Storage(e)) => return Err(SessionError::Storage(e)),
                            _ => {}
                        }
                    }
                }
                self.profile_due.remove(&chat_id);
                changed = true;
            }
        }
        if changed {
            self.save().await?;
        }
        if !offline && (self.key_packages_used || self.key_packages_stale()) {
            match self.ensure_key_packages().await {
                Ok(()) => self.key_packages_used = false,
                Err(SessionError::Storage(e)) => return Err(SessionError::Storage(e)),
                Err(_) => {}
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Live updates and push
    // -----------------------------------------------------------------------

    /// Where to open the relay's WebSocket.
    pub fn stream_url(&self) -> String {
        let base = if let Some(rest) = self.relay_url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.relay_url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.relay_url.clone()
        };
        format!("{base}/v1/stream")
    }

    /// The first frame to send on the WebSocket.
    pub fn stream_hello(&self) -> String {
        serde_json::to_string(&ClientFrame::Auth {
            token: self.token.clone(),
        })
        .expect("serializing a frame")
    }

    /// A frame saying we're typing in a chat, encrypted for its members.
    pub fn typing_frame(&self, chat_id: &str) -> Result<String> {
        let payload = self.engine.typing_signal(chat_id, self.platform.now_ms())?;
        Ok(serde_json::to_string(&ClientFrame::Typing {
            chat_id: chat_id.to_owned(),
            payload: Bytes(payload),
        })
        .expect("serializing a frame"))
    }

    /// Makes sense of a frame from the relay's WebSocket.
    pub fn read_stream_frame(&self, text: &str) -> StreamUpdate {
        match serde_json::from_str::<ServerFrame>(text) {
            Ok(ServerFrame::Ready) => StreamUpdate::Ready,
            Ok(ServerFrame::Mail) => StreamUpdate::Mail,
            Ok(ServerFrame::Typing { chat_id, payload }) => match self.engine.open_typing(&chat_id, &payload.0) {
                Ok(Some(who)) => StreamUpdate::Typing { chat_id, who },
                _ => StreamUpdate::Ignored,
            },
            Ok(ServerFrame::Error { error }) => StreamUpdate::Error { error },
            Err(_) => StreamUpdate::Ignored,
        }
    }

    /// The relay's public key for web push subscriptions.
    pub async fn push_key(&self) -> Result<String> {
        let res: VapidKeyResponse = self.get("/v1/push/key").await?;
        Ok(res.public_key)
    }

    /// Where the relay should send this device's (empty) wake-up pushes.
    pub async fn set_push(&self, subscription: &PushSubscription) -> Result<()> {
        let _: serde_json::Value = decode(
            self.request("PUT", "/v1/devices/me/push", Some(json_body(subscription)))
                .await?,
        )?;
        Ok(())
    }

    pub async fn clear_push(&self) -> Result<()> {
        let _: serde_json::Value = decode(self.request("DELETE", "/v1/devices/me/push", None).await?)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn relay_request<P: Platform>(
    platform: &P,
    base: &str,
    token: Option<&str>,
    method: &'static str,
    path: &str,
    body: Option<(&'static str, Vec<u8>)>,
) -> Result<Vec<u8>, ApiError> {
    let (content_type, body) = match body {
        Some((ct, b)) => (Some(ct), Some(b)),
        None => (None, None),
    };
    let res = platform
        .fetch(HttpRequest {
            method,
            url: format!("{base}{path}"),
            bearer: token.map(str::to_owned),
            content_type,
            body,
        })
        .await
        .map_err(ApiError::Offline)?;
    if (200..300).contains(&res.status) {
        return Ok(res.body);
    }
    let err: Option<ErrorResponse> = serde_json::from_slice(&res.body).ok();
    if res.status == 409 && err.as_ref().is_some_and(|e| e.current_epoch.is_some()) {
        return Err(ApiError::Conflict);
    }
    Err(ApiError::Status {
        status: res.status,
        message: err.map(|e| e.error).unwrap_or_default(),
    })
}

/// The body of a successful response, or the relay's error.
pub fn check_status(res: HttpResponse) -> Result<Vec<u8>> {
    if (200..300).contains(&res.status) {
        return Ok(res.body);
    }
    let err: Option<ErrorResponse> = serde_json::from_slice(&res.body).ok();
    Err(SessionError::Relay {
        status: res.status,
        message: err.map(|e| e.error).unwrap_or_default(),
    })
}

fn json_body<B: Serialize>(body: &B) -> (&'static str, Vec<u8>) {
    (
        "application/json",
        serde_json::to_vec(body).expect("request types always serialize"),
    )
}

fn decode<T: DeserializeOwned>(bytes: Vec<u8>) -> Result<T, ApiError> {
    serde_json::from_slice(&bytes).map_err(|e| ApiError::Status {
        status: 200,
        message: format!("unexpected reply: {e}"),
    })
}

/// No answer, or the server (or a proxy in front of it) failed: the request
/// may or may not have been applied.
fn is_transient(e: &ApiError) -> bool {
    matches!(e, ApiError::Offline(_) | ApiError::Status { status: 500.., .. })
}

fn retryable<T>(res: &Result<T, ApiError>) -> bool {
    res.as_ref().err().is_some_and(is_transient)
}

/// The relay's rule: 3-32 of lowercase letters, digits, `_`, `.`, `-`.
pub fn validate_username(name: &str) -> Result<()> {
    let ok_len = (3..=32).contains(&name.len());
    let ok_chars = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'));
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err(invalid(
            "usernames are 3-32 characters: lowercase letters, digits, '_', '.' or '-'",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_follow_the_relay_rules() {
        for ok in ["bob", "alice_1", "j.doe", "a-b", "abcdefghijklmnopqrstuvwxyz012345"] {
            assert!(validate_username(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "ab",
            "Bob",
            "bob smith",
            "bob/x",
            "b\u{e9}b",
            "abcdefghijklmnopqrstuvwxyz0123456",
            "../x",
        ] {
            assert!(validate_username(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_unanswered_requests_are_retried() {
        assert!(is_transient(&ApiError::Offline("reset".into())));
        assert!(is_transient(&ApiError::Status {
            status: 502,
            message: String::new()
        }));
        assert!(!is_transient(&ApiError::Conflict));
        assert!(!is_transient(&ApiError::Status {
            status: 403,
            message: String::new()
        }));
    }
}
