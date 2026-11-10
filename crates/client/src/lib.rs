//! Native client.
//!
//! Glues the encryption core to the relay and to disk. The web app and the
//! iPhone app will have their own versions of the two platform pieces here,
//! storage ([`SecureStore`]) and transport ([`Api`]); the core stays the same.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use messenger_core::{username_of, device_of, ChatInfo, ChatMessage, Engine, Event, OutgoingCommit};
use messenger_protocol::*;
use rand::RngCore;
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Single-use KeyPackages to keep on the relay.
pub const KEY_PACKAGE_BATCH: usize = 20;
/// Top the pool back up when it falls below this.
pub const KEY_PACKAGE_LOW_WATER: u64 = 5;
/// How many times to catch up and retry after the relay reports a newer epoch.
const MAX_EPOCH_RETRIES: usize = 5;
/// How many times to resend the same Commit after a network error.
const TRANSPORT_RETRIES: usize = 3;

// ---------------------------------------------------------------------------
// Encrypted state on disk
// ---------------------------------------------------------------------------

/// Keeps the client state encrypted at rest with AES-256-GCM.
///
/// The key lives in `device.key`, readable only by the owner. That file stands
/// in for the iOS Keychain in the iPhone app, and for a non-extractable Web
/// Crypto key in the web app.
pub struct SecureStore {
    dir: PathBuf,
    key: [u8; 32],
}

const STATE_FILE: &str = "state.bin";
const KEY_FILE: &str = "device.key";
const STATE_AAD: &[u8] = b"messenger-client-state-v1";

impl SecureStore {
    /// Creates a new store with a fresh random key. Fails if one exists.
    pub fn create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        if dir.join(KEY_FILE).exists() || dir.join(STATE_FILE).exists() {
            bail!("{} already holds a device; use a different --dir", dir.display());
        }
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        write_private(&dir.join(KEY_FILE), &key)?;
        Ok(SecureStore {
            dir: dir.to_owned(),
            key,
        })
    }

    pub fn open(dir: &Path) -> Result<Self> {
        let raw = std::fs::read(dir.join(KEY_FILE))
            .with_context(|| format!("no device in {} (run `msg register` first)", dir.display()))?;
        let key: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("{} is corrupt", KEY_FILE))?;
        Ok(SecureStore {
            dir: dir.to_owned(),
            key,
        })
    }

    pub fn save(&self, plaintext: &[u8]) -> Result<()> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: STATE_AAD,
                },
            )
            .map_err(|_| anyhow!("encrypting state failed"))?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        // Write-then-rename, so a crash mid-save never leaves a torn file.
        let tmp = self.dir.join(format!("{STATE_FILE}.tmp"));
        write_private(&tmp, &out)?;
        std::fs::rename(&tmp, self.dir.join(STATE_FILE))?;
        Ok(())
    }

    pub fn load(&self) -> Result<Vec<u8>> {
        let raw = std::fs::read(self.dir.join(STATE_FILE))?;
        if raw.len() < 12 + 16 {
            bail!("{} is truncated", STATE_FILE);
        }
        let (nonce, ciphertext) = raw.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: STATE_AAD,
                },
            )
            .map_err(|_| anyhow!("{} failed to decrypt (wrong key or tampered)", STATE_FILE))
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Relay API
// ---------------------------------------------------------------------------

/// Errors from the relay, with the one case callers act on split out.
#[derive(Debug)]
pub enum ApiError {
    /// `409`: the chat moved to a newer epoch.
    EpochConflict { current_epoch: Option<u64> },
    Status { status: StatusCode, message: String },
    Transport(reqwest::Error),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::EpochConflict { current_epoch } => {
                write!(f, "the chat moved to a newer epoch ({current_epoch:?})")
            }
            ApiError::Status { status, message } => write!(f, "relay answered {status}: {message}"),
            ApiError::Transport(e) => write!(f, "couldn't reach the relay: {e}"),
        }
    }
}

impl std::error::Error for ApiError {}

pub struct Api {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

impl Api {
    pub fn new(base: &str, token: Option<String>) -> Self {
        Api {
            http: reqwest::Client::new(),
            base: base.trim_end_matches('/').to_owned(),
            token,
        }
    }

    async fn send<T: DeserializeOwned>(&self, req: reqwest::RequestBuilder) -> Result<T, ApiError> {
        let req = match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        };
        let res = req.send().await.map_err(ApiError::Transport)?;
        let status = res.status();
        if status.is_success() {
            return res.json::<T>().await.map_err(ApiError::Transport);
        }
        let body: Option<ErrorResponse> = res.json().await.ok();
        if status == StatusCode::CONFLICT {
            if let Some(ErrorResponse {
                current_epoch: Some(e),
                ..
            }) = body
            {
                return Err(ApiError::EpochConflict {
                    current_epoch: Some(e),
                });
            }
        }
        Err(ApiError::Status {
            status,
            message: body.map(|b| b.error).unwrap_or_default(),
        })
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, ApiError> {
        self.send(self.http.post(format!("{}{}", self.base, path)).json(body)).await
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        self.send(self.http.get(format!("{}{}", self.base, path))).await
    }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SavedClient {
    relay_url: String,
    device_token: String,
    /// base64 of the core's snapshot.
    engine: String,
}

pub struct Client {
    api: Api,
    relay_url: String,
    token: String,
    store: SecureStore,
    engine: Engine,
}

impl Client {
    /// Signs up a new user with an invite code and sets this directory up as
    /// their device.
    pub async fn register(relay_url: &str, dir: &Path, invite_code: &str, username: &str) -> Result<Self> {
        let store = SecureStore::create(dir)?;
        let mut engine = Engine::new(username)?;
        let api = Api::new(relay_url, None);
        let res: RegisterResponse = api
            .post(
                "/v1/accounts",
                &RegisterRequest {
                    invite_code: invite_code.to_owned(),
                    username: username.to_owned(),
                },
            )
            .await?;
        engine.set_device_id(&res.device_id);
        let mut client = Client {
            api: Api::new(relay_url, Some(res.device_token.clone())),
            relay_url: relay_url.to_owned(),
            token: res.device_token,
            store,
            engine,
        };
        client.save()?;
        client.publish_key_packages(KEY_PACKAGE_BATCH).await?;
        Ok(client)
    }

    /// Opens an existing device, such as after a restart.
    pub fn open(dir: &Path) -> Result<Self> {
        let store = SecureStore::open(dir)?;
        let saved: SavedClient = serde_json::from_slice(&store.load()?)?;
        let engine = Engine::import_state(&STANDARD.decode(&saved.engine)?)?;
        Ok(Client {
            api: Api::new(&saved.relay_url, Some(saved.device_token.clone())),
            relay_url: saved.relay_url,
            token: saved.device_token,
            store,
            engine,
        })
    }

    /// Persists everything, encrypted. Called before any ciphertext leaves
    /// the device and before acknowledging mail.
    fn save(&self) -> Result<()> {
        let saved = SavedClient {
            relay_url: self.relay_url.clone(),
            device_token: self.token.clone(),
            engine: STANDARD.encode(self.engine.export_state()?),
        };
        self.store.save(&serde_json::to_vec(&saved)?)
    }

    pub fn username(&self) -> &str {
        self.engine.username()
    }

    pub fn identity(&self) -> Result<String> {
        Ok(self.engine.identity()?)
    }

    pub fn chats(&self) -> Vec<ChatInfo> {
        self.engine.chats()
    }

    pub fn members(&self, chat_id: &str) -> Result<Vec<String>> {
        Ok(self.engine.members(chat_id)?)
    }

    pub fn epoch(&self, chat_id: &str) -> Result<u64> {
        Ok(self.engine.epoch(chat_id)?)
    }

    pub fn epoch_authenticator(&self, chat_id: &str) -> Result<String> {
        Ok(self.engine.epoch_authenticator(chat_id)?)
    }

    pub fn history(&self, chat_id: &str) -> Vec<ChatMessage> {
        self.engine.history(chat_id)
    }

    /// Finds a chat by a unique prefix of its id.
    pub fn resolve_chat(&self, prefix: &str) -> Result<String> {
        let matches: Vec<String> = self
            .engine
            .chats()
            .into_iter()
            .map(|c| c.chat_id)
            .filter(|id| id.starts_with(prefix))
            .collect();
        match matches.as_slice() {
            [one] => Ok(one.clone()),
            [] => bail!("no chat starts with {prefix}"),
            _ => bail!("{prefix} matches more than one chat; type more of the id"),
        }
    }

    /// Mints an invite code for a friend.
    pub async fn invite(&self) -> Result<String> {
        let res: InviteResponse = self.api.post("/v1/invites", &serde_json::json!({})).await?;
        Ok(res.code)
    }

    /// Uploads `count` fresh KeyPackages and a new last-resort package.
    pub async fn publish_key_packages(&mut self, count: usize) -> Result<u64> {
        let (single_use, last_resort) = self.engine.generate_key_packages(count, true)?;
        // The private halves must be on disk before the public halves go out.
        self.save()?;
        let res: KeyPackageCount = self
            .api
            .post(
                "/v1/key-packages",
                &UploadKeyPackagesRequest {
                    key_packages: single_use.into_iter().map(Bytes).collect(),
                    last_resort: last_resort.map(Bytes),
                },
            )
            .await?;
        Ok(res.available)
    }

    /// Tops the relay's pool of our KeyPackages back up if it's running low.
    pub async fn ensure_key_packages(&mut self) -> Result<()> {
        let res: KeyPackageCount = self.api.get("/v1/key-packages/count").await?;
        if res.available < KEY_PACKAGE_LOW_WATER {
            self.publish_key_packages(KEY_PACKAGE_BATCH).await?;
        }
        Ok(())
    }

    /// Starts a chat and adds `usernames` to it.
    pub async fn create_chat(&mut self, usernames: &[&str]) -> Result<String> {
        let chat_id = self.engine.create_chat()?;
        self.save()?;
        let _: serde_json::Value = self
            .api
            .post("/v1/chats", &CreateChatRequest { chat_id: chat_id.clone() })
            .await?;
        if !usernames.is_empty() {
            self.add_members(&chat_id, usernames).await?;
        }
        Ok(chat_id)
    }

    /// Adds every device of each user to the chat.
    pub async fn add_members(&mut self, chat_id: &str, usernames: &[&str]) -> Result<()> {
        let mut invitees = Vec::new();
        for username in usernames {
            let res: ClaimKeyPackagesResponse = self
                .api
                .post(
                    &format!("/v1/users/{username}/key-packages/claim"),
                    &serde_json::json!({}),
                )
                .await?;
            for d in res.devices {
                invitees.push((username.to_string(), d.device_id, d.key_package.into_inner()));
            }
        }
        self.commit_with_retry(chat_id, |engine| engine.add_members(chat_id, &invitees))
            .await
    }

    /// Removes every device of each user from the chat.
    pub async fn remove_members(&mut self, chat_id: &str, usernames: &[&str]) -> Result<()> {
        self.commit_with_retry(chat_id, |engine| {
            let devices: Vec<String> = engine
                .members(chat_id)?
                .iter()
                .filter(|id| usernames.contains(&username_of(id)))
                .map(|id| device_of(id).to_owned())
                .collect();
            if devices.is_empty() {
                return Err(messenger_core::CoreError::UnknownMember(usernames.join(", ")));
            }
            engine.remove_members(chat_id, &devices)
        })
        .await
    }

    /// Replaces this device's keys in the chat.
    pub async fn rotate_keys(&mut self, chat_id: &str) -> Result<()> {
        self.commit_with_retry(chat_id, |engine| engine.self_update(chat_id))
            .await
    }

    /// Makes a Commit, submits it, and on an epoch conflict catches up and
    /// makes it again.
    ///
    /// Known gap, for the Phase 1 outbox: if the app crashes between the
    /// relay accepting a Commit and `confirm_commit`, the pending Commit is
    /// stuck on restart. The fix is to persist the Commit bytes and resubmit
    /// them on start (the relay treats an identical resubmission as success).
    async fn commit_with_retry(
        &mut self,
        chat_id: &str,
        make: impl Fn(&mut Engine) -> Result<OutgoingCommit, messenger_core::CoreError>,
    ) -> Result<()> {
        let path = format!("/v1/chats/{chat_id}/commits");
        for _ in 0..MAX_EPOCH_RETRIES {
            let out = make(&mut self.engine)?;
            self.save()?;
            let req = CommitRequest {
                epoch: out.epoch,
                commit: Bytes(out.commit),
                welcome: out.welcome.map(Bytes),
                added_devices: out.added_devices,
                removed_devices: out.removed_devices,
            };
            let mut res: Result<CommitResponse, ApiError> = self.api.post(&path, &req).await;
            // If the network dropped, resend the very same bytes: when the
            // relay already applied them it answers success again, so we
            // never abort a Commit the rest of the chat has already merged.
            for attempt in 1..=TRANSPORT_RETRIES {
                if !matches!(res, Err(ApiError::Transport(_))) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
                res = self.api.post(&path, &req).await;
            }
            match res {
                Ok(_) => {
                    self.engine.confirm_commit(chat_id)?;
                    self.save()?;
                    return Ok(());
                }
                Err(ApiError::EpochConflict { .. }) => {
                    self.engine.abort_commit(chat_id)?;
                    self.save()?;
                    self.sync().await?;
                }
                Err(e) => {
                    self.engine.abort_commit(chat_id)?;
                    self.save()?;
                    return Err(e.into());
                }
            }
        }
        bail!("gave up after {MAX_EPOCH_RETRIES} epoch conflicts")
    }

    /// Encrypts and sends a text message. If the chat moved on meanwhile, it
    /// catches up and re-encrypts for the new epoch.
    pub async fn send(&mut self, chat_id: &str, text: &str) -> Result<ChatMessage> {
        let draft = self.engine.new_draft(text, now_ms())?;
        for _ in 0..MAX_EPOCH_RETRIES {
            let out = self.engine.encrypt(chat_id, &draft)?;
            // The ratchet moved; save before the ciphertext leaves.
            self.save()?;
            let res: Result<SendMessageResponse, ApiError> = self
                .api
                .post(
                    &format!("/v1/chats/{chat_id}/messages"),
                    &SendMessageRequest {
                        epoch: out.epoch,
                        ciphertext: Bytes(out.ciphertext),
                    },
                )
                .await;
            match res {
                Ok(_) => {
                    let msg = self.engine.record_sent(chat_id, &draft)?;
                    self.save()?;
                    return Ok(msg);
                }
                Err(ApiError::EpochConflict { .. }) => {
                    self.sync().await?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        bail!("gave up after {MAX_EPOCH_RETRIES} epoch conflicts")
    }

    /// Fetches and processes everything waiting in this device's mailbox,
    /// then tells the relay to delete it.
    pub async fn sync(&mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        loop {
            let res: MailboxResponse = self.api.get("/v1/mailbox?after=0&limit=200").await?;
            let Some(last) = res.items.last().map(|i| i.id) else {
                break;
            };
            for item in res.items {
                let outcome = match item.kind {
                    MailKind::Welcome => self.engine.handle_welcome(&item.chat_id, &item.payload.0),
                    MailKind::Commit | MailKind::Message => {
                        self.engine.handle_group_message(&item.chat_id, &item.payload.0)
                    }
                };
                match outcome {
                    Ok(evts) => events.extend(evts),
                    Err(e) => events.push(Event::Dropped {
                        chat_id: item.chat_id.clone(),
                        reason: e.to_string(),
                    }),
                }
            }
            // Save before acknowledging: once acknowledged, the relay deletes it.
            self.save()?;
            let _: serde_json::Value = self
                .api
                .post("/v1/mailbox/ack", &AckRequest { up_to: last })
                .await?;
        }
        if events.iter().any(|e| matches!(e, Event::JoinedChat { .. })) {
            // Joining used up a KeyPackage.
            self.ensure_key_packages().await?;
        }
        Ok(events)
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
