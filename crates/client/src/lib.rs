//! Native client: the shared [`Session`] on a computer.
//!
//! All the app's logic lives in `messenger-session`. This crate only supplies
//! the platform: HTTP through reqwest, and state kept encrypted in a folder
//! ([`SecureStore`]). The web app supplies the same two things from the
//! browser, and the iPhone app will from iOS.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
pub use messenger_session::{
    device_of, open_attachment, username_of, Attachment, Body, ChatInfo, ChatMessage, ChatSummary, Contact, CoreError,
    Engine, Event, HttpRequest, HttpResponse, ImageInfo, Notice, Platform, PushSubscription, ReceiptStatus, Session,
    SessionError, Settings, StreamUpdate, VerifyOutcome,
};
use rand::RngCore;

/// A device on this computer.
pub type Client = Session<NativePlatform>;

/// Signs up with an invite code and makes `dir` the new device's home.
pub async fn register(relay_url: &str, dir: &Path, invite_code: &str, username: &str) -> Result<Client> {
    let store = SecureStore::create(dir)?;
    let key_file = store.key_path();
    match Session::register(NativePlatform::new(store), relay_url, invite_code, username).await {
        Ok(client) => Ok(client),
        Err(e) => {
            // Nothing was saved; free the folder for another try.
            let _ = std::fs::remove_file(key_file);
            Err(e.into())
        }
    }
}

/// Opens the device in `dir`, such as after a restart.
pub fn open(dir: &Path) -> Result<Client> {
    let store = SecureStore::open(dir)?;
    let saved = store.load()?;
    Ok(Session::open(NativePlatform::new(store), &saved)?)
}

/// Finds a chat by a unique prefix of its id.
pub fn resolve_chat(client: &Client, prefix: &str) -> Result<String> {
    let matches: Vec<String> = client
        .engine()
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

// ---------------------------------------------------------------------------
// The platform
// ---------------------------------------------------------------------------

pub struct NativePlatform {
    http: reqwest::Client,
    store: SecureStore,
}

impl NativePlatform {
    pub fn new(store: SecureStore) -> Self {
        NativePlatform {
            http: reqwest::Client::new(),
            store,
        }
    }
}

impl Platform for NativePlatform {
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes()).map_err(|e| e.to_string())?;
        let mut builder = self.http.request(method, &req.url);
        if let Some(token) = &req.bearer {
            builder = builder.bearer_auth(token);
        }
        if let Some(ct) = req.content_type {
            builder = builder.header(reqwest::header::CONTENT_TYPE, ct);
        }
        if let Some(body) = req.body {
            builder = builder.body(body);
        }
        let res = builder.send().await.map_err(|e| e.to_string())?;
        let status = res.status().as_u16();
        let body = res.bytes().await.map_err(|e| e.to_string())?.to_vec();
        Ok(HttpResponse { status, body })
    }

    async fn save(&self, state: &[u8]) -> Result<(), String> {
        self.store.save(state).map_err(|e| format!("{e:#}"))
    }

    async fn sleep(&self, ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await
    }

    fn now_ms(&self) -> i64 {
        now_ms()
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Encrypted state on disk
// ---------------------------------------------------------------------------

/// Keeps the session's state encrypted at rest with AES-256-GCM.
///
/// The key lives in `device.key`, readable only by the owner. That file
/// stands in for the iOS Keychain in the iPhone app, and for a
/// non-extractable Web Crypto key in the web app.
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
        let key: [u8; 32] = raw.try_into().map_err(|_| anyhow!("{} is corrupt", KEY_FILE))?;
        Ok(SecureStore {
            dir: dir.to_owned(),
            key,
        })
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join(KEY_FILE)
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
