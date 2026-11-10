//! The encryption core.
//!
//! Every chat, 1:1 included, is an MLS group (RFC 9420) whose members are
//! devices. This crate owns all keys and all plaintext. It does no networking
//! and touches no files: callers move bytes to and from the relay, and store
//! the opaque snapshot from [`Engine::export_state`] wherever their platform
//! keeps secrets (an encrypted file here, IndexedDB on the web, SQLCipher on
//! iPhone). That keeps the same code usable from WebAssembly and from iOS.
//!
//! Two rules callers must follow, both enforced by the native client:
//! 1. Persist the snapshot **before** sending any ciphertext this engine
//!    produced. Otherwise a crash could roll back a ratchet and reuse a key.
//! 2. Persist the snapshot **before** acknowledging mail to the relay, so a
//!    crash never loses a message that was already deleted from the relay.

use std::collections::{BTreeMap, HashMap};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use openmls::prelude::*;
// The TLS codec traits share their names with serde's derives, so bring them
// in anonymously for their methods.
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};

/// X25519 + AES-128-GCM + SHA-256 + Ed25519: MLS's mandatory-to-implement suite.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Encrypted messages are padded to a multiple of this many bytes, so the
/// relay learns less about message length.
pub const PADDING_BYTES: usize = 256;

const SNAPSHOT_VERSION: u32 = 1;
const PAYLOAD_VERSION: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("this device isn't registered with a relay yet")]
    NotRegistered,
    #[error("unknown chat {0}")]
    UnknownChat(String),
    #[error("this device is no longer a member of chat {0}")]
    NotAMember(String),
    #[error("{0} is not a member of this chat")]
    UnknownMember(String),
    #[error("rejected KeyPackage: {0}")]
    InvalidKeyPackage(String),
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("MLS error: {0}")]
    Mls(String),
    #[error("couldn't restore saved state: {0}")]
    State(String),
}

type Result<T> = std::result::Result<T, CoreError>;

trait MlsResultExt<T> {
    fn mls(self) -> Result<T>;
}

impl<T, E: std::fmt::Debug> MlsResultExt<T> for std::result::Result<T, E> {
    fn mls(self) -> Result<T> {
        self.map_err(|e| CoreError::Mls(format!("{e:?}")))
    }
}

/// A chat this device belongs to, or used to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatInfo {
    pub chat_id: String,
    /// False once this device has been removed from the chat.
    pub active: bool,
}

/// A decrypted message in local history.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    /// Random id chosen by the sender, used to drop duplicates.
    pub id: String,
    pub chat_id: String,
    /// The sender's identity, `username/device_id`, as authenticated by MLS.
    pub sender: String,
    pub body: String,
    /// The sender's clock, in Unix milliseconds.
    pub sent_at_ms: i64,
    pub outgoing: bool,
}

/// What happened while processing mail from the relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    JoinedChat {
        chat_id: String,
        members: Vec<String>,
    },
    Message(ChatMessage),
    MembersChanged {
        chat_id: String,
        by: String,
        added: Vec<String>,
        removed: Vec<String>,
        epoch: u64,
    },
    KeysUpdated {
        chat_id: String,
        by: String,
        epoch: u64,
    },
    RemovedFromChat {
        chat_id: String,
        by: String,
    },
    /// Mail that couldn't be processed. It is dropped, never retried forever.
    Dropped {
        chat_id: String,
        reason: String,
    },
}

/// A Commit ready to submit to the relay. It stays pending in the engine
/// until [`Engine::confirm_commit`] or [`Engine::abort_commit`].
#[derive(Clone, Debug)]
pub struct OutgoingCommit {
    pub chat_id: String,
    /// The epoch the Commit was made in. The relay accepts it only if the
    /// chat is still at this epoch.
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub added_devices: Vec<String>,
    pub removed_devices: Vec<String>,
}

/// An encrypted application message ready to submit to the relay.
#[derive(Clone, Debug)]
pub struct OutgoingMessage {
    pub chat_id: String,
    pub epoch: u64,
    pub ciphertext: Vec<u8>,
}

/// Serialized KeyPackages: single-use ones, plus an optional last-resort one.
pub type KeyPackages = (Vec<Vec<u8>>, Option<Vec<u8>>);

/// Text the user wrote, with an id that survives re-encryption if the relay
/// asks for a retry in a newer epoch.
#[derive(Clone, Debug)]
pub struct Draft {
    pub id: String,
    pub body: String,
    pub sent_at_ms: i64,
}

/// What travels inside the MLS ciphertext. `kind` leaves room for receipts,
/// reactions and edits later.
#[derive(Serialize, Deserialize)]
struct Payload {
    v: u8,
    id: String,
    kind: String,
    body: String,
    sent_at_ms: i64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Profile {
    username: String,
    device_id: Option<String>,
    signature_public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    profile: Profile,
    chats: BTreeMap<String, ChatInfo>,
    messages: Vec<ChatMessage>,
    /// The OpenMLS key-value store, base64 keys and values.
    mls: Vec<(String, String)>,
}

pub struct Engine {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    profile: Profile,
    chats: BTreeMap<String, ChatInfo>,
    messages: Vec<ChatMessage>,
    groups: HashMap<String, MlsGroup>,
}

impl Engine {
    /// A brand-new device for `username`. Creates its signing key.
    pub fn new(username: &str) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).mls()?;
        signer.store(provider.storage()).mls()?;
        Ok(Engine {
            profile: Profile {
                username: username.to_owned(),
                device_id: None,
                signature_public_key: signer.to_public_vec(),
            },
            provider,
            signer,
            chats: BTreeMap::new(),
            messages: Vec::new(),
            groups: HashMap::new(),
        })
    }

    pub fn username(&self) -> &str {
        &self.profile.username
    }

    pub fn device_id(&self) -> Option<&str> {
        self.profile.device_id.as_deref()
    }

    /// Set once, after the relay registers this device.
    pub fn set_device_id(&mut self, device_id: &str) {
        self.profile.device_id = Some(device_id.to_owned());
    }

    /// `username/device_id`: the identity inside this device's MLS credential.
    pub fn identity(&self) -> Result<String> {
        let device = self.profile.device_id.as_ref().ok_or(CoreError::NotRegistered)?;
        Ok(format!("{}/{}", self.profile.username, device))
    }

    fn credential_with_key(&self) -> Result<CredentialWithKey> {
        Ok(CredentialWithKey {
            credential: BasicCredential::new(self.identity()?.into_bytes()).into(),
            signature_key: self.signer.to_public_vec().into(),
        })
    }

    fn create_config() -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .padding_size(PADDING_BYTES)
            // Commits travel encrypted too, so the relay can't read who was
            // added or removed.
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build()
    }

    fn join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .padding_size(PADDING_BYTES)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build()
    }

    // -----------------------------------------------------------------------
    // KeyPackages
    // -----------------------------------------------------------------------

    /// Makes `count` single-use KeyPackages, plus one reusable last-resort
    /// package if asked. Their private keys stay in this engine: persist the
    /// snapshot before uploading the public halves.
    pub fn generate_key_packages(&mut self, count: usize, with_last_resort: bool) -> Result<KeyPackages> {
        let cred = self.credential_with_key()?;
        let mut single_use = Vec::with_capacity(count);
        for _ in 0..count {
            let bundle = KeyPackage::builder()
                .build(CIPHERSUITE, &self.provider, &self.signer, cred.clone())
                .mls()?;
            single_use.push(bundle.key_package().tls_serialize_detached().mls()?);
        }
        let last_resort = if with_last_resort {
            let bundle = KeyPackage::builder()
                .mark_as_last_resort()
                .build(CIPHERSUITE, &self.provider, &self.signer, cred)
                .mls()?;
            Some(bundle.key_package().tls_serialize_detached().mls()?)
        } else {
            None
        };
        Ok((single_use, last_resort))
    }

    // -----------------------------------------------------------------------
    // Chats
    // -----------------------------------------------------------------------

    /// Starts a chat with just this device in it, at epoch 0. Returns the chat
    /// id (the hex MLS group id).
    pub fn create_chat(&mut self) -> Result<String> {
        let cred = self.credential_with_key()?;
        let id_bytes = self.provider.rand().random_vec(16).mls()?;
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &Self::create_config(),
            GroupId::from_slice(&id_bytes),
            cred,
        )
        .mls()?;
        let chat_id = hex::encode(id_bytes);
        self.chats.insert(
            chat_id.clone(),
            ChatInfo {
                chat_id: chat_id.clone(),
                active: true,
            },
        );
        self.groups.insert(chat_id.clone(), group);
        Ok(chat_id)
    }

    fn group(&self, chat_id: &str) -> Result<&MlsGroup> {
        self.groups
            .get(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))
    }

    pub fn chats(&self) -> Vec<ChatInfo> {
        self.chats.values().cloned().collect()
    }

    pub fn epoch(&self, chat_id: &str) -> Result<u64> {
        Ok(self.group(chat_id)?.epoch().as_u64())
    }

    pub fn is_active(&self, chat_id: &str) -> bool {
        self.groups.get(chat_id).map(|g| g.is_active()).unwrap_or(false)
    }

    /// Member identities (`username/device_id`), sorted.
    pub fn members(&self, chat_id: &str) -> Result<Vec<String>> {
        let mut out: Vec<String> = self
            .group(chat_id)?
            .members()
            .map(|m| identity_of(&m.credential))
            .collect();
        out.sort();
        Ok(out)
    }

    /// A hash of the current epoch's secrets. Devices that agree on it share
    /// the exact same group state; the Phase 0 test compares it across
    /// devices.
    pub fn epoch_authenticator(&self, chat_id: &str) -> Result<String> {
        Ok(hex::encode(self.group(chat_id)?.epoch_authenticator().as_slice()))
    }

    pub fn history(&self, chat_id: &str) -> Vec<ChatMessage> {
        self.messages
            .iter()
            .filter(|m| m.chat_id == chat_id)
            .cloned()
            .collect()
    }

    // -----------------------------------------------------------------------
    // Commits
    // -----------------------------------------------------------------------

    /// Adds devices to a chat. `invitees` are `(username, device_id,
    /// key_package)` triples claimed from the relay. Each KeyPackage is
    /// verified and must carry the identity `username/device_id`.
    pub fn add_members(
        &mut self,
        chat_id: &str,
        invitees: &[(String, String, Vec<u8>)],
    ) -> Result<OutgoingCommit> {
        let mut key_packages = Vec::with_capacity(invitees.len());
        let mut added_devices = Vec::with_capacity(invitees.len());
        for (username, device_id, bytes) in invitees {
            let kp_in = KeyPackageIn::tls_deserialize_exact(bytes.as_slice())
                .map_err(|e| CoreError::InvalidKeyPackage(format!("{e:?}")))?;
            let kp = kp_in
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| CoreError::InvalidKeyPackage(format!("{e:?}")))?;
            let found = identity_of(kp.leaf_node().credential());
            let expected = format!("{username}/{device_id}");
            if found != expected {
                return Err(CoreError::InvalidKeyPackage(format!(
                    "expected identity {expected}, got {found}"
                )));
            }
            key_packages.push(kp);
            added_devices.push(device_id.clone());
        }

        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        if !group.is_active() {
            return Err(CoreError::NotAMember(chat_id.to_owned()));
        }
        let epoch = group.epoch().as_u64();
        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &self.signer, &key_packages)
            .mls()?;
        Ok(OutgoingCommit {
            chat_id: chat_id.to_owned(),
            epoch,
            commit: commit.to_bytes().mls()?,
            welcome: Some(welcome.to_bytes().mls()?),
            added_devices,
            removed_devices: Vec::new(),
        })
    }

    /// Removes devices (by device id) from a chat.
    pub fn remove_members(&mut self, chat_id: &str, device_ids: &[String]) -> Result<OutgoingCommit> {
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        if !group.is_active() {
            return Err(CoreError::NotAMember(chat_id.to_owned()));
        }
        let mut leaves = Vec::with_capacity(device_ids.len());
        for device_id in device_ids {
            let member = group
                .members()
                .find(|m| device_of(&identity_of(&m.credential)) == device_id.as_str())
                .ok_or_else(|| CoreError::UnknownMember(device_id.clone()))?;
            leaves.push(member.index);
        }
        let epoch = group.epoch().as_u64();
        let (commit, _welcome, _group_info) = group
            .remove_members(&self.provider, &self.signer, &leaves)
            .mls()?;
        Ok(OutgoingCommit {
            chat_id: chat_id.to_owned(),
            epoch,
            commit: commit.to_bytes().mls()?,
            welcome: None,
            added_devices: Vec::new(),
            removed_devices: device_ids.to_vec(),
        })
    }

    /// Replaces this device's keys in a chat (post-compromise security).
    pub fn self_update(&mut self, chat_id: &str) -> Result<OutgoingCommit> {
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        if !group.is_active() {
            return Err(CoreError::NotAMember(chat_id.to_owned()));
        }
        let epoch = group.epoch().as_u64();
        let (commit, _welcome, _group_info) = group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .mls()?
            .into_contents();
        Ok(OutgoingCommit {
            chat_id: chat_id.to_owned(),
            epoch,
            commit: commit.to_bytes().mls()?,
            welcome: None,
            added_devices: Vec::new(),
            removed_devices: Vec::new(),
        })
    }

    /// The relay accepted our pending Commit: move to the new epoch.
    pub fn confirm_commit(&mut self, chat_id: &str) -> Result<()> {
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        group.merge_pending_commit(&self.provider).mls()
    }

    /// The relay rejected our pending Commit (another one won the epoch).
    pub fn abort_commit(&mut self, chat_id: &str) -> Result<()> {
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        group.clear_pending_commit(self.provider.storage()).mls()
    }

    // -----------------------------------------------------------------------
    // Messages
    // -----------------------------------------------------------------------

    /// Wraps text in a draft with a fresh random id.
    pub fn new_draft(&self, body: &str, now_ms: i64) -> Result<Draft> {
        Ok(Draft {
            id: hex::encode(self.provider.rand().random_vec(16).mls()?),
            body: body.to_owned(),
            sent_at_ms: now_ms,
        })
    }

    /// Encrypts a draft for the chat's current epoch.
    pub fn encrypt(&mut self, chat_id: &str, draft: &Draft) -> Result<OutgoingMessage> {
        let payload = serde_json::to_vec(&Payload {
            v: PAYLOAD_VERSION,
            id: draft.id.clone(),
            kind: "text".into(),
            body: draft.body.clone(),
            sent_at_ms: draft.sent_at_ms,
        })
        .map_err(|e| CoreError::Malformed(e.to_string()))?;
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        if !group.is_active() {
            return Err(CoreError::NotAMember(chat_id.to_owned()));
        }
        let epoch = group.epoch().as_u64();
        let out = group
            .create_message(&self.provider, &self.signer, &payload)
            .mls()?;
        Ok(OutgoingMessage {
            chat_id: chat_id.to_owned(),
            epoch,
            ciphertext: out.to_bytes().mls()?,
        })
    }

    /// The relay accepted the message: add it to local history.
    pub fn record_sent(&mut self, chat_id: &str, draft: &Draft) -> Result<ChatMessage> {
        let msg = ChatMessage {
            id: draft.id.clone(),
            chat_id: chat_id.to_owned(),
            sender: self.identity()?,
            body: draft.body.clone(),
            sent_at_ms: draft.sent_at_ms,
            outgoing: true,
        };
        if !self.has_message(chat_id, &msg.id) {
            self.messages.push(msg.clone());
        }
        Ok(msg)
    }

    fn has_message(&self, chat_id: &str, id: &str) -> bool {
        self.messages.iter().any(|m| m.chat_id == chat_id && m.id == id)
    }

    // -----------------------------------------------------------------------
    // Incoming mail
    // -----------------------------------------------------------------------

    /// A Welcome: this device was added to `chat_id`.
    pub fn handle_welcome(&mut self, chat_id: &str, bytes: &[u8]) -> Result<Vec<Event>> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| CoreError::Malformed(format!("{e:?}")))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(CoreError::Malformed("expected a Welcome".into())),
        };
        let staged = StagedWelcome::new_from_welcome(&self.provider, &Self::join_config(), welcome, None)
            .mls()?;
        let group = staged.into_group(&self.provider).mls()?;
        let actual = hex::encode(group.group_id().as_slice());
        if actual != chat_id {
            return Err(CoreError::Malformed(format!(
                "Welcome is for chat {actual}, relay said {chat_id}"
            )));
        }
        let mut members: Vec<String> = group.members().map(|m| identity_of(&m.credential)).collect();
        members.sort();
        self.chats.insert(
            chat_id.to_owned(),
            ChatInfo {
                chat_id: chat_id.to_owned(),
                active: true,
            },
        );
        self.groups.insert(chat_id.to_owned(), group);
        Ok(vec![Event::JoinedChat {
            chat_id: chat_id.to_owned(),
            members,
        }])
    }

    /// A Commit or an application message for a chat we're in.
    pub fn handle_group_message(&mut self, chat_id: &str, bytes: &[u8]) -> Result<Vec<Event>> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| CoreError::Malformed(format!("{e:?}")))?;
        let protocol_message = msg
            .try_into_protocol_message()
            .map_err(|e| CoreError::Malformed(format!("{e:?}")))?;
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        if group.group_id().as_slice() != protocol_message.group_id().as_slice() {
            return Err(CoreError::Malformed("message is for a different group".into()));
        }

        let processed = group.process_message(&self.provider, protocol_message).mls()?;
        let sender = identity_of(processed.credential());

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                let payload: Payload = serde_json::from_slice(&app.into_bytes())
                    .map_err(|e| CoreError::Malformed(format!("bad payload: {e}")))?;
                if payload.v != PAYLOAD_VERSION || payload.kind != "text" {
                    return Err(CoreError::Malformed(format!(
                        "unsupported payload v{} kind {}",
                        payload.v, payload.kind
                    )));
                }
                if self.has_message(chat_id, &payload.id) {
                    return Ok(Vec::new());
                }
                let msg = ChatMessage {
                    id: payload.id,
                    chat_id: chat_id.to_owned(),
                    sender,
                    body: payload.body,
                    sent_at_ms: payload.sent_at_ms,
                    outgoing: false,
                };
                self.messages.push(msg.clone());
                Ok(vec![Event::Message(msg)])
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                // Read who's affected before merging changes the tree.
                let added: Vec<String> = staged
                    .add_proposals()
                    .map(|p| identity_of(p.add_proposal().key_package().leaf_node().credential()))
                    .collect();
                let removed_leaves: Vec<LeafNodeIndex> = staged
                    .remove_proposals()
                    .map(|p| p.remove_proposal().removed())
                    .collect();
                let removed: Vec<String> = group
                    .members()
                    .filter(|m| removed_leaves.contains(&m.index))
                    .map(|m| identity_of(&m.credential))
                    .collect();
                let self_removed = staged.self_removed();

                group.merge_staged_commit(&self.provider, *staged).mls()?;
                let epoch = group.epoch().as_u64();

                if self_removed {
                    if let Some(chat) = self.chats.get_mut(chat_id) {
                        chat.active = false;
                    }
                    return Ok(vec![Event::RemovedFromChat {
                        chat_id: chat_id.to_owned(),
                        by: sender,
                    }]);
                }
                if added.is_empty() && removed.is_empty() {
                    Ok(vec![Event::KeysUpdated {
                        chat_id: chat_id.to_owned(),
                        by: sender,
                        epoch,
                    }])
                } else {
                    Ok(vec![Event::MembersChanged {
                        chat_id: chat_id.to_owned(),
                        by: sender,
                        added,
                        removed,
                        epoch,
                    }])
                }
            }
            // Phase 0 never sends standalone proposals; ignore any that show up.
            _ => Ok(Vec::new()),
        }
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    /// Everything this device knows, as one opaque blob. It contains private
    /// keys and plaintext history: the platform layer must encrypt it at rest.
    pub fn export_state(&self) -> Result<Vec<u8>> {
        let mls = {
            let values = self
                .provider
                .storage()
                .values
                .read()
                .map_err(|_| CoreError::State("key store lock poisoned".into()))?;
            values
                .iter()
                .map(|(k, v)| (STANDARD.encode(k), STANDARD.encode(v)))
                .collect()
        };
        let snapshot = Snapshot {
            version: SNAPSHOT_VERSION,
            profile: self.profile.clone(),
            chats: self.chats.clone(),
            messages: self.messages.clone(),
            mls,
        };
        serde_json::to_vec(&snapshot).map_err(|e| CoreError::State(e.to_string()))
    }

    /// Rebuilds an engine from [`Engine::export_state`].
    pub fn import_state(bytes: &[u8]) -> Result<Self> {
        let snapshot: Snapshot =
            serde_json::from_slice(bytes).map_err(|e| CoreError::State(e.to_string()))?;
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(CoreError::State(format!(
                "unsupported snapshot version {}",
                snapshot.version
            )));
        }
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| CoreError::State("key store lock poisoned".into()))?;
            for (k, v) in snapshot.mls {
                let k = STANDARD.decode(k).map_err(|e| CoreError::State(e.to_string()))?;
                let v = STANDARD.decode(v).map_err(|e| CoreError::State(e.to_string()))?;
                values.insert(k, v);
            }
        }
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &snapshot.profile.signature_public_key,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| CoreError::State("signing key missing".into()))?;

        let mut groups = HashMap::new();
        for chat_id in snapshot.chats.keys() {
            let id = hex::decode(chat_id).map_err(|e| CoreError::State(e.to_string()))?;
            if let Some(group) = MlsGroup::load(provider.storage(), &GroupId::from_slice(&id)).mls()? {
                groups.insert(chat_id.clone(), group);
            }
        }
        Ok(Engine {
            provider,
            signer,
            profile: snapshot.profile,
            chats: snapshot.chats,
            messages: snapshot.messages,
            groups,
        })
    }
}

/// The identity string inside a basic credential.
fn identity_of(credential: &Credential) -> String {
    String::from_utf8_lossy(credential.serialized_content()).into_owned()
}

/// `alice/1f2e…` -> `1f2e…`
pub fn device_of(identity: &str) -> &str {
    identity.split_once('/').map(|(_, d)| d).unwrap_or(identity)
}

/// `alice/1f2e…` -> `alice`
pub fn username_of(identity: &str) -> &str {
    identity.split_once('/').map(|(u, _)| u).unwrap_or(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: &str, id: &str) -> Engine {
        let mut e = Engine::new(name).unwrap();
        e.set_device_id(id);
        e
    }

    fn one_kp(e: &mut Engine) -> Vec<u8> {
        e.generate_key_packages(1, false).unwrap().0.remove(0)
    }

    #[test]
    fn two_devices_exchange_a_message_without_a_relay() {
        let mut alice = device("alice", "a1");
        let mut bob = device("bob", "b1");
        let chat = alice.create_chat().unwrap();

        let kp = one_kp(&mut bob);
        let out = alice
            .add_members(&chat, &[("bob".into(), "b1".into(), kp)])
            .unwrap();
        alice.confirm_commit(&chat).unwrap();
        bob.handle_welcome(&chat, out.welcome.as_ref().unwrap()).unwrap();
        assert_eq!(alice.members(&chat).unwrap(), bob.members(&chat).unwrap());
        assert_eq!(
            alice.epoch_authenticator(&chat).unwrap(),
            bob.epoch_authenticator(&chat).unwrap()
        );

        let draft = alice.new_draft("hi bob", 1).unwrap();
        let msg = alice.encrypt(&chat, &draft).unwrap();
        let events = bob.handle_group_message(&chat, &msg.ciphertext).unwrap();
        match &events[..] {
            [Event::Message(m)] => {
                assert_eq!(m.body, "hi bob");
                assert_eq!(m.sender, "alice/a1");
            }
            other => panic!("unexpected events {other:?}"),
        }
        // Padding hides the exact length.
        let short = alice.encrypt(&chat, &alice.new_draft("a", 2).unwrap()).unwrap();
        let longer = alice.encrypt(&chat, &alice.new_draft("abcdefghij", 3).unwrap()).unwrap();
        assert_eq!(short.ciphertext.len(), longer.ciphertext.len());
    }

    #[test]
    fn rejects_a_key_package_with_the_wrong_identity() {
        let mut alice = device("alice", "a1");
        let mut mallory = device("mallory", "m1");
        let chat = alice.create_chat().unwrap();
        let kp = one_kp(&mut mallory);
        let err = alice
            .add_members(&chat, &[("bob".into(), "b1".into(), kp)])
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidKeyPackage(_)), "{err}");
    }

    #[test]
    fn state_survives_export_and_import() {
        let mut alice = device("alice", "a1");
        let mut bob = device("bob", "b1");
        let chat = alice.create_chat().unwrap();
        let kp = one_kp(&mut bob);
        let out = alice.add_members(&chat, &[("bob".into(), "b1".into(), kp)]).unwrap();
        alice.confirm_commit(&chat).unwrap();
        bob.handle_welcome(&chat, out.welcome.as_ref().unwrap()).unwrap();

        // Both devices restart.
        let mut alice = Engine::import_state(&alice.export_state().unwrap()).unwrap();
        let mut bob = Engine::import_state(&bob.export_state().unwrap()).unwrap();

        let msg = alice.encrypt(&chat, &alice.new_draft("after restart", 5).unwrap()).unwrap();
        let events = bob.handle_group_message(&chat, &msg.ciphertext).unwrap();
        assert!(matches!(&events[..], [Event::Message(m)] if m.body == "after restart"));
    }
}
