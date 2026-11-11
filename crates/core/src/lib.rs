//! The encryption core.
//!
//! Every chat, 1:1 included, is an MLS group (RFC 9420) whose members are
//! devices. This crate owns all keys and all plaintext. It does no networking
//! and touches no files: callers move bytes to and from the relay, and store
//! the opaque snapshot from [`Engine::export_state`] wherever their platform
//! keeps secrets (an encrypted file, IndexedDB on the web, SQLCipher on
//! iPhone). That keeps the same code usable from WebAssembly and from iOS.
//!
//! Identity: each person has one long-term **identity key**. It signs each of
//! their device keys, and that signature travels inside the device's MLS
//! credential. Friends pin each other's identity key the first time they see
//! it, can confirm it in person by scanning a QR code, and get a warning if
//! it ever changes.
//!
//! Two rules callers must follow, both enforced by the session layer:
//! 1. Persist the snapshot **before** sending any ciphertext this engine
//!    produced. Otherwise a crash could roll back a ratchet and reuse a key.
//! 2. Persist the snapshot **before** acknowledging mail to the relay, so a
//!    crash never loses a message that was already deleted from the relay.

use std::collections::{BTreeMap, HashMap};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload as AeadPayload},
    Aes256Gcm, Key, Nonce,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use openmls::prelude::*;
// The TLS codec traits share their names with serde's derives, so bring them
// in anonymously for their methods.
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// X25519 + AES-128-GCM + SHA-256 + Ed25519: MLS's mandatory-to-implement suite.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Encrypted messages are padded to a multiple of this many bytes, so the
/// relay learns less about message length.
pub const PADDING_BYTES: usize = 256;

const SNAPSHOT_VERSION: u32 = 2;
const PAYLOAD_VERSION: u8 = 2;
const CREDENTIAL_VERSION: u8 = 1;
const DEVICE_BINDING_LABEL: &[u8] = b"messenger-device-binding-v1\0";
const FINGERPRINT_LABEL: &[u8] = b"messenger-fingerprint-v1\0";
const TYPING_EXPORT_LABEL: &str = "messenger typing v1";
const QR_PREFIX: &str = "msgr1:";

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
    #[error("rejected identity: {0}")]
    InvalidIdentity(String),
    /// Adding this person would use a different identity key from the one
    /// you verified in person. Verify again, or call
    /// [`Engine::reset_verification`] to accept the new key.
    #[error("{0}'s security code changed since you verified it")]
    IdentityChanged(String),
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("attachment failed its integrity check")]
    AttachmentTampered,
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

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A chat this device belongs to, or used to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatInfo {
    pub chat_id: String,
    /// False once this device has been removed from the chat.
    pub active: bool,
}

/// An encrypted photo or file stored on the relay. The key is only ever
/// inside an MLS-encrypted message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attachment {
    pub blob_id: String,
    /// base64 AES-256-GCM key.
    pub key: String,
    /// hex SHA-256 of the ciphertext, checked before decrypting.
    pub sha256: String,
    pub mime: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// A tiny base64 preview, shown while the full image downloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Delivered,
    Read,
}

/// What a message says. Travels inside the MLS ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Body {
    Text {
        text: String,
    },
    Image {
        attachment: Attachment,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caption: Option<String>,
    },
    /// "I received / read these messages."
    Receipt {
        status: ReceiptStatus,
        ids: Vec<String>,
    },
    /// "Call me this." Sent to each chat when the name changes.
    Profile {
        display_name: String,
    },
}

impl Body {
    /// Text and photos show up in history and wake people up; receipts and
    /// profile updates don't.
    pub fn is_visible(&self) -> bool {
        matches!(self, Body::Text { .. } | Body::Image { .. })
    }
}

/// Something that happened in a chat, shown as a grey line in its history.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Notice {
    /// This device joined; `members` were already there.
    Joined {
        members: Vec<String>,
    },
    MembersChanged {
        added: Vec<String>,
        removed: Vec<String>,
    },
    /// This device was removed from the chat.
    Removed,
    IdentityChanged {
        username: String,
        was_verified: bool,
    },
    NotYourDevice {
        member: String,
    },
    /// A message arrived that couldn't be decrypted or understood.
    Undecryptable {
        reason: String,
    },
}

/// A message, or a [`Notice`], in local history.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    /// Random id chosen by the sender, used to drop duplicates.
    pub id: String,
    pub chat_id: String,
    /// The sender's identity, `username/device_id`, as authenticated by MLS.
    pub sender: String,
    /// The text, or a photo's caption.
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<Attachment>,
    /// The sender's clock, in Unix milliseconds.
    pub sent_at_ms: i64,
    pub outgoing: bool,
    /// For our own messages: who has received and who has read them.
    #[serde(default)]
    pub delivered_to: Vec<String>,
    #[serde(default)]
    pub read_by: Vec<String>,
    /// For messages from others: whether we've read it. Our own are always read.
    #[serde(default)]
    pub read: bool,
    /// Set for notices; `sender` is then whoever caused it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<Notice>,
}

/// Someone this device has seen in a chat, with their pinned identity key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    pub username: String,
    /// base64 Ed25519 identity key, pinned the first time we saw it.
    pub identity_key: String,
    /// True once confirmed in person with a QR code.
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The code matches the key their devices use. They're now verified.
    Verified,
    /// The code does NOT match the key the relay handed us. Someone may be
    /// intercepting: don't trust this contact until it's resolved.
    Mismatch,
}

/// What happened while processing mail from the relay.
// Events are few and short-lived, so a big `Message` variant costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    JoinedChat {
        chat_id: String,
        /// Who added us.
        by: String,
        members: Vec<String>,
    },
    Message(ChatMessage),
    Receipt {
        chat_id: String,
        by: String,
        status: ReceiptStatus,
        ids: Vec<String>,
    },
    ProfileUpdated {
        username: String,
        display_name: String,
    },
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
    /// A contact's identity key changed (say they reinstalled, or someone is
    /// impersonating them). Their verification is reset; show a warning and
    /// ask to verify again. Louder if they had been verified.
    IdentityChanged {
        chat_id: String,
        username: String,
        was_verified: bool,
    },
    /// A device in this chat uses your username with someone else's
    /// identity key: an old install of yours, or someone impersonating you.
    /// Offer to remove it.
    NotYourDevice {
        chat_id: String,
        member: String,
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
    /// Receipts and profile updates shouldn't wake anyone's phone.
    pub silent: bool,
}

/// Something to send, with an id that survives re-encryption if the relay
/// asks for a retry in a newer epoch.
#[derive(Clone, Debug)]
pub struct Draft {
    pub id: String,
    pub sent_at_ms: i64,
    pub body: Body,
}

/// Serialized KeyPackages: single-use ones, plus an optional last-resort one.
pub type KeyPackages = (Vec<Vec<u8>>, Option<Vec<u8>>);

/// An encrypted attachment, ready to upload, and what the message needs to
/// open it.
pub struct SealedAttachment {
    pub ciphertext: Vec<u8>,
    pub key: String,
    pub sha256: String,
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Payload {
    v: u8,
    id: String,
    sent_at_ms: i64,
    #[serde(flatten)]
    body: Body,
}

/// What a device's MLS credential says: who it belongs to, and that person's
/// identity key vouching for this device's signing key.
#[derive(Serialize, Deserialize)]
struct CredentialClaims {
    v: u8,
    user: String,
    device: String,
    /// base64 identity public key.
    ik: String,
    /// base64 identity-key signature over the device binding.
    sig: String,
}

/// A member whose identity binding checked out.
struct VerifiedMember {
    user: String,
    device: String,
    identity_key: Vec<u8>,
}

impl VerifiedMember {
    fn identity(&self) -> String {
        format!("{}/{}", self.user, self.device)
    }
}

/// How a member's identity key compares with what we have pinned.
enum Pin {
    /// Never seen this person before.
    New,
    Same,
    Changed {
        was_verified: bool,
    },
    /// Claims to be us, with someone else's identity key. Never legitimate:
    /// all of a person's devices share one identity key.
    Impostor,
}

#[derive(Serialize, Deserialize)]
struct TypingSignal {
    sender: String,
    at_ms: i64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Profile {
    username: String,
    device_id: Option<String>,
    signature_public_key: Vec<u8>,
    identity_public_key: Vec<u8>,
    display_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    profile: Profile,
    chats: BTreeMap<String, ChatInfo>,
    messages: Vec<ChatMessage>,
    contacts: BTreeMap<String, Contact>,
    /// The OpenMLS key-value store, base64 keys and values.
    mls: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

pub struct Engine {
    provider: OpenMlsRustCrypto,
    /// This device's MLS signing key.
    signer: SignatureKeyPair,
    /// This person's identity key, which vouches for their devices.
    identity: SignatureKeyPair,
    profile: Profile,
    chats: BTreeMap<String, ChatInfo>,
    messages: Vec<ChatMessage>,
    contacts: BTreeMap<String, Contact>,
    groups: HashMap<String, MlsGroup>,
}

impl Engine {
    /// A brand-new person and device. Creates the identity key and this
    /// device's signing key.
    pub fn new(username: &str) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).mls()?;
        signer.store(provider.storage()).mls()?;
        let identity = SignatureKeyPair::new(SignatureScheme::ED25519).mls()?;
        identity.store(provider.storage()).mls()?;
        Ok(Engine {
            profile: Profile {
                username: username.to_owned(),
                device_id: None,
                signature_public_key: signer.to_public_vec(),
                identity_public_key: identity.to_public_vec(),
                display_name: None,
            },
            provider,
            signer,
            identity,
            chats: BTreeMap::new(),
            messages: Vec::new(),
            contacts: BTreeMap::new(),
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

    /// `username/device_id`.
    pub fn identity(&self) -> Result<String> {
        let device = self.profile.device_id.as_ref().ok_or(CoreError::NotRegistered)?;
        Ok(format!("{}/{}", self.profile.username, device))
    }

    pub fn display_name(&self) -> Option<&str> {
        self.profile.display_name.as_deref()
    }

    pub fn set_display_name(&mut self, name: &str) {
        self.profile.display_name = Some(name.to_owned());
    }

    // -----------------------------------------------------------------------
    // Credentials and identity
    // -----------------------------------------------------------------------

    fn binding(user: &str, device: &str, device_signature_key: &[u8]) -> Vec<u8> {
        let mut b = DEVICE_BINDING_LABEL.to_vec();
        b.extend_from_slice(user.as_bytes());
        b.push(0);
        b.extend_from_slice(device.as_bytes());
        b.push(0);
        b.extend_from_slice(device_signature_key);
        b
    }

    fn credential_with_key(&self) -> Result<CredentialWithKey> {
        let device = self.profile.device_id.clone().ok_or(CoreError::NotRegistered)?;
        let binding = Self::binding(&self.profile.username, &device, self.signer.public());
        let sig = self.identity.sign(&binding).mls()?;
        let claims = CredentialClaims {
            v: CREDENTIAL_VERSION,
            user: self.profile.username.clone(),
            device,
            ik: STANDARD.encode(self.identity.public()),
            sig: STANDARD.encode(sig),
        };
        let bytes = serde_json::to_vec(&claims).map_err(|e| CoreError::Malformed(e.to_string()))?;
        Ok(CredentialWithKey {
            credential: BasicCredential::new(bytes).into(),
            signature_key: self.signer.to_public_vec().into(),
        })
    }

    /// Checks that a member's identity key really vouches for its device key.
    fn verify_member(&self, credential: &Credential, device_signature_key: &[u8]) -> Result<VerifiedMember> {
        let claims: CredentialClaims = serde_json::from_slice(credential.serialized_content())
            .map_err(|_| CoreError::InvalidIdentity("credential isn't in our format".into()))?;
        if claims.v != CREDENTIAL_VERSION {
            return Err(CoreError::InvalidIdentity(format!("credential version {}", claims.v)));
        }
        let ik = STANDARD
            .decode(&claims.ik)
            .map_err(|_| CoreError::InvalidIdentity("bad identity key".into()))?;
        let sig = STANDARD
            .decode(&claims.sig)
            .map_err(|_| CoreError::InvalidIdentity("bad signature".into()))?;
        let binding = Self::binding(&claims.user, &claims.device, device_signature_key);
        self.provider
            .crypto()
            .verify_signature(SignatureScheme::ED25519, &binding, &ik, &sig)
            .map_err(|_| {
                CoreError::InvalidIdentity(format!("{}'s identity key didn't sign this device key", claims.user))
            })?;
        Ok(VerifiedMember {
            user: claims.user,
            device: claims.device,
            identity_key: ik,
        })
    }

    fn pin_status(&self, member: &VerifiedMember) -> Pin {
        if member.user == self.profile.username {
            return if member.identity_key == self.profile.identity_public_key {
                Pin::Same
            } else {
                Pin::Impostor
            };
        }
        match self.contacts.get(&member.user) {
            None => Pin::New,
            Some(c) if c.identity_key == STANDARD.encode(&member.identity_key) => Pin::Same,
            Some(c) => Pin::Changed {
                was_verified: c.verified,
            },
        }
    }

    /// Pins a contact's identity key the first time we see it (trust on
    /// first use) and warns if it later changes, or if a device in
    /// `chat_id` uses our name with someone else's key.
    ///
    /// Someone else's commits only ever produce warnings here: refusing one
    /// would leave this device stuck in an old epoch, cut off from the chat,
    /// which would hand anyone who can trick a member a way to do just that.
    fn observe(&mut self, chat_id: &str, member: &VerifiedMember) -> Option<Event> {
        let ik = STANDARD.encode(&member.identity_key);
        match self.pin_status(member) {
            Pin::Same => None,
            Pin::Impostor => Some(Event::NotYourDevice {
                chat_id: chat_id.to_owned(),
                member: member.identity(),
            }),
            Pin::New => {
                self.contacts.insert(
                    member.user.clone(),
                    Contact {
                        username: member.user.clone(),
                        identity_key: ik,
                        verified: false,
                        display_name: None,
                    },
                );
                None
            }
            Pin::Changed { was_verified } => {
                let c = self.contacts.get_mut(&member.user).expect("pinned");
                c.identity_key = ik;
                c.verified = false;
                Some(Event::IdentityChanged {
                    chat_id: chat_id.to_owned(),
                    username: member.user.clone(),
                    was_verified,
                })
            }
        }
    }

    pub fn contacts(&self) -> Vec<Contact> {
        self.contacts.values().cloned().collect()
    }

    pub fn contact(&self, username: &str) -> Option<&Contact> {
        self.contacts.get(username)
    }

    /// Marks a contact verified after comparing safety numbers some other
    /// trusted way, such as reading them out on a call.
    pub fn mark_verified(&mut self, username: &str) -> Result<()> {
        let c = self
            .contacts
            .get_mut(username)
            .ok_or_else(|| CoreError::UnknownMember(username.to_owned()))?;
        c.verified = true;
        Ok(())
    }

    /// Accepts that a verified contact's identity key changed, without
    /// verifying in person. The next add pins the new key, unverified.
    pub fn reset_verification(&mut self, username: &str) {
        if let Some(c) = self.contacts.get_mut(username) {
            c.verified = false;
        }
    }

    /// What this person's QR code encodes: their username and identity key.
    pub fn verification_code(&self) -> String {
        format!(
            "{QR_PREFIX}{}:{}",
            self.profile.username,
            URL_SAFE_NO_PAD.encode(&self.profile.identity_public_key)
        )
    }

    /// After scanning a friend's QR code in person: does it match the key
    /// their devices use in our chats?
    pub fn verify_code(&mut self, code: &str) -> Result<VerifyOutcome> {
        let rest = code
            .strip_prefix(QR_PREFIX)
            .ok_or_else(|| CoreError::Malformed("not a verification code".into()))?;
        let (user, ik) = rest
            .rsplit_once(':')
            .ok_or_else(|| CoreError::Malformed("not a verification code".into()))?;
        let ik = URL_SAFE_NO_PAD
            .decode(ik)
            .map_err(|_| CoreError::Malformed("not a verification code".into()))?;
        if user == self.profile.username {
            return Err(CoreError::Malformed("that's your own code".into()));
        }
        let ik = STANDARD.encode(ik);
        match self.contacts.get_mut(user) {
            Some(c) if c.identity_key == ik => {
                c.verified = true;
                Ok(VerifyOutcome::Verified)
            }
            Some(_) => Ok(VerifyOutcome::Mismatch),
            None => {
                // Verified in person before ever chatting: pin it now.
                self.contacts.insert(
                    user.to_owned(),
                    Contact {
                        username: user.to_owned(),
                        identity_key: ik,
                        verified: true,
                        display_name: None,
                    },
                );
                Ok(VerifyOutcome::Verified)
            }
        }
    }

    /// The 60-digit safety number for us and `username`, the same on both
    /// phones. Comparing it out loud is the alternative to scanning a QR code.
    pub fn safety_number(&self, username: &str) -> Result<String> {
        let contact = self
            .contacts
            .get(username)
            .ok_or_else(|| CoreError::UnknownMember(username.to_owned()))?;
        let theirs_ik = STANDARD
            .decode(&contact.identity_key)
            .map_err(|e| CoreError::State(e.to_string()))?;
        let mut halves = [
            fingerprint(&self.profile.username, &self.profile.identity_public_key),
            fingerprint(username, &theirs_ik),
        ];
        halves.sort();
        Ok(format!("{} {}", halves[0], halves[1]))
    }

    // -----------------------------------------------------------------------
    // Configs and KeyPackages
    // -----------------------------------------------------------------------

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

    /// Deletes a chat from this device: its keys and its history. Other
    /// members are unaffected (removing this device is up to them).
    pub fn forget_chat(&mut self, chat_id: &str) -> Result<()> {
        if let Some(mut group) = self.groups.remove(chat_id) {
            group.delete(self.provider.storage()).mls()?;
        }
        self.chats.remove(chat_id);
        self.messages.retain(|m| m.chat_id != chat_id);
        Ok(())
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
    /// the exact same group state.
    pub fn epoch_authenticator(&self, chat_id: &str) -> Result<String> {
        Ok(hex::encode(self.group(chat_id)?.epoch_authenticator().as_slice()))
    }

    /// The newest line in a chat's history, for the chat list.
    pub fn last_message(&self, chat_id: &str) -> Option<&ChatMessage> {
        self.messages.iter().rev().find(|m| m.chat_id == chat_id)
    }

    pub fn history(&self, chat_id: &str) -> Vec<ChatMessage> {
        self.messages.iter().filter(|m| m.chat_id == chat_id).cloned().collect()
    }

    // -----------------------------------------------------------------------
    // Commits
    // -----------------------------------------------------------------------

    /// Adds devices to a chat. `invitees` are `(username, device_id,
    /// key_package)` triples claimed from the relay. Each KeyPackage must be
    /// validly signed, belong to `username/device_id`, and carry a device key
    /// that person's identity key vouches for.
    ///
    /// Refuses a person you verified in person whose identity key has since
    /// changed ([`CoreError::IdentityChanged`]). For anyone else a changed key
    /// is allowed but comes back as an [`Event::IdentityChanged`] warning.
    pub fn add_members(
        &mut self,
        chat_id: &str,
        invitees: &[(String, String, Vec<u8>)],
    ) -> Result<(OutgoingCommit, Vec<Event>)> {
        let mut key_packages = Vec::with_capacity(invitees.len());
        let mut added_devices = Vec::with_capacity(invitees.len());
        let mut members: Vec<VerifiedMember> = Vec::with_capacity(invitees.len());
        for (username, device_id, bytes) in invitees {
            let kp_in = KeyPackageIn::tls_deserialize_exact(bytes.as_slice())
                .map_err(|e| CoreError::InvalidKeyPackage(format!("{e:?}")))?;
            let kp = kp_in
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| CoreError::InvalidKeyPackage(format!("{e:?}")))?;
            let member = self
                .verify_member(kp.leaf_node().credential(), kp.leaf_node().signature_key().as_slice())
                .map_err(|e| CoreError::InvalidKeyPackage(e.to_string()))?;
            if member.user != *username || member.device != *device_id {
                return Err(CoreError::InvalidKeyPackage(format!(
                    "expected {username}/{device_id}, got {}",
                    member.identity()
                )));
            }
            match self.pin_status(&member) {
                Pin::Impostor => {
                    return Err(CoreError::InvalidKeyPackage(format!(
                        "{} uses your name with someone else's identity key",
                        member.identity()
                    )))
                }
                Pin::Changed { was_verified: true } => return Err(CoreError::IdentityChanged(member.user)),
                Pin::New | Pin::Same | Pin::Changed { .. } => {}
            }
            if members
                .iter()
                .any(|m| m.user == member.user && m.identity_key != member.identity_key)
            {
                return Err(CoreError::InvalidKeyPackage(format!(
                    "{}'s devices disagree about their identity key",
                    member.user
                )));
            }
            key_packages.push(kp);
            added_devices.push(device_id.clone());
            members.push(member);
        }

        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        if !group.is_active() {
            return Err(CoreError::NotAMember(chat_id.to_owned()));
        }
        let epoch = group.epoch().as_u64();
        let (commit, welcome, _group_info) = group.add_members(&self.provider, &self.signer, &key_packages).mls()?;
        let out = OutgoingCommit {
            chat_id: chat_id.to_owned(),
            epoch,
            commit: commit.to_bytes().mls()?,
            welcome: Some(welcome.to_bytes().mls()?),
            added_devices,
            removed_devices: Vec::new(),
        };
        let events = members.iter().filter_map(|m| self.observe(chat_id, m)).collect();
        Ok((out, events))
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
        let (commit, _welcome, _group_info) = group.remove_members(&self.provider, &self.signer, &leaves).mls()?;
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
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        if !group.is_active() {
            return Err(CoreError::NotAMember(chat_id.to_owned()));
        }
        let epoch = group.epoch().as_u64();
        let (commit, _welcome, _group_info) = group
            .self_update(provider, signer, LeafNodeParameters::default())
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
        let provider = &self.provider;
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        group.merge_pending_commit(provider).mls()
    }

    /// The relay rejected our pending Commit (another one won the epoch).
    pub fn abort_commit(&mut self, chat_id: &str) -> Result<()> {
        let provider = &self.provider;
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        group.clear_pending_commit(provider.storage()).mls()
    }

    // -----------------------------------------------------------------------
    // Messages
    // -----------------------------------------------------------------------

    /// Wraps a body in a draft with a fresh random id.
    pub fn new_draft(&self, body: Body, now_ms: i64) -> Result<Draft> {
        Ok(Draft {
            id: hex::encode(self.provider.rand().random_vec(16).mls()?),
            sent_at_ms: now_ms,
            body,
        })
    }

    pub fn new_text_draft(&self, text: &str, now_ms: i64) -> Result<Draft> {
        self.new_draft(Body::Text { text: text.to_owned() }, now_ms)
    }

    /// Encrypts a draft for the chat's current epoch.
    pub fn encrypt(&mut self, chat_id: &str, draft: &Draft) -> Result<OutgoingMessage> {
        let payload = serde_json::to_vec(&Payload {
            v: PAYLOAD_VERSION,
            id: draft.id.clone(),
            sent_at_ms: draft.sent_at_ms,
            body: draft.body.clone(),
        })
        .map_err(|e| CoreError::Malformed(e.to_string()))?;
        let provider = &self.provider;
        let signer = &self.signer;
        let group = self
            .groups
            .get_mut(chat_id)
            .ok_or_else(|| CoreError::UnknownChat(chat_id.to_owned()))?;
        if !group.is_active() {
            return Err(CoreError::NotAMember(chat_id.to_owned()));
        }
        let epoch = group.epoch().as_u64();
        let out = group.create_message(provider, signer, &payload).mls()?;
        Ok(OutgoingMessage {
            chat_id: chat_id.to_owned(),
            epoch,
            ciphertext: out.to_bytes().mls()?,
            silent: !draft.body.is_visible(),
        })
    }

    /// The relay accepted the message. Text and photos go into local
    /// history; returns the history entry if there is one.
    pub fn record_sent(&mut self, chat_id: &str, draft: &Draft) -> Result<Option<ChatMessage>> {
        let (body, attachment) = match &draft.body {
            Body::Text { text } => (text.clone(), None),
            Body::Image { attachment, caption } => (caption.clone().unwrap_or_default(), Some(attachment.clone())),
            Body::Receipt { .. } | Body::Profile { .. } => return Ok(None),
        };
        let msg = ChatMessage {
            id: draft.id.clone(),
            chat_id: chat_id.to_owned(),
            sender: self.identity()?,
            body,
            attachment,
            sent_at_ms: draft.sent_at_ms,
            outgoing: true,
            delivered_to: Vec::new(),
            read_by: Vec::new(),
            read: true,
            notice: None,
        };
        if !self.has_message(chat_id, &msg.id) {
            self.messages.push(msg.clone());
        }
        Ok(Some(msg))
    }

    fn has_message(&self, chat_id: &str, id: &str) -> bool {
        self.messages.iter().any(|m| m.chat_id == chat_id && m.id == id)
    }

    /// Marks everything others sent in this chat as read. Returns the ids
    /// that weren't read before, for a read receipt (empty: nothing to send).
    pub fn mark_read(&mut self, chat_id: &str) -> Vec<String> {
        self.messages
            .iter_mut()
            .filter(|m| m.chat_id == chat_id && !m.read)
            .map(|m| {
                m.read = true;
                m.id.clone()
            })
            .collect()
    }

    pub fn unread_count(&self, chat_id: &str) -> usize {
        self.messages.iter().filter(|m| m.chat_id == chat_id && !m.read).count()
    }

    /// Adds a grey line to a chat's history. `sender` is whoever caused it.
    pub fn record_notice(&mut self, chat_id: &str, sender: &str, notice: Notice, at_ms: i64) -> Result<ChatMessage> {
        let msg = ChatMessage {
            id: hex::encode(self.provider.rand().random_vec(16).mls()?),
            chat_id: chat_id.to_owned(),
            sender: sender.to_owned(),
            body: String::new(),
            attachment: None,
            sent_at_ms: at_ms,
            outgoing: false,
            delivered_to: Vec::new(),
            read_by: Vec::new(),
            read: true,
            notice: Some(notice),
        };
        self.messages.push(msg.clone());
        Ok(msg)
    }

    /// The notice to record for an event, if it deserves one, as
    /// `(chat_id, sender, notice)`.
    pub fn notice_for(&self, event: &Event) -> Option<(String, String, Notice)> {
        let me = self.identity().unwrap_or_default();
        match event {
            Event::JoinedChat { chat_id, by, members } => Some((
                chat_id.clone(),
                by.clone(),
                Notice::Joined {
                    members: members.clone(),
                },
            )),
            Event::MembersChanged {
                chat_id,
                by,
                added,
                removed,
                ..
            } => Some((
                chat_id.clone(),
                by.clone(),
                Notice::MembersChanged {
                    added: added.clone(),
                    removed: removed.clone(),
                },
            )),
            Event::RemovedFromChat { chat_id, by } => Some((chat_id.clone(), by.clone(), Notice::Removed)),
            Event::IdentityChanged {
                chat_id,
                username,
                was_verified,
            } => Some((
                chat_id.clone(),
                me,
                Notice::IdentityChanged {
                    username: username.clone(),
                    was_verified: *was_verified,
                },
            )),
            Event::NotYourDevice { chat_id, member } => {
                Some((chat_id.clone(), me, Notice::NotYourDevice { member: member.clone() }))
            }
            Event::Dropped { chat_id, reason } if self.chats.contains_key(chat_id) => {
                Some((chat_id.clone(), me, Notice::Undecryptable { reason: reason.clone() }))
            }
            _ => None,
        }
    }

    // -----------------------------------------------------------------------
    // Typing
    // -----------------------------------------------------------------------

    fn typing_key(&self, chat_id: &str) -> Result<(u64, [u8; 32])> {
        let group = self.group(chat_id)?;
        if !group.is_active() {
            return Err(CoreError::NotAMember(chat_id.to_owned()));
        }
        let secret = group
            .export_secret(self.provider.crypto(), TYPING_EXPORT_LABEL, chat_id.as_bytes(), 32)
            .mls()?;
        let key: [u8; 32] = secret
            .try_into()
            .map_err(|_| CoreError::Mls("exporter returned the wrong length".into()))?;
        Ok((group.epoch().as_u64(), key))
    }

    /// An encrypted "I'm typing" signal for the chat. It uses a key exported
    /// from the current epoch instead of the message ratchet, so the relay
    /// can drop it (it's never stored) without disturbing message keys.
    pub fn typing_signal(&self, chat_id: &str, now_ms: i64) -> Result<Vec<u8>> {
        let (epoch, key) = self.typing_key(chat_id)?;
        let plaintext = serde_json::to_vec(&TypingSignal {
            sender: self.identity()?,
            at_ms: now_ms,
        })
        .map_err(|e| CoreError::Malformed(e.to_string()))?;
        let nonce = self.provider.rand().random_vec(12).mls()?;
        let mut aad = chat_id.as_bytes().to_vec();
        aad.extend_from_slice(&epoch.to_be_bytes());
        let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
            .encrypt(
                Nonce::from_slice(&nonce),
                AeadPayload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::Mls("typing encryption failed".into()))?;
        let mut out = epoch.to_be_bytes().to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Who's typing, if the signal is valid, current and not our own.
    pub fn open_typing(&self, chat_id: &str, signal: &[u8]) -> Result<Option<String>> {
        if signal.len() < 8 + 12 + 16 {
            return Ok(None);
        }
        let (epoch_bytes, rest) = signal.split_at(8);
        let (nonce, ct) = rest.split_at(12);
        let epoch = u64::from_be_bytes(epoch_bytes.try_into().expect("8 bytes"));
        let (current, key) = self.typing_key(chat_id)?;
        if epoch != current {
            return Ok(None);
        }
        let mut aad = chat_id.as_bytes().to_vec();
        aad.extend_from_slice(&epoch.to_be_bytes());
        let Ok(plaintext) = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
            .decrypt(Nonce::from_slice(nonce), AeadPayload { msg: ct, aad: &aad })
        else {
            return Ok(None);
        };
        let Ok(signal) = serde_json::from_slice::<TypingSignal>(&plaintext) else {
            return Ok(None);
        };
        if Some(signal.sender.as_str()) == self.identity().ok().as_deref() {
            return Ok(None);
        }
        Ok(Some(signal.sender))
    }

    // -----------------------------------------------------------------------
    // Attachments
    // -----------------------------------------------------------------------

    /// Encrypts a photo or file with a fresh key, ready to upload.
    pub fn seal_attachment(&self, plaintext: &[u8]) -> Result<SealedAttachment> {
        let key = self.provider.rand().random_vec(32).mls()?;
        let nonce = self.provider.rand().random_vec(12).mls()?;
        let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| CoreError::Mls("attachment encryption failed".into()))?;
        let mut ciphertext = nonce;
        ciphertext.extend_from_slice(&ct);
        let sha256 = hex::encode(Sha256::digest(&ciphertext));
        Ok(SealedAttachment {
            ciphertext,
            key: STANDARD.encode(key),
            sha256,
        })
    }
}

/// Checks an attachment downloaded from the relay against the hash in the
/// message, then decrypts it.
pub fn open_attachment(ciphertext: &[u8], attachment: &Attachment) -> Result<Vec<u8>> {
    if hex::encode(Sha256::digest(ciphertext)) != attachment.sha256 || ciphertext.len() < 12 + 16 {
        return Err(CoreError::AttachmentTampered);
    }
    let key = STANDARD
        .decode(&attachment.key)
        .map_err(|_| CoreError::AttachmentTampered)?;
    if key.len() != 32 {
        return Err(CoreError::AttachmentTampered);
    }
    let (nonce, ct) = ciphertext.split_at(12);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| CoreError::AttachmentTampered)
}

impl Engine {
    // -----------------------------------------------------------------------
    // Incoming mail
    // -----------------------------------------------------------------------

    /// A Welcome: this device was added to `chat_id`. Every member's identity
    /// binding must check out, or the Welcome is refused.
    pub fn handle_welcome(&mut self, chat_id: &str, bytes: &[u8]) -> Result<Vec<Event>> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| CoreError::Malformed(format!("{e:?}")))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(CoreError::Malformed("expected a Welcome".into())),
        };
        if self.is_active(chat_id) {
            return Err(CoreError::Malformed(format!("already a member of chat {chat_id}")));
        }
        let staged = StagedWelcome::build_from_welcome(&self.provider, &Self::join_config(), welcome)
            .mls()?
            // Rejoining a chat we were removed from replaces the old state.
            .replace_old_group()
            // MLS lifetimes on members' original KeyPackages would otherwise
            // lock newcomers out of chats where someone hasn't rotated keys
            // for a few months. Identities are checked below either way.
            .skip_lifetime_validation()
            .build()
            .mls()?;
        let actual = hex::encode(staged.group_context().group_id().as_slice());
        if actual != chat_id {
            return Err(CoreError::Malformed(format!(
                "Welcome is for chat {actual}, relay said {chat_id}"
            )));
        }
        let mut verified = Vec::new();
        for m in staged.members() {
            verified.push(self.verify_member(&m.credential, &m.signature_key)?);
        }
        let by = identity_of(staged.welcome_sender().mls()?.credential());
        let group = staged.into_group(&self.provider).mls()?;
        let mut events: Vec<Event> = verified.iter().filter_map(|m| self.observe(chat_id, m)).collect();
        let mut members: Vec<String> = verified.iter().map(|m| m.identity()).collect();
        members.sort();
        self.chats.insert(
            chat_id.to_owned(),
            ChatInfo {
                chat_id: chat_id.to_owned(),
                active: true,
            },
        );
        self.groups.insert(chat_id.to_owned(), group);
        events.insert(
            0,
            Event::JoinedChat {
                chat_id: chat_id.to_owned(),
                by,
                members,
            },
        );
        Ok(events)
    }

    /// A Commit or an application message for a chat we're in.
    pub fn handle_group_message(&mut self, chat_id: &str, bytes: &[u8]) -> Result<Vec<Event>> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| CoreError::Malformed(format!("{e:?}")))?;
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
                if payload.v != PAYLOAD_VERSION {
                    return Err(CoreError::Malformed(format!("unsupported payload v{}", payload.v)));
                }
                self.apply_payload(chat_id, sender, payload)
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                // Check every new device's identity binding before merging.
                // A broken binding only comes from a member whose app skipped
                // the checks in add_members, so refuse it even though that
                // leaves this device behind in the old epoch.
                let mut new_members = Vec::new();
                for p in staged.add_proposals() {
                    let leaf = p.add_proposal().key_package().leaf_node();
                    new_members.push(self.verify_member(leaf.credential(), leaf.signature_key().as_slice())?);
                }
                if let Some(leaf) = staged.update_path_leaf_node() {
                    // New keys, same owner: a member can't turn into someone else.
                    let member = self.verify_member(leaf.credential(), leaf.signature_key().as_slice())?;
                    if member.identity() != sender {
                        return Err(CoreError::InvalidIdentity(format!(
                            "{sender} tried to become {}",
                            member.identity()
                        )));
                    }
                }
                let added: Vec<String> = new_members.iter().map(|m| m.identity()).collect();
                let removed_leaves: Vec<LeafNodeIndex> = staged
                    .remove_proposals()
                    .map(|p| p.remove_proposal().removed())
                    .collect();
                let group = self.groups.get_mut(chat_id).expect("checked above");
                let removed: Vec<String> = group
                    .members()
                    .filter(|m| removed_leaves.contains(&m.index))
                    .map(|m| identity_of(&m.credential))
                    .collect();
                let self_removed = staged.self_removed();

                group.merge_staged_commit(&self.provider, *staged).mls()?;
                let epoch = group.epoch().as_u64();

                let mut events: Vec<Event> = new_members.iter().filter_map(|m| self.observe(chat_id, m)).collect();
                if self_removed {
                    if let Some(chat) = self.chats.get_mut(chat_id) {
                        chat.active = false;
                    }
                    events.push(Event::RemovedFromChat {
                        chat_id: chat_id.to_owned(),
                        by: sender,
                    });
                } else if added.is_empty() && removed.is_empty() {
                    events.push(Event::KeysUpdated {
                        chat_id: chat_id.to_owned(),
                        by: sender,
                        epoch,
                    });
                } else {
                    events.push(Event::MembersChanged {
                        chat_id: chat_id.to_owned(),
                        by: sender,
                        added,
                        removed,
                        epoch,
                    });
                }
                Ok(events)
            }
            // We never send standalone proposals; ignore any that show up.
            _ => Ok(Vec::new()),
        }
    }

    fn apply_payload(&mut self, chat_id: &str, sender: String, payload: Payload) -> Result<Vec<Event>> {
        match payload.body {
            Body::Text { .. } | Body::Image { .. } => {
                if self.has_message(chat_id, &payload.id) {
                    return Ok(Vec::new());
                }
                let (body, attachment) = match payload.body {
                    Body::Text { text } => (text, None),
                    Body::Image { attachment, caption } => (caption.unwrap_or_default(), Some(attachment)),
                    _ => unreachable!("matched above"),
                };
                let msg = ChatMessage {
                    id: payload.id,
                    chat_id: chat_id.to_owned(),
                    sender,
                    body,
                    attachment,
                    sent_at_ms: payload.sent_at_ms,
                    outgoing: false,
                    delivered_to: Vec::new(),
                    read_by: Vec::new(),
                    read: false,
                    notice: None,
                };
                self.messages.push(msg.clone());
                Ok(vec![Event::Message(msg)])
            }
            Body::Receipt { status, ids } => {
                for m in self
                    .messages
                    .iter_mut()
                    .filter(|m| m.chat_id == chat_id && m.outgoing && ids.contains(&m.id))
                {
                    if !m.delivered_to.contains(&sender) {
                        m.delivered_to.push(sender.clone());
                    }
                    if status == ReceiptStatus::Read && !m.read_by.contains(&sender) {
                        m.read_by.push(sender.clone());
                    }
                }
                Ok(vec![Event::Receipt {
                    chat_id: chat_id.to_owned(),
                    by: sender,
                    status,
                    ids,
                }])
            }
            Body::Profile { display_name } => {
                let username = username_of(&sender).to_owned();
                let display_name: String = display_name.chars().take(64).collect();
                if let Some(c) = self.contacts.get_mut(&username) {
                    c.display_name = Some(display_name.clone());
                }
                Ok(vec![Event::ProfileUpdated { username, display_name }])
            }
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
            contacts: self.contacts.clone(),
            mls,
        };
        serde_json::to_vec(&snapshot).map_err(|e| CoreError::State(e.to_string()))
    }

    /// Rebuilds an engine from [`Engine::export_state`].
    pub fn import_state(bytes: &[u8]) -> Result<Self> {
        let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(|e| CoreError::State(e.to_string()))?;
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
        .ok_or_else(|| CoreError::State("device signing key missing".into()))?;
        let identity = SignatureKeyPair::read(
            provider.storage(),
            &snapshot.profile.identity_public_key,
            SignatureScheme::ED25519,
        )
        .ok_or_else(|| CoreError::State("identity key missing".into()))?;

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
            identity,
            profile: snapshot.profile,
            chats: snapshot.chats,
            messages: snapshot.messages,
            contacts: snapshot.contacts,
            groups,
        })
    }
}

/// 30 digits identifying `user`'s identity key, in six groups of five.
/// Hashed many times so finding a lookalike key is expensive.
fn fingerprint(user: &str, identity_key: &[u8]) -> String {
    let mut digest = Sha256::new()
        .chain_update(FINGERPRINT_LABEL)
        .chain_update(user.as_bytes())
        .chain_update([0u8])
        .chain_update(identity_key)
        .finalize()
        .to_vec();
    for _ in 0..5200 {
        digest = Sha256::new()
            .chain_update(&digest)
            .chain_update(identity_key)
            .finalize()
            .to_vec();
    }
    digest
        .chunks(5)
        .take(6)
        .map(|c| {
            let n = c.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `username/device_id` from a credential, for display and lookups.
fn identity_of(credential: &Credential) -> String {
    match serde_json::from_slice::<CredentialClaims>(credential.serialized_content()) {
        Ok(c) => format!("{}/{}", c.user, c.device),
        Err(_) => String::from_utf8_lossy(credential.serialized_content()).into_owned(),
    }
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
mod tests;
