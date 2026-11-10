//! Wire types shared by the relay server and every client.
//!
//! Everything the relay stores or forwards is described here. Message bodies,
//! commits and welcomes are opaque MLS ciphertext ([`Bytes`]); the relay only
//! ever sees routing data: usernames, device ids, chat ids, epochs and sizes.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Opaque bytes, carried as base64 in JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Bytes(v)
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map(Bytes)
            .map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Accounts and devices
// ---------------------------------------------------------------------------

/// `POST /v1/accounts` — sign up with an invite code. Registers the first
/// device of a new user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub invite_code: String,
    pub username: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub device_id: String,
    /// A random 256-bit secret, returned exactly once. The relay keeps only
    /// its SHA-256 hash, so a leaked relay database reveals no usable tokens.
    pub device_token: String,
}

/// `POST /v1/invites` — any signed-in user can invite a friend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteResponse {
    pub code: String,
    /// Unix seconds.
    pub expires_at: i64,
}

// ---------------------------------------------------------------------------
// Key directory
// ---------------------------------------------------------------------------

/// `POST /v1/key-packages` — upload single-use KeyPackages, plus optionally a
/// reusable last-resort package that is handed out when the pool runs dry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadKeyPackagesRequest {
    pub key_packages: Vec<Bytes>,
    pub last_resort: Option<Bytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPackageCount {
    /// Single-use packages still waiting to be claimed.
    pub available: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimedKeyPackage {
    pub device_id: String,
    pub key_package: Bytes,
}

/// `POST /v1/users/{username}/key-packages/claim` — one KeyPackage per device
/// of that user. Single-use packages are deleted as they are handed out.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimKeyPackagesResponse {
    pub username: String,
    pub devices: Vec<ClaimedKeyPackage>,
}

// ---------------------------------------------------------------------------
// Chats
// ---------------------------------------------------------------------------

/// `POST /v1/chats` — register a new chat. The caller becomes its only
/// member, at epoch 0. The chat id is the hex MLS group id; the relay learns
/// nothing else about the chat (no name, no type).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateChatRequest {
    pub chat_id: String,
}

/// `POST /v1/chats/{chat_id}/commits` — submit an MLS Commit made in `epoch`.
///
/// The relay accepts exactly one Commit per epoch. If another member got there
/// first it answers `409 Conflict`; the sender then catches up and retries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitRequest {
    pub epoch: u64,
    pub commit: Bytes,
    /// Present when the Commit adds members.
    pub welcome: Option<Bytes>,
    pub added_devices: Vec<String>,
    pub removed_devices: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitResponse {
    /// The chat's epoch after this Commit.
    pub epoch: u64,
    pub chat_seq: u64,
}

/// `POST /v1/chats/{chat_id}/messages` — send an encrypted application
/// message. It must be made in the chat's current epoch, or the relay answers
/// `409 Conflict` and the sender re-encrypts after catching up. That way no
/// device ever needs keys from an older epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub epoch: u64,
    pub ciphertext: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub chat_seq: u64,
}

// ---------------------------------------------------------------------------
// Mailbox
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailKind {
    /// An MLS Welcome: this device was added to a chat.
    Welcome,
    /// An MLS Commit: the chat's membership or keys changed.
    Commit,
    /// An encrypted application message.
    Message,
}

impl MailKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MailKind::Welcome => "welcome",
            MailKind::Commit => "commit",
            MailKind::Message => "message",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "welcome" => Some(MailKind::Welcome),
            "commit" => Some(MailKind::Commit),
            "message" => Some(MailKind::Message),
            _ => None,
        }
    }
}

/// One item waiting in a device's mailbox. `id` grows monotonically per relay,
/// so processing in `id` order gives every device the same order per chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailItem {
    pub id: u64,
    pub chat_id: String,
    pub chat_seq: u64,
    pub kind: MailKind,
    pub payload: Bytes,
    /// Unix seconds, set by the relay.
    pub created_at: i64,
}

/// `GET /v1/mailbox?after={id}&limit={n}`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailboxResponse {
    pub items: Vec<MailItem>,
}

/// `POST /v1/mailbox/ack` — the device saved everything up to `up_to`; the
/// relay deletes those items for good.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AckRequest {
    pub up_to: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    /// Set on `409 Conflict` for commits and messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_epoch: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_as_base64() {
        let b = Bytes(vec![0, 1, 2, 250, 255]);
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, "\"AAEC+v8=\"");
        let back: Bytes = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);
    }
}
