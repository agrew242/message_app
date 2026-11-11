//! SQLite storage for the relay.
//!
//! What lives here is deliberately boring: usernames, device token hashes,
//! public KeyPackages, which devices share a chat, and ciphertext waiting in
//! mailboxes. Nothing in this database can be decrypted by the relay.

use std::path::Path;

use rusqlite::Connection;

pub const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
-- Overwrite deleted rows with zeros, so delivered mail is really gone from disk.
PRAGMA secure_delete = ON;

CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 of the device token; the token itself is never stored.
    token_hash  BLOB NOT NULL UNIQUE,
    push_token  TEXT,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
    code_hash   BLOB PRIMARY KEY,
    created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    used_by     TEXT REFERENCES users(id) ON DELETE SET NULL,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS key_packages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    data        BLOB NOT NULL,
    last_resort INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS key_packages_by_device ON key_packages(device_id, last_resort, id);

CREATE TABLE IF NOT EXISTS chats (
    -- Hex MLS group id. No name, no type: those stay encrypted between phones.
    id               TEXT PRIMARY KEY,
    epoch            INTEGER NOT NULL DEFAULT 0,
    next_seq         INTEGER NOT NULL DEFAULT 1,
    created_at       INTEGER NOT NULL
);

-- Hashes of accepted Commits, so a device that crashed before hearing back
-- can resubmit its Commit and learn it went through, even after newer ones.
CREATE TABLE IF NOT EXISTS commit_log (
    chat_id     TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    epoch       INTEGER NOT NULL,   -- the epoch the Commit was made in
    hash        BLOB NOT NULL,
    chat_seq    INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (chat_id, epoch)
);
CREATE INDEX IF NOT EXISTS commit_log_by_age ON commit_log(created_at);

CREATE TABLE IF NOT EXISTS chat_members (
    chat_id     TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (chat_id, device_id)
);

CREATE TABLE IF NOT EXISTS mailbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    chat_id     TEXT NOT NULL,
    chat_seq    INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    payload     BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mailbox_by_device ON mailbox(device_id, id);
CREATE INDEX IF NOT EXISTS mailbox_by_age ON mailbox(created_at);

-- Where to send a device's content-free wake-up pushes.
CREATE TABLE IF NOT EXISTS push_subscriptions (
    device_id   TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    endpoint    TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- Encrypted attachments (photos). The key is inside the message, never here.
CREATE TABLE IF NOT EXISTS blobs (
    id          TEXT PRIMARY KEY,
    uploader    TEXT REFERENCES devices(id) ON DELETE SET NULL,
    data        BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS blobs_by_age ON blobs(created_at);

-- The relay's own keys, such as its VAPID key for web push.
CREATE TABLE IF NOT EXISTS server_keys (
    name        TEXT PRIMARY KEY,
    value       BLOB NOT NULL
);
"#;

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    // WAL keeps writes fast and crash-safe; the Phase 0 test checks this
    // file and its WAL for plaintext.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Writes a consistent, compacted copy of the database at `db` to `dest`
/// (which must not exist). Safe while the relay is running.
pub fn backup(db: &Path, dest: &Path) -> anyhow::Result<()> {
    let conn = Connection::open(db)?;
    let dest = dest
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("backup path must be valid UTF-8"))?;
    conn.execute("VACUUM INTO ?1", [dest])?;
    Ok(())
}
