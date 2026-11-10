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
    last_commit_hash BLOB,
    created_at       INTEGER NOT NULL
);

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
"#;

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    // WAL keeps writes fast and crash-safe; the Phase 0 test checks this
    // file and its WAL for plaintext.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}
