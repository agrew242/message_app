# message_app

A private, end-to-end encrypted messenger for a small group of friends, in the style of Facebook Messenger. Messages are encrypted on each phone with MLS ([RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)) and kept only on the devices. A small relay server passes along ciphertext it can't read and deletes it once it's delivered.

**Status: Phase 1, the web app.** It installs on an iPhone's Home Screen from Safari: no App Store, no Apple fee. The full plan is in the [system design doc](https://claude.ai/artifact/3cyaWTaF7SDzJ8VtQHjjvR).

**To set it up for your friends, follow [deploy/SETUP.md](deploy/SETUP.md).**

## What it does

- Sign-up with single-use invite codes (or invite links); usernames, no phone numbers
- 1:1 and group chats; add and remove people
- Text, and photos (shrunk and stripped of location data before they're encrypted)
- Delivered and read receipts (read receipts can be turned off), typing indicators, unread counts
- Live delivery over a WebSocket, and notifications that say only "New message"
- Verifying friends by scanning QR codes or comparing a 60-digit safety number, with warnings if a key changes
- An optional app PIN that encrypts everything stored on the device under a key derived from it

## How it fits together

| Path | What it is |
| --- | --- |
| `crates/core` | The encryption core: OpenMLS 0.9, every chat an MLS group of devices. Identity keys, verification, message kinds, attachments, typing. All keys and plaintext live here; it does no networking and touches no files. |
| `crates/session` | Everything the app *does*, on any platform: sign-up, sending, syncing, receipts, photos, crash recovery. The network, storage and clock come from a small `Platform` trait. |
| `crates/wasm` | The session compiled to WebAssembly for the browser: one `Messenger` class, JSON in and out. `smoke.mjs` runs it in Node against a real relay. |
| `crates/relay` | The relay server (Axum + SQLite): invites, the KeyPackage directory, per-device mailboxes, one order per chat, live hints, web push, encrypted photo storage. It never decrypts anything. |
| `crates/protocol` | The JSON wire types shared by the relay and clients. |
| `crates/client` | The session on a computer: reqwest plus an encrypted folder, the `msg` command-line tool, and the end-to-end tests. |
| `app/` | The Flutter web app. `app/web/messenger/` bridges Dart to the WebAssembly core: encrypted IndexedDB storage, the live connection, photos, QR scanning, push. |
| `deploy/` | Docker Compose for the relay with Caddy (HTTPS), backups, and the setup guide. |

## Tests

```sh
cargo test --workspace     # core, session, relay rules, and end-to-end runs
```

The end-to-end tests run real clients against a real relay:

- `phase0_gate.rs`: three clients stay in sync through joining, a restart, key rotation, a commit race, a stale-epoch send and a removal. Afterwards, neither the relay's database nor the devices' saved state holds any message text.
- `phase1_session.rs`: names, receipts, photos and typing. It also simulates lost replies, dropped connections and crashes partway through a Commit, then checks that everyone ends up in the same state.
- `relay_rules.rs`: the relay's ordering, access and retention rules over raw HTTP.

CI (`.github/workflows/ci.yml`) also does the following:

- Builds the WebAssembly core and runs `crates/wasm/smoke.mjs`.
- Builds the Flutter app and runs its widget tests.
- Runs `app/web_tests/run.mjs` in headless Chrome: the encrypted storage and PIN lock, then two people in two browser profiles going through the real app (sign-up, invite, chat, reply). It also checks that nothing trips the Content-Security-Policy.
- Builds the relay's container.

To run the browser tests locally, you need Chrome, the `wasm32-unknown-unknown` Rust target, `wasm-bindgen-cli` and Flutter. Follow the same steps as the `web` job in `ci.yml`.

## Try the relay by hand

```sh
cargo build --release
RELAY_DB=relay.db ./target/release/messenger-relay      # prints the first invite code

M=./target/release/msg                                   # each --dir is one device
$M --dir alice register --relay http://127.0.0.1:8080 --invite <code> --username alice
$M --dir alice invite                                    # an invite code for bob
$M --dir bob register --relay http://127.0.0.1:8080 --invite <bob's code> --username bob
$M --dir alice new-chat bob
$M --dir alice send <chat id prefix> "hi bob"
$M --dir bob sync
$M --dir bob whoami                                      # bob's verification code
$M --dir alice verify <bob's code>
```

## How the security works

- **Encryption:** MLS with X25519, AES-128-GCM, SHA-256 and Ed25519. Commits are encrypted too, so the relay can't see who joined or left. Messages are padded to 256-byte steps.
- **Identity:** each person has an Ed25519 identity key that signs each of their device keys. The signature travels in the device's MLS credential, and every app checks it whenever a device is added. The first key seen for a friend is pinned, and a later change is flagged. A friend you've verified can't be re-added with a different key until you accept it.
- **Ordering:** the relay accepts one Commit per epoch, messages only for the current epoch, and a Commit only from a device that has read everything waiting for it in that chat. No device keeps old epoch keys, which keeps forward secrecy strong.
- **No lost or reused keys:** state is saved before any ciphertext leaves the device and before delivered mail is acknowledged. A Commit is saved as "in flight" before it's sent, and resolved after a crash: the relay recognizes a Commit it already accepted.
- **On the device (web):** the session's state and cached photos are encrypted with AES-256-GCM in IndexedDB. With an app PIN, the key is wrapped by PBKDF2-SHA-256 (600,000 rounds) over the PIN. Only one tab runs at a time.
- **On the relay:** usernames, hashed device tokens, public KeyPackages, chat membership, and ciphertext waiting to be delivered. Delivered mail is deleted and overwritten (`secure_delete`), and anything left expires after 30 days. Logs record routes and status codes only.
- **Notifications** are empty pushes that wake the phone, which then fetches and decrypts on its own.
- **The web app's code** is built by GitHub Actions from this repository and served from GitHub Pages, not from the relay. A compromised relay can't change it. Each deploy publishes `SHA256SUMS` of every file. A Content-Security-Policy keeps any other code from running.

## Known limits

- **No outside security review yet.** Use Signal for anything truly sensitive until there's been one.
- **Login** is a random bearer token per device (stored hashed). The planned signed-challenge login, and rate limiting, come later.
- **One device per person** for now. Linking devices and encrypted backups are Phase 4.
- **History** is saved as one encrypted blob per change, which is fine for a friend group's volume but should become per-message storage later.
- **Fonts:** Flutter loads its default font from Google Fonts, so Google sees when the app starts (never what's in it).
- **Trust in members:** a member's app reports who it added or removed. A malicious member could confuse delivery, but can't read anything they shouldn't.
