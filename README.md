# message_app

A private, end-to-end encrypted messenger for a small group of friends. Messages are encrypted on each phone with MLS ([RFC 9420](https://datatracker.ietf.org/doc/rfc9420/)) and kept only on the devices. A small relay server passes along ciphertext it can't read and deletes it once it's delivered.

This is **Phase 0**: the encryption core and the relay server, driven from a command-line client. There are no app screens yet. The full plan is in the [system design doc](https://claude.ai/artifact/3cyaWTaF7SDzJ8VtQHjjvR).

## Phase 0 gate: passed

The design doc's gate for this phase is: *three test clients stay in sync, and a database dump shows no plaintext.* `crates/client/tests/phase0_gate.rs` checks exactly that. Three clients share one group chat while it runs through:

- sign-up with single-use invite codes
- a group chat with messages in both directions
- a client restart from its encrypted saved state
- key rotation (post-compromise security)
- two members committing at once (the relay accepts one; the other catches up and retries)
- a message sent on an out-of-date epoch (refused, re-encrypted, delivered)
- removing a member, who then gets nothing and can't send

After each step, every member must agree on the members, the epoch and the epoch's secrets. At the end, the test searches the relay's database (including its write-ahead log) and every device's saved state for message text, and finds none.

A second test, `crates/client/tests/relay_rules.rs`, checks the relay's rules over raw HTTP. It covers one Commit per epoch, safe resends of the same Commit, refusing out-of-date messages, delivery order, members-only posting, sign-in, and deleting mail once it's acknowledged.

```sh
cargo test --workspace
```

## Layout

| Crate | What it does |
| --- | --- |
| `crates/core` | The encryption core: OpenMLS 0.9, every chat is an MLS group. It holds all keys and plaintext, does no networking and touches no files, so the same code can build for the web (WebAssembly) and for iPhone. |
| `crates/relay` | The relay server (Axum + SQLite). It handles invite sign-up, the KeyPackage directory, per-device mailboxes, and putting each chat's changes in one order. It never decrypts anything. |
| `crates/protocol` | The JSON wire types shared by the relay and clients. |
| `crates/client` | The native client: HTTP to the relay, state encrypted on disk, and the `msg` command-line tool. |

## Try it by hand

```sh
cargo build --release

# Terminal 1: the relay prints the first invite code on first start
RELAY_DB=relay.db RELAY_ADDR=127.0.0.1:8080 ./target/release/messenger-relay

# Terminal 2: each --dir is one device
M=./target/release/msg
$M --dir alice register --relay http://127.0.0.1:8080 --invite <code> --username alice
$M --dir alice invite                          # prints an invite code for bob
$M --dir bob register --relay http://127.0.0.1:8080 --invite <bob's code> --username bob
$M --dir alice new-chat bob                    # prints the chat id
$M --dir alice send <first 8 chars of chat id> "hi bob"
$M --dir bob sync
$M --dir bob history <chat>
$M --dir alice rotate <chat>                   # fresh keys for alice
```

## How the security works in this phase

- **Encryption:** MLS with the mandatory-to-implement suite (X25519, AES-128-GCM, SHA-256, Ed25519). Commits are encrypted too, so the relay can't see who was added or removed. Messages are padded to 256-byte steps to hide their length.
- **Ordering:** the relay accepts exactly one Commit per epoch, and only accepts messages tagged with the chat's current epoch. No device keeps old epoch keys, which keeps forward secrecy strong.
- **No lost or reused keys:** clients save their state before any ciphertext leaves the device, and before telling the relay to delete delivered mail.
- **At rest on the device:** state is encrypted with AES-256-GCM. The key sits in `device.key` (owner-only permissions). That file stands in for the iOS Keychain or a non-extractable Web Crypto key.
- **At rest on the relay:** only usernames, device token hashes, public KeyPackages, chat membership and ciphertext waiting in mailboxes. Delivered mail is deleted, and SQLite's `secure_delete` overwrites it. Anything left waiting expires after 30 days.
- **Logs:** route templates and status codes only, never request bodies, usernames or chat ids.

## Not done yet (Phase 1 and later)

- **Key verification:** clients currently trust the relay's key directory. QR-code verification and the identity key that signs each device's keys come next. Until then, a compromised relay could add a key it controls.
- **Login:** each device uses a random bearer token, stored only as a hash. The design's signed challenge login comes later.
- **Delivery:** clients poll for mail. WebSocket delivery and web push arrive with the web app.
- **Not built yet:** photos and files, receipts, typing indicators, multiple devices per person, rate limiting, and any web or iPhone app.
- **Trust in members:** the relay trusts the member lists that clients send with each Commit. A malicious member could confuse delivery, but can't read anything they shouldn't.
- **Not production-ready:** it hasn't had an outside security review. Run the relay behind a TLS proxy such as Caddy, and never expose it over plain HTTP.
