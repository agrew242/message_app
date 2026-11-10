//! The Phase 0 gate from the design doc:
//! "three test clients stay in sync, and a database dump shows no plaintext".
//!
//! One relay, three devices (alice, bob, carol), one group chat. The test
//! walks through everything Phase 0 promises: joining, messaging, a restart,
//! key rotation, a commit race, a stale-epoch send, and removing a member.
//! Along the way it checks that all members agree on the group state, and at
//! the end that neither the relay's database nor the devices' saved state
//! contains any message text.

use std::path::Path;

use messenger_client::Client;
use messenger_core::Event;
use messenger_relay::Relay;
use tokio::net::TcpListener;

/// Message bodies that must never appear in plaintext on disk.
const CANARIES: &[&str] = &[
    "canary-1 hello from alice 7f3a9c",
    "canary-2 bob replies 51e0d2",
    "canary-3 carol after restart 9b8c44",
    "canary-4 after bob rotated 2aa7f1",
    "canary-5 sent on a stale epoch e61c03",
    "canary-6 carol is gone 0d94be",
];

async fn start_relay(dir: &Path) -> (String, String, std::sync::Arc<Relay>) {
    let relay = Relay::open(&dir.join("relay.db")).unwrap();
    let invite = relay.bootstrap_invite().unwrap().expect("fresh relay");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(messenger_relay::serve(listener, relay.clone()));
    (url, invite, relay)
}

fn bodies_from(events: &[Event], sender_prefix: &str) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Message(m) if m.sender.starts_with(sender_prefix) => Some(m.body.clone()),
            _ => None,
        })
        .collect()
}

fn assert_no_drops(who: &str, events: &[Event]) {
    for e in events {
        assert!(!matches!(e, Event::Dropped { .. }), "{who} dropped mail: {e:?}");
    }
}

/// All clients agree on members, epoch and the epoch's secrets.
fn assert_in_sync(chat: &str, clients: &[&Client]) {
    let first = clients[0];
    for c in &clients[1..] {
        assert_eq!(first.members(chat).unwrap(), c.members(chat).unwrap(), "members differ");
        assert_eq!(first.epoch(chat).unwrap(), c.epoch(chat).unwrap(), "epochs differ");
        assert_eq!(
            first.epoch_authenticator(chat).unwrap(),
            c.epoch_authenticator(chat).unwrap(),
            "group state differs"
        );
    }
}

fn file_contains(path: &Path, needle: &str) -> bool {
    match std::fs::read(path) {
        Ok(bytes) => bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
        Err(_) => false,
    }
}

/// Searches the relay database, its write-ahead log, and every device's
/// saved state for message text.
fn assert_no_plaintext_on_disk(tmp: &Path) {
    let mut files = vec![
        tmp.join("relay.db"),
        tmp.join("relay.db-wal"),
        tmp.join("relay.db-shm"),
    ];
    for device in ["alice", "bob", "carol"] {
        files.push(tmp.join(device).join("state.bin"));
    }
    for file in &files {
        for canary in CANARIES {
            assert!(
                !file_contains(file, canary),
                "found plaintext {canary:?} in {}",
                file.display()
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_clients_stay_in_sync_and_the_relay_sees_no_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp = tmp.path();
    let (url, first_invite, relay) = start_relay(tmp).await;

    // --- Sign-up: alice uses the first invite, then invites her friends.
    let mut alice = Client::register(&url, &tmp.join("alice"), &first_invite, "alice").await.unwrap();
    let bob_invite = alice.invite().await.unwrap();
    let carol_invite = alice.invite().await.unwrap();
    let mut bob = Client::register(&url, &tmp.join("bob"), &bob_invite, "bob").await.unwrap();
    let mut carol = Client::register(&url, &tmp.join("carol"), &carol_invite, "carol").await.unwrap();

    // An invite works only once.
    let reuse = Client::register(&url, &tmp.join("mallory"), &bob_invite, "mallory").await;
    assert!(reuse.is_err(), "a used invite code was accepted again");

    // --- Alice starts a group chat with bob and carol.
    let chat = alice.create_chat(&["bob", "carol"]).await.unwrap();
    for (name, client) in [("bob", &mut bob), ("carol", &mut carol)] {
        let events = client.sync().await.unwrap();
        assert_no_drops(name, &events);
        assert!(
            events.iter().any(|e| matches!(e, Event::JoinedChat { chat_id, .. } if *chat_id == chat)),
            "{name} didn't join: {events:?}"
        );
    }
    assert_in_sync(&chat, &[&alice, &bob, &carol]);
    assert_eq!(alice.members(&chat).unwrap().len(), 3);

    // --- Messages flow both ways.
    alice.send(&chat, CANARIES[0]).await.unwrap();

    // While the message waits on the relay, the relay holds only ciphertext.
    assert!(relay.pending_mail().unwrap() >= 2, "expected mail waiting for bob and carol");
    assert_no_plaintext_on_disk(tmp);

    let bob_events = bob.sync().await.unwrap();
    let carol_events = carol.sync().await.unwrap();
    assert_eq!(bodies_from(&bob_events, "alice/"), vec![CANARIES[0]]);
    assert_eq!(bodies_from(&carol_events, "alice/"), vec![CANARIES[0]]);

    bob.send(&chat, CANARIES[1]).await.unwrap();
    assert_eq!(bodies_from(&alice.sync().await.unwrap(), "bob/"), vec![CANARIES[1]]);
    assert_eq!(bodies_from(&carol.sync().await.unwrap(), "bob/"), vec![CANARIES[1]]);

    // --- Carol's device restarts and carries on from its saved state.
    let carol_dir = tmp.join("carol");
    drop(carol);
    let mut carol = Client::open(&carol_dir).unwrap();
    let history: Vec<String> = carol.history(&chat).into_iter().map(|m| m.body).collect();
    assert_eq!(history, vec![CANARIES[0], CANARIES[1]], "carol lost history on restart");
    carol.send(&chat, CANARIES[2]).await.unwrap();
    assert_eq!(bodies_from(&alice.sync().await.unwrap(), "carol/"), vec![CANARIES[2]]);
    assert_eq!(bodies_from(&bob.sync().await.unwrap(), "carol/"), vec![CANARIES[2]]);
    assert_in_sync(&chat, &[&alice, &bob, &carol]);

    // --- Bob rotates his keys (post-compromise security).
    let before = alice.epoch(&chat).unwrap();
    bob.rotate_keys(&chat).await.unwrap();
    for (name, client) in [("alice", &mut alice), ("carol", &mut carol)] {
        let events = client.sync().await.unwrap();
        assert_no_drops(name, &events);
        assert!(
            events.iter().any(|e| matches!(e, Event::KeysUpdated { by, .. } if by.starts_with("bob/"))),
            "{name} missed bob's key update: {events:?}"
        );
    }
    assert_eq!(alice.epoch(&chat).unwrap(), before + 1);
    assert_in_sync(&chat, &[&alice, &bob, &carol]);
    alice.send(&chat, CANARIES[3]).await.unwrap();
    assert_eq!(bodies_from(&bob.sync().await.unwrap(), "alice/"), vec![CANARIES[3]]);
    assert_eq!(bodies_from(&carol.sync().await.unwrap(), "alice/"), vec![CANARIES[3]]);

    // --- A commit race: alice and carol both rotate from the same epoch.
    // Alice wins; carol's commit is refused, she catches up and retries.
    let race_epoch = alice.epoch(&chat).unwrap();
    alice.rotate_keys(&chat).await.unwrap();
    assert_eq!(carol.epoch(&chat).unwrap(), race_epoch, "carol should still be behind");
    carol.rotate_keys(&chat).await.unwrap();
    assert_eq!(carol.epoch(&chat).unwrap(), race_epoch + 2);
    assert_no_drops("alice", &alice.sync().await.unwrap());
    assert_no_drops("bob", &bob.sync().await.unwrap());
    assert_in_sync(&chat, &[&alice, &bob, &carol]);

    // --- A send on a stale epoch: bob rotates, alice sends without syncing.
    // The relay refuses the stale ciphertext; alice catches up and re-sends.
    bob.rotate_keys(&chat).await.unwrap();
    alice.send(&chat, CANARIES[4]).await.unwrap();
    assert_eq!(bodies_from(&bob.sync().await.unwrap(), "alice/"), vec![CANARIES[4]]);
    assert_eq!(bodies_from(&carol.sync().await.unwrap(), "alice/"), vec![CANARIES[4]]);
    assert_in_sync(&chat, &[&alice, &bob, &carol]);

    // --- Alice removes carol.
    alice.remove_members(&chat, &["carol"]).await.unwrap();
    let bob_events = bob.sync().await.unwrap();
    assert!(
        bob_events.iter().any(|e| matches!(e, Event::MembersChanged { removed, .. } if removed.iter().any(|r| r.starts_with("carol/")))),
        "bob didn't see carol leave: {bob_events:?}"
    );
    let carol_events = carol.sync().await.unwrap();
    assert!(
        carol_events.iter().any(|e| matches!(e, Event::RemovedFromChat { .. })),
        "carol wasn't told she was removed: {carol_events:?}"
    );
    assert_in_sync(&chat, &[&alice, &bob]);
    assert_eq!(alice.members(&chat).unwrap().len(), 2);

    // After removal, carol gets nothing and can't send.
    alice.send(&chat, CANARIES[5]).await.unwrap();
    assert_eq!(bodies_from(&bob.sync().await.unwrap(), "alice/"), vec![CANARIES[5]]);
    let carol_after = carol.sync().await.unwrap();
    assert!(bodies_from(&carol_after, "").is_empty(), "removed member still got: {carol_after:?}");
    assert!(carol.send(&chat, "should fail").await.is_err());

    // --- The gate: delivered mail is gone, and no plaintext is on disk.
    assert_eq!(relay.pending_mail().unwrap(), 0, "delivered mail wasn't deleted");
    assert_no_plaintext_on_disk(tmp);

    // Sanity check that the scan can find text at all: usernames are stored
    // in plaintext on the relay by design, so the scan must see them.
    let relay_files_mention_bob = file_contains(&tmp.join("relay.db"), "bob")
        || file_contains(&tmp.join("relay.db-wal"), "bob");
    assert!(relay_files_mention_bob, "the plaintext scan isn't reading the relay files");
}
