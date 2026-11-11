//! Engine tests with no relay: engines hand each other bytes directly.

use super::*;

const NOW: i64 = 1_700_000_000_000;

fn device(user: &str, device_id: &str) -> Engine {
    let mut e = Engine::new(user).unwrap();
    e.set_device_id(device_id);
    e
}

fn key_package(e: &mut Engine) -> Vec<u8> {
    let (mut kps, _) = e.generate_key_packages(1, false).unwrap();
    kps.pop().unwrap()
}

fn invite(e: &mut Engine) -> (String, String, Vec<u8>) {
    (
        e.username().to_owned(),
        e.device_id().unwrap().to_owned(),
        key_package(e),
    )
}

/// `from` adds `to` to `chat` and `to` joins. Returns `from`'s events.
fn add(from: &mut Engine, chat: &str, to: &mut Engine) -> Vec<Event> {
    let inv = invite(to);
    let (commit, events) = from.add_members(chat, &[inv]).unwrap();
    from.confirm_commit(chat).unwrap();
    to.handle_welcome(chat, commit.welcome.as_ref().unwrap()).unwrap();
    events
}

/// A new chat between `a` and `b`.
fn pair(a: &mut Engine, b: &mut Engine) -> String {
    let chat = a.create_chat().unwrap();
    add(a, &chat, b);
    chat
}

fn send(from: &mut Engine, chat: &str, body: Body) -> (Draft, OutgoingMessage) {
    let draft = from.new_draft(body, NOW).unwrap();
    let out = from.encrypt(chat, &draft).unwrap();
    from.record_sent(chat, &draft).unwrap();
    (draft, out)
}

fn text(t: &str) -> Body {
    Body::Text { text: t.to_owned() }
}

fn receive(to: &mut Engine, out: &OutgoingMessage) -> Vec<Event> {
    to.handle_group_message(&out.chat_id, &out.ciphertext).unwrap()
}

fn only_message(events: Vec<Event>) -> ChatMessage {
    match events.as_slice() {
        [Event::Message(m)] => m.clone(),
        other => panic!("expected one message, got {other:?}"),
    }
}

/// A KeyPackage for `claimed_user/claimed_device` whose credential names
/// `claimed_ik` as the identity key, but whose binding Mallory's own
/// identity key actually signed.
fn forged_key_package(mallory: &Engine, claimed_user: &str, claimed_device: &str, claimed_ik: &[u8]) -> Vec<u8> {
    let binding = Engine::binding(claimed_user, claimed_device, mallory.signer.public());
    let sig = mallory.identity.sign(&binding).unwrap();
    let claims = CredentialClaims {
        v: CREDENTIAL_VERSION,
        user: claimed_user.to_owned(),
        device: claimed_device.to_owned(),
        ik: STANDARD.encode(claimed_ik),
        sig: STANDARD.encode(sig),
    };
    let cred = CredentialWithKey {
        credential: BasicCredential::new(serde_json::to_vec(&claims).unwrap()).into(),
        signature_key: mallory.signer.to_public_vec().into(),
    };
    let bundle = KeyPackage::builder()
        .build(CIPHERSUITE, &mallory.provider, &mallory.signer, cred)
        .unwrap();
    bundle.key_package().tls_serialize_detached().unwrap()
}

#[test]
fn two_devices_exchange_a_message_without_a_relay() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut alice, &mut bob);
    assert_eq!(alice.members(&chat).unwrap(), vec!["alice/a1", "bob/b1"]);
    assert_eq!(bob.members(&chat).unwrap(), alice.members(&chat).unwrap());
    assert_eq!(
        alice.epoch_authenticator(&chat).unwrap(),
        bob.epoch_authenticator(&chat).unwrap()
    );

    let (_, short) = send(&mut alice, &chat, text("hi"));
    assert!(!short.silent);
    let got = only_message(receive(&mut bob, &short));
    assert_eq!(got.sender, "alice/a1");
    assert_eq!(got.body, "hi");
    assert!(!got.outgoing && !got.read);

    // Padding hides the difference between short and longer messages.
    let (_, longer) = send(&mut alice, &chat, text(&"x".repeat(60)));
    assert_eq!(short.ciphertext.len(), longer.ciphertext.len());
    receive(&mut bob, &longer);

    let (_, reply) = send(&mut bob, &chat, text("hey"));
    assert_eq!(only_message(receive(&mut alice, &reply)).body, "hey");

    // The same message delivered twice is only shown once.
    assert_eq!(alice.history(&chat).len(), 3);
    assert_eq!(bob.history(&chat).len(), 3);
}

#[test]
fn rejects_a_key_package_with_the_wrong_identity() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = alice.create_chat().unwrap();
    let kp = key_package(&mut bob);
    let err = alice
        .add_members(&chat, &[("bob".into(), "someone-else".into(), kp)])
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidKeyPackage(_)), "{err}");
}

#[test]
fn forged_identity_bindings_are_rejected() {
    let mut alice = device("alice", "a1");
    let bob = device("bob", "b1");
    let mallory = device("mallory", "m1");
    let chat = alice.create_chat().unwrap();

    // Mallory claims Bob's identity key, but can't make it sign her device.
    let forged = forged_key_package(&mallory, "bob", "b2", bob.identity.public());
    let err = alice
        .add_members(&chat, &[("bob".into(), "b2".into(), forged)])
        .unwrap_err();
    assert!(err.to_string().contains("didn't sign"), "{err}");

    // A credential in some other format is refused too.
    let cred = CredentialWithKey {
        credential: BasicCredential::new(b"bob/b2".to_vec()).into(),
        signature_key: mallory.signer.to_public_vec().into(),
    };
    let plain = KeyPackage::builder()
        .build(CIPHERSUITE, &mallory.provider, &mallory.signer, cred)
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let err = alice
        .add_members(&chat, &[("bob".into(), "b2".into(), plain)])
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidKeyPackage(_)), "{err}");
}

#[test]
fn receivers_reject_commits_that_add_forged_devices() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let mallory = device("mallory", "m1");
    let chat = pair(&mut alice, &mut bob);

    // Bob's client is compromised and skips the checks in add_members.
    let forged = forged_key_package(&mallory, "carol", "c1", bob.identity.public());
    let kp = KeyPackageIn::tls_deserialize_exact(forged.as_slice())
        .unwrap()
        .validate(bob.provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let group = bob.groups.get_mut(&chat).unwrap();
    let (commit, _, _) = group.add_members(&bob.provider, &bob.signer, &[kp]).unwrap();

    let err = alice
        .handle_group_message(&chat, &commit.to_bytes().unwrap())
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidIdentity(_)), "{err}");
}

#[test]
fn members_cannot_change_who_they_are() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut alice, &mut bob);

    // Bob signs a binding for a new name and swaps it into his leaf.
    let binding = Engine::binding("carol", "c1", bob.signer.public());
    let claims = CredentialClaims {
        v: CREDENTIAL_VERSION,
        user: "carol".into(),
        device: "c1".into(),
        ik: STANDARD.encode(bob.identity.public()),
        sig: STANDARD.encode(bob.identity.sign(&binding).unwrap()),
    };
    let cred = CredentialWithKey {
        credential: BasicCredential::new(serde_json::to_vec(&claims).unwrap()).into(),
        signature_key: bob.signer.to_public_vec().into(),
    };
    let params = LeafNodeParameters::builder().with_credential_with_key(cred).build();
    let group = bob.groups.get_mut(&chat).unwrap();
    let (commit, _, _) = group
        .self_update(&bob.provider, &bob.signer, params)
        .unwrap()
        .into_contents();

    let err = alice
        .handle_group_message(&chat, &commit.to_bytes().unwrap())
        .unwrap_err();
    assert!(err.to_string().contains("tried to become carol/c1"), "{err}");
}

#[test]
fn identity_keys_are_pinned_and_changes_are_flagged() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut alice, &mut bob);

    let pinned = alice.contact("bob").unwrap().clone();
    assert_eq!(pinned.identity_key, STANDARD.encode(bob.identity.public()));
    assert!(!pinned.verified);
    // Bob pinned Alice when he joined.
    assert!(bob.contact("alice").is_some());

    // Bob reinstalls: same name, new identity key. Allowed, but flagged.
    let mut bob2 = device("bob", "b2");
    let inv = invite(&mut bob2);
    let (commit, events) = alice.add_members(&chat, &[inv]).unwrap();
    alice.confirm_commit(&chat).unwrap();
    assert_eq!(
        events,
        vec![Event::IdentityChanged {
            chat_id: chat.clone(),
            username: "bob".into(),
            was_verified: false
        }]
    );
    // Bob's new install joins, and is told his old one is still there.
    let events = bob2.handle_welcome(&chat, commit.welcome.as_ref().unwrap()).unwrap();
    assert!(events.contains(&Event::NotYourDevice {
        chat_id: chat.clone(),
        member: "bob/b1".into()
    }));
    assert_eq!(
        alice.contact("bob").unwrap().identity_key,
        STANDARD.encode(bob2.identity.public())
    );

    // Alice verifies the new key in person...
    assert_eq!(
        alice.verify_code(&bob2.verification_code()).unwrap(),
        VerifyOutcome::Verified
    );
    assert!(alice.contact("bob").unwrap().verified);

    // ...so a third key for "bob" is refused outright.
    let mut bob3 = device("bob", "b3");
    let inv = invite(&mut bob3);
    let err = alice.add_members(&chat, std::slice::from_ref(&inv)).unwrap_err();
    assert!(matches!(err, CoreError::IdentityChanged(ref u) if u == "bob"), "{err}");

    // Unless she explicitly accepts it.
    alice.reset_verification("bob");
    let (_, events) = alice.add_members(&chat, &[inv]).unwrap();
    assert_eq!(
        events,
        vec![Event::IdentityChanged {
            chat_id: chat.clone(),
            username: "bob".into(),
            was_verified: false
        }]
    );
}

#[test]
fn others_adding_a_changed_key_still_warns_loudly() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let carol = device("carol", "c1");
    let chat = pair(&mut alice, &mut bob);

    // Bob verified Carol in person. Alice has never met her, and the relay
    // hands Alice someone else's "carol".
    bob.verify_code(&carol.verification_code()).unwrap();
    let mut fake = device("carol", "c2");
    let inv = invite(&mut fake);
    let (commit, events) = alice.add_members(&chat, &[inv]).unwrap();
    assert!(events.is_empty(), "Alice had nothing pinned for carol");
    alice.confirm_commit(&chat).unwrap();

    // Bob can't stop Alice's commit, but he's told, and Carol is unverified.
    let events = bob.handle_group_message(&chat, &commit.commit).unwrap();
    assert_eq!(
        events[0],
        Event::IdentityChanged {
            chat_id: chat.clone(),
            username: "carol".into(),
            was_verified: true
        }
    );
    assert!(matches!(events[1], Event::MembersChanged { ref added, .. } if added == &vec!["carol/c2".to_string()]));
    assert!(!bob.contact("carol").unwrap().verified);
}

#[test]
fn a_device_using_my_name_with_another_key_is_flagged() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut bob, &mut alice);

    // Someone registers a second "alice" device with their own identity key.
    let mut fake = device("alice", "a2");

    // Alice can't be tricked into adding it...
    let inv = invite(&mut fake);
    let err = alice.add_members(&chat, &[inv]).unwrap_err();
    assert!(err.to_string().contains("uses your name"), "{err}");

    // ...and if Bob adds it (he's warned too), Alice stays in the chat and
    // is told, so she can remove it.
    let inv = invite(&mut fake);
    let (commit, events) = bob.add_members(&chat, &[inv]).unwrap();
    assert_eq!(
        events,
        vec![Event::IdentityChanged {
            chat_id: chat.clone(),
            username: "alice".into(),
            was_verified: false
        }]
    );
    bob.confirm_commit(&chat).unwrap();
    let events = alice.handle_group_message(&chat, &commit.commit).unwrap();
    assert_eq!(
        events[0],
        Event::NotYourDevice {
            chat_id: chat.clone(),
            member: "alice/a2".into()
        }
    );
    let commit = alice.remove_members(&chat, &["a2".into()]).unwrap();
    alice.confirm_commit(&chat).unwrap();
    bob.handle_group_message(&chat, &commit.commit).unwrap();
    assert_eq!(bob.members(&chat).unwrap(), vec!["alice/a1", "bob/b1"]);
}

#[test]
fn safety_numbers_match_on_both_phones() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    pair(&mut alice, &mut bob);

    let a = alice.safety_number("bob").unwrap();
    let b = bob.safety_number("alice").unwrap();
    assert_eq!(a, b);
    assert_eq!(a.chars().filter(char::is_ascii_digit).count(), 60);
    assert_eq!(a.split(' ').count(), 12);

    // Scanning each other's QR codes verifies both ways.
    assert_eq!(
        alice.verify_code(&bob.verification_code()).unwrap(),
        VerifyOutcome::Verified
    );
    assert_eq!(
        bob.verify_code(&alice.verification_code()).unwrap(),
        VerifyOutcome::Verified
    );
    assert!(alice.contact("bob").unwrap().verified);
    assert!(bob.contact("alice").unwrap().verified);

    // A code for a different key under Bob's name doesn't match.
    let impostor = device("bob", "b9");
    assert_eq!(
        alice.verify_code(&impostor.verification_code()).unwrap(),
        VerifyOutcome::Mismatch
    );
    // And a mismatch never changes what was pinned.
    assert_eq!(
        alice.contact("bob").unwrap().identity_key,
        STANDARD.encode(bob.identity.public())
    );

    // Or, comparing the numbers on a call instead of scanning:
    let mut carol = device("carol", "c1");
    pair(&mut bob, &mut carol);
    assert!(!bob.contact("carol").unwrap().verified);
    bob.mark_verified("carol").unwrap();
    assert!(bob.contact("carol").unwrap().verified);
    assert!(bob.mark_verified("nobody").is_err());

    assert!(alice.verify_code(&alice.verification_code()).is_err());
    assert!(alice.verify_code("not a code").is_err());
    assert!(alice.safety_number("nobody").is_err());

    // Different people get different numbers.
    let mut carol = device("carol", "c1");
    pair(&mut alice, &mut carol);
    assert_ne!(alice.safety_number("carol").unwrap(), a);
}

#[test]
fn verifying_before_ever_chatting_pins_the_key() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    assert_eq!(
        alice.verify_code(&bob.verification_code()).unwrap(),
        VerifyOutcome::Verified
    );

    // The relay hands Alice a different "bob": refused, because she verified.
    let mut fake = device("bob", "b2");
    let chat = alice.create_chat().unwrap();
    let inv = invite(&mut fake);
    assert!(matches!(
        alice.add_members(&chat, &[inv]),
        Err(CoreError::IdentityChanged(_))
    ));
    // The real Bob is fine.
    let inv = invite(&mut bob);
    let (_, events) = alice.add_members(&chat, &[inv]).unwrap();
    assert!(events.is_empty());
}

#[test]
fn photos_round_trip_and_tampering_is_caught() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut alice, &mut bob);

    let photo = b"\xff\xd8\xff\xe0 pretend this is a JPEG".to_vec();
    let sealed = alice.seal_attachment(&photo).unwrap();
    assert!(!sealed.ciphertext.windows(7).any(|w| w == b"pretend"));
    let attachment = Attachment {
        blob_id: "0123456789abcdef0123456789abcdef".into(),
        key: sealed.key.clone(),
        sha256: sealed.sha256.clone(),
        mime: "image/jpeg".into(),
        size: photo.len() as u64,
        width: Some(4),
        height: Some(3),
        thumbnail: None,
    };
    let (_, out) = send(
        &mut alice,
        &chat,
        Body::Image {
            attachment: attachment.clone(),
            caption: Some("look".into()),
        },
    );
    assert!(!out.silent);
    let got = only_message(receive(&mut bob, &out));
    assert_eq!(got.body, "look");
    let att = got.attachment.unwrap();
    assert_eq!(att, attachment);
    assert_eq!(open_attachment(&sealed.ciphertext, &att).unwrap(), photo);

    // The relay swaps a byte: caught by the hash before decrypting.
    let mut tampered = sealed.ciphertext.clone();
    tampered[20] ^= 1;
    assert!(matches!(
        open_attachment(&tampered, &att),
        Err(CoreError::AttachmentTampered)
    ));
    // Right bytes, wrong key: caught by the cipher.
    let other = alice.seal_attachment(&photo).unwrap();
    let wrong_key = Attachment {
        key: other.key,
        ..att.clone()
    };
    assert!(matches!(
        open_attachment(&sealed.ciphertext, &wrong_key),
        Err(CoreError::AttachmentTampered)
    ));
    // Alice's own history shows the photo too.
    assert_eq!(alice.history(&chat)[0].attachment.as_ref(), Some(&attachment));
}

#[test]
fn receipts_mark_messages_delivered_and_read() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut alice, &mut bob);

    let (draft, out) = send(&mut alice, &chat, text("are you there?"));
    receive(&mut bob, &out);
    assert_eq!(bob.unread_count(&chat), 1);
    assert_eq!(alice.unread_count(&chat), 0);

    let (_, delivered) = send(
        &mut bob,
        &chat,
        Body::Receipt {
            status: ReceiptStatus::Delivered,
            ids: vec![draft.id.clone()],
        },
    );
    assert!(delivered.silent);
    let events = receive(&mut alice, &delivered);
    assert_eq!(
        events,
        vec![Event::Receipt {
            chat_id: chat.clone(),
            by: "bob/b1".into(),
            status: ReceiptStatus::Delivered,
            ids: vec![draft.id.clone()],
        }]
    );
    let mine = &alice.history(&chat)[0];
    assert_eq!(mine.delivered_to, vec!["bob/b1"]);
    assert!(mine.read_by.is_empty());

    // Bob opens the chat.
    let ids = bob.mark_read(&chat);
    assert_eq!(ids, vec![draft.id.clone()]);
    assert!(bob.mark_read(&chat).is_empty());
    assert_eq!(bob.unread_count(&chat), 0);
    let (_, read) = send(
        &mut bob,
        &chat,
        Body::Receipt {
            status: ReceiptStatus::Read,
            ids,
        },
    );
    receive(&mut alice, &read);
    assert_eq!(alice.history(&chat)[0].read_by, vec!["bob/b1"]);

    // Receipts never show up as messages.
    assert_eq!(alice.history(&chat).len(), 1);
    assert_eq!(bob.history(&chat).len(), 1);
}

#[test]
fn typing_signals_are_encrypted_and_expire_with_the_epoch() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut alice, &mut bob);

    let signal = alice.typing_signal(&chat, NOW).unwrap();
    assert!(!signal.windows(5).any(|w| w == b"alice"));
    assert_eq!(bob.open_typing(&chat, &signal).unwrap().as_deref(), Some("alice/a1"));
    // Our own signal echoed back is ignored.
    assert_eq!(alice.open_typing(&chat, &signal).unwrap(), None);

    let mut tampered = signal.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(bob.open_typing(&chat, &tampered).unwrap(), None);
    assert_eq!(bob.open_typing(&chat, b"short").unwrap(), None);

    // Another chat's key can't open it.
    let mut carol = device("carol", "c1");
    let other = pair(&mut bob, &mut carol);
    assert_eq!(bob.open_typing(&other, &signal).unwrap(), None);

    // After a key rotation, old signals are stale.
    let commit = alice.self_update(&chat).unwrap();
    alice.confirm_commit(&chat).unwrap();
    bob.handle_group_message(&chat, &commit.commit).unwrap();
    assert_eq!(bob.open_typing(&chat, &signal).unwrap(), None);
    let fresh = alice.typing_signal(&chat, NOW).unwrap();
    assert_eq!(bob.open_typing(&chat, &fresh).unwrap().as_deref(), Some("alice/a1"));
}

#[test]
fn profile_updates_set_display_names() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut alice, &mut bob);

    bob.set_display_name("Bobby");
    assert_eq!(bob.display_name(), Some("Bobby"));
    let (_, out) = send(
        &mut bob,
        &chat,
        Body::Profile {
            display_name: "Bobby".into(),
        },
    );
    assert!(out.silent);
    assert_eq!(
        receive(&mut alice, &out),
        vec![Event::ProfileUpdated {
            username: "bob".into(),
            display_name: "Bobby".into()
        }]
    );
    assert_eq!(alice.contact("bob").unwrap().display_name.as_deref(), Some("Bobby"));
    assert!(alice.history(&chat).is_empty());
    assert!(bob.history(&chat).is_empty());
}

#[test]
fn a_removed_member_can_be_added_back() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut alice, &mut bob);

    let commit = alice.remove_members(&chat, &["b1".into()]).unwrap();
    alice.confirm_commit(&chat).unwrap();
    let events = bob.handle_group_message(&chat, &commit.commit).unwrap();
    assert!(matches!(events.as_slice(), [Event::RemovedFromChat { .. }]));
    assert!(!bob.is_active(&chat));
    assert!(bob.encrypt(&chat, &bob.new_text_draft("hi", NOW).unwrap()).is_err());

    add(&mut alice, &chat, &mut bob);
    assert!(bob.is_active(&chat));
    let (_, out) = send(&mut alice, &chat, text("welcome back"));
    assert_eq!(only_message(receive(&mut bob, &out)).body, "welcome back");
}

#[test]
fn state_survives_export_and_import() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = pair(&mut alice, &mut bob);
    alice.set_display_name("Alice");
    alice.verify_code(&bob.verification_code()).unwrap();
    let (_, out) = send(&mut alice, &chat, text("before"));
    receive(&mut bob, &out);

    let code = alice.verification_code();
    let mut alice = Engine::import_state(&alice.export_state().unwrap()).unwrap();
    let mut bob = Engine::import_state(&bob.export_state().unwrap()).unwrap();

    assert_eq!(alice.verification_code(), code);
    assert_eq!(alice.display_name(), Some("Alice"));
    assert!(alice.contact("bob").unwrap().verified);
    assert_eq!(bob.unread_count(&chat), 1);
    assert_eq!(alice.history(&chat).len(), 1);

    let (_, out) = send(&mut alice, &chat, text("after"));
    assert_eq!(only_message(receive(&mut bob, &out)).body, "after");
    let (_, out) = send(&mut bob, &chat, text("still works"));
    assert_eq!(only_message(receive(&mut alice, &out)).body, "still works");

    // Key packages made before a restart still work after it.
    let mut carol = device("carol", "c1");
    let inv = invite(&mut carol);
    let mut carol = Engine::import_state(&carol.export_state().unwrap()).unwrap();
    let (commit, _) = alice.add_members(&chat, &[inv]).unwrap();
    alice.confirm_commit(&chat).unwrap();
    carol.handle_welcome(&chat, commit.welcome.as_ref().unwrap()).unwrap();
    bob.handle_group_message(&chat, &commit.commit).unwrap();
    assert_eq!(
        carol.epoch_authenticator(&chat).unwrap(),
        bob.epoch_authenticator(&chat).unwrap()
    );
}

#[test]
fn old_snapshots_are_refused_cleanly() {
    let alice = device("alice", "a1");
    let mut snapshot: serde_json::Value = serde_json::from_slice(&alice.export_state().unwrap()).unwrap();
    snapshot["version"] = 1.into();
    let result = Engine::import_state(&serde_json::to_vec(&snapshot).unwrap());
    assert!(matches!(result, Err(CoreError::State(_))));
}

#[test]
fn events_become_notices_in_history() {
    let mut alice = device("alice", "a1");
    let mut bob = device("bob", "b1");
    let chat = alice.create_chat().unwrap();
    let inv = invite(&mut bob);
    let (commit, _) = alice.add_members(&chat, &[inv]).unwrap();
    alice.confirm_commit(&chat).unwrap();
    let events = bob.handle_welcome(&chat, commit.welcome.as_ref().unwrap()).unwrap();
    assert_eq!(
        events,
        vec![Event::JoinedChat {
            chat_id: chat.clone(),
            by: "alice/a1".into(),
            members: vec!["alice/a1".into(), "bob/b1".into()],
        }]
    );
    let (chat_id, sender, notice) = bob.notice_for(&events[0]).unwrap();
    let line = bob.record_notice(&chat_id, &sender, notice, NOW).unwrap();
    assert_eq!(line.sender, "alice/a1");
    assert!(line.read, "notices never count as unread");
    assert_eq!(bob.unread_count(&chat), 0);
    assert_eq!(bob.history(&chat), vec![line]);

    // Mail for a chat we've never heard of doesn't invent one.
    let dropped = Event::Dropped {
        chat_id: "ffff".into(),
        reason: "nope".into(),
    };
    assert!(bob.notice_for(&dropped).is_none());
    // Plain messages aren't notices.
    let (_, out) = send(&mut alice, &chat, text("hi"));
    let events = receive(&mut bob, &out);
    assert!(bob.notice_for(&events[0]).is_none());
}
