//! Phase 1 features end to end through the shared session and a real relay:
//! names, receipts, photos, notices, verification, typing, and recovering
//! from dropped connections and crashes in the middle of a Commit.
//!
//! The test platform keeps "disk" in memory so a test can crash a device
//! (drop it) and reopen it from exactly what it last saved, and it can cut
//! the connection before a request or lose the reply after the relay has
//! acted on it.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use messenger_client::{
    now_ms, Event, HttpRequest, HttpResponse, ImageInfo, Notice, Platform, Session, SessionError, StreamUpdate,
    VerifyOutcome,
};
use messenger_relay::Relay;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    /// The request never reaches the relay.
    NoConnection,
    /// The relay acts on it, but the reply never arrives.
    LoseReply,
}

/// What survives a crash, plus the test's levers.
#[derive(Clone, Default)]
struct Handles {
    disk: Rc<RefCell<Vec<u8>>>,
    faults: Rc<RefCell<Vec<(String, Fault, usize)>>>,
    clock_offset_ms: Rc<Cell<i64>>,
}

impl Handles {
    fn platform(&self) -> TestPlatform {
        TestPlatform {
            http: reqwest::Client::new(),
            h: self.clone(),
        }
    }

    /// The next `times` requests whose URL contains `url_part` fail.
    fn fail(&self, url_part: &str, fault: Fault, times: usize) {
        self.faults.borrow_mut().push((url_part.to_owned(), fault, times));
    }

    /// The device restarts from whatever it last saved.
    fn reopen(&self) -> Session<TestPlatform> {
        let saved = self.disk.borrow().clone();
        Session::open(self.platform(), &saved).unwrap()
    }
}

struct TestPlatform {
    http: reqwest::Client,
    h: Handles,
}

impl Platform for TestPlatform {
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let fault = {
            let mut faults = self.h.faults.borrow_mut();
            let hit = faults
                .iter_mut()
                .find(|(part, _, left)| *left > 0 && req.url.contains(part.as_str()));
            hit.map(|(_, fault, left)| {
                *left -= 1;
                *fault
            })
        };
        if fault == Some(Fault::NoConnection) {
            return Err("simulated: no connection".into());
        }
        let method = reqwest::Method::from_bytes(req.method.as_bytes()).unwrap();
        let mut b = self.http.request(method, &req.url);
        if let Some(t) = &req.bearer {
            b = b.bearer_auth(t);
        }
        if let Some(ct) = req.content_type {
            b = b.header("content-type", ct);
        }
        if let Some(body) = req.body {
            b = b.body(body);
        }
        let res = b.send().await.map_err(|e| e.to_string())?;
        let status = res.status().as_u16();
        let body = res.bytes().await.map_err(|e| e.to_string())?.to_vec();
        if fault == Some(Fault::LoseReply) {
            return Err("simulated: connection dropped before the reply".into());
        }
        Ok(HttpResponse { status, body })
    }

    async fn save(&self, state: &[u8]) -> Result<(), String> {
        *self.h.disk.borrow_mut() = state.to_vec();
        Ok(())
    }

    async fn sleep(&self, _ms: u64) {}

    fn now_ms(&self) -> i64 {
        now_ms() + self.h.clock_offset_ms.get()
    }
}

type Device = Session<TestPlatform>;

struct World {
    url: String,
    _tmp: tempfile::TempDir,
}

async fn world() -> (World, String) {
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::open(&tmp.path().join("relay.db")).unwrap();
    let invite = relay.bootstrap_invite().unwrap().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(messenger_relay::serve(listener, relay));
    (World { url, _tmp: tmp }, invite)
}

async fn signup(world: &World, invite: &str, name: &str) -> (Device, Handles) {
    let h = Handles::default();
    let device = Session::register(h.platform(), &world.url, invite, name).await.unwrap();
    (device, h)
}

/// Alice plus friends who signed up with her invites.
async fn people(names: &[&str]) -> (World, Vec<(Device, Handles)>) {
    let (world, first) = world().await;
    let alice = signup(&world, &first, names[0]).await;
    let mut out = vec![alice];
    for name in &names[1..] {
        let code = out[0].0.invite().await.unwrap();
        out.push(signup(&world, &code, name).await);
    }
    (world, out)
}

fn assert_in_sync(chat: &str, a: &Device, b: &Device) {
    let (a, b) = (a.engine(), b.engine());
    assert_eq!(a.members(chat).unwrap(), b.members(chat).unwrap());
    assert_eq!(a.epoch(chat).unwrap(), b.epoch(chat).unwrap());
    assert_eq!(
        a.epoch_authenticator(chat).unwrap(),
        b.epoch_authenticator(chat).unwrap()
    );
}

fn no_drops(events: &[Event]) {
    for e in events {
        assert!(!matches!(e, Event::Dropped { .. }), "dropped: {e:?}");
    }
}

fn texts(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Message(m) => Some(m.body.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn names_receipts_photos_and_notices_work_end_to_end() {
    let (_world, mut ppl) = people(&["alice", "bob"]).await;
    let (mut bob, _) = ppl.pop().unwrap();
    let (mut alice, _) = ppl.pop().unwrap();
    alice.set_display_name("Alice A.").await.unwrap();
    bob.set_display_name("Bobby").await.unwrap();

    // Starting a chat with someone who doesn't exist leaves nothing behind.
    let err = alice.create_chat(&["nobody"]).await.unwrap_err();
    assert!(err.to_string().contains("no one called nobody"), "{err}");
    assert!(alice.chat_list().is_empty());

    let chat = alice.create_chat(&["bob"]).await.unwrap();
    let events = bob.sync().await.unwrap();
    no_drops(&events);
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::JoinedChat { by, .. } if by.starts_with("alice/"))));
    // Alice told the newcomer her name as soon as he was in.
    assert_eq!(bob.name_of("alice"), "Alice A.");
    assert_eq!(bob.chat_list()[0].title, "Alice A.");
    // And bob told the chat his when he joined.
    alice.sync().await.unwrap();
    assert_eq!(alice.name_of("bob"), "Bobby");
    assert_eq!(alice.chat_list()[0].title, "Bobby");

    // Both histories open with a grey line about the join.
    let first = &alice.engine().history(&chat)[0];
    assert!(matches!(&first.notice, Some(Notice::MembersChanged { added, .. }) if added[0].starts_with("bob/")));
    let first = &bob.engine().history(&chat)[0];
    assert!(matches!(&first.notice, Some(Notice::Joined { .. })));

    // Delivered, then read.
    let sent = alice.send_text(&chat, "hello bob").await.unwrap();
    assert_eq!(texts(&bob.sync().await.unwrap()), vec!["hello bob"]);
    assert_eq!(bob.chat_list()[0].unread, 1);
    alice.sync().await.unwrap();
    let mine = |a: &Device| a.engine().history(&chat).into_iter().find(|m| m.id == sent.id).unwrap();
    assert_eq!(mine(&alice).delivered_to.len(), 1);
    assert!(mine(&alice).read_by.is_empty());
    bob.mark_read(&chat).await.unwrap();
    assert_eq!(bob.chat_list()[0].unread, 0);
    alice.sync().await.unwrap();
    assert_eq!(mine(&alice).read_by, vec![bob.identity().unwrap()]);

    // With read receipts off, alice only learns it was delivered.
    bob.set_read_receipts(false).await.unwrap();
    let sent = alice.send_text(&chat, "secretly read").await.unwrap();
    bob.sync().await.unwrap();
    bob.mark_read(&chat).await.unwrap();
    alice.sync().await.unwrap();
    let m = alice
        .engine()
        .history(&chat)
        .into_iter()
        .find(|m| m.id == sent.id)
        .unwrap();
    assert_eq!(m.delivered_to.len(), 1);
    assert!(m.read_by.is_empty());

    // A photo: encrypted on the relay, whole again on bob's side.
    let photo: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let info = ImageInfo {
        mime: "image/png".into(),
        width: Some(640),
        height: Some(480),
        thumbnail: Some("data:image/png;base64,AAAA".into()),
        caption: Some("the view".into()),
    };
    alice.send_image(&chat, &photo, info).await.unwrap();
    let events = bob.sync().await.unwrap();
    let Some(Event::Message(m)) = events.iter().find(|e| matches!(e, Event::Message(_))) else {
        panic!("no photo in {events:?}");
    };
    assert_eq!(m.body, "the view");
    let att = m.attachment.clone().unwrap();
    assert_eq!(
        (att.width, att.height, att.size),
        (Some(640), Some(480), photo.len() as u64)
    );
    assert_eq!(bob.fetch_attachment(&att).await.unwrap(), photo);
    assert!(bob
        .send_image(&chat, b"not an image", ImageInfo::default())
        .await
        .is_err());

    // Verifying each other in person.
    assert_eq!(
        alice.verify_code(&bob.engine().verification_code()).await.unwrap(),
        VerifyOutcome::Verified
    );
    assert_eq!(
        alice.engine().safety_number("bob").unwrap(),
        bob.engine().safety_number("alice").unwrap()
    );
    assert!(alice.engine().contact("bob").unwrap().verified);
}

#[tokio::test]
async fn a_commit_whose_reply_was_lost_is_settled_after_a_crash() {
    let (_world, mut ppl) = people(&["alice", "bob"]).await;
    let (mut bob, _) = ppl.pop().unwrap();
    let (mut alice, alice_h) = ppl.pop().unwrap();
    let chat = alice.create_chat(&["bob"]).await.unwrap();
    no_drops(&bob.sync().await.unwrap());
    alice.sync().await.unwrap();

    // Alice rotates her keys; the relay applies it, but every reply is lost.
    alice_h.fail("/commits", Fault::LoseReply, 10);
    let err = alice.rotate_keys(&chat).await.unwrap_err();
    assert!(matches!(err, SessionError::Offline(_)), "{err}");
    // Her app is killed before the network comes back.
    drop(alice);
    alice_h.faults.borrow_mut().clear();

    // Meanwhile bob sees her Commit and moves the chat on again.
    let events = bob.sync().await.unwrap();
    no_drops(&events);
    assert!(events.iter().any(|e| matches!(e, Event::KeysUpdated { .. })));
    bob.rotate_keys(&chat).await.unwrap();

    // Alice restarts: her saved Commit is recognized as having landed,
    // then she catches up with bob's.
    let mut alice = alice_h.reopen();
    no_drops(&alice.sync().await.unwrap());
    assert_in_sync(&chat, &alice, &bob);
    alice.send_text(&chat, "back").await.unwrap();
    assert_eq!(texts(&bob.sync().await.unwrap()), vec!["back"]);
    bob.send_text(&chat, "welcome back").await.unwrap();
    assert_eq!(texts(&alice.sync().await.unwrap()), vec!["welcome back"]);
}

#[tokio::test]
async fn a_commit_that_never_left_is_sent_after_a_restart() {
    let (_world, mut ppl) = people(&["alice", "bob", "carol"]).await;
    let (mut carol, _) = ppl.pop().unwrap();
    let (mut bob, _) = ppl.pop().unwrap();
    let (mut alice, alice_h) = ppl.pop().unwrap();
    let chat = alice.create_chat(&["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    // Adding carol: the Commit is made and saved, but can't be sent.
    alice_h.fail("/commits", Fault::NoConnection, 10);
    assert!(matches!(
        alice.add_members(&chat, &["carol"]).await,
        Err(SessionError::Offline(_))
    ));
    // Nothing else can happen in that chat until it's settled.
    assert!(alice.send_text(&chat, "hi").await.is_err());
    drop(alice);
    alice_h.faults.borrow_mut().clear();

    let mut alice = alice_h.reopen();
    no_drops(&alice.sync().await.unwrap());
    assert_eq!(alice.engine().members(&chat).unwrap().len(), 3);
    let events = carol.sync().await.unwrap();
    assert!(events.iter().any(|e| matches!(e, Event::JoinedChat { .. })));
    no_drops(&bob.sync().await.unwrap());
    assert_in_sync(&chat, &alice, &carol);
    assert_in_sync(&chat, &alice, &bob);
    assert!(alice
        .engine()
        .history(&chat)
        .iter()
        .any(|m| matches!(&m.notice, Some(Notice::MembersChanged { added, .. }) if added[0].starts_with("carol/"))));
}

#[tokio::test]
async fn messages_waiting_in_the_old_epoch_survive_a_commit() {
    let (_world, mut ppl) = people(&["alice", "bob"]).await;
    let (mut bob, _) = ppl.pop().unwrap();
    let (mut alice, _) = ppl.pop().unwrap();
    let chat = alice.create_chat(&["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    // Bob writes; alice rotates keys before she has read it.
    bob.send_text(&chat, "read me first").await.unwrap();
    alice.rotate_keys(&chat).await.unwrap();
    let events = alice.sync().await.unwrap();
    no_drops(&events);
    let history: Vec<String> = alice.engine().history(&chat).into_iter().map(|m| m.body).collect();
    assert!(history.contains(&"read me first".to_owned()), "{history:?}");
    no_drops(&bob.sync().await.unwrap());
    assert_in_sync(&chat, &alice, &bob);
}

#[tokio::test]
async fn key_packages_are_replaced_before_they_expire() {
    let (_world, mut ppl) = people(&["alice", "bob"]).await;
    let (mut bob, _) = ppl.pop().unwrap();
    let (mut alice, alice_h) = ppl.pop().unwrap();
    assert_eq!(alice.key_packages_available().await.unwrap(), 20);
    bob.create_chat(&["alice"]).await.unwrap();
    assert_eq!(alice.key_packages_available().await.unwrap(), 19);
    alice.sync().await.unwrap();

    // A month later, the whole batch is swapped for fresh ones.
    alice_h.clock_offset_ms.set(29 * 24 * 3600 * 1000);
    alice.sync().await.unwrap();
    assert_eq!(alice.key_packages_available().await.unwrap(), 20);
    // And not again the next day: one more claimed stays claimed.
    bob.create_chat(&["alice"]).await.unwrap();
    alice_h.clock_offset_ms.set(30 * 24 * 3600 * 1000);
    alice.sync().await.unwrap();
    assert_eq!(alice.key_packages_available().await.unwrap(), 19);
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(device: &Device) -> Ws {
    let (mut ws, _) = tokio_tungstenite::connect_async(device.stream_url()).await.unwrap();
    ws.send(Message::Text(device.stream_hello().into())).await.unwrap();
    ws
}

async fn next_update(device: &Device, ws: &mut Ws) -> Option<StreamUpdate> {
    loop {
        let msg = tokio::time::timeout(Duration::from_millis(1500), ws.next())
            .await
            .ok()??;
        match msg.ok()? {
            Message::Text(t) => return Some(device.read_stream_frame(t.as_str())),
            Message::Close(_) => return None,
            _ => continue,
        }
    }
}

#[tokio::test]
async fn live_updates_and_typing_through_the_session() {
    let (_world, mut ppl) = people(&["alice", "bob"]).await;
    let (mut bob, _) = ppl.pop().unwrap();
    let (mut alice, _) = ppl.pop().unwrap();
    let chat = alice.create_chat(&["bob"]).await.unwrap();
    bob.sync().await.unwrap();
    alice.sync().await.unwrap();

    let mut alice_ws = connect(&alice).await;
    assert_eq!(next_update(&alice, &mut alice_ws).await, Some(StreamUpdate::Ready));
    let mut bob_ws = connect(&bob).await;
    assert_eq!(next_update(&bob, &mut bob_ws).await, Some(StreamUpdate::Ready));

    // Bob types: alice sees who, though the relay only saw ciphertext.
    bob_ws
        .send(Message::Text(bob.typing_frame(&chat).unwrap().into()))
        .await
        .unwrap();
    assert_eq!(
        next_update(&alice, &mut alice_ws).await,
        Some(StreamUpdate::Typing {
            chat_id: chat.clone(),
            who: bob.identity().unwrap()
        })
    );

    // A message is announced, then fetched by syncing.
    bob.send_text(&chat, "ping").await.unwrap();
    assert_eq!(next_update(&alice, &mut alice_ws).await, Some(StreamUpdate::Mail));
    assert_eq!(texts(&alice.sync().await.unwrap()), vec!["ping"]);
    assert!(alice.stream_url().starts_with("ws://") && alice.stream_url().ends_with("/v1/stream"));
}
