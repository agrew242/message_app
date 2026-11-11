//! The relay's ordering and access rules, tested over raw HTTP with opaque
//! bytes. The relay never parses MLS, so fake payloads are fine here.

use messenger_protocol::*;
use messenger_relay::Relay;
use reqwest::StatusCode;
use serde_json::json;
use tokio::net::TcpListener;

struct Device {
    id: String,
    token: String,
}

async fn register(http: &reqwest::Client, url: &str, invite: &str, username: &str) -> Device {
    let res: RegisterResponse = http
        .post(format!("{url}/v1/accounts"))
        .json(&RegisterRequest {
            invite_code: invite.into(),
            username: username.into(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    Device {
        id: res.device_id,
        token: res.device_token,
    }
}

async fn invite(http: &reqwest::Client, url: &str, who: &Device) -> String {
    let res: InviteResponse = http
        .post(format!("{url}/v1/invites"))
        .bearer_auth(&who.token)
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    res.code
}

async fn post(
    http: &reqwest::Client,
    url: &str,
    who: &Device,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let res = http
        .post(format!("{url}{path}"))
        .bearer_auth(&who.token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = res.status();
    (status, res.json().await.unwrap_or(json!(null)))
}

async fn mailbox(http: &reqwest::Client, url: &str, who: &Device) -> Vec<MailItem> {
    let res: MailboxResponse = http
        .get(format!("{url}/v1/mailbox"))
        .bearer_auth(&who.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    res.items
}

fn b64(bytes: &[u8]) -> serde_json::Value {
    serde_json::to_value(Bytes(bytes.to_vec())).unwrap()
}

#[tokio::test]
async fn relay_enforces_epochs_membership_and_auth() {
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::open(&tmp.path().join("relay.db")).unwrap();
    let first = relay.bootstrap_invite().unwrap().unwrap();
    assert!(
        relay.bootstrap_invite().unwrap().is_some(),
        "still no users, so another bootstrap is fine"
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(messenger_relay::serve(listener, relay.clone()));
    let http = reqwest::Client::new();

    let alice = register(&http, &url, &first, "alice").await;
    assert!(
        relay.bootstrap_invite().unwrap().is_none(),
        "no bootstrap once users exist"
    );
    let code = invite(&http, &url, &alice).await;
    let bob = register(&http, &url, &code, "bob").await;
    let code = invite(&http, &url, &alice).await;
    let carol = register(&http, &url, &code, "carol").await;

    // No token, no access.
    let res = http.get(format!("{url}/v1/mailbox")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // And nothing the relay says is cacheable.
    assert_eq!(res.headers()["cache-control"], "no-store");

    let chat = "00112233445566778899aabbccddeeff";
    let commits = format!("/v1/chats/{chat}/commits");
    let messages = format!("/v1/chats/{chat}/messages");
    let (s, _) = post(&http, &url, &alice, "/v1/chats", json!({ "chat_id": chat })).await;
    assert_eq!(s, StatusCode::OK);

    // Adding the same device twice in one Commit is refused.
    let (s, _) = post(
        &http,
        &url,
        &alice,
        &commits,
        json!({
            "epoch": 0, "commit": b64(b"c0"), "welcome": b64(b"w0"),
            "added_devices": [bob.id, bob.id], "removed_devices": []
        }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Epoch 0 -> 1, adding bob.
    let add_bob = json!({
        "epoch": 0, "commit": b64(b"commit-add-bob"), "welcome": b64(b"welcome-bob"),
        "added_devices": [bob.id], "removed_devices": []
    });
    let (s, body) = post(&http, &url, &alice, &commits, add_bob.clone()).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["epoch"], 1);

    // Resending the identical Commit (say the response was lost) succeeds
    // again without delivering anything twice.
    let (s, body) = post(&http, &url, &alice, &commits, add_bob).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["epoch"], 1);
    let bob_mail = mailbox(&http, &url, &bob).await;
    assert_eq!(bob_mail.len(), 1);
    assert_eq!(bob_mail[0].kind, MailKind::Welcome);

    // A different Commit for the old epoch loses the race.
    let (s, body) = post(
        &http,
        &url,
        &alice,
        &commits,
        json!({
            "epoch": 0, "commit": b64(b"other"), "welcome": null,
            "added_devices": [], "removed_devices": []
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(body["current_epoch"], 1);

    // Messages must be for the current epoch.
    let (s, body) = post(
        &http,
        &url,
        &alice,
        &messages,
        json!({ "epoch": 0, "ciphertext": b64(b"stale") }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(body["current_epoch"], 1);
    let (s, _) = post(
        &http,
        &url,
        &alice,
        &messages,
        json!({ "epoch": 1, "ciphertext": b64(b"fresh") }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Bob gets the Welcome, then the message, in chat order.
    let bob_mail = mailbox(&http, &url, &bob).await;
    assert_eq!(bob_mail.len(), 2);
    assert_eq!((bob_mail[0].kind, bob_mail[0].chat_seq), (MailKind::Welcome, 1));
    assert_eq!((bob_mail[1].kind, bob_mail[1].chat_seq), (MailKind::Message, 2));
    assert!(bob_mail[0].id < bob_mail[1].id);
    assert_eq!(bob_mail[1].payload.0, b"fresh");

    // The sender never gets its own mail back.
    assert!(mailbox(&http, &url, &alice).await.is_empty());

    // Carol isn't in the chat: she can't post to it.
    let (s, _) = post(
        &http,
        &url,
        &carol,
        &messages,
        json!({ "epoch": 1, "ciphertext": b64(b"x") }),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = post(
        &http,
        &url,
        &carol,
        &commits,
        json!({
            "epoch": 1, "commit": b64(b"x"), "welcome": null, "added_devices": [], "removed_devices": []
        }),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Acknowledged mail is deleted.
    let up_to = bob_mail.last().unwrap().id;
    let (s, _) = post(&http, &url, &bob, "/v1/mailbox/ack", json!({ "up_to": up_to })).await;
    assert_eq!(s, StatusCode::OK);
    assert!(mailbox(&http, &url, &bob).await.is_empty());
    assert_eq!(relay.pending_mail().unwrap(), 0);
}

async fn key_package_count(http: &reqwest::Client, url: &str, who: &Device) -> u64 {
    let res: KeyPackageCount = http
        .get(format!("{url}/v1/key-packages/count"))
        .bearer_auth(&who.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    res.available
}

#[tokio::test]
async fn commits_wait_for_unread_mail_and_are_recognized_when_resent() {
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::open(&tmp.path().join("relay.db")).unwrap();
    let first = relay.bootstrap_invite().unwrap().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(messenger_relay::serve(listener, relay.clone()));
    let http = reqwest::Client::new();

    let alice = register(&http, &url, &first, "alice").await;
    let code = invite(&http, &url, &alice).await;
    let bob = register(&http, &url, &code, "bob").await;

    let chat = "aabbccddeeff00112233445566778899";
    let commits = format!("/v1/chats/{chat}/commits");
    let messages = format!("/v1/chats/{chat}/messages");
    post(&http, &url, &alice, "/v1/chats", json!({ "chat_id": chat })).await;
    let (s, _) = post(
        &http,
        &url,
        &alice,
        &commits,
        json!({
            "epoch": 0, "commit": b64(b"add-bob"), "welcome": b64(b"w"),
            "added_devices": [bob.id], "removed_devices": []
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let mail = mailbox(&http, &url, &bob).await;
    post(
        &http,
        &url,
        &bob,
        "/v1/mailbox/ack",
        json!({ "up_to": mail.last().unwrap().id }),
    )
    .await;

    // Bob says something in epoch 1 that alice hasn't read yet.
    let (s, _) = post(
        &http,
        &url,
        &bob,
        &messages,
        json!({ "epoch": 1, "ciphertext": b64(b"hi") }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Alice can't move the chat to epoch 2 until she's read it: afterwards
    // she could never decrypt it.
    let rotate = json!({
        "epoch": 1, "commit": b64(b"alice-rotates"), "welcome": null,
        "added_devices": [], "removed_devices": []
    });
    let (s, body) = post(&http, &url, &alice, &commits, rotate.clone()).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(body["current_epoch"], 1);
    let mail = mailbox(&http, &url, &alice).await;
    post(
        &http,
        &url,
        &alice,
        "/v1/mailbox/ack",
        json!({ "up_to": mail.last().unwrap().id }),
    )
    .await;
    let (s, body) = post(&http, &url, &alice, &commits, rotate.clone()).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["epoch"], 2);

    // Bob moves the chat on again...
    let mail = mailbox(&http, &url, &bob).await;
    post(
        &http,
        &url,
        &bob,
        "/v1/mailbox/ack",
        json!({ "up_to": mail.last().unwrap().id }),
    )
    .await;
    let (s, _) = post(
        &http,
        &url,
        &bob,
        &commits,
        json!({
            "epoch": 2, "commit": b64(b"bob-rotates"), "welcome": null,
            "added_devices": [], "removed_devices": []
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // ...and alice, whose app crashed before hearing back about her Commit,
    // resends it: the relay still recognizes it, and delivers nothing twice.
    let (s, body) = post(&http, &url, &alice, &commits, rotate).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["epoch"], 2);
    assert!(mailbox(&http, &url, &bob).await.is_empty());
    // Someone else's bytes for that epoch don't match.
    let (s, _) = post(
        &http,
        &url,
        &alice,
        &commits,
        json!({
            "epoch": 1, "commit": b64(b"not-what-landed"), "welcome": null,
            "added_devices": [], "removed_devices": []
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn key_packages_can_be_replaced_wholesale() {
    let tmp = tempfile::tempdir().unwrap();
    let relay = Relay::open(&tmp.path().join("relay.db")).unwrap();
    let first = relay.bootstrap_invite().unwrap().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(messenger_relay::serve(listener, relay.clone()));
    let http = reqwest::Client::new();
    let alice = register(&http, &url, &first, "alice").await;

    let batch = |n: usize| -> Vec<serde_json::Value> { (0..n).map(|i| b64(format!("kp-{i}").as_bytes())).collect() };
    post(
        &http,
        &url,
        &alice,
        "/v1/key-packages",
        json!({ "key_packages": batch(5), "last_resort": null }),
    )
    .await;
    post(
        &http,
        &url,
        &alice,
        "/v1/key-packages",
        json!({ "key_packages": batch(5), "last_resort": null }),
    )
    .await;
    assert_eq!(key_package_count(&http, &url, &alice).await, 10);
    let (s, body) = post(
        &http,
        &url,
        &alice,
        "/v1/key-packages",
        json!({
            "key_packages": batch(3), "last_resort": b64(b"lr"), "replace": true
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["available"], 3);
}

#[tokio::test]
async fn backups_are_complete_copies() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("relay.db");
    let relay = Relay::open(&db).unwrap();
    let first = relay.bootstrap_invite().unwrap().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(messenger_relay::serve(listener, relay.clone()));
    let http = reqwest::Client::new();
    let alice = register(&http, &url, &first, "alice").await;

    let copy = tmp.path().join("backup.db");
    messenger_relay::db::backup(&db, &copy).unwrap();
    assert!(messenger_relay::db::backup(&db, &copy).is_err(), "never overwrites");

    // The copy has alice: no bootstrap invite, and her token still works.
    let restored = Relay::open(&copy).unwrap();
    assert!(restored.bootstrap_invite().unwrap().is_none());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url2 = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(messenger_relay::serve(listener, restored));
    let res = http
        .get(format!("{url2}/v1/mailbox"))
        .bearer_auth(&alice.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
