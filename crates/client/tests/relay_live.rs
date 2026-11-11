//! The relay's Phase 1 features: live WebSocket wake-ups, encrypted typing
//! signals, web push subscriptions, encrypted photo storage and CORS.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use messenger_protocol::*;
use messenger_relay::{Relay, RelayConfig};
use reqwest::StatusCode;
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

struct Device {
    id: String,
    token: String,
}

struct Env {
    url: String,
    http: reqwest::Client,
    alice: Device,
    bob: Device,
    carol: Device,
    _tmp: tempfile::TempDir,
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

/// alice and bob share chat `CHAT`; carol is registered but not in it.
const CHAT: &str = "aabbccddeeff00112233445566778899";

async fn setup() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let config = RelayConfig {
        allowed_origins: vec!["https://app.example.com".into()],
        ..RelayConfig::default()
    };
    let relay = Relay::open_with(&tmp.path().join("relay.db"), config).unwrap();
    let first = relay.bootstrap_invite().unwrap().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(messenger_relay::serve(listener, relay));
    let http = reqwest::Client::new();
    let alice = register(&http, &url, &first, "alice").await;
    let code = invite(&http, &url, &alice).await;
    let bob = register(&http, &url, &code, "bob").await;
    let code = invite(&http, &url, &alice).await;
    let carol = register(&http, &url, &code, "carol").await;

    let post = |who: &Device, path: &str, body: serde_json::Value| {
        http.post(format!("{url}{path}"))
            .bearer_auth(&who.token)
            .json(&body)
            .send()
    };
    post(&alice, "/v1/chats", json!({ "chat_id": CHAT }))
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    post(
        &alice,
        &format!("/v1/chats/{CHAT}/commits"),
        json!({
            "epoch": 0, "commit": Bytes(b"c".to_vec()), "welcome": Bytes(b"w".to_vec()),
            "added_devices": [bob.id], "removed_devices": []
        }),
    )
    .await
    .unwrap()
    .error_for_status()
    .unwrap();

    Env {
        url,
        http,
        alice,
        bob,
        carol,
        _tmp: tmp,
    }
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(env: &Env, who: &Device) -> Ws {
    let ws_url = format!("{}/v1/stream", env.url.replacen("http", "ws", 1));
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let auth = serde_json::to_string(&ClientFrame::Auth {
        token: who.token.clone(),
    })
    .unwrap();
    ws.send(Message::Text(auth.into())).await.unwrap();
    assert_eq!(next_frame(&mut ws).await, Some(ServerFrame::Ready));
    ws
}

/// The next server frame, skipping pings; `None` on timeout.
async fn next_frame(ws: &mut Ws) -> Option<ServerFrame> {
    loop {
        let msg = tokio::time::timeout(Duration::from_millis(1500), ws.next())
            .await
            .ok()??;
        match msg.ok()? {
            Message::Text(t) => return serde_json::from_str(t.as_str()).ok(),
            Message::Close(_) => return None,
            _ => continue,
        }
    }
}

#[tokio::test]
async fn websocket_says_mail_but_never_carries_it() {
    let env = setup().await;
    // Bob has a Welcome waiting, so he hears about it as soon as he connects.
    let mut bob = connect(&env, &env.bob).await;
    assert_eq!(next_frame(&mut bob).await, Some(ServerFrame::Mail));

    // A new message arrives while he's connected.
    env.http
        .post(format!("{}/v1/chats/{CHAT}/messages", env.url))
        .bearer_auth(&env.alice.token)
        .json(&json!({ "epoch": 1, "ciphertext": Bytes(b"secret ciphertext".to_vec()) }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(next_frame(&mut bob).await, Some(ServerFrame::Mail));
}

#[tokio::test]
async fn websocket_rejects_a_bad_token() {
    let env = setup().await;
    let ws_url = format!("{}/v1/stream", env.url.replacen("http", "ws", 1));
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let auth = serde_json::to_string(&ClientFrame::Auth { token: "nope".into() }).unwrap();
    ws.send(Message::Text(auth.into())).await.unwrap();
    assert!(matches!(next_frame(&mut ws).await, Some(ServerFrame::Error { .. })));
}

#[tokio::test]
async fn typing_reaches_members_only_and_is_rate_limited() {
    let env = setup().await;
    let mut alice = connect(&env, &env.alice).await;
    let mut bob = connect(&env, &env.bob).await;
    let mut carol = connect(&env, &env.carol).await;
    assert_eq!(next_frame(&mut bob).await, Some(ServerFrame::Mail)); // his pending Welcome

    let typing = |payload: &[u8]| {
        Message::Text(
            serde_json::to_string(&ClientFrame::Typing {
                chat_id: CHAT.into(),
                payload: Bytes(payload.to_vec()),
            })
            .unwrap()
            .into(),
        )
    };
    alice.send(typing(b"encrypted typing")).await.unwrap();
    assert_eq!(
        next_frame(&mut bob).await,
        Some(ServerFrame::Typing {
            chat_id: CHAT.into(),
            payload: Bytes(b"encrypted typing".to_vec())
        })
    );
    // A second signal inside a second is dropped.
    alice.send(typing(b"again")).await.unwrap();
    assert_eq!(next_frame(&mut bob).await, None);
    // Carol isn't in the chat: she hears nothing, and can't type into it.
    assert_eq!(next_frame(&mut carol).await, None);
    carol.send(typing(b"intruder")).await.unwrap();
    assert_eq!(next_frame(&mut bob).await, None);
}

#[tokio::test]
async fn push_subscriptions_must_point_at_a_real_push_service() {
    let env = setup().await;
    let key: VapidKeyResponse = env
        .http
        .get(format!("{}/v1/push/key", env.url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(key.public_key.len() > 80, "base64url of a 65-byte P-256 point");

    let put = |endpoint: &str| {
        env.http
            .put(format!("{}/v1/devices/me/push", env.url))
            .bearer_auth(&env.bob.token)
            .json(&json!({ "endpoint": endpoint, "keys": { "p256dh": "x", "auth": "y" } }))
            .send()
    };
    assert_eq!(
        put("https://web.push.apple.com/abc").await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        put("http://web.push.apple.com/abc").await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        put("https://169.254.169.254/latest").await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn attachments_round_trip_for_signed_in_devices_only() {
    let env = setup().await;
    let ciphertext = vec![7u8; 300_000];
    let res: BlobResponse = env
        .http
        .post(format!("{}/v1/blobs", env.url))
        .bearer_auth(&env.alice.token)
        .body(ciphertext.clone())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(res.size, 300_000);

    let got = env
        .http
        .get(format!("{}/v1/blobs/{}", env.url, res.id))
        .bearer_auth(&env.bob.token)
        .send()
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    assert_eq!(got.bytes().await.unwrap().as_ref(), ciphertext.as_slice());

    let anonymous = env
        .http
        .get(format!("{}/v1/blobs/{}", env.url, res.id))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let too_big = env
        .http
        .post(format!("{}/v1/blobs", env.url))
        .bearer_auth(&env.alice.token)
        .body(vec![0u8; messenger_relay::MAX_BLOB_BYTES + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(too_big.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn cors_allows_only_the_configured_web_app() {
    let env = setup().await;
    let preflight = |origin: &str| {
        env.http
            .request(reqwest::Method::OPTIONS, format!("{}/v1/mailbox", env.url))
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Headers", "authorization")
            .send()
    };
    let ok = preflight("https://app.example.com").await.unwrap();
    assert_eq!(
        ok.headers().get("access-control-allow-origin").unwrap(),
        "https://app.example.com"
    );
    let other = preflight("https://evil.example.com").await.unwrap();
    assert!(other.headers().get("access-control-allow-origin").is_none());
}
