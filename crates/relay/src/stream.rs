//! `GET /v1/stream`: the live WebSocket.
//!
//! 1. The client's first frame is `{"type":"auth","token":...}`.
//! 2. The relay answers `ready`, plus `mail` if anything is already waiting.
//! 3. From then on the relay says `mail` whenever something arrives (the
//!    client fetches it over HTTPS), and forwards encrypted `typing` signals
//!    between connected chat members.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use messenger_protocol::{ClientFrame, ServerFrame};

use crate::Relay;

const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(25);
/// One typing signal per second per connection is plenty.
const TYPING_MIN_GAP: Duration = Duration::from_secs(1);

pub async fn stream(State(relay): State<Arc<Relay>>, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(16 * 1024)
        .on_upgrade(move |socket| handle(relay, socket))
}

async fn handle(relay: Arc<Relay>, socket: WebSocket) {
    let (mut tx, mut rx) = socket.split();

    let first = tokio::time::timeout(AUTH_TIMEOUT, rx.next()).await;
    let device = match first {
        Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<ClientFrame>(text.as_str()) {
            Ok(ClientFrame::Auth { token }) => relay.authenticate(&token).ok().flatten(),
            _ => None,
        },
        _ => None,
    };
    let Some(device) = device else {
        let _ = send(&mut tx, &ServerFrame::Error {
            error: "first frame must be a valid auth frame".into(),
        })
        .await;
        return;
    };

    let (conn_id, mut outbox) = relay.hub.register(&device.device_id);
    let mut ok = send(&mut tx, &ServerFrame::Ready).await.is_ok();
    if ok && relay.has_mail(&device.device_id) {
        ok = send(&mut tx, &ServerFrame::Mail).await.is_ok();
    }

    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    let mut last_typing = Instant::now() - TYPING_MIN_GAP;
    while ok {
        tokio::select! {
            incoming = rx.next() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(ClientFrame::Typing { chat_id, payload }) = serde_json::from_str(text.as_str()) {
                        if last_typing.elapsed() >= TYPING_MIN_GAP {
                            last_typing = Instant::now();
                            relay.forward_typing(&device, &chat_id, payload);
                        }
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
            Some(frame) = outbox.recv() => {
                ok = send(&mut tx, &frame).await.is_ok();
            }
            _ = ping.tick() => {
                ok = tx.send(Message::Ping(Default::default())).await.is_ok();
            }
        }
    }
    relay.hub.unregister(&device.device_id, conn_id);
}

async fn send<S>(tx: &mut S, frame: &ServerFrame) -> Result<(), axum::Error>
where
    S: SinkExt<Message, Error = axum::Error> + Unpin,
{
    let json = serde_json::to_string(frame).expect("frames always serialize");
    tx.send(Message::Text(json.into())).await
}
