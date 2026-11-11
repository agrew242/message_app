//! The shared session, compiled to WebAssembly for the web app.
//!
//! JavaScript (and Dart, through JS interop) gets one class, `Messenger`.
//! Results travel as JSON strings, bytes (saved state, photos) as
//! `Uint8Array`s. Every method returns a Promise, and they run one at a
//! time: a session is one device, and its operations must not interleave.
//!
//! The network is the global `fetch`, so the same build runs in browsers and
//! in Node (the smoke test). Storage is a callback from the host: it gets the
//! state as bytes and must store it durably before its Promise resolves. The
//! web app encrypts it with a Web Crypto key before writing to IndexedDB.

use std::rc::Rc;

use futures_util::lock::Mutex;
use js_sys::{Function, Object, Promise, Reflect, Uint8Array};
use messenger_session::{
    Attachment, CoreError, HttpRequest, HttpResponse, ImageInfo, Platform, PushSubscription, Session, SessionError,
    Settings, VerifyOutcome,
};
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::{future_to_promise, JsFuture};

// ---------------------------------------------------------------------------
// The platform: fetch, a save callback, setTimeout and Date.now
// ---------------------------------------------------------------------------

pub struct WasmPlatform {
    save: Function,
}

fn js_text(e: JsValue) -> String {
    if let Some(s) = e.as_string() {
        return s;
    }
    Reflect::get(&e, &"message".into())
        .ok()
        .and_then(|m| m.as_string())
        .unwrap_or_else(|| format!("{e:?}"))
}

fn global_fn(name: &str) -> Result<Function, String> {
    Reflect::get(&js_sys::global(), &name.into())
        .map_err(js_text)?
        .dyn_into::<Function>()
        .map_err(|_| format!("{name} isn't available here"))
}

impl Platform for WasmPlatform {
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, String> {
        let init = Object::new();
        let set = |obj: &Object, k: &str, v: &JsValue| Reflect::set(obj, &k.into(), v).map(|_| ()).map_err(js_text);
        set(&init, "method", &req.method.into())?;
        let headers = Object::new();
        if let Some(token) = &req.bearer {
            set(&headers, "authorization", &format!("Bearer {token}").into())?;
        }
        if let Some(ct) = req.content_type {
            set(&headers, "content-type", &ct.into())?;
        }
        set(&init, "headers", &headers)?;
        if let Some(body) = &req.body {
            set(&init, "body", &Uint8Array::from(body.as_slice()))?;
        }
        let promise: Promise = global_fn("fetch")?
            .call2(&js_sys::global(), &req.url.into(), &init)
            .map_err(js_text)?
            .dyn_into()
            .map_err(|_| "fetch didn't return a promise".to_string())?;
        let res = JsFuture::from(promise).await.map_err(js_text)?;
        let status = Reflect::get(&res, &"status".into())
            .map_err(js_text)?
            .as_f64()
            .unwrap_or(0.0) as u16;
        let array_buffer = Reflect::get(&res, &"arrayBuffer".into())
            .map_err(js_text)?
            .dyn_into::<Function>()
            .map_err(|_| "response has no arrayBuffer()".to_string())?;
        let buf = JsFuture::from(
            array_buffer
                .call0(&res)
                .map_err(js_text)?
                .dyn_into::<Promise>()
                .map_err(|_| "arrayBuffer() didn't return a promise".to_string())?,
        )
        .await
        .map_err(js_text)?;
        Ok(HttpResponse {
            status,
            body: Uint8Array::new(&buf).to_vec(),
        })
    }

    async fn save(&self, state: &[u8]) -> Result<(), String> {
        let ret = self
            .save
            .call1(&JsValue::NULL, &Uint8Array::from(state))
            .map_err(js_text)?;
        if let Ok(p) = ret.dyn_into::<Promise>() {
            JsFuture::from(p).await.map_err(js_text)?;
        }
        Ok(())
    }

    async fn sleep(&self, ms: u64) {
        let promise = Promise::new(&mut |resolve, _reject| {
            if let Ok(set_timeout) = global_fn("setTimeout") {
                let _ = set_timeout.call2(&JsValue::NULL, &resolve, &JsValue::from_f64(ms as f64));
            } else {
                let _ = resolve.call0(&JsValue::NULL);
            }
        });
        let _ = JsFuture::from(promise).await;
    }

    fn now_ms(&self) -> i64 {
        js_sys::Date::now() as i64
    }
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

/// A JavaScript `Error` whose `name` says what kind of failure it was:
/// `Offline`, `Invalid`, `Relay`, `Storage`, `Busy`, `IdentityChanged`,
/// `NotAMember`, `NotFound`, `Untrusted` or `Crypto`.
fn js_error(e: SessionError) -> JsValue {
    let name = match &e {
        SessionError::Offline(_) => "Offline",
        SessionError::Invalid(_) => "Invalid",
        SessionError::Relay { .. } => "Relay",
        SessionError::Storage(_) => "Storage",
        SessionError::TooManyConflicts => "Busy",
        SessionError::Core(CoreError::IdentityChanged(_)) => "IdentityChanged",
        SessionError::Core(CoreError::NotAMember(_)) => "NotAMember",
        SessionError::Core(CoreError::UnknownChat(_) | CoreError::UnknownMember(_)) => "NotFound",
        SessionError::Core(CoreError::InvalidKeyPackage(_) | CoreError::InvalidIdentity(_)) => "Untrusted",
        SessionError::Core(_) => "Crypto",
    };
    let err = js_sys::Error::new(&e.to_string());
    err.set_name(name);
    err.into()
}

fn bad_input(msg: String) -> JsValue {
    let err = js_sys::Error::new(&msg);
    err.set_name("Invalid");
    err.into()
}

fn json<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_json::to_string(value)
        .map(JsValue::from)
        .map_err(|e| bad_input(e.to_string()))
}

fn parse<T: DeserializeOwned>(text: &str) -> Result<T, JsValue> {
    serde_json::from_str(text).map_err(|e| bad_input(format!("bad JSON argument: {e}")))
}

#[derive(Serialize)]
struct Me {
    username: String,
    identity: String,
    display_name: Option<String>,
    verification_code: String,
    relay_url: String,
    settings: Settings,
}

// ---------------------------------------------------------------------------
// The class
// ---------------------------------------------------------------------------

type Shared = Rc<Mutex<Session<WasmPlatform>>>;

/// One signed-in device.
#[wasm_bindgen]
pub struct Messenger {
    inner: Shared,
}

/// Runs `f` with the session locked, as a Promise.
macro_rules! op {
    ($self:ident, |$s:ident| $body:expr) => {{
        let inner = $self.inner.clone();
        future_to_promise(async move {
            #[allow(unused_mut)]
            let mut $s = inner.lock().await;
            $body
        })
    }};
}

#[wasm_bindgen]
impl Messenger {
    /// Signs up with an invite code. `save(bytes)` is called whenever the
    /// state changes and must resolve once it's stored.
    pub async fn register(
        relay_url: String,
        invite_code: String,
        username: String,
        save: Function,
    ) -> Result<Messenger, JsValue> {
        let session = Session::register(WasmPlatform { save }, &relay_url, &invite_code, &username)
            .await
            .map_err(js_error)?;
        Ok(Messenger {
            inner: Rc::new(Mutex::new(session)),
        })
    }

    /// Picks up from saved state, such as when the app starts.
    pub fn open(saved: &[u8], save: Function) -> Result<Messenger, JsValue> {
        let session = Session::open(WasmPlatform { save }, saved).map_err(js_error)?;
        Ok(Messenger {
            inner: Rc::new(Mutex::new(session)),
        })
    }

    /// `{username, identity, display_name, verification_code, relay_url, settings}`
    pub fn whoami(&self) -> Promise {
        op!(self, |s| json(&Me {
            username: s.username().to_owned(),
            identity: s.identity().map_err(js_error)?,
            display_name: s.engine().display_name().map(str::to_owned),
            verification_code: s.engine().verification_code(),
            relay_url: s.relay_url().to_owned(),
            settings: s.settings().clone(),
        }))
    }

    /// The chat list, newest first, as JSON.
    #[wasm_bindgen(js_name = chatList)]
    pub fn chat_list(&self) -> Promise {
        op!(self, |s| json(&s.chat_list()))
    }

    /// A chat's messages and notices, oldest first, as JSON.
    pub fn history(&self, chat_id: String) -> Promise {
        op!(self, |s| json(&s.engine().history(&chat_id)))
    }

    /// `username/device` of everyone in the chat, as JSON.
    pub fn members(&self, chat_id: String) -> Promise {
        op!(self, |s| json(
            &s.engine().members(&chat_id).map_err(|e| js_error(e.into()))?
        ))
    }

    /// Everyone you've chatted with, as JSON.
    pub fn contacts(&self) -> Promise {
        op!(self, |s| json(&s.engine().contacts()))
    }

    #[wasm_bindgen(js_name = nameOf)]
    pub fn name_of(&self, username: String) -> Promise {
        op!(self, |s| Ok(JsValue::from(s.name_of(&username))))
    }

    #[wasm_bindgen(js_name = safetyNumber)]
    pub fn safety_number(&self, username: String) -> Promise {
        op!(self, |s| Ok(JsValue::from(
            s.engine().safety_number(&username).map_err(|e| js_error(e.into()))?
        )))
    }

    /// A fresh invite code for a friend.
    pub fn invite(&self) -> Promise {
        op!(self, |s| Ok(JsValue::from(s.invite().await.map_err(js_error)?)))
    }

    /// Starts a chat with a JSON list of usernames. Resolves to its id.
    #[wasm_bindgen(js_name = createChat)]
    pub fn create_chat(&self, usernames_json: String) -> Promise {
        op!(self, |s| {
            let names: Vec<String> = parse(&usernames_json)?;
            Ok(JsValue::from(s.create_chat(&names).await.map_err(js_error)?))
        })
    }

    #[wasm_bindgen(js_name = addMembers)]
    pub fn add_members(&self, chat_id: String, usernames_json: String) -> Promise {
        op!(self, |s| {
            let names: Vec<String> = parse(&usernames_json)?;
            s.add_members(&chat_id, &names).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    #[wasm_bindgen(js_name = removeMembers)]
    pub fn remove_members(&self, chat_id: String, usernames_json: String) -> Promise {
        op!(self, |s| {
            let names: Vec<String> = parse(&usernames_json)?;
            s.remove_members(&chat_id, &names).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Removes devices by id (JSON list), e.g. one that isn't really yours.
    #[wasm_bindgen(js_name = removeDevices)]
    pub fn remove_devices(&self, chat_id: String, device_ids_json: String) -> Promise {
        op!(self, |s| {
            let ids: Vec<String> = parse(&device_ids_json)?;
            s.remove_devices(&chat_id, &ids).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    #[wasm_bindgen(js_name = rotateKeys)]
    pub fn rotate_keys(&self, chat_id: String) -> Promise {
        op!(self, |s| {
            s.rotate_keys(&chat_id).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    #[wasm_bindgen(js_name = forgetChat)]
    pub fn forget_chat(&self, chat_id: String) -> Promise {
        op!(self, |s| {
            s.forget_chat(&chat_id).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Resolves to the sent message, as JSON.
    #[wasm_bindgen(js_name = sendText)]
    pub fn send_text(&self, chat_id: String, text: String) -> Promise {
        op!(self, |s| json(&s.send_text(&chat_id, &text).await.map_err(js_error)?))
    }

    /// `info_json`: `{mime, width?, height?, thumbnail?, caption?}`.
    /// Resolves to the sent message, as JSON.
    #[wasm_bindgen(js_name = sendImage)]
    pub fn send_image(&self, chat_id: String, bytes: Vec<u8>, info_json: String) -> Promise {
        op!(self, |s| {
            let info: ImageInfo = parse(&info_json)?;
            json(&s.send_image(&chat_id, &bytes, info).await.map_err(js_error)?)
        })
    }

    /// Downloads and decrypts a photo, given a message's `attachment` JSON.
    #[wasm_bindgen(js_name = fetchAttachment)]
    pub fn fetch_attachment(&self, attachment_json: String) -> Promise {
        op!(self, |s| {
            let attachment: Attachment = parse(&attachment_json)?;
            let bytes = s.fetch_attachment(&attachment).await.map_err(js_error)?;
            Ok(Uint8Array::from(bytes.as_slice()).into())
        })
    }

    /// Marks a chat read (and tells the senders, if read receipts are on).
    #[wasm_bindgen(js_name = markRead)]
    pub fn mark_read(&self, chat_id: String) -> Promise {
        op!(self, |s| {
            s.mark_read(&chat_id).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    #[wasm_bindgen(js_name = setDisplayName)]
    pub fn set_display_name(&self, name: String) -> Promise {
        op!(self, |s| {
            s.set_display_name(&name).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    #[wasm_bindgen(js_name = setReadReceipts)]
    pub fn set_read_receipts(&self, on: bool) -> Promise {
        op!(self, |s| {
            s.set_read_receipts(on).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// After scanning a friend's QR code. Resolves to `"verified"` or
    /// `"mismatch"`.
    #[wasm_bindgen(js_name = verifyCode)]
    pub fn verify_code(&self, code: String) -> Promise {
        op!(self, |s| {
            let outcome = s.verify_code(&code).await.map_err(js_error)?;
            Ok(JsValue::from(match outcome {
                VerifyOutcome::Verified => "verified",
                VerifyOutcome::Mismatch => "mismatch",
            }))
        })
    }

    #[wasm_bindgen(js_name = resetVerification)]
    pub fn reset_verification(&self, username: String) -> Promise {
        op!(self, |s| {
            s.reset_verification(&username).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Fetches and processes everything waiting. Resolves to the events, as
    /// JSON.
    pub fn sync(&self) -> Promise {
        op!(self, |s| json(&s.sync().await.map_err(js_error)?))
    }

    /// Where to open the live WebSocket.
    #[wasm_bindgen(js_name = streamUrl)]
    pub fn stream_url(&self) -> Promise {
        op!(self, |s| Ok(JsValue::from(s.stream_url())))
    }

    /// The first frame to send on the WebSocket.
    #[wasm_bindgen(js_name = streamHello)]
    pub fn stream_hello(&self) -> Promise {
        op!(self, |s| Ok(JsValue::from(s.stream_hello())))
    }

    /// A frame announcing that we're typing in a chat.
    #[wasm_bindgen(js_name = typingFrame)]
    pub fn typing_frame(&self, chat_id: String) -> Promise {
        op!(self, |s| Ok(JsValue::from(s.typing_frame(&chat_id).map_err(js_error)?)))
    }

    /// What a WebSocket frame means, as JSON: `{type: "ready" | "mail" |
    /// "typing" | "error" | "ignored", ...}`.
    #[wasm_bindgen(js_name = readStreamFrame)]
    pub fn read_stream_frame(&self, text: String) -> Promise {
        op!(self, |s| json(&s.read_stream_frame(&text)))
    }

    /// The relay's public key for `PushManager.subscribe`.
    #[wasm_bindgen(js_name = pushKey)]
    pub fn push_key(&self) -> Promise {
        op!(self, |s| Ok(JsValue::from(s.push_key().await.map_err(js_error)?)))
    }

    /// Registers a push subscription (`JSON.stringify(subscription)`).
    #[wasm_bindgen(js_name = setPush)]
    pub fn set_push(&self, subscription_json: String) -> Promise {
        op!(self, |s| {
            let sub: PushSubscription = parse(&subscription_json)?;
            s.set_push(&sub).await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }

    #[wasm_bindgen(js_name = clearPush)]
    pub fn clear_push(&self) -> Promise {
        op!(self, |s| {
            s.clear_push().await.map_err(js_error)?;
            Ok(JsValue::UNDEFINED)
        })
    }
}
