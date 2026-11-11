//! Web push, the way the design calls for it: content-free.
//!
//! The relay sends an **empty** push to wake the app ("you have mail"); the
//! phone then fetches the ciphertext over HTTPS and decrypts it itself. Apple
//! never sees message content, only that a push happened. Empty pushes need
//! no payload encryption, just a VAPID signature (RFC 8292) identifying this
//! relay to the push service.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::RngCore;
use reqwest::Url;

/// At most one wake-up per device in this window. One push is enough: the
/// app fetches everything waiting when it opens.
pub const PUSH_DEBOUNCE: Duration = Duration::from_secs(15);

/// Push services the relay is willing to call. Subscriptions pointing
/// anywhere else are refused, so a client can't make the relay send requests
/// into your own network.
pub const DEFAULT_PUSH_HOSTS: &[&str] = &[
    ".push.apple.com",
    "fcm.googleapis.com",
    "updates.push.services.mozilla.com",
    ".notify.windows.com",
];

pub struct Push {
    key: SigningKey,
    public_key: String,
    subject: String,
    allowed_hosts: Vec<String>,
    http: reqwest::Client,
    last_sent: Mutex<HashMap<String, Instant>>,
}

pub enum PushOutcome {
    Sent,
    /// The subscription is dead (404/410): forget it.
    Gone,
    Failed(String),
}

impl Push {
    pub fn new(private_key: &[u8; 32], subject: String, allowed_hosts: Vec<String>) -> anyhow::Result<Self> {
        let key = SigningKey::from_bytes(&(*private_key).into())?;
        let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().to_encoded_point(false).as_bytes());
        Ok(Push {
            key,
            public_key,
            subject,
            allowed_hosts,
            http: reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?,
            last_sent: Mutex::new(HashMap::new()),
        })
    }

    /// A fresh P-256 private key.
    pub fn generate_private_key() -> [u8; 32] {
        loop {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            if SigningKey::from_bytes(&bytes.into()).is_ok() {
                return bytes;
            }
        }
    }

    /// For `PushManager.subscribe({ applicationServerKey })`.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn endpoint_allowed(&self, endpoint: &str) -> bool {
        let Ok(url) = Url::parse(endpoint) else {
            return false;
        };
        if url.scheme() != "https" {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        self.allowed_hosts.iter().any(|allowed| {
            if let Some(suffix) = allowed.strip_prefix('.') {
                host.ends_with(&format!(".{suffix}"))
            } else {
                host == allowed
            }
        })
    }

    /// True if this device hasn't been pushed within [`PUSH_DEBOUNCE`], and
    /// records the push.
    pub fn should_send(&self, device_id: &str) -> bool {
        let mut last = self.last_sent.lock().expect("push lock poisoned");
        let now = Instant::now();
        match last.get(device_id) {
            Some(t) if now.duration_since(*t) < PUSH_DEBOUNCE => false,
            _ => {
                last.insert(device_id.to_owned(), now);
                true
            }
        }
    }

    /// The VAPID JWT for one push service origin (RFC 8292).
    pub fn vapid_jwt(&self, audience: &str, now_unix: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "aud": audience,
                "exp": now_unix + 12 * 3600,
                "sub": self.subject,
            })
            .to_string(),
        );
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = self.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    /// Sends one empty wake-up push.
    pub async fn send(&self, endpoint: &str, now_unix: i64) -> PushOutcome {
        if !self.endpoint_allowed(endpoint) {
            return PushOutcome::Gone;
        }
        let Ok(url) = Url::parse(endpoint) else {
            return PushOutcome::Gone;
        };
        let audience = url.origin().ascii_serialization();
        let auth = format!("vapid t={}, k={}", self.vapid_jwt(&audience, now_unix), self.public_key);
        let res = self
            .http
            .post(url)
            .header("TTL", "86400")
            .header("Urgency", "high")
            .header("Authorization", auth)
            .header("Content-Length", "0")
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => PushOutcome::Sent,
            Ok(r) if r.status().as_u16() == 404 || r.status().as_u16() == 410 => PushOutcome::Gone,
            Ok(r) => PushOutcome::Failed(format!("push service answered {}", r.status())),
            Err(e) => PushOutcome::Failed(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    fn push() -> Push {
        Push::new(
            &Push::generate_private_key(),
            "mailto:admin@example.com".into(),
            DEFAULT_PUSH_HOSTS.iter().map(|s| s.to_string()).collect(),
        )
        .unwrap()
    }

    #[test]
    fn only_https_endpoints_at_known_push_services_are_allowed() {
        let p = push();
        assert!(p.endpoint_allowed("https://web.push.apple.com/QGuQyavXutnMH..."));
        assert!(p.endpoint_allowed("https://fcm.googleapis.com/fcm/send/abc"));
        assert!(!p.endpoint_allowed("http://web.push.apple.com/abc"), "plain http");
        assert!(!p.endpoint_allowed("https://evil.example.com/abc"));
        assert!(!p.endpoint_allowed("https://push.apple.com.evil.com/abc"));
        assert!(!p.endpoint_allowed("https://10.0.0.5/admin"));
        assert!(!p.endpoint_allowed("not a url"));
    }

    #[test]
    fn vapid_jwt_is_a_valid_es256_token() {
        let p = push();
        let jwt = p.vapid_jwt("https://web.push.apple.com", 1_000_000);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://web.push.apple.com");
        assert_eq!(claims["exp"], 1_000_000 + 12 * 3600);
        assert_eq!(claims["sub"], "mailto:admin@example.com");

        let public = URL_SAFE_NO_PAD.decode(p.public_key()).unwrap();
        assert_eq!(public.len(), 65, "uncompressed P-256 point");
        let vk = VerifyingKey::from_sec1_bytes(&public).unwrap();
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).unwrap();
    }

    #[test]
    fn pushes_to_one_device_are_debounced() {
        let p = push();
        assert!(p.should_send("d1"));
        assert!(!p.should_send("d1"));
        assert!(p.should_send("d2"));
    }
}
