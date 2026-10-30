//! Credentials, session tokens and the numeric-comparison pairing handshake (mutual
//! commit-then-reveal over X25519). A line-for-line port of the Python state machine; the
//! primitives are x25519-dalek, hkdf, hmac, sha2 and aes-gcm, all standard and maintained.
//! Nothing here invents cryptography. All state is in memory: a restart means re-pairing.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

pub const PAIRING_WINDOW_SECONDS: u64 = 180;
pub const SESSION_TOKEN_TTL_SECONDS: u64 = 3600;

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// H(nonce || pubkey), SHA-256.
pub fn commitment(nonce: &[u8], pubkey: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(nonce);
    h.update(pubkey);
    h.finalize().into()
}

/// (session_key, four_digit_code). Salt = phone_nonce || companion_nonce; info labels and the
/// companion_pub || phone_pub context are byte-identical to companion_server.py.
pub fn derive_pairing_material(
    shared: &[u8],
    phone_nonce: &[u8],
    companion_nonce: &[u8],
    companion_pub: &[u8],
    phone_pub: &[u8],
) -> ([u8; 32], String) {
    let mut context = companion_pub.to_vec();
    context.extend_from_slice(phone_pub);
    let mut salt = phone_nonce.to_vec();
    salt.extend_from_slice(companion_nonce);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    let mut info = b"arrowbridge-pairing-session-key|".to_vec();
    info.extend_from_slice(&context);
    hk.expand(&info, &mut key).expect("32 bytes is a valid length");
    let mut code_material = [0u8; 32];
    let mut info = b"arrowbridge-pairing-code|".to_vec();
    info.extend_from_slice(&context);
    hk.expand(&info, &mut code_material).expect("32 bytes is a valid length");
    let n = u32::from_be_bytes([code_material[0], code_material[1], code_material[2], code_material[3]]);
    (key, format!("{:04}", n % 10000))
}

pub fn proof_hex(session_key: &[u8], handshake_id: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key).expect("hmac takes any key length");
    mac.update(handshake_id.as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("os randomness");
    b
}

#[derive(Debug, PartialEq, Eq)]
pub enum PairError {
    BadRequest(String),
    Conflict,
    NotFound,
}

struct Handshake {
    id: String,
    phone_pub: Vec<u8>,
    phone_commitment: Vec<u8>,
    companion_pub: [u8; 32],
    companion_nonce: [u8; 16],
    shared_secret: [u8; 32],
    session_key: Option<[u8; 32]>,
    code: Option<String>,
    revealed: bool,
    machine_confirmed: bool,
    finished: bool,
    failed: bool,
}

struct Window {
    open: bool,
    expires_at: Option<Instant>,
    hs: Option<Handshake>,
}

pub struct Pairing {
    window: Mutex<Window>,
    window_len: Duration,
    sessions: Mutex<HashMap<String, Instant>>,
    credentials: Mutex<Vec<String>>,
    pair_key: String,
}

fn field_str<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(Value::as_str)
}

fn b64_strict(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

impl Pairing {
    pub fn new(pair_key: String) -> Pairing {
        Pairing::with_window(pair_key, Duration::from_secs(PAIRING_WINDOW_SECONDS))
    }

    pub fn with_window(pair_key: String, window_len: Duration) -> Pairing {
        Pairing {
            window: Mutex::new(Window { open: false, expires_at: None, hs: None }),
            window_len,
            sessions: Mutex::new(HashMap::new()),
            credentials: Mutex::new(Vec::new()),
            pair_key,
        }
    }

    // ---------------------------------------------------------------- credentials
    pub fn raw_key_ok(&self, presented: &str) -> bool {
        !presented.is_empty() && ct_eq(presented.as_bytes(), self.pair_key.as_bytes())
    }

    /// Any of the three credential kinds: the raw key, a live session token, a phone credential.
    pub fn credential_ok(&self, presented: &str) -> bool {
        if presented.is_empty() {
            return false;
        }
        if self.raw_key_ok(presented) {
            return true;
        }
        if self.session_token_valid(presented) {
            return true;
        }
        let creds = self.credentials.lock().unwrap();
        let mut hit = false;
        for c in creds.iter() {
            hit |= ct_eq(c.as_bytes(), presented.as_bytes());
        }
        hit
    }

    pub fn mint_session_token(&self) -> String {
        let token = crate::config::token_urlsafe(32);
        self.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), Instant::now() + Duration::from_secs(SESSION_TOKEN_TTL_SECONDS));
        token
    }

    fn session_token_valid(&self, presented: &str) -> bool {
        let mut map = self.sessions.lock().unwrap();
        let now = Instant::now();
        let mut found = None;
        for (tok, exp) in map.iter() {
            if ct_eq(tok.as_bytes(), presented.as_bytes()) {
                found = Some((tok.clone(), *exp));
            }
        }
        match found {
            None => false,
            Some((tok, exp)) if exp < now => {
                map.remove(&tok);
                false
            }
            Some(_) => true,
        }
    }

    // ---------------------------------------------------------------- the window
    fn expire_locked(w: &mut Window) {
        if w.open && w.expires_at.is_none_or(|t| Instant::now() >= t) {
            w.open = false;
            w.expires_at = None;
            w.hs = None;
        }
    }

    pub fn window_is_open(&self) -> bool {
        let mut w = self.window.lock().unwrap();
        Self::expire_locked(&mut w);
        w.open
    }

    pub fn open_window(&self) -> u64 {
        let mut w = self.window.lock().unwrap();
        w.open = true;
        w.expires_at = Some(Instant::now() + self.window_len);
        w.hs = None;
        crate::log::event("pairing_window_opened");
        self.window_len.as_secs()
    }

    fn close_locked(w: &mut Window) {
        w.open = false;
        w.expires_at = None;
        w.hs = None;
    }

    pub fn close_window(&self) {
        Self::close_locked(&mut self.window.lock().unwrap());
    }

    pub fn cancel(&self) {
        self.close_window();
        crate::log::event("pairing_window_cancelled");
    }

    // ---------------------------------------------------------------- status (machine side)
    pub fn status(&self) -> Value {
        let w = self.window.lock().unwrap();
        match &w.hs {
            None => json!({"open": true, "handshake_id": null, "code": null, "revealed": false,
                           "machine_confirmed": false, "phone_confirmed": false}),
            Some(h) => json!({"open": true, "handshake_id": h.id, "code": h.code, "revealed": h.revealed,
                              "machine_confirmed": h.machine_confirmed, "phone_confirmed": h.finished}),
        }
    }

    // ---------------------------------------------------------------- round one
    pub fn start(&self, body: &Value) -> Result<Value, PairError> {
        let bad = || PairError::BadRequest("expected a JSON body with base64 \"public_key\" and \"commitment\"".into());
        let phone_pub = field_str(body, "public_key").and_then(b64_strict).ok_or_else(bad)?;
        let phone_commitment = field_str(body, "commitment").and_then(b64_strict).ok_or_else(bad)?;
        if phone_commitment.len() != 32 {
            return Err(PairError::BadRequest("commitment must be a 32-byte SHA-256 digest".into()));
        }
        let phone_pub_arr: [u8; 32] = phone_pub
            .as_slice()
            .try_into()
            .map_err(|_| PairError::BadRequest("invalid X25519 public key".into()))?;
        let mut w = self.window.lock().unwrap();
        if let Some(h) = &w.hs {
            if !h.finished && !h.failed {
                return Err(PairError::Conflict);
            }
        }
        let secret = StaticSecret::from(random::<32>());
        let companion_pub = PublicKey::from(&secret).to_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(phone_pub_arr));
        if !shared.was_contributory() {
            // A low-order point gives an all-zero secret. The Python let this raise (a 500).
            return Err(PairError::BadRequest("invalid X25519 public key".into()));
        }
        let companion_nonce = random::<16>();
        let companion_commitment = commitment(&companion_nonce, &companion_pub);
        let id = crate::config::token_urlsafe(16);
        w.hs = Some(Handshake {
            id: id.clone(),
            phone_pub,
            phone_commitment,
            companion_pub,
            companion_nonce,
            shared_secret: shared.to_bytes(),
            session_key: None,
            code: None,
            revealed: false,
            machine_confirmed: false,
            finished: false,
            failed: false,
        });
        crate::log::event("pairing_started");
        Ok(json!({"handshake_id": id, "public_key": B64.encode(companion_pub),
                  "commitment": B64.encode(companion_commitment)}))
    }

    // ---------------------------------------------------------------- round two
    pub fn reveal(&self, body: &Value) -> Result<Value, PairError> {
        let bad = || PairError::BadRequest("expected a JSON body with \"handshake_id\" and a base64 \"nonce\"".into());
        let id = field_str(body, "handshake_id").ok_or_else(bad)?;
        let phone_nonce = field_str(body, "nonce").and_then(b64_strict).ok_or_else(bad)?;
        let mut w = self.window.lock().unwrap();
        let ok = matches!(&w.hs, Some(h) if h.id == id && !h.finished && !h.failed && !h.revealed);
        if !ok {
            return Err(PairError::NotFound);
        }
        let h = w.hs.as_mut().expect("checked");
        let expected = commitment(&phone_nonce, &h.phone_pub);
        if !ct_eq(&expected, &h.phone_commitment) {
            h.failed = true;
            Self::close_locked(&mut w);
            crate::log::event("pairing_reveal_refused");
            return Err(PairError::NotFound);
        }
        let (key, code) =
            derive_pairing_material(&h.shared_secret, &phone_nonce, &h.companion_nonce, &h.companion_pub, &h.phone_pub);
        h.session_key = Some(key);
        h.code = Some(code);
        h.revealed = true;
        crate::log::event("pairing_revealed");
        Ok(json!({"companion_nonce": B64.encode(h.companion_nonce)}))
    }

    /// The owner, at the machine, confirming the four digits match.
    pub fn confirm(&self, body: &Value) -> Result<Value, PairError> {
        let id = field_str(body, "handshake_id")
            .ok_or_else(|| PairError::BadRequest("expected a JSON body with \"handshake_id\"".into()))?;
        let mut w = self.window.lock().unwrap();
        match w.hs.as_mut() {
            Some(h) if h.id == id && !h.finished && !h.failed && h.revealed => {
                h.machine_confirmed = true;
                crate::log::event("pairing_confirmed_at_machine");
                Ok(json!({"machine_confirmed": true}))
            }
            _ => Err(PairError::NotFound),
        }
    }

    pub fn finish(&self, body: &Value) -> Result<Value, PairError> {
        let (id, proof) = match (field_str(body, "handshake_id"), field_str(body, "proof")) {
            (Some(i), Some(p)) => (i, p),
            _ => return Err(PairError::BadRequest("expected a JSON body with \"handshake_id\" and \"proof\"".into())),
        };
        let session_key;
        {
            let mut w = self.window.lock().unwrap();
            let usable = matches!(&w.hs, Some(h) if h.id == id && !h.finished && !h.failed && h.revealed);
            if !usable {
                // Same as the Python: any unusable finish closes the window.
                Self::close_locked(&mut w);
                return Err(PairError::NotFound);
            }
            let h = w.hs.as_mut().expect("checked");
            let key = h.session_key.expect("revealed implies a key");
            let expected = proof_hex(&key, id);
            let proof_ok = ct_eq(proof.as_bytes(), expected.as_bytes());
            if !h.machine_confirmed || !proof_ok {
                h.failed = true;
                Self::close_locked(&mut w);
                crate::log::event("pairing_finish_refused");
                return Err(PairError::NotFound);
            }
            h.finished = true;
            session_key = key;
        }
        let credential = format!("pc_{}", crate::config::token_urlsafe(32));
        self.credentials.lock().unwrap().push(credential.clone());
        let cipher = Aes256Gcm::new_from_slice(&session_key).expect("32-byte key");
        let nonce_bytes = random::<12>();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: credential.as_bytes(), aad: id.as_bytes() })
            .expect("aes-gcm encrypt");
        self.close_window();
        crate::log::STATS.pairings.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        crate::log::event("pairing_finished");
        Ok(json!({"credential_nonce": B64.encode(nonce_bytes), "credential_ciphertext": B64.encode(ct)}))
    }
}
