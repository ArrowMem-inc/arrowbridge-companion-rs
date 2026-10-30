//! The numeric-comparison handshake, driven over real HTTP by a Rust phone. The phone side is
//! ported from the Python test driver (test_pairing_handshake.py).

mod common;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use arrowbridge_companion::pairing::{Pairing, commitment, derive_pairing_material, proof_hex};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use common::*;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

const KEY_HEADER: &str = "X-ArrowBridge-Pair";

fn boot() -> (SocketAddr, String, arrowbridge_companion::server::RunningServer) {
    let cfg = config(&[("ARROWBRIDGE_PAIR_KEY", "handshake-test-key-0123456789")]);
    let (_s, r) = start_server(cfg);
    (r.addr, "handshake-test-key-0123456789".to_string(), r)
}

struct Phone {
    sk: StaticSecret,
    pubk: [u8; 32],
    nonce: [u8; 16],
}

fn phone() -> Phone {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let sk = StaticSecret::from(seed);
    let pubk = PublicKey::from(&sk).to_bytes();
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    Phone { sk, pubk, nonce }
}

struct Session {
    id: String,
    key: [u8; 32],
    code: String,
}

/// Rounds one and two. Verifies the companion's commitment on the phone side, as the protocol
/// requires of every client.
fn run_to_code(addr: SocketAddr, p: &Phone) -> Session {
    let (st, _) = post_json(addr, "/pair-open", &[], &json!({}));
    assert_eq!(st, 200);
    let (st, s) = post_json(
        addr,
        "/pair-start",
        &[],
        &json!({"public_key": B64.encode(p.pubk), "commitment": B64.encode(commitment(&p.nonce, &p.pubk))}),
    );
    assert_eq!(st, 200, "{s}");
    let id = s["handshake_id"].as_str().unwrap().to_string();
    let cpub = B64.decode(s["public_key"].as_str().unwrap()).unwrap();
    let ccom = B64.decode(s["commitment"].as_str().unwrap()).unwrap();
    let (st, r) = post_json(addr, "/pair-reveal", &[], &json!({"handshake_id": id, "nonce": B64.encode(p.nonce)}));
    assert_eq!(st, 200, "{r}");
    let cnonce = B64.decode(r["companion_nonce"].as_str().unwrap()).unwrap();
    assert_eq!(commitment(&cnonce, &cpub).to_vec(), ccom, "phone-side check of the companion reveal");
    let shared = p.sk.diffie_hellman(&PublicKey::from(<[u8; 32]>::try_from(cpub.clone()).unwrap())).to_bytes();
    let (key, code) = derive_pairing_material(&shared, &p.nonce, &cnonce, &cpub, &p.pubk);
    Session { id, key, code }
}

#[test]
fn full_handshake_yields_a_credential_that_then_authenticates() {
    let (addr, _k, running) = boot();
    let p = phone();
    let s = run_to_code(addr, &p);

    // The owner reads the same four digits at the machine.
    let (st, status) = get_json(addr, "/pair-status", &[]);
    assert_eq!(st, 200);
    assert_eq!(status["code"].as_str().unwrap(), s.code);
    assert_eq!(status["machine_confirmed"], false);

    let (st, _) = post_json(addr, "/pair-confirm", &[], &json!({"handshake_id": s.id}));
    assert_eq!(st, 200);
    let (st, fin) = post_json(addr, "/pair-finish", &[], &json!({"handshake_id": s.id, "proof": proof_hex(&s.key, &s.id)}));
    assert_eq!(st, 200, "{fin}");
    let nonce = B64.decode(fin["credential_nonce"].as_str().unwrap()).unwrap();
    let ct = B64.decode(fin["credential_ciphertext"].as_str().unwrap()).unwrap();
    let cred = Aes256Gcm::new_from_slice(&s.key)
        .unwrap()
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: s.id.as_bytes() })
        .unwrap();
    let cred = String::from_utf8(cred).unwrap();
    assert!(cred.starts_with("pc_"));

    // The per-phone credential now works on a gated route, in both header forms.
    let (st, _) = get_json(addr, "/health", &[(KEY_HEADER, cred.as_str())]);
    assert_eq!(st, 200);
    let bearer = format!("{} {}", ["Bea", "rer"].concat(), cred);
    let (st, _) = get_json(addr, "/health", &[("Authorization", bearer.as_str())]);
    assert_eq!(st, 200);
    // A wrong one does not, and the window is closed again.
    let (st, _) = get_json(addr, "/health", &[(KEY_HEADER, "pc_wrong")]);
    assert_eq!(st, 404);
    let (st, _) = post_json(addr, "/pair-start", &[], &json!({}));
    assert_eq!(st, 404);
    running.shutdown();
}

#[test]
fn finish_without_machine_confirmation_issues_nothing_and_closes_the_window() {
    let (addr, _k, running) = boot();
    let p = phone();
    let s = run_to_code(addr, &p);
    let (st, _) = post_json(addr, "/pair-finish", &[], &json!({"handshake_id": s.id, "proof": proof_hex(&s.key, &s.id)}));
    assert_eq!(st, 404);
    let (st, _) = get_json(addr, "/pair-status", &[]);
    assert_eq!(st, 404, "window closed after a refused finish");
    running.shutdown();
}

#[test]
fn a_wrong_proof_issues_nothing() {
    let (addr, _k, running) = boot();
    let p = phone();
    let s = run_to_code(addr, &p);
    post_json(addr, "/pair-confirm", &[], &json!({"handshake_id": s.id}));
    let (st, body) = post_json(addr, "/pair-finish", &[], &json!({"handshake_id": s.id, "proof": proof_hex(&[7u8; 32], &s.id)}));
    assert_eq!(st, 404);
    assert!(body.get("credential_ciphertext").is_none());
    running.shutdown();
}

#[test]
fn a_reveal_that_does_not_match_the_commitment_fails_the_handshake() {
    let (addr, _k, running) = boot();
    let p = phone();
    post_json(addr, "/pair-open", &[], &json!({}));
    let (_, s) = post_json(
        addr,
        "/pair-start",
        &[],
        &json!({"public_key": B64.encode(p.pubk), "commitment": B64.encode(commitment(&p.nonce, &p.pubk))}),
    );
    let id = s["handshake_id"].as_str().unwrap();
    let (st, body) = post_json(addr, "/pair-reveal", &[], &json!({"handshake_id": id, "nonce": B64.encode([9u8; 16])}));
    assert_eq!(st, 404);
    assert!(body.get("companion_nonce").is_none(), "the companion nonce must not leak on a bad reveal");
    let (st, _) = get_json(addr, "/pair-status", &[]);
    assert_eq!(st, 404);
    running.shutdown();
}

#[test]
fn companion_nonce_is_never_revealed_in_round_one() {
    let (addr, _k, running) = boot();
    let p = phone();
    post_json(addr, "/pair-open", &[], &json!({}));
    let (_, s) = post_json(
        addr,
        "/pair-start",
        &[],
        &json!({"public_key": B64.encode(p.pubk), "commitment": B64.encode(commitment(&p.nonce, &p.pubk))}),
    );
    let keys: Vec<&str> = s.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["commitment", "handshake_id", "public_key"]);
    let (_, status) = get_json(addr, "/pair-status", &[]);
    assert_eq!(status["code"], Value::Null, "no code exists before the reveal");
    running.shutdown();
}

#[test]
fn routes_are_404_with_no_window_and_a_second_start_is_409() {
    let (addr, _k, running) = boot();
    let p = phone();
    let start_body = json!({"public_key": B64.encode(p.pubk), "commitment": B64.encode(commitment(&p.nonce, &p.pubk))});
    for path in ["/pair-start", "/pair-reveal", "/pair-finish", "/pair-confirm"] {
        assert_eq!(post_json(addr, path, &[], &start_body).0, 404, "{path} with no window");
    }
    post_json(addr, "/pair-open", &[], &json!({}));
    assert_eq!(post_json(addr, "/pair-start", &[], &start_body).0, 200);
    assert_eq!(post_json(addr, "/pair-start", &[], &start_body).0, 409);
    // Garbage inputs are 400, not a crash.
    post_json(addr, "/pair-open", &[], &json!({}));
    assert_eq!(post_json(addr, "/pair-start", &[], &json!({"public_key": "!!", "commitment": "!!"})).0, 400);
    assert_eq!(
        post_json(addr, "/pair-start", &[], &json!({"public_key": B64.encode([1u8; 31]), "commitment": B64.encode([0u8; 32])})).0,
        400
    );
    assert_eq!(
        post_json(addr, "/pair-start", &[], &json!({"public_key": B64.encode([1u8; 32]), "commitment": B64.encode([0u8; 16])})).0,
        400
    );
    // A low-order point (all zero) is refused rather than yielding a known shared secret.
    assert_eq!(
        post_json(addr, "/pair-start", &[], &json!({"public_key": B64.encode([0u8; 32]), "commitment": B64.encode([0u8; 32])})).0,
        400
    );
    running.shutdown();
}

#[test]
fn the_window_expires() {
    let p = Pairing::with_window("k".into(), Duration::from_millis(60));
    assert!(!p.window_is_open());
    p.open_window();
    assert!(p.window_is_open());
    std::thread::sleep(Duration::from_millis(120));
    assert!(!p.window_is_open());
}

#[test]
fn owner_routes_refuse_a_proxy_header_and_session_tokens_cannot_mint_tokens() {
    let (addr, key, running) = boot();
    let fwd = [("X-Forwarded-For", "10.0.0.9")];
    assert_eq!(get_json(addr, "/pair-info", &fwd).0, 404);
    assert_eq!(post_json(addr, "/pair-open", &fwd, &json!({})).0, 404);
    assert_eq!(get_json(addr, "/pair-info", &[]).0, 200);

    let (st, tok) = post_json(addr, "/pair-session", &[(KEY_HEADER, key.as_str())], &json!({}));
    assert_eq!(st, 200);
    let token = tok["token"].as_str().unwrap().to_string();
    assert_eq!(get_json(addr, "/health", &[(KEY_HEADER, token.as_str())]).0, 200);
    assert_eq!(post_json(addr, "/pair-session", &[(KEY_HEADER, token.as_str())], &json!({})).0, 404);
    running.shutdown();
}
