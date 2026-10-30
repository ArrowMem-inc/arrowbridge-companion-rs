//! Replays what the Python companion actually did, recorded by tests/fixtures generation
//! (the Python server was run against a fake model server and every response captured).

mod common;
use arrowbridge_companion::guard;
use arrowbridge_companion::pairing::{commitment, derive_pairing_material, proof_hex};
use common::*;
use serde_json::{Value, json};

fn rust_server() -> (std::net::SocketAddr, FakeUpstream, arrowbridge_companion::server::RunningServer) {
    let fx = fixture("routes.json");
    let pair_value = fx["key"].as_str().unwrap().to_string();
    let prompt = std::env::temp_dir().join(format!("ab_prompt_{}.txt", std::process::id()));
    std::fs::write(&prompt, fx["system_prompt"].as_str().unwrap()).unwrap();
    let up = fake_upstream();
    let url = format!("http://127.0.0.1:{}", up.port);
    let map = format!("alpha=m-alpha,beta=m-beta@{url}");
    let cfg = config(&[
        ("ARROWBRIDGE_PAIR_KEY", &pair_value),
        ("ARROWBRIDGE_UPSTREAM_URL", &url),
        ("ARROWBRIDGE_UPSTREAM_MODEL", "m-default"),
        ("ARROWBRIDGE_MODEL_MAP", &map),
        ("ARROWBRIDGE_SYSTEM_PROMPT_FILE", prompt.to_str().unwrap()),
        ("ARROWBRIDGE_DEVICE_NAME", "fixture-box"),
    ]);
    let (_shared, running) = start_server(cfg);
    (running.addr, up, running)
}

/// Parse an SSE body into (event, data-json) pairs.
fn sse_events(body: &str) -> Vec<(String, Value)> {
    body.split("\n\n")
        .filter(|b| !b.is_empty())
        .map(|b| {
            let mut lines = b.lines();
            let ev = lines.next().unwrap().strip_prefix("event: ").unwrap().to_string();
            let data = lines.next().unwrap().strip_prefix("data: ").unwrap();
            (ev, serde_json::from_str(data).unwrap())
        })
        .collect()
}

#[test]
fn every_recorded_route_matches_the_python() {
    let fx = fixture("routes.json");
    let (addr, up, running) = rust_server();
    let mut checked = 0;
    for case in fx["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        up.seen.lock().unwrap().clear();
        let method = case["method"].as_str().unwrap();
        let path = case["path"].as_str().unwrap();
        let headers: Vec<(String, String)> = case["headers"]
            .as_object()
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect())
            .unwrap_or_default();
        let hdr: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let (status, ct, body) = match name {
            "bad_content_length" => raw(addr, b"POST /chat HTTP/1.0\r\nContent-Length: abc\r\n\r\n"),
            "oversized_content_length" => raw(
                addr,
                format!("POST /chat HTTP/1.0\r\nContent-Length: {}\r\n\r\n", (1 << 20) + 1).as_bytes(),
            ),
            _ => {
                let body: Option<Vec<u8>> = if let Some(r) = case.get("raw").and_then(Value::as_str) {
                    Some(r.as_bytes().to_vec())
                } else if !case["body"].is_null() {
                    Some(case["body"].to_string().into_bytes())
                } else {
                    None
                };
                request(addr, method, path, &hdr, body.as_deref())
            }
        };
        assert_eq!(status as u64, case["status"].as_u64().unwrap(), "{name}: status");

        if let Some(text) = case.get("text").and_then(Value::as_str) {
            let got = String::from_utf8(body).unwrap();
            if name == "msg_stream" {
                assert!(ct.starts_with("text/event-stream"), "{name}: content type {ct}");
                assert_eq!(sse_events(&got), sse_events(text), "{name}: SSE events");
            } else {
                assert_eq!(got, text, "{name}: body");
            }
        } else {
            let mut want = case["json"].clone();
            let mut have: Value = serde_json::from_slice(&body).unwrap_or_else(|_| panic!("{name}: not json"));
            match name {
                "pair_session_ok_shape" => {
                    assert_eq!(have["token"].as_str().unwrap().len(), want["token"].as_str().unwrap().len());
                    have["token"] = json!("T");
                    want["token"] = json!("T");
                }
                "health" | "health_bearer" => {
                    assert_eq!(have["upstream"], format!("http://127.0.0.1:{}", up.port));
                    have["upstream"] = json!("U");
                    want["upstream"] = json!("U");
                }
                "pair_info_loopback" => {
                    assert_eq!(have["addresses"].as_array().unwrap().len(), want["addresses"].as_array().unwrap().len());
                    have["addresses"] = json!([]);
                    want["addresses"] = json!([]);
                }
                _ => {}
            }
            assert_eq!(have, want, "{name}: json body");
        }
        let want_ct = case["content_type"].as_str().unwrap_or("application/json");
        assert_eq!(ct.split(';').next().unwrap(), want_ct.split(';').next().unwrap(), "{name}: content type");

        // What the model server was sent must be identical too (model, messages, system, ...).
        let want_seen = case["upstream_seen"].as_array().cloned().unwrap_or_default();
        let have_seen = up.seen.lock().unwrap().clone();
        assert_eq!(have_seen.len(), want_seen.len(), "{name}: upstream call count");
        for (h, w) in have_seen.iter().zip(want_seen.iter()) {
            assert_eq!(h.path, w["path"].as_str().unwrap(), "{name}: upstream path");
            assert_eq!(h.body, w["body"], "{name}: upstream body");
            assert_eq!(h.auth.as_deref(), w["auth"].as_str(), "{name}: upstream auth header");
        }
        checked += 1;
    }
    running.shutdown();
    assert!(checked >= 28, "replayed {checked}");
}

#[test]
fn telephone_guard_matches_the_python_on_the_recorded_corpus() {
    let fx = fixture("telguard.json");
    let cases = fx.as_array().unwrap();
    for c in cases {
        let (out, off) = guard::redact(c["in"].as_str().unwrap());
        assert_eq!(out, c["out"].as_str().unwrap(), "input {:?}", c["in"]);
        let want: Vec<&str> = c["offenders"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(off.iter().map(String::as_str).collect::<Vec<_>>(), want, "offenders for {:?}", c["in"]);
    }
    assert!(cases.len() >= 20);
}

#[test]
fn sse_body_matches_the_python_builder() {
    use arrowbridge_companion::server::build_sse_body;
    let fx = fixture("sse.json");
    for c in fx.as_array().unwrap() {
        let usage = if c["usage"].is_null() { None } else { Some(&c["usage"]) };
        let got = build_sse_body(c["text"].as_str().unwrap(), c["stop_reason"].as_str().unwrap(), usage, c["model"].as_str(), "m-default");
        assert_eq!(sse_events(&got), sse_events(c["body"].as_str().unwrap()), "{c}");
    }
}

#[test]
fn pairing_math_matches_the_python_byte_for_byte() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};
    let fx = fixture("pairing.json");
    let h = &fx["handshake"];
    let g = |k: &str| hex(h[k].as_str().unwrap());

    // The recorded exchange: the Rust phone-side math reaches the Python's shared secret,
    // commitments, session key, code and proof, and opens the credential the Python sealed.
    let sk = StaticSecret::from(<[u8; 32]>::try_from(g("phone_priv")).unwrap());
    assert_eq!(PublicKey::from(&sk).to_bytes().to_vec(), g("phone_pub"));
    let comp_pub = PublicKey::from(<[u8; 32]>::try_from(g("companion_pub")).unwrap());
    assert_eq!(sk.diffie_hellman(&comp_pub).to_bytes().to_vec(), g("shared_secret"));
    assert_eq!(commitment(&g("phone_nonce"), &g("phone_pub")).to_vec(), g("phone_commitment"));
    assert_eq!(commitment(&g("companion_nonce"), &g("companion_pub")).to_vec(), g("companion_commitment"));
    let (key, code) = derive_pairing_material(&g("shared_secret"), &g("phone_nonce"), &g("companion_nonce"), &g("companion_pub"), &g("phone_pub"));
    assert_eq!(key.to_vec(), g("session_key"));
    assert_eq!(code, h["code"].as_str().unwrap());
    let id = h["handshake_id"].as_str().unwrap();
    assert_eq!(proof_hex(&key, id), h["proof"].as_str().unwrap());
    let b64 = base64::engine::general_purpose::STANDARD;
    let nonce = b64.decode(h["credential_nonce"].as_str().unwrap()).unwrap();
    let ct = b64.decode(h["credential_ciphertext"].as_str().unwrap()).unwrap();
    let pt = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad: id.as_bytes() })
        .unwrap();
    assert_eq!(String::from_utf8(pt).unwrap(), h["credential"].as_str().unwrap());

    // Twenty random derivations.
    let vectors = fx["vectors"].as_array().unwrap();
    for v in vectors {
        let g = |k: &str| hex(v[k].as_str().unwrap());
        let (k, c) = derive_pairing_material(&g("shared"), &g("phone_nonce"), &g("comp_nonce"), &g("comp_pub"), &g("phone_pub"));
        assert_eq!(k.to_vec(), g("key"));
        assert_eq!(c, v["code"].as_str().unwrap());
    }
    assert_eq!(vectors.len(), 20);
}
