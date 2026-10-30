//! Listener, routing and handlers. Route-for-route port of companion_server.py's Handler.

use crate::config::{Config, Target};
use crate::guard;
use crate::http::{self, ReadError, Request, Response};
use crate::log::{self, STATS, bump};
use crate::pairing::{PairError, Pairing};
use crate::upstream;
use serde_json::{Map, Value, json};
use socket2::{Domain, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

const MAX_CONNECTIONS: usize = 64;
const CONN_TIMEOUT: Duration = Duration::from_secs(60);
pub const OWNER_HEADER: &str = "X-ArrowBridge-Owner";
const STOP_REASON_DEFAULT: &str = "end_turn";

/// Bind a listening socket. `reuse` sets SO_REUSEADDR: with it, a restarted process can bind a
/// port whose previous connections are still in TIME_WAIT. Without it the bind fails with
/// EADDRINUSE for up to a minute, which is the ThreadingTCPServer defect.
pub fn bind_listener(addr: SocketAddr, reuse: bool) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::STREAM, None)?;
    sock.set_reuse_address(reuse)?;
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    Ok(sock.into())
}

pub struct Shared {
    pub cfg: Config,
    pub pairing: Pairing,
    pub listen_port: u16,
    /// Port of the loopback owner listener (0 when there is none).
    pub owner_port: AtomicU16,
    last_model: Mutex<Option<String>>,
}

impl Shared {
    pub fn new(cfg: Config, listen_port: u16) -> Shared {
        let pairing = Pairing::new(cfg.pair_key.clone());
        Shared { cfg, pairing, listen_port, owner_port: AtomicU16::new(0), last_model: Mutex::new(None) }
    }
}

/// Which listener a connection arrived on. `Owner` is the loopback-only listener that carries
/// the owner routes while the main listener is on a LAN address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Main,
    Owner,
}

pub struct RunningServer {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl RunningServer {
    /// Stop accepting and release the port. In-flight connections finish on their own threads.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let wake = if self.addr.ip().is_unspecified() { SocketAddr::new(Ipv4Addr::LOCALHOST.into(), self.addr.port()) } else { self.addr };
        let _ = TcpStream::connect_timeout(&wake, Duration::from_secs(2));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }

    pub fn wait(mut self) {
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

pub fn start(shared: Arc<Shared>, listener: TcpListener) -> RunningServer {
    start_role(shared, listener, Role::Main)
}

pub fn start_role(shared: Arc<Shared>, listener: TcpListener, role: Role) -> RunningServer {
    let addr = listener.local_addr().expect("bound listener has an address");
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let active = Arc::new(AtomicUsize::new(0));
    let join = std::thread::spawn(move || {
        for conn in listener.incoming() {
            if stop2.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = conn else { continue };
            if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                bump(&STATS.dropped_connections);
                continue;
            }
            active.fetch_add(1, Ordering::SeqCst);
            let shared = shared.clone();
            let active = active.clone();
            std::thread::spawn(move || {
                handle_connection(&shared, role, stream);
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        // listener drops here: the port is released
    });
    RunningServer { addr, stop, join: Some(join) }
}

fn handle_connection(shared: &Shared, role: Role, mut stream: TcpStream) {
    stream.set_read_timeout(Some(CONN_TIMEOUT)).ok();
    stream.set_write_timeout(Some(CONN_TIMEOUT)).ok();
    let peer = match stream.peer_addr() {
        Ok(a) => a.ip(),
        Err(_) => return,
    };
    let resp = match http::read_request(&mut stream) {
        Ok(req) => {
            bump(&STATS.requests);
            handle(shared, role, peer, &req)
        }
        Err(ReadError::Gone) => return,
        Err(ReadError::Reply(r)) => r,
    };
    let _ = http::write_response(&mut stream, &resp);
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

// ------------------------------------------------------------------ gates

fn presented_credential(req: &Request) -> String {
    let p = req.header("X-ArrowBridge-Pair").unwrap_or("").trim().to_string();
    if !p.is_empty() {
        return p;
    }
    let auth = req.header("Authorization").unwrap_or("").trim();
    if auth.len() >= 7 && auth.is_char_boundary(7) && auth[..7].eq_ignore_ascii_case(&["bea", "rer "].concat()) {
        return auth[7..].trim().to_string();
    }
    String::new()
}

/// A genuinely local caller: a loopback peer and no proxy header.
pub fn local_owner_ok(peer: IpAddr, req: &Request) -> bool {
    let loop_peer = peer == IpAddr::V4(Ipv4Addr::LOCALHOST) || peer == IpAddr::V6(Ipv6Addr::LOCALHOST);
    loop_peer && !["X-Forwarded-For", "Forwarded"].iter().any(|h| req.header(h).is_some_and(|v| !v.is_empty()))
}

fn refuse() -> Response {
    bump(&STATS.refused);
    Response::not_found()
}

// ------------------------------------------------------------------ helpers

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Only user/assistant turns with truthy content pass; a `system` turn never does.
fn clean_history(history: Option<&Value>) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(Value::Array(turns)) = history {
        for t in turns {
            if let Value::Object(o) = t {
                let role = o.get("role").and_then(Value::as_str);
                if matches!(role, Some("user") | Some("assistant")) {
                    if let Some(c) = o.get("content") {
                        if truthy(c) {
                            out.push(json!({"role": role.unwrap(), "content": c}));
                        }
                    }
                }
            }
        }
    }
    out
}

fn read_json(req: &Request) -> Result<Value, ()> {
    if req.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&req.body).map_err(|_| ())
}

fn resolve_model(shared: &Shared, requested: Option<&str>) -> (String, Target) {
    if let Some(name) = requested.filter(|n| !n.is_empty()) {
        if let Some((m, t)) = shared.cfg.model_map.get(name) {
            return (m.clone(), t.clone());
        }
        log::event("unknown_model_fallback");
    }
    (shared.cfg.upstream_model.clone(), shared.cfg.upstream.clone())
}

fn note_model_switch(shared: &Shared, model: &str) {
    let mut last = shared.last_model.lock().unwrap();
    if last.as_deref().is_some_and(|p| p != model) {
        log::event("model_switch");
    }
    *last = Some(model.to_string());
}

fn pair_err(e: PairError) -> Response {
    match e {
        PairError::BadRequest(m) => Response::error(400, &m),
        PairError::Conflict => Response::error(409, "a handshake is already in progress"),
        PairError::NotFound => Response::not_found(),
    }
}

fn pairing_address(shared: &Shared) -> String {
    if !shared.cfg.lan_exposed() {
        return String::new();
    }
    let host = match shared.cfg.bind {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    };
    format!("http://{host}:{}", shared.listen_port)
}

// ------------------------------------------------------------------ routing

/// The Host header, reduced to an IP literal (port and v6 brackets removed). A hostname is None.
fn host_ip(req: &Request) -> Option<IpAddr> {
    let h = req.header("Host")?.trim();
    if let Some(rest) = h.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        if !(tail.is_empty() || tail.starts_with(':')) {
            return None;
        }
        return addr.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    let h = match h.rsplit_once(':') {
        Some((a, port)) if !a.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => a,
        _ => h,
    };
    h.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// DNS-rebinding gate (C1): the Host must be an IP literal equal to the bound address or a
/// loopback literal. A name, a missing Host or any other address is refused.
pub fn host_allowed(shared: &Shared, req: &Request) -> bool {
    host_ip(req).is_some_and(|ip| ip.is_loopback() || ip == shared.cfg.bind)
}

fn is_owner_route(method: &str, path: &str) -> bool {
    match method {
        "GET" => matches!(path, "/pair-info" | "/pair-status" | "/pair"),
        _ => matches!(path, "/pair-open" | "/pair-confirm" | "/pair-cancel"),
    }
}

fn forbidden() -> Response {
    bump(&STATS.refused);
    Response::error(403, "forbidden")
}

pub fn handle(shared: &Shared, role: Role, peer: IpAddr, req: &Request) -> Response {
    if !host_allowed(shared, req) {
        return forbidden();
    }
    let owner_route = is_owner_route(&req.method, &req.path);
    // Owner routes live on the main listener only while it is loopback; on a LAN bind they are
    // served by the loopback owner listener alone, and that listener serves nothing else.
    match role {
        Role::Owner if !owner_route => return refuse(),
        Role::Main if owner_route && shared.cfg.lan_exposed() => return refuse(),
        _ => {}
    }
    // C2: an owner POST must carry a header a browser simple request cannot send.
    if owner_route && req.method == "POST" && req.header(OWNER_HEADER).map(str::trim) != Some("1") {
        return forbidden();
    }
    if req.method == "GET" { handle_get(shared, peer, req) } else { handle_post(shared, peer, req) }
}

fn handle_get(shared: &Shared, peer: IpAddr, req: &Request) -> Response {
    match req.path.as_str() {
        "/pair-test" => return Response::html(crate::page::PAIR_TEST_PAGE.to_string()),
        "/pair-info" => {
            if !local_owner_ok(peer, req) {
                return refuse();
            }
            let owner = shared.owner_port.load(Ordering::SeqCst);
            let local_port = if shared.cfg.lan_exposed() && owner != 0 { owner } else { shared.listen_port };
            let mut addrs = vec![format!("http://127.0.0.1:{local_port}")];
            if shared.cfg.lan_exposed() {
                addrs.push(pairing_address(shared));
            }
            return Response::json(200, &json!({"pair_key": shared.cfg.pair_key, "addresses": addrs, "tls": false}));
        }
        "/pair-status" => {
            if !local_owner_ok(peer, req) || !shared.pairing.window_is_open() {
                return refuse();
            }
            return Response::json(200, &shared.pairing.status());
        }
        "/pair" => {
            if !local_owner_ok(peer, req) {
                return refuse();
            }
            return Response::html(crate::page::pair_page(&pairing_address(shared), &shared.cfg.device_name));
        }
        _ => {}
    }
    if !shared.pairing.credential_ok(&presented_credential(req)) {
        return refuse();
    }
    if req.path == "/health" {
        let models: Vec<&String> = shared.cfg.model_map.keys().collect();
        let model = if shared.cfg.upstream_model.is_empty() { Value::Null } else { json!(shared.cfg.upstream_model) };
        return Response::json(
            200,
            &json!({"status": "ok", "upstream": shared.cfg.upstream.url, "model": model,
                    "models": models, "pack_active": false}),
        );
    }
    Response::not_found()
}

fn handle_post(shared: &Shared, peer: IpAddr, req: &Request) -> Response {
    let p = &shared.pairing;
    let body = || read_json(req);
    match req.path.as_str() {
        "/pair-session" => {
            if !p.raw_key_ok(&presented_credential(req)) {
                return refuse();
            }
            return Response::json(
                200,
                &json!({"token": p.mint_session_token(), "expires_in": crate::pairing::SESSION_TOKEN_TTL_SECONDS}),
            );
        }
        "/pair-open" => {
            if !local_owner_ok(peer, req) {
                return refuse();
            }
            let secs = p.open_window();
            return Response::json(200, &json!({"open": true, "expires_in": secs}));
        }
        "/pair-confirm" => {
            if !local_owner_ok(peer, req) || !p.window_is_open() {
                return refuse();
            }
            return match body() {
                Ok(b) => p.confirm(&b).map(|v| Response::json(200, &v)).unwrap_or_else(pair_err),
                Err(()) => Response::error(400, "expected a JSON body with \"handshake_id\""),
            };
        }
        "/pair-cancel" => {
            if !local_owner_ok(peer, req) {
                return refuse();
            }
            p.cancel();
            return Response::json(200, &json!({"cancelled": true}));
        }
        "/pair-start" | "/pair-reveal" | "/pair-finish" => {
            if !p.window_is_open() {
                return refuse();
            }
            let (parsed, msg) = match req.path.as_str() {
                "/pair-start" => (body(), "expected a JSON body with base64 \"public_key\" and \"commitment\""),
                "/pair-reveal" => (body(), "expected a JSON body with \"handshake_id\" and a base64 \"nonce\""),
                _ => (body(), "expected a JSON body with \"handshake_id\" and \"proof\""),
            };
            let Ok(b) = parsed else { return Response::error(400, msg) };
            let r = match req.path.as_str() {
                "/pair-start" => p.start(&b),
                "/pair-reveal" => p.reveal(&b),
                _ => p.finish(&b),
            };
            return r.map(|v| Response::json(200, &v)).unwrap_or_else(pair_err);
        }
        _ => {}
    }
    if !p.credential_ok(&presented_credential(req)) {
        return refuse();
    }
    match req.path.as_str() {
        "/v1/messages/count_tokens" => handle_count_tokens(shared, req),
        "/v1/messages" => handle_messages(shared, req),
        "/chat" => handle_chat(shared, req),
        _ => Response::not_found(),
    }
}

// ------------------------------------------------------------------ /chat

fn handle_chat(shared: &Shared, req: &Request) -> Response {
    let cfg = &shared.cfg;
    let parsed = read_json(req).ok().and_then(|b| b.get("message").cloned().map(|m| (m, b.get("history").cloned())));
    let Some((message, history)) = parsed else {
        return Response::error(400, "expected a JSON body with a \"message\" string");
    };
    if cfg.upstream_model.is_empty() {
        return Response::error(500, "ARROWBRIDGE_UPSTREAM_MODEL is not set");
    }
    let mut messages = Vec::new();
    if !cfg.system_prompt.is_empty() {
        messages.push(json!({"role": "system", "content": cfg.system_prompt}));
    }
    messages.extend(clean_history(history.as_ref()));
    messages.push(json!({"role": "user", "content": message}));
    let payload = json!({"model": cfg.upstream_model, "messages": messages});
    let text = upstream::post_json(
        &cfg.upstream,
        "/v1/chat/completions",
        payload.to_string().as_bytes(),
        &cfg.upstream_key,
        Duration::from_secs(60),
    )
    .ok()
    .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
    .and_then(|d| d.pointer("/choices/0/message/content").cloned());
    let Some(text) = text else {
        bump(&STATS.upstream_errors);
        return Response::error(502, "could not reach the local model");
    };
    let reply = guard::compose_reply(text.as_str().unwrap_or(""));
    Response::json(200, &json!({"reply": reply, "model": cfg.upstream_model, "backend": "local"}))
}

// ------------------------------------------------------------------ /v1/messages

fn anthropic_payload(text: &str, stop_reason: Value, usage: Option<Value>, model: Option<&str>, default_model: &str) -> Value {
    let usage = usage.filter(truthy).unwrap_or_else(|| json!({"input_tokens": 0, "output_tokens": 0}));
    let model = model.filter(|m| !m.is_empty()).or(Some(default_model).filter(|m| !m.is_empty())).unwrap_or("local");
    json!({"id": "msg_local", "type": "message", "role": "assistant",
           "content": [{"type": "text", "text": text}], "model": model,
           "stop_reason": stop_reason, "stop_sequence": null, "usage": usage})
}

fn sse_event(kind: &str, data: &Value) -> String {
    format!("event: {kind}\ndata: {data}\n\n")
}

/// A complete, valid Messages stream built from a reply already held in full: the whole text
/// arrives as one delta, because the telephone guard needs all of it first.
pub fn build_sse_body(text: &str, stop_reason: &str, usage: Option<&Value>, model: Option<&str>, default_model: &str) -> String {
    let mut usage_map: Map<String, Value> = usage.and_then(Value::as_object).cloned().unwrap_or_default();
    let out_tokens = usage_map.get("output_tokens").cloned().unwrap_or(json!(0));
    usage_map.insert("output_tokens".into(), json!(0));
    let mut start = anthropic_payload("", Value::Null, Some(Value::Object(usage_map)), model, default_model);
    start["content"] = json!([]);
    [
        sse_event("message_start", &json!({"type": "message_start", "message": start})),
        sse_event("content_block_start", &json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})),
        sse_event("content_block_delta", &json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}})),
        sse_event("content_block_stop", &json!({"type": "content_block_stop", "index": 0})),
        sse_event("message_delta", &json!({"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": null}, "usage": {"output_tokens": out_tokens}})),
        sse_event("message_stop", &json!({"type": "message_stop"})),
    ]
    .concat()
}

fn messages_response(shared: &Shared, text: &str, stop: &str, usage: Option<Value>, stream: bool, model: Option<&str>) -> Response {
    let dm = &shared.cfg.upstream_model;
    if stream {
        return Response {
            status: 200,
            content_type: "text/event-stream",
            extra: vec![("Cache-Control", "no-cache")],
            body: build_sse_body(text, stop, usage.as_ref(), model, dm).into_bytes(),
        };
    }
    Response::json(200, &anthropic_payload(text, json!(stop), usage, model, dm))
}

fn handle_messages(shared: &Shared, req: &Request) -> Response {
    let cfg = &shared.cfg;
    // Always answers 200, even on a bad body or a dead upstream: a Messages client renders body
    // text as a chat message only on a 2xx.
    let body = match read_json(req) {
        Ok(b @ Value::Object(_)) => b,
        _ => return messages_response(shared, "(malformed request body)", STOP_REASON_DEFAULT, None, false, None),
    };
    let stream = body.get("stream").is_some_and(truthy);
    let messages = match body.get("messages") {
        Some(Value::Array(a)) if !a.is_empty() => body["messages"].clone(),
        _ => {
            return messages_response(shared, "(expected a non-empty \"messages\" array)", STOP_REASON_DEFAULT, None, stream, None);
        }
    };
    let (model_id, target) = resolve_model(shared, body.get("model").and_then(Value::as_str));
    note_model_switch(shared, &model_id);
    if model_id.is_empty() {
        return messages_response(shared, "ARROWBRIDGE_UPSTREAM_MODEL is not set", STOP_REASON_DEFAULT, None, stream, Some(&model_id));
    }
    let max_tokens = body.get("max_tokens").filter(|v| truthy(v)).cloned().unwrap_or(json!(1024));
    let mut payload = json!({"model": model_id, "messages": clean_history(Some(&messages)),
                             "max_tokens": max_tokens, "stream": false});
    if !cfg.system_prompt.is_empty() {
        payload["system"] = json!(cfg.system_prompt);
    }
    let data = upstream::post_json(&target, "/v1/messages", payload.to_string().as_bytes(), &cfg.upstream_key, Duration::from_secs(240))
        .ok()
        .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
        .filter(Value::is_object);
    let Some(data) = data else {
        bump(&STATS.upstream_errors);
        return messages_response(shared, "(could not reach the local model)", STOP_REASON_DEFAULT, None, stream, Some(&model_id));
    };
    let text: String = data
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                .map(|b| b.get("text").and_then(Value::as_str).unwrap_or(""))
                .collect()
        })
        .unwrap_or_default();
    let stop = data.get("stop_reason").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(STOP_REASON_DEFAULT);
    let usage = data.get("usage").cloned().filter(truthy);
    let reply = guard::compose_reply(&text);
    messages_response(shared, &reply, stop, usage, stream, Some(&model_id))
}

fn handle_count_tokens(shared: &Shared, req: &Request) -> Response {
    let cfg = &shared.cfg;
    let Ok(Value::Object(mut body)) = read_json(req) else {
        return Response::error(400, "malformed request body");
    };
    if cfg.upstream_model.is_empty() {
        return Response::error(500, "ARROWBRIDGE_UPSTREAM_MODEL is not set");
    }
    body.insert("model".into(), json!(cfg.upstream_model));
    match upstream::post_json(
        &cfg.upstream,
        "/v1/messages/count_tokens",
        Value::Object(body).to_string().as_bytes(),
        &cfg.upstream_key,
        Duration::from_secs(30),
    ) {
        Ok(raw) => Response { status: 200, content_type: "application/json", extra: vec![], body: raw },
        Err(_) => {
            bump(&STATS.upstream_errors);
            Response::error(502, "could not reach the local model")
        }
    }
}
