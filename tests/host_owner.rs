//! C1 (Host allowlist), C2 (owner header) and the loopback owner listener.

mod common;
use arrowbridge_companion::server::{self, Role, Shared};
use common::*;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn owner_hdr() -> [(&'static str, &'static str); 1] {
    [("X-ArrowBridge-Owner", "1")]
}

// ---- C1

#[test]
fn hostname_host_is_403_on_every_route_dns_rebinding_shape() {
    let (_s, run) = start_server(config(&[("ARROWBRIDGE_PAIR_KEY", "k-test")]));
    let addr = run.addr;
    for path in ["/pair-info", "/pair-test", "/health", "/pair-status"] {
        let (st, _, body) = raw_host(addr, "GET", path, "evil.example.com:8788", &[]);
        assert_eq!(st, 403, "{path}");
        assert!(!String::from_utf8_lossy(&body).contains("k-test"));
    }
    let (st, _, _) = raw_host(addr, "POST", "/pair-open", "rebind.test", &owner_hdr());
    assert_eq!(st, 403);
    // a name that merely looks numeric, a different private address, a missing Host
    assert_eq!(raw_host(addr, "GET", "/pair-info", "127.0.0.1.evil.test", &[]).0, 403);
    assert_eq!(raw_host(addr, "GET", "/pair-info", "192.168.9.9:8788", &[]).0, 403);
    assert_eq!(raw(addr, b"GET /pair-info HTTP/1.0\r\n\r\n").0, 403);
    // the real forms still work: loopback v4 with and without port, and localhost is NOT allowed
    assert_eq!(raw_host(addr, "GET", "/pair-info", "127.0.0.1", &[]).0, 200);
    assert_eq!(raw_host(addr, "GET", "/pair-info", &format!("127.0.0.1:{}", addr.port()), &[]).0, 200);
    assert_eq!(raw_host(addr, "GET", "/pair-info", "localhost", &[]).0, 403);
    run.shutdown();
}

#[test]
fn host_equal_to_the_lan_bind_is_allowed_and_a_third_address_is_not() {
    let bind: IpAddr = "192.168.1.20".parse().unwrap();
    let (shared, _l) = synthetic_lan(bind);
    let mk = |host: &str| arrowbridge_companion::http::Request {
        method: "GET".into(),
        path: "/health".into(),
        headers: vec![("Host".into(), host.into())],
        body: vec![],
    };
    assert!(server::host_allowed(&shared, &mk("192.168.1.20:8788")));
    assert!(server::host_allowed(&shared, &mk("127.0.0.1:8788")));
    assert!(server::host_allowed(&shared, &mk("[::1]:8788")));
    assert!(!server::host_allowed(&shared, &mk("192.168.1.21:8788")));
    assert!(!server::host_allowed(&shared, &mk("example.com")));
    assert!(!server::host_allowed(&shared, &mk("[fe80::1]:8788")));
}

fn synthetic_lan(bind: IpAddr) -> (Arc<Shared>, ()) {
    let cfg = config(&[("ARROWBRIDGE_BIND", &bind.to_string()), ("ARROWBRIDGE_PAIR_KEY", "k-test")]);
    (Arc::new(Shared::new(cfg, 8788)), ())
}

// ---- C2

#[test]
fn owner_post_without_the_header_is_403_and_with_it_works() {
    let (_s, run) = start_server(config(&[]));
    let addr = run.addr;
    // a browser simple request: cross-origin, form-ish content type, no custom header
    let (st, _, _) = request(addr, "POST", "/pair-open", &[("Origin", "http://evil.test")], Some(b"{}"));
    assert_eq!(st, 403);
    let (st, _, _) = request(addr, "POST", "/pair-cancel", &[], Some(b"{}"));
    assert_eq!(st, 403);
    let (st, _, _) = request(addr, "POST", "/pair-confirm", &[], Some(b"{}"));
    assert_eq!(st, 403);
    // the window never opened
    assert_eq!(get_json(addr, "/pair-status", &[]).0, 404);
    // wrong value is also refused
    let (st, _, _) = request(addr, "POST", "/pair-open", &[("X-ArrowBridge-Owner", "0")], Some(b"{}"));
    assert_eq!(st, 403);
    let (st, _) = post_json(addr, "/pair-open", &[], &json!({}));
    assert_eq!(st, 200);
    assert_eq!(get_json(addr, "/pair-status", &[]).0, 200);
    run.shutdown();
}

#[test]
fn the_machine_side_pair_page_sends_the_owner_header_on_all_three_posts() {
    let page = std::fs::read_to_string(format!("{}/src/pair_page.html", env!("CARGO_MANIFEST_DIR"))).unwrap();
    assert_eq!(page.matches("'X-ArrowBridge-Owner': '1'").count(), 3);
}

// ---- owner listener

fn lan_ip() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.168.255.255:9").ok().or_else(|| s.connect("10.255.255.255:9").ok())?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if v4.is_private() => Some(v4),
        _ => None,
    }
}

#[test]
fn owner_routes_are_reachable_on_loopback_and_404_on_the_lan_listener() {
    let Some(ip) = lan_ip() else {
        eprintln!("SKIP: no private LAN address on this host; the handle()-level test below still runs");
        return;
    };
    let cfg = config(&[("ARROWBRIDGE_BIND", &ip.to_string()), ("ARROWBRIDGE_PAIR_KEY", "k-test")]);
    let lan_l = server::bind_listener(SocketAddr::new(ip.into(), 0), true).unwrap();
    let own_l = server::bind_listener(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), true).unwrap();
    let (lan_addr, own_addr) = (lan_l.local_addr().unwrap(), own_l.local_addr().unwrap());
    let shared = Arc::new(Shared::new(cfg, lan_addr.port()));
    shared.owner_port.store(own_addr.port(), Ordering::SeqCst);
    let a = server::start(shared.clone(), lan_l);
    let b = server::start_role(shared.clone(), own_l, Role::Owner);

    // LAN listener, Host is its own address: owner routes are 404, never served
    assert_eq!(get_json(lan_addr, "/pair-info", &[]).0, 404);
    assert_eq!(get_json(lan_addr, "/pair", &[]).0, 404);
    assert_eq!(post_json(lan_addr, "/pair-open", &[], &json!({})).0, 404);
    // owner listener on loopback: served, with the header
    let (st, info) = get_json(own_addr, "/pair-info", &[]);
    assert_eq!(st, 200);
    assert_eq!(info["addresses"][0], format!("http://127.0.0.1:{}", own_addr.port()));
    assert_eq!(request(own_addr, "POST", "/pair-open", &[], Some(b"{}")).0, 403);
    assert_eq!(post_json(own_addr, "/pair-open", &[], &json!({})).0, 200);
    // the owner listener serves nothing but owner routes
    assert_eq!(get_json(own_addr, "/health", &[("X-ArrowBridge-Pair", "k-test")]).0, 404);
    assert_eq!(post_json(own_addr, "/pair-start", &[], &json!({})).0, 404);
    // and the LAN listener still serves its own public page
    assert_eq!(request(lan_addr, "GET", "/pair-test", &[], None).0, 200);
    a.shutdown();
    b.shutdown();
}

#[test]
fn handle_level_owner_routing_on_a_lan_bind() {
    use arrowbridge_companion::http::Request;
    let bind: IpAddr = "192.168.1.20".parse().unwrap();
    let (shared, _) = synthetic_lan(bind);
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let req = |m: &str, p: &str, host: &str, hdr: bool| Request {
        method: m.into(),
        path: p.into(),
        headers: [("Host".to_string(), host.to_string())].into_iter().chain(hdr.then(|| ("X-ArrowBridge-Owner".to_string(), "1".to_string()))).collect(),
        body: b"{}".to_vec(),
    };
    // main listener, loopback peer, owner routes: 404 even with Host and header right
    assert_eq!(server::handle(&shared, Role::Main, lo, &req("GET", "/pair-info", "127.0.0.1:8788", false)).status, 404);
    assert_eq!(server::handle(&shared, Role::Main, lo, &req("POST", "/pair-open", "127.0.0.1:8788", true)).status, 404);
    // owner listener: GET served, POST needs header
    assert_eq!(server::handle(&shared, Role::Owner, lo, &req("GET", "/pair-info", "127.0.0.1:8789", false)).status, 200);
    assert_eq!(server::handle(&shared, Role::Owner, lo, &req("POST", "/pair-open", "127.0.0.1:8789", false)).status, 403);
    assert_eq!(server::handle(&shared, Role::Owner, lo, &req("POST", "/pair-open", "127.0.0.1:8789", true)).status, 200);
    // a LAN peer reaching the owner listener (should be impossible) is still refused
    let lan_peer: IpAddr = "192.168.1.50".parse().unwrap();
    assert_eq!(server::handle(&shared, Role::Owner, lan_peer, &req("GET", "/pair-info", "127.0.0.1:8789", false)).status, 404);
}
