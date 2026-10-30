//! The restart bug (a restart strands the port) and the bind policy (never public).

mod common;
use arrowbridge_companion::config::{Config, check_bind};
use arrowbridge_companion::server::{self, Shared};
use common::*;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::Arc;

fn serve_on(addr: SocketAddr, reuse: bool) -> std::io::Result<arrowbridge_companion::server::RunningServer> {
    let listener = server::bind_listener(addr, reuse)?;
    let port = listener.local_addr()?.port();
    let shared = Arc::new(Shared::new(config(&[]), port));
    Ok(server::start(shared, listener))
}

/// One served request leaves the connection in TIME_WAIT on the server side, which is exactly
/// the state a restarted service finds its port in.
fn leave_time_wait(addr: SocketAddr) {
    let (status, _, _) = request(addr, "GET", "/pair-test", &[], None);
    assert_eq!(status, 200);
}

#[test]
fn restart_on_the_same_port_succeeds_repeatedly() {
    let first = serve_on("127.0.0.1:0".parse().unwrap(), true).unwrap();
    let addr = first.addr;
    leave_time_wait(addr);
    first.shutdown();
    for round in 0..3 {
        let again = serve_on(addr, true).unwrap_or_else(|e| panic!("restart {round} on port {} failed: {e}", addr.port()));
        assert_eq!(again.addr, addr);
        leave_time_wait(addr);
        again.shutdown();
    }
}

/// Falsification of the test above: the same sequence WITHOUT SO_REUSEADDR (what Python's
/// ThreadingTCPServer did with allow_reuse_address False) must fail. If this ever starts
/// passing, the restart test above has stopped proving anything.
#[test]
fn without_reuse_addr_the_same_restart_is_stranded() {
    let first = serve_on("127.0.0.1:0".parse().unwrap(), true).unwrap();
    let addr = first.addr;
    leave_time_wait(addr);
    first.shutdown();
    let err = server::bind_listener(addr, false).expect_err("a bind without SO_REUSEADDR should hit TIME_WAIT");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
}

#[test]
fn bind_policy_table() {
    let ok = ["127.0.0.1", "127.9.9.9", "::1", "192.168.1.20", "10.1.2.3", "172.16.5.5", "172.31.255.1", "169.254.1.1", "fd00::1", "fe80::1"];
    for a in ok {
        assert!(check_bind(a.parse::<IpAddr>().unwrap()).is_ok(), "{a} should be allowed");
    }
    let refused = [
        "0.0.0.0", "::", "8.8.8.8", "1.1.1.1", "100.64.0.1", "172.32.0.1", "172.15.0.1", "192.0.2.10",
        "224.0.0.251", "255.255.255.255", "2001:4860:4860::8888", "::ffff:8.8.8.8",
    ];
    for a in refused {
        assert!(check_bind(a.parse::<IpAddr>().unwrap()).is_err(), "{a} should be refused");
    }
}

#[test]
fn config_refuses_public_binds_and_tls_it_cannot_serve() {
    for bad in ["0.0.0.0", "::", "8.8.8.8", "100.64.1.1", "not-an-ip"] {
        let map = [("ARROWBRIDGE_BIND".to_string(), bad.to_string())];
        let r = Config::from_lookup(&|k| map.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()));
        assert!(r.is_err(), "{bad} must be refused");
    }
    let tls = [("ARROWBRIDGE_TLS_CERT".to_string(), "/x".to_string())];
    assert!(Config::from_lookup(&|k| tls.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())).is_err());
    // Unset means loopback.
    let c = Config::from_lookup(&|_| None).unwrap();
    assert_eq!(c.bind, "127.0.0.1".parse::<IpAddr>().unwrap());
    assert!(!c.lan_exposed());
}

/// The real binary, as systemd would start it: a public or wildcard bind exits 2 before any
/// socket is opened.
#[test]
fn the_binary_refuses_to_start_on_a_public_bind() {
    let exe = env!("CARGO_BIN_EXE_arrowbridge-companion");
    for bad in ["0.0.0.0", "::", "8.8.8.8"] {
        let out = Command::new(exe)
            .env_clear()
            .env("ARROWBRIDGE_BIND", bad)
            .env("ARROWBRIDGE_PORT", "0")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "bind {bad}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("REFUSES TO START"), "bind {bad}");
    }
}
