use arrowbridge_companion::config::Config;
use arrowbridge_companion::server::{self, Shared};
use arrowbridge_companion::{discovery, log};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn refuse(msg: &str) -> ! {
    eprintln!("ArrowBridge REFUSES TO START.\n  {msg}");
    std::process::exit(2);
}

fn main() {
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => refuse(&e.0),
    };
    // SO_REUSEADDR is always on: a restart must never strand the service in TIME_WAIT.
    let listener = match server::bind_listener(SocketAddr::new(cfg.bind, cfg.port), true) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ArrowBridge could not bind its port ({:?}).", e.kind());
            std::process::exit(1);
        }
    };
    if cfg.key_generated {
        log::event("pair_key_generated_for_this_run (read it at GET /pair-info on this machine; set ARROWBRIDGE_PAIR_KEY or ARROWBRIDGE_PAIR_KEY_FILE to keep one across restarts)");
    }
    log::event(&format!(
        "listening lan_exposed={} models_configured={} upstream_model_set={}",
        cfg.lan_exposed(),
        cfg.model_map.len(),
        !cfg.upstream_model.is_empty()
    ));
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(cfg.port);

    #[cfg(feature = "mdns")]
    let advertiser = if cfg.lan_exposed() && cfg.discovery {
        match discovery::Advertiser::start(cfg.bind, port, &cfg.device_name) {
            Ok(a) => Some(a),
            Err(_) => {
                log::event("mdns_unavailable (the companion still works; a phone needs the address typed in)");
                None
            }
        }
    } else {
        None
    };
    #[cfg(not(feature = "mdns"))]
    let _ = &discovery::SERVICE_TYPE;

    let lan = cfg.lan_exposed();
    let owner_bind = SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), cfg.owner_port);
    let shared = Arc::new(Shared::new(cfg, port));
    // On a LAN bind the owner routes (pairing page, window, confirm) are served only here.
    let owner = if lan {
        match server::bind_listener(owner_bind, true) {
            Ok(l) => {
                let op = l.local_addr().map(|a| a.port()).unwrap_or(0);
                shared.owner_port.store(op, std::sync::atomic::Ordering::SeqCst);
                Some(server::start_role(shared.clone(), l, server::Role::Owner))
            }
            Err(e) => {
                eprintln!("ArrowBridge could not bind its loopback owner port ({:?}).", e.kind());
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    let running = server::start(shared, listener);

    std::thread::spawn(|| {
        let mut last = String::new();
        loop {
            std::thread::sleep(Duration::from_secs(300));
            let now = log::counts_line();
            if now != last {
                log::event(&now);
                last = now;
            }
        }
    });

    // Block until SIGTERM or SIGINT, then stop announcing and release the port.
    let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT])
        .expect("install signal handlers");
    let _ = signals.forever().next();
    #[cfg(feature = "mdns")]
    if let Some(a) = advertiser {
        a.stop();
    }
    if let Some(o) = owner {
        o.shutdown();
    }
    running.shutdown();
    log::event(&log::counts_line());
}
