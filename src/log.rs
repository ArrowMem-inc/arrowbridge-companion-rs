//! Counts-only logging. Nothing here ever receives a request body, a reply, a path, a query
//! string, a peer address, a key or a token: the only inputs are fixed event names and numbers.
//! The Python companion logged the peer address and path of every request; this one does not.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Stats {
    pub requests: AtomicU64,
    pub refused: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub numbers_removed: AtomicU64,
    pub pairings: AtomicU64,
    pub dropped_connections: AtomicU64,
}

pub static STATS: Stats = Stats {
    requests: AtomicU64::new(0),
    refused: AtomicU64::new(0),
    upstream_errors: AtomicU64::new(0),
    numbers_removed: AtomicU64::new(0),
    pairings: AtomicU64::new(0),
    dropped_connections: AtomicU64::new(0),
};

static CAPTURE: Mutex<Option<Vec<String>>> = Mutex::new(None);

pub fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// One fixed-vocabulary line. Callers pass literals and numbers, never user content.
pub fn event(line: &str) {
    if let Ok(mut guard) = CAPTURE.lock() {
        if let Some(buf) = guard.as_mut() {
            buf.push(line.to_string());
        }
    }
    eprintln!("arrowbridge: {line}");
}

/// The counters as one line.
pub fn counts_line() -> String {
    let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
    format!(
        "counts requests={} refused={} upstream_errors={} numbers_removed={} pairings={} dropped_connections={}",
        g(&STATS.requests),
        g(&STATS.refused),
        g(&STATS.upstream_errors),
        g(&STATS.numbers_removed),
        g(&STATS.pairings),
        g(&STATS.dropped_connections)
    )
}

pub fn capture_start() {
    *CAPTURE.lock().unwrap() = Some(Vec::new());
}

pub fn capture_take() -> Vec<String> {
    CAPTURE.lock().unwrap().take().unwrap_or_default()
}
