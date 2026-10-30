//! Telephone guard. Port of tel_guard.py: any North American number, any five or six digit run
//! and 988 are removed from a reply; 911 survives. Removed, not masked.

use fancy_regex::Regex;
use std::sync::OnceLock;

fn tel() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Same pattern as the Python, including the lookbehind (hence fancy-regex).
        Regex::new(r"(?<![\d-])(?:1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b|\b\d{5,6}\b|\b9(?:11|88)\b")
            .expect("static pattern")
    })
}

fn multi_space() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[ \t]{2,}").expect("static pattern"))
}

fn space_before_punct() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r" ([.,;:!?])").expect("static pattern"))
}

/// Returns (cleaned_text, removed_strings). Only "911" is allowed through.
pub fn redact(text: &str) -> (String, Vec<String>) {
    let mut offenders = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in tel().find_iter(text).flatten() {
        out.push_str(&text[last..m.start()]);
        let found = m.as_str();
        if found == "911" {
            out.push_str(found);
        } else {
            offenders.push(found.to_string());
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    if !offenders.is_empty() {
        crate::log::event(&format!("tel_guard removed={}", offenders.len()));
        crate::log::STATS
            .numbers_removed
            .fetch_add(offenders.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }
    let collapsed = multi_space().replace_all(&out, " ");
    let tidy = space_before_punct().replace_all(&collapsed, "$1");
    (tidy.into_owned(), offenders)
}

/// What the user sees for one turn (compose_reply with no safety module): redact, then strip.
pub fn compose_reply(model_text: &str) -> String {
    redact(model_text).0.trim().to_string()
}
