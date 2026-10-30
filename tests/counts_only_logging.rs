//! Counts-only logging. This file holds ONE test because the log capture is process-global.

mod common;
use arrowbridge_companion::log;
use common::*;
use serde_json::json;

#[test]
fn nothing_a_caller_sends_or_a_model_says_reaches_the_log() {
    log::capture_start();
    let up = fake_upstream();
    let url = format!("http://127.0.0.1:{}", up.port);
    let cfg = config(&[
        ("ARROWBRIDGE_PAIR_KEY", "logtest-key-MARKERKEY-0123456789"),
        ("ARROWBRIDGE_UPSTREAM_URL", &url),
        ("ARROWBRIDGE_UPSTREAM_MODEL", "m-default"),
    ]);
    let (_s, running) = start_server(cfg);
    let addr = running.addr;
    let k = [("X-ArrowBridge-Pair", "logtest-key-MARKERKEY-0123456789")];

    // Positive control: the capture really sees what is logged, so an empty result means something.
    log::event("control MARKERCONTROL");

    post_json(addr, "/chat?q=MARKERQUERY", &k, &json!({"message": "MARKERMESSAGE", "history": [{"role": "user", "content": "MARKERHISTORY"}]}));
    post_json(addr, "/v1/messages", &k, &json!({"model": "MARKERMODEL", "messages": [{"role": "user", "content": "MARKERMSG2"}]}));
    get_json(addr, "/MARKERPATH", &[("X-ArrowBridge-Pair", "MARKERWRONGKEY")]);
    post_json(addr, "/pair-open", &[], &json!({}));
    running.shutdown();

    let lines = log::capture_take();
    let all = lines.join("\n");
    assert!(all.contains("MARKERCONTROL"), "control line must be captured: {all}");
    for needle in [
        "MARKERQUERY", "MARKERMESSAGE", "MARKERHISTORY", "MARKERMODEL", "MARKERMSG2", "MARKERPATH", "MARKERWRONGKEY",
        "MARKERKEY", "127.0.0.1", "/chat", "/v1/messages", "Call", "Dial", "800", "613",
    ] {
        assert!(!all.contains(needle), "log leaked {needle:?}:\n{all}");
    }
    // The model's two telephone numbers were removed and counted, never quoted.
    assert!(all.contains("tel_guard removed=1"), "{all}");
    assert!(log::counts_line().contains("numbers_removed="));
}
