//! The two HTML pages and the QR payload against what the Python rendered.

mod common;
use arrowbridge_companion::page::{html_escape, pair_page, qr_payload};
use common::fixture;

#[test]
fn loopback_pair_page_is_byte_identical_to_the_python_page() {
    let want = std::fs::read_to_string(format!("{}/tests/fixtures/pair_page_loopback.html", env!("CARGO_MANIFEST_DIR"))).unwrap();
    assert_eq!(pair_page("", "fixture-box"), want);
}

#[test]
fn qr_payload_is_byte_identical_to_the_python_json() {
    let vectors = fixture("qr_payloads.json");
    for v in vectors.as_array().unwrap() {
        assert_eq!(qr_payload(v["address"].as_str().unwrap(), v["name"].as_str().unwrap()), v["payload"].as_str().unwrap());
    }
    assert_eq!(vectors.as_array().unwrap().len(), 4);
}

#[test]
fn html_escape_matches_python() {
    for v in fixture("html_escape.json").as_array().unwrap() {
        assert_eq!(html_escape(v["in"].as_str().unwrap()), v["out"].as_str().unwrap());
    }
}

#[test]
fn lan_pair_page_carries_a_qr_and_an_escaped_name_and_never_a_key() {
    let page = pair_page("http://192.168.1.20:8788", "Box <1>");
    assert!(page.contains("data:image/svg+xml;base64,"));
    assert!(page.contains("Box &lt;1&gt;"));
    assert!(page.contains("http://192.168.1.20:8788"));
    assert!(!page.contains("$qr_block") && !page.contains("$device_name") && !page.contains("$address_display"));
}
