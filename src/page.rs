//! The two HTML pages. Both are the Python companion's pages byte for byte (see src/*.html);
//! only the three template slots on the machine-side page are filled here.

use base64::Engine;

const PAIR_PAGE: &str = include_str!("pair_page.html");
pub const PAIR_TEST_PAGE: &str = include_str!("pair_test.html");

/// Python's html.escape(s, quote=True).
pub fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#x27;"),
            c => o.push(c),
        }
    }
    o
}

/// A JSON string the way Python's json.dumps writes it (ensure_ascii on).
fn py_json_string(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) <= 0x7f => o.push(c),
            c => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    o.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    o.push('"');
    o
}

/// The exact, non-secret QR payload: compact JSON, keys sorted, address and name only.
pub fn qr_payload(address: &str, name: &str) -> String {
    format!("{{\"address\":{},\"name\":{}}}", py_json_string(address), py_json_string(name))
}

fn qr_data_uri(payload: &str) -> Option<String> {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M).ok()?;
    let svg_text = code
        .render()
        .module_dimensions(6, 6)
        .dark_color(svg::Color("#10231A"))
        .light_color(svg::Color("#FFFFFF"))
        .build();
    Some(format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(svg_text)
    ))
}

/// The machine-side GET /pair page. `address` is "" when bound to loopback.
pub fn pair_page(address: &str, name: &str) -> String {
    let (qr_block, address_display) = if address.is_empty() {
        (
            "<p class=\"p-muted\">Bind a LAN address (ARROWBRIDGE_BIND) to show a scannable code here.</p>".to_string(),
            "(loopback only, not reachable from a phone)".to_string(),
        )
    } else {
        let block = match qr_data_uri(&qr_payload(address, name)) {
            Some(src) => format!(
                "<div class=\"pair-qr\"><img alt=\"Scan with your ArrowBridge client to pair\" src=\"{src}\"></div>"
            ),
            None => "<p class=\"p-muted\">Could not generate a QR code.</p>".to_string(),
        };
        (block, address.to_string())
    };
    PAIR_PAGE
        .replace("$qr_block", &qr_block)
        .replace("$device_name", &html_escape(name))
        .replace("$address_display", &html_escape(&address_display))
}
