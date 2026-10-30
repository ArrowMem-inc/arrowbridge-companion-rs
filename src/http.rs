//! Just enough HTTP/1.0 for this service: one request, one response, connection closed. The
//! Python companion also spoke HTTP/1.0 (BaseHTTPRequestHandler default), so a client sees the
//! same framing.

use std::io::{Read, Write};

pub const MAX_BODY_BYTES: usize = 1 << 20;
const MAX_HEAD_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// Path with any query string removed.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// First header with this name (case-insensitive), value as sent.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub extra: Vec<(&'static str, &'static str)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, v: &serde_json::Value) -> Response {
        Response {
            status,
            content_type: "application/json",
            extra: vec![],
            body: serde_json::to_vec(v).expect("serialisable"),
        }
    }
    pub fn html(body: String) -> Response {
        Response { status: 200, content_type: "text/html; charset=utf-8", extra: vec![], body: body.into_bytes() }
    }
    pub fn not_found() -> Response {
        Response::json(404, &serde_json::json!({"error": "not found"}))
    }
    pub fn error(status: u16, msg: &str) -> Response {
        Response::json(status, &serde_json::json!({ "error": msg }))
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

pub fn write_response<W: Write>(w: &mut W, r: &Response) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.0 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    );
    for (k, v) in &r.extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    w.write_all(head.as_bytes())?;
    w.write_all(&r.body)?;
    w.flush()
}

pub enum ReadError {
    /// Peer went away or timed out: nothing to answer.
    Gone,
    /// Answer with this and close.
    Reply(Response),
}

pub fn read_request<R: Read>(r: &mut R) -> Result<Request, ReadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = find_subslice(&buf, b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(ReadError::Reply(Response::error(400, "request head too large")));
        }
        match r.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(ReadError::Gone),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut already = buf[head_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let (method, target) = match (parts.next(), parts.next()) {
        (Some(m), Some(t)) => (m.to_string(), t.to_string()),
        _ => return Err(ReadError::Reply(Response::error(400, "bad request line"))),
    };
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let path = target.split(['?', '#']).next().unwrap_or("").to_string();
    let mut req = Request { method, path, headers, body: Vec::new() };

    if req.method == "POST" {
        // The whole body is read BEFORE any gate answers (see companion_server.py do_POST): a
        // reply written over an unread body ends in a reset and the client loses the reply.
        let len = match req.header("Content-Length") {
            None => 0i64,
            Some(v) => match v.trim().parse::<i64>() {
                Ok(n) => n,
                Err(_) => return Err(ReadError::Reply(Response::error(400, "malformed Content-Length"))),
            },
        };
        if len < 0 || len as usize > MAX_BODY_BYTES {
            return Err(ReadError::Reply(Response::error(400, "invalid or oversized Content-Length")));
        }
        let len = len as usize;
        while already.len() < len {
            match r.read(&mut chunk) {
                Ok(0) | Err(_) => return Err(ReadError::Gone),
                Ok(n) => already.extend_from_slice(&chunk[..n]),
            }
        }
        already.truncate(len);
        req.body = already;
    } else if req.method != "GET" {
        return Err(ReadError::Reply(Response::error(501, "unsupported method")));
    }
    Ok(req)
}

pub fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}
