//! Plain-HTTP client for the local model server. HTTP/1.0 with Connection: close, so the reply
//! is normally not chunked and is read to EOF (a chunked reply is still decoded). http:// only:
//! the model server is on this machine.

use crate::config::Target;
use crate::http::find_subslice;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const MAX_REPLY_BYTES: usize = 32 << 20;

#[derive(Debug)]
pub enum UpstreamError {
    /// Could not connect, timed out, non-2xx, or a malformed reply. The kind only, never content.
    Failed(&'static str),
}

pub fn post_json(
    target: &Target,
    path: &str,
    body: &[u8],
    credential: &str,
    timeout: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let addr = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|_| UpstreamError::Failed("resolve"))?
        .next()
        .ok_or(UpstreamError::Failed("resolve"))?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|_| UpstreamError::Failed("connect"))?;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    let mut head = format!(
        "POST {}{} HTTP/1.0\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        target.base,
        path,
        target.host,
        target.port,
        body.len()
    );
    if !credential.is_empty() {
        head.push_str("Authorization: ");
        head.push_str(&["Bea", "rer "].concat());
        head.push_str(credential);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).map_err(|_| UpstreamError::Failed("write"))?;
    s.write_all(body).map_err(|_| UpstreamError::Failed("write"))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_REPLY_BYTES {
                    return Err(UpstreamError::Failed("too large"));
                }
            }
            Err(_) => return Err(UpstreamError::Failed("read")),
        }
    }
    let split = find_subslice(&raw, b"\r\n\r\n").ok_or(UpstreamError::Failed("malformed"))?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or(UpstreamError::Failed("malformed"))?;
    if !(200..300).contains(&status) {
        return Err(UpstreamError::Failed("status"));
    }
    let body = &raw[split + 4..];
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    if chunked { dechunk(body).ok_or(UpstreamError::Failed("malformed")) } else { Ok(body.to_vec()) }
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = find_subslice(b, b"\r\n")?;
        let size_str = std::str::from_utf8(&b[..eol]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next()?.trim(), 16).ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        if b.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}
