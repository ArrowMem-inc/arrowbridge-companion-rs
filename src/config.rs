//! Configuration from the same ARROWBRIDGE_* variables the Python companion read.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// Path prefix, no trailing slash ("" for none).
    pub base: String,
    /// The URL as configured, trailing slash trimmed (reported by /health).
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: IpAddr,
    pub port: u16,
    /// Loopback-only listener for the owner routes, used when `bind` is a LAN address.
    pub owner_port: u16,
    pub upstream: Target,
    pub upstream_model: String,
    pub upstream_key: String,
    pub pair_key: String,
    pub key_generated: bool,
    pub model_map: BTreeMap<String, (String, Target)>,
    pub system_prompt: String,
    pub device_name: String,
    pub discovery: bool,
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The bind policy. Loopback or a private LAN address only. Anything that listens on every
/// interface, or on an address that is routable on the public internet, is refused.
pub fn check_bind(ip: IpAddr) -> Result<(), String> {
    if ip.is_unspecified() {
        return Err(format!(
            "ARROWBRIDGE_BIND={ip} listens on every interface this machine has. Name the one \
             address of the interface your phone shares with this machine instead."
        ));
    }
    if ip.is_loopback() {
        return Ok(());
    }
    match ip {
        IpAddr::V4(v4) => {
            // is_private: 10/8, 172.16/12, 192.168/16. is_link_local: 169.254/16.
            if v4.is_private() || v4.is_link_local() {
                Ok(())
            } else {
                Err(format!(
                    "ARROWBRIDGE_BIND={v4} is not a loopback, private (RFC 1918) or link-local \
                     address. The LAN rung never binds a public or shared-range address."
                ))
            }
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            let unique_local = first & 0xfe00 == 0xfc00;
            let link_local = first & 0xffc0 == 0xfe80;
            if unique_local || link_local {
                Ok(())
            } else {
                Err(format!(
                    "ARROWBRIDGE_BIND={v6} is not a loopback, unique-local or link-local address."
                ))
            }
        }
    }
}

pub fn parse_http_url(raw: &str) -> Result<Target, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let rest = trimmed.strip_prefix("http://").ok_or_else(|| {
        format!("upstream URL must start with http:// (this build talks plain HTTP to a local model server): {trimmed}")
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err("upstream URL has no host".into());
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']').ok_or("unterminated [ in upstream URL")?;
        let host = &stripped[..end];
        let after = &stripped[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| "bad upstream port")?,
            None => 80,
        };
        (host.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().map_err(|_| "bad upstream port")?)
    } else {
        (authority.to_string(), 80)
    };
    Ok(Target { host, port, base: path.trim_end_matches('/').to_string(), url: trimmed.to_string() })
}

/// ARROWBRIDGE_MODEL_MAP: comma separated NAME=upstream_model[@url].
pub fn parse_model_map(raw: &str, default: &Target) -> Result<BTreeMap<String, (String, Target)>, String> {
    let mut out = BTreeMap::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, rest) = part.split_once('=').unwrap_or((part, ""));
        let name = name.trim();
        let rest = if rest.trim().is_empty() { name } else { rest.trim() };
        let (model, url) = rest.split_once('@').unwrap_or((rest, ""));
        let target = if url.trim().is_empty() { default.clone() } else { parse_http_url(url)? };
        out.insert(name.to_string(), (model.trim().to_string(), target));
    }
    Ok(out)
}

fn random_urlsafe(n: usize) -> String {
    use base64::Engine;
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("os randomness");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

pub fn token_urlsafe(n: usize) -> String {
    random_urlsafe(n)
}

impl Config {
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
        let var = |k: &str| get(k).unwrap_or_default();
        let bind_raw = var("ARROWBRIDGE_BIND");
        let bind_raw = bind_raw.trim();
        let bind: IpAddr = match bind_raw {
            "" | "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            other => other.parse().map_err(|_| {
                ConfigError(format!("ARROWBRIDGE_BIND must be an IP address, got {other:?}"))
            })?,
        };
        check_bind(bind).map_err(ConfigError)?;

        let port = match var("ARROWBRIDGE_PORT").trim() {
            "" => 8788,
            p => p.parse::<u16>().map_err(|_| ConfigError("ARROWBRIDGE_PORT is not a port number".into()))?,
        };
        let owner_port = match var("ARROWBRIDGE_OWNER_PORT").trim() {
            "" => port.checked_add(1).unwrap_or(0),
            p => p.parse::<u16>().map_err(|_| ConfigError("ARROWBRIDGE_OWNER_PORT is not a port number".into()))?,
        };
        let upstream_raw = match var("ARROWBRIDGE_UPSTREAM_URL").trim() {
            "" => "http://127.0.0.1:8080".to_string(),
            u => u.to_string(),
        };
        let upstream = parse_http_url(&upstream_raw).map_err(ConfigError)?;
        let upstream_key = get("ARROWBRIDGE_UPSTREAM_KEY").unwrap_or_else(|| "local".to_string());
        let model_map = parse_model_map(&var("ARROWBRIDGE_MODEL_MAP"), &upstream).map_err(ConfigError)?;

        // Pairing key: env, else a 0600 key file (what start-companion.sh did), else generated.
        let mut pair_key = var("ARROWBRIDGE_PAIR_KEY").trim().to_string();
        if pair_key.is_empty() {
            let file = var("ARROWBRIDGE_PAIR_KEY_FILE");
            let file = file.trim();
            if !file.is_empty() {
                pair_key = std::fs::read_to_string(file)
                    .map_err(|e| ConfigError(format!("ARROWBRIDGE_PAIR_KEY_FILE did not load ({:?})", e.kind())))?
                    .trim()
                    .to_string();
                if pair_key.is_empty() {
                    return Err(ConfigError("ARROWBRIDGE_PAIR_KEY_FILE is empty".into()));
                }
            }
        }
        let key_generated = pair_key.is_empty();
        if key_generated {
            pair_key = random_urlsafe(32);
        }

        // TLS is not in this build. Python served TLS when both variables were set; silently
        // serving plaintext instead would be worse than refusing.
        if !var("ARROWBRIDGE_TLS_CERT").trim().is_empty() || !var("ARROWBRIDGE_TLS_KEY").trim().is_empty() {
            return Err(ConfigError(
                "ARROWBRIDGE_TLS_CERT/_KEY are set but this build has no TLS. Unset both to run in \
                 pairing-key-only mode."
                    .into(),
            ));
        }

        let prompt_path = var("ARROWBRIDGE_SYSTEM_PROMPT_FILE");
        let prompt_path = prompt_path.trim();
        let system_prompt = if prompt_path.is_empty() {
            String::new()
        } else {
            std::fs::read_to_string(prompt_path)
                .map_err(|e| ConfigError(format!("ARROWBRIDGE_SYSTEM_PROMPT_FILE did not load ({:?})", e.kind())))?
                .trim()
                .to_string()
        };

        let device_name = {
            let n = var("ARROWBRIDGE_DEVICE_NAME");
            let n = n.trim();
            if n.is_empty() { hostname() } else { n.to_string() }
        };
        Ok(Config {
            bind,
            port,
            owner_port,
            upstream,
            upstream_model: var("ARROWBRIDGE_UPSTREAM_MODEL"),
            upstream_key,
            pair_key,
            key_generated,
            model_map,
            system_prompt,
            device_name,
            discovery: var("ARROWBRIDGE_NO_DISCOVERY").trim() != "1",
        })
    }

    pub fn from_env() -> Result<Config, ConfigError> {
        Config::from_lookup(&|k| std::env::var(k).ok())
    }

    pub fn lan_exposed(&self) -> bool {
        !self.bind.is_loopback()
    }
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "arrowbridge".to_string())
}
