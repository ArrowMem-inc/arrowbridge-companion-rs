# arrowbridge-companion (Rust)

The ArrowBridge companion, ported from the Python `arrowbridge-companion`. It is a small local HTTP checkpoint between a model server on your own machine and the
phone that asks it questions. It pairs by a pinned key on your own LAN, binds to one address,
removes telephone numbers a model invented before a reply leaves, and talks to nothing but the
model server on this machine.

Apache-2.0. Local commits only so far; nothing here has been pushed.

## Known limits (read before you bind to a LAN address)

- **No TLS, so a LAN bind is cleartext on that LAN.** The per-phone `pc_` credential and every
  chat travel unencrypted between the phone and this machine. Anyone on the same network segment
  who can see the traffic can read and replay them. TLS is out of v0.1. v0.1 is scoped to the
  pure-LAN rung: a home network you control, nothing across the internet, no relay.
- **Host header check.** Every request must carry a Host that is an IP literal equal to the bound
  address or a loopback literal (`127.0.0.1`, `[::1]`). Anything else, including a hostname such
  as `localhost` or a missing Host, is answered 403. This closes DNS rebinding from a web page.
- **Owner routes need a custom header.** `POST /pair-open`, `/pair-confirm` and `/pair-cancel`
  require `X-ArrowBridge-Owner: 1`, which a browser simple request cannot send; without it the
  answer is 403. The machine-side pairing page sends it. This page differs from the Python page
  by that header only.
- **Second listener on a LAN bind.** When `ARROWBRIDGE_BIND` is a LAN address, the owner routes
  (`/pair`, `/pair-info`, `/pair-status`, `/pair-open`, `/pair-confirm`, `/pair-cancel`) are NOT
  served on it (404). A second listener on `127.0.0.1:ARROWBRIDGE_OWNER_PORT` (default: the main
  port plus one) serves only those routes, so the desktop app can pair. On a loopback bind there
  is one listener and nothing changes.
- A failed pairing step from a LAN neighbour can still close the open pairing window (C4, not
  fixed here).

## How it replaces the Python

Same environment variables, same routes, same JSON, same pairing handshake. Stop the Python
service, start this one, and a phone paired against the Python companion pairs against this one
without change (credentials are in memory in both, so a restart means re-pairing either way).

```
cargo build --release
install -Dm755 target/release/arrowbridge-companion ~/.local/bin/arrowbridge-companion
```

Then the user unit: `contrib/arrowbridge-companion.service` and `contrib/companion.env.example`
(the install lines are at the top of the unit file).

## Why it exists: the restart bug

The Python server was a `ThreadingTCPServer` with `allow_reuse_address` False. After a restart,
connections from the old process sit in TIME_WAIT and the new bind fails with "address in use"
for up to a minute, so the service looked dead after every restart. Here the listener is built
with `socket2` and `SO_REUSEADDR` is set explicitly (`server::bind_listener`).
`tests/restart_and_bind.rs` restarts three times on one port, and a paired test shows the same
sequence WITHOUT the flag fails with `AddrInUse`, so the restart test cannot pass by accident.

## The bind rule (stricter than the Python)

`ARROWBRIDGE_BIND` is one address. Allowed: loopback, RFC 1918 private (10/8, 172.16/12,
192.168/16), IPv4 link-local, IPv6 unique-local and link-local. Refused with exit status 2 before
any socket opens: `0.0.0.0`, `::`, every public address, the 100.64/10 shared range, multicast,
and the documentation ranges. Unset means `127.0.0.1`. The Python refused only the two wildcards.

## What is identical

- Every route and its gate order: `/chat`, `/v1/messages` (including the always-200 behaviour and
  the one-delta SSE body), `/v1/messages/count_tokens`, `/health`, `/pair-test`, `/pair-info`,
  `/pair`, `/pair-open`, `/pair-status`, `/pair-confirm`, `/pair-cancel`, `/pair-start`,
  `/pair-reveal`, `/pair-finish`, `/pair-session`. Unpaired callers get 404, never 401.
- The handshake: X25519, mutual commit-then-reveal with SHA-256, HKDF-SHA256 with the same salts
  and `info` labels, a four digit code, an HMAC-SHA256 proof, the per-phone credential sealed with
  AES-256-GCM under the session key with the handshake id as AAD, a 180 second window.
- Header forms (`X-ArrowBridge-Pair` or a bearer token), the 1 MiB body cap read before any gate,
  60 s socket timeout, HTTP/1.0 framing.
- The telephone guard, regex and cleanup passes included. 911 survives, everything else goes.
- The machine-side pairing page and the test page, byte for byte.
- The QR payload (compact JSON, sorted keys, ASCII-escaped).
- The mDNS service name `_arrowbridge._tcp.local.` and its two TXT keys.

How that was checked: the Python companion was run against a fake model server and every
response was recorded (`tests/fixtures`), plus a full handshake with fixed phone material, twenty
random derivations and a 20-string guard corpus. The Rust tests replay all of it. The Python
phone-side test driver was also run against the release binary and paired.

## What changed

- Bind policy (above).
- Counts-only logging. The Python logged the peer address and path of every request. This logs
  fixed event names and counters, never a path, query, address, key, token, body or reply, and
  `tests/counts_only_logging.rs` fails if any marker leaks. A generated pairing key is no longer
  printed to the log; read it at `GET /pair-info` on this machine.
- SO_REUSEADDR (above).
- TLS is not in this build. If `ARROWBRIDGE_TLS_CERT` or `_KEY` is set the service refuses to
  start rather than quietly serving plaintext.
- The upstream and every model-map URL must be `http://`.
- The optional `arrowbridge_pack` Python hook (a footer, a second redaction pass, extra allowed
  numbers) is not ported. The Python repo ships none, so reply behaviour is unchanged.
- `ARROWBRIDGE_PAIR_KEY_FILE` is read by the binary itself (the shell wrapper did that before).
- `GET /pair-test?key=...` now serves the page. In the Python the query string made the path
  not match and the page was a 404, contrary to its README.
- mDNS advertises only the bound address, not every local IPv4 address.
- A low-order X25519 public key in `/pair-start` is a 400 (the Python would 500).
- At most 64 connections at once.
- No `arrowmem-core` dependency: the Python never used the sealed envelope. Its cryptography is
  the standard primitives above, ported to maintained crates (`x25519-dalek`, `hkdf`, `hmac`,
  `sha2`, `aes-gcm`); nothing is invented.

## Known, carried over from the Python

- With a LAN bind the owner routes (`/pair`, `/pair-open`, `/pair-status`, `/pair-confirm`,
  `/pair-cancel`, `/pair-info`) are unreachable: they demand a loopback peer, and a process on
  this machine reaching the LAN address arrives from that address, while nothing listens on
  loopback. Measured: 404 via the LAN address, connection refused via 127.0.0.1.
- Any unusable `/pair-finish` closes the open window, so anyone on the LAN can close the owner's
  180 second window by posting a bogus id.

## Tests

```
cargo test
cargo clippy --all-targets -- -D warnings
```

`mdns` is a default feature; `--no-default-features` builds without it.

## License

Apache-2.0. See `LICENSE`.
