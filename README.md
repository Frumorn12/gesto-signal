# gesto-signal

> Formerly waypad-signal. The binary, unit and environment variables keep the `waypad-` prefix for now; the protocol strings are unchanged.

Rendezvous server that lets a [Gesto](https://github.com/Frumorn12/gesto) phone reach its PC from a foreign
network — mobile data, a friend's Wi-Fi, a hotel — without port forwarding and
without punching a hole in your router.

## Why this exists

The Gesto daemon ([gesto-linux](https://github.com/Frumorn12/gesto-linux)) listens on your LAN. From outside, your router's NAT makes it
unreachable, and if your ISP uses CGNAT even port forwarding will not help.

The fix is that **neither side listens**: both the daemon and the phone dial
*out* to this server over WebSocket, which NAT always allows. The server then
introduces them to each other so they can negotiate a direct WebRTC connection
via ICE. Once that succeeds the media and input flow **peer to peer**; this
server sees none of it. Only when both peers sit behind NATs hostile enough to
defeat hole punching does traffic fall back through a TURN relay.

## Trust model

This server is deliberately **not** a trusted party.

- It never sees your session content. SDP and ICE candidates pass through
  verbatim as opaque payloads; the media and input streams never touch it.
- It holds no host secrets and cannot impersonate a host.
- The peers still run the normal Gesto end-to-end handshake (P-256 ECDH,
  ECDSA host identity, AES-GCM) over the transport it helped establish. A
  malicious signaling server can deny service, not eavesdrop.

The one thing it must get right is **not letting an attacker squat on someone
else's fingerprint**, which would let them intercept connection attempts. So a
host proves ownership: it presents its public key, the server checks the key
really hashes to the claimed fingerprint, then challenges it to sign a random
nonce with the matching private key.

Authorising a *phone* is left to the host, which already keeps a trusted-device
list. This server only introduces; it does not vouch.

## Protocol

WebSocket at `/ws`, JSON messages tagged with `type`. `GET /health` returns
liveness plus host/session counts.

### Host registration

```
host → {"type":"register","fingerprint":"262f:ecde:...","public_key":"<base64>"}
host ← {"type":"challenge","nonce":"<base64, 32 bytes>"}
host → {"type":"register_proof","signature":"<base64 ECDSA P-256 ASN.1>"}
host ← {"type":"registered","fingerprint":"262f:ecde:..."}
```

The signed transcript is:

```
"WAYPAD-SIGNAL-REGISTER-v1" || fingerprint (utf-8) || nonce
```

The domain prefix keeps a signature made here from being replayable against the
Waypad control-channel handshake, which signs `WAYPAD-HANDSHAKE-v1`.

Challenges are single-use and expire after 30 seconds. A failed proof burns the
challenge.

### Phone connection

```
phone → {"type":"connect","fingerprint":"262f:ecde:..."}
phone ← {"type":"connected","session":"<uuid>"}
host  ← {"type":"peer_joined","session":"<uuid>"}
```

### Relaying

```
→ {"type":"signal","session":"<uuid>","payload":{ ...SDP or ICE... }}
← {"type":"signal","session":"<uuid>","payload":{ ...same... }}
```

`payload` is forwarded untouched. A connection may only relay into a session it
is genuinely one end of, so guessing a session id gains nothing.

### Teardown

```
→ {"type":"leave","session":"<uuid>"}
← {"type":"peer_left","session":"<uuid>","reason":"peer_disconnected"}
```

Dropping the socket has the same effect. If a host reconnects and re-registers,
the previous socket is evicted and its sessions are closed.

### Errors

`{"type":"error","reason":"<slug>","detail":"<optional>"}` with slugs
`fingerprint_mismatch`, `bad_signature`, `challenge_expired`, `host_offline`,
`host_busy`, `server_full`, `unknown_session`, `not_a_session_member`,
`not_identified`, `already_identified`, `hosts_cannot_connect`, `bad_message`,
`handshake_timeout`.

## Build and run

```bash
cargo build --release
cargo test
./target/release/waypad-signal
```

Configuration is environment-only:

| Variable | Default | Meaning |
|---|---|---|
| `WAYPAD_SIGNAL_BIND` | `0.0.0.0:47790` | Listen address |
| `WAYPAD_SIGNAL_MAX_SESSIONS_PER_HOST` | `8` | Concurrent phones per host |
| `WAYPAD_SIGNAL_MAX_HOSTS` | `512` | Registered hosts |
| `RUST_LOG` | `info` | Log filter |

## Deployment

Run it behind a reverse proxy that terminates TLS, and point the daemon and app
at `wss://`. Plain `ws://` is only appropriate for local testing: the payloads
are not secret, but TLS stops a network observer from learning who is connecting
to whom, and many mobile networks interfere with unencrypted WebSockets.

An nginx location block:

```nginx
location /ws {
    proxy_pass http://127.0.0.1:47790;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 3600s;
}
```

`proxy_read_timeout` matters: signaling sockets stay idle for long stretches
while a session is running peer to peer.

A systemd unit is in `systemd/waypad-signal.service`.

## What this does not do

- It is **not** a TURN server. When ICE hole punching fails you also need a
  relay; run [coturn](https://github.com/coturn/coturn) alongside it and hand
  the credentials to both peers. Budget real bandwidth for it — TURN carries
  the whole video stream.
- It does not authenticate phones. That is the host's job.
- It keeps no persistent state; everything lives in memory and a restart drops
  all registrations. Hosts are expected to reconnect.

## Status

Early. The protocol above is implemented and covered by unit and end-to-end
tests, but the daemon and Android clients that speak it are still being built.
