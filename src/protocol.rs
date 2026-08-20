//! Wire messages exchanged over the signaling WebSocket.
//!
//! The server is a dumb relay: it never inspects or stores the `payload` of a
//! `Signal` message. SDP and ICE candidates pass through verbatim, and the
//! peers authenticate each other end-to-end with the existing Waypad handshake
//! once the WebRTC transport is up.

use serde::{Deserialize, Serialize};

/// Domain separator for the registration challenge, so a signature produced
/// here can never be replayed against the Waypad control-channel handshake.
pub const REGISTER_TRANSCRIPT_PREFIX: &[u8] = b"WAYPAD-SIGNAL-REGISTER-v1";

pub const PROTOCOL_VERSION: u32 = 1;

/// Messages sent by a peer to the signaling server.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// A daemon claiming its host fingerprint. Must be followed by a proof.
    Register {
        fingerprint: String,
        public_key: String,
    },
    /// The signature over the server-issued nonce that completes registration.
    RegisterProof {
        signature: String,
    },
    /// A phone asking to be put in touch with a registered host.
    Connect {
        fingerprint: String,
    },
    /// Opaque SDP/ICE payload to forward to the other end of a session.
    Signal {
        session: String,
        payload: serde_json::Value,
    },
    /// Explicit teardown; the server also cleans up on socket close.
    Leave {
        session: String,
    },
    Ping,
}

/// Messages sent by the signaling server to a peer.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Welcome {
        protocol: u32,
    },
    /// Nonce the host must sign to prove it owns the fingerprint it claimed.
    Challenge {
        nonce: String,
    },
    Registered {
        fingerprint: String,
    },
    /// Sent to the host when a phone opens a session with it.
    PeerJoined {
        session: String,
    },
    /// Sent to the phone once the server has a live host to relay to.
    Connected {
        session: String,
    },
    Signal {
        session: String,
        payload: serde_json::Value,
    },
    PeerLeft {
        session: String,
        reason: String,
    },
    Pong,
    Error {
        reason: String,
        detail: Option<String>,
    },
}

impl ServerMessage {
    pub fn error(reason: &str) -> Self {
        Self::Error {
            reason: reason.to_string(),
            detail: None,
        }
    }

    pub fn error_with(reason: &str, detail: impl Into<String>) -> Self {
        Self::Error {
            reason: reason.to_string(),
            detail: Some(detail.into()),
        }
    }
}
