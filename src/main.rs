//! Waypad signaling server.
//!
//! A minimal, deliberately untrusted rendezvous point. Both the Linux daemon
//! and the Android app dial *out* to it, which is what makes Waypad reachable
//! from a foreign network without port forwarding. It relays WebRTC SDP offers
//! and ICE candidates and nothing else: it cannot decrypt a Waypad session and
//! holds no host secrets.

use std::{env, net::SocketAddr};
use tracing_subscriber::EnvFilter;
use waypad_signal::{
    registry::{Limits, Registry},
    server,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let address: SocketAddr = env::var("WAYPAD_SIGNAL_BIND")
        .unwrap_or_else(|_| "0.0.0.0:47790".to_string())
        .parse()?;
    let limits = Limits {
        max_sessions_per_host: parse_env("WAYPAD_SIGNAL_MAX_SESSIONS_PER_HOST", 8),
        max_hosts: parse_env("WAYPAD_SIGNAL_MAX_HOSTS", 512),
    };

    server::serve(address, Registry::new(limits)).await
}

fn parse_env(key: &str, fallback: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}
