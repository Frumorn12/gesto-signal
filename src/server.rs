//! WebSocket endpoint and the per-connection state machine.

use axum::{
    Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    auth,
    protocol::{ClientMessage, PROTOCOL_VERSION, ServerMessage},
    registry::{ConnectionId, Registry},
};

/// A registration challenge is single-use and short-lived, so a leaked nonce
/// cannot be replayed later.
const CHALLENGE_TTL: Duration = Duration::from_secs(30);

/// Guards against a client parking on the socket without ever authenticating.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

pub fn router(registry: Arc<Registry>) -> Router {
    Router::new()
        .route("/ws", get(websocket_handler))
        .route("/health", get(health))
        .with_state(registry)
}

async fn health(State(registry): State<Arc<Registry>>) -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "protocol": PROTOCOL_VERSION,
        "hosts": registry.host_count(),
        "sessions": registry.session_count(),
    }))
}

async fn websocket_handler(
    upgrade: WebSocketUpgrade,
    State(registry): State<Arc<Registry>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| handle_socket(socket, registry, peer))
}

/// What a connection has proven about itself so far.
enum Role {
    Anonymous,
    AwaitingProof {
        fingerprint: String,
        public_key: Vec<u8>,
        nonce: Vec<u8>,
        issued: tokio::time::Instant,
    },
    /// The registry owns the fingerprint→connection mapping, so this is a
    /// marker: the connection has proven who it is and may relay.
    Host,
    Peer,
}

async fn handle_socket(socket: WebSocket, registry: Arc<Registry>, peer: SocketAddr) {
    let connection: ConnectionId = Uuid::new_v4();
    let (mut ws_sink, mut ws_stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();

    // One task owns the write half so the registry can push to a connection
    // from anywhere without sharing the sink.
    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let Ok(json) = serde_json::to_string(&message) else {
                continue;
            };
            if ws_sink.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
        let _ = ws_sink.close().await;
    });

    let _ = tx.send(ServerMessage::Welcome {
        protocol: PROTOCOL_VERSION,
    });
    debug!(%connection, %peer, "signaling connection opened");

    let mut role = Role::Anonymous;
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;

    loop {
        let next = tokio::select! {
            message = ws_stream.next() => message,
            _ = tokio::time::sleep_until(deadline), if matches!(role, Role::Anonymous | Role::AwaitingProof { .. }) => {
                let _ = tx.send(ServerMessage::error("handshake_timeout"));
                break;
            }
        };
        let Some(Ok(message)) = next else {
            break;
        };
        let text = match message {
            Message::Text(text) => text,
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) | Message::Binary(_) => continue,
        };
        let parsed: ClientMessage = match serde_json::from_str(text.as_str()) {
            Ok(parsed) => parsed,
            Err(err) => {
                let _ = tx.send(ServerMessage::error_with("bad_message", err.to_string()));
                continue;
            }
        };
        if !handle_message(parsed, &mut role, &registry, connection, &tx, peer) {
            break;
        }
    }

    registry.drop_connection(connection);
    drop(tx);
    let _ = writer.await;
    debug!(%connection, %peer, "signaling connection closed");
}

/// Processes one client message. Returns `false` when the connection should close.
fn handle_message(
    message: ClientMessage,
    role: &mut Role,
    registry: &Arc<Registry>,
    connection: ConnectionId,
    tx: &mpsc::UnboundedSender<ServerMessage>,
    peer: SocketAddr,
) -> bool {
    match message {
        ClientMessage::Ping => {
            let _ = tx.send(ServerMessage::Pong);
        }

        ClientMessage::Register {
            fingerprint,
            public_key,
        } => {
            if !matches!(role, Role::Anonymous) {
                let _ = tx.send(ServerMessage::error("already_identified"));
                return true;
            }
            let public_key = match auth::decode(&public_key, "public_key") {
                Ok(bytes) => bytes,
                Err(err) => {
                    let _ = tx.send(ServerMessage::error_with("bad_public_key", err.to_string()));
                    return true;
                }
            };
            if let Err(err) = auth::verify_fingerprint(&fingerprint, &public_key) {
                warn!(%peer, %fingerprint, "rejected fingerprint claim");
                let _ = tx.send(ServerMessage::error_with(
                    "fingerprint_mismatch",
                    err.to_string(),
                ));
                return true;
            }
            let nonce = match auth::random_nonce() {
                Ok(nonce) => nonce,
                Err(_) => {
                    let _ = tx.send(ServerMessage::error("internal_error"));
                    return false;
                }
            };
            let _ = tx.send(ServerMessage::Challenge {
                nonce: auth::encode(&nonce),
            });
            *role = Role::AwaitingProof {
                fingerprint,
                public_key,
                nonce,
                issued: tokio::time::Instant::now(),
            };
        }

        ClientMessage::RegisterProof { signature } => {
            let Role::AwaitingProof {
                fingerprint,
                public_key,
                nonce,
                issued,
            } = role
            else {
                let _ = tx.send(ServerMessage::error("unexpected_proof"));
                return true;
            };
            if issued.elapsed() > CHALLENGE_TTL {
                let _ = tx.send(ServerMessage::error("challenge_expired"));
                *role = Role::Anonymous;
                return true;
            }
            let signature = match auth::decode(&signature, "signature") {
                Ok(bytes) => bytes,
                Err(err) => {
                    let _ = tx.send(ServerMessage::error_with("bad_signature", err.to_string()));
                    return true;
                }
            };
            if auth::verify_registration(public_key, fingerprint, nonce, &signature).is_err() {
                warn!(%peer, %fingerprint, "registration proof failed");
                let _ = tx.send(ServerMessage::error("bad_signature"));
                // A failed proof burns the challenge; the host must start over.
                *role = Role::Anonymous;
                return true;
            }
            let fingerprint = fingerprint.clone();
            if let Err(err) = registry.register_host(&fingerprint, connection, tx.clone()) {
                let _ = tx.send(ServerMessage::error(&err.to_string()));
                return true;
            }
            let _ = tx.send(ServerMessage::Registered { fingerprint });
            *role = Role::Host;
        }

        ClientMessage::Connect { fingerprint } => {
            if matches!(role, Role::Host) {
                let _ = tx.send(ServerMessage::error("hosts_cannot_connect"));
                return true;
            }
            match registry.open_session(&fingerprint, connection, tx.clone()) {
                Ok(session) => {
                    let _ = tx.send(ServerMessage::Connected { session });
                    *role = Role::Peer;
                }
                Err(err) => {
                    debug!(%peer, %fingerprint, error = %err, "connect rejected");
                    let _ = tx.send(ServerMessage::error(&err.to_string()));
                }
            }
        }

        ClientMessage::Signal { session, payload } => {
            if matches!(role, Role::Anonymous | Role::AwaitingProof { .. }) {
                let _ = tx.send(ServerMessage::error("not_identified"));
                return true;
            }
            if let Err(err) = registry.relay(&session, connection, payload) {
                let _ = tx.send(ServerMessage::error(&err.to_string()));
            }
        }

        ClientMessage::Leave { session } => {
            registry.close_session(&session, Some(connection), "peer_left");
        }
    }
    true
}

pub async fn serve(address: SocketAddr, registry: Arc<Registry>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    info!(%address, "waypad-signal listening");
    axum::serve(
        listener,
        router(registry).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
